/*
 * hookManager.c —— PTE hook 核心管理（多槽位版）
 *
 * 主链路：
 *   安装：读原页 → ghost_alloc 分配 ghost 页 → dbi_recompile_page 重编译
 *         → 写入 ghost 物理页 → 同步 i-cache → 填写槽位并武装
 *         → 设置目标页 UXN
 *   触发：do_mem_abort 前置（main.c）→ hook_handle_fault()
 *         → 按 (pid, 页地址) 匹配槽位 → 查 offset_map 得到 ghost PC
 *         → 改写用户态 pc → 跳过原函数
 *   卸载：解除武装 → 恢复原 PTE → ghost_free 释放 ghost 页 → 清空槽位
 *
 * 多 hook 模型：
 *   - UXN 以页为单位，一个槽位对应一个 4KB 目标页；
 *   - 同页多个函数入口共享槽位，登记在 addrs[]（仅决定命中时是否 dump）；
 *   - 槽位表共 MAX_RECORD 项；安装路径由单线程 workqueue 串行化，
 *     fault 路径（kprobe 原子上下文）只读槽位，发布/撤下靠
 *     "字段填完 → smp_wmb → armed=true" / "armed=false → smp_wmb → 释放" 保证。
 *
 * 上下文分层（重要）：
 *   kprobe 前置处理运行在 BRK 异常上下文（关中断、禁睡眠），
 *   install_hook / hook_request_uninstall 只分配请求项并入队，
 *   真正的安装/卸载（do_install / do_uninstall）由 kworker
 *   在进程上下文执行，可以随便睡眠。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/workqueue.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "hookManager.h"
#include "callback.h"

#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

/* ghost 页搜索半径：以目标页为中心前后 32MB */
#define HOOK_GHOST_RANGE    (32UL * 1024 * 1024)
/* ghost 页数：重编译单页的典型膨胀 < 4 倍，4 页（16KB，order-2）足够；
 * 更高阶的连续物理页在内存紧张时容易卡在分配里（此前 hang 的嫌疑点） */
#define HOOK_GHOST_PAGES    4

/* 请求类型 */
#define BP_OP_INSTALL   1
#define BP_OP_UNINSTALL 2


/*
 * 多 hook 支持：
 *   - UXN 以页为单位，一个槽位（hook_record）对应一个 4KB 目标页；
 *   - 同一页内的多个函数入口共享一个槽位（同一次 ghost 分配与 UXN 设置），
 *     入口地址登记在槽位的 addrs[] 表里，仅用于"精确命中时 dump 参数"，
 *     重定向对整页生效；
 *   - 槽位总数 MAX_RECORD，超出后新安装被拒绝。
 */
#define MAX_RECORD           16
#define HOOK_ADDRS_PER_PAGE  8


/*
 * BRK 探针：观察"ghost 页内某偏移被执行"的时刻。
 * 原理：执行流被 UXN 重定向进 ghost 后就不再产生异常，页内中途点
 * 内核感知不到。因此在 ghost 里观察点对应位置覆盖一条 BRK 指令，
 * 触发 EL0 BRK 异常（EC=0x3C），由 do_debug_exception 的 kprobe 接管：
 * dump 寄存器现场后，把 pc 改到 ghost 末尾的"清扫槽"（被覆盖指令的
 * 重生成副本 + 跳回正常后继的 B），执行流无损继续。
 */
#define BRK_MAGIC       0xBE00U     /* BRK imm16 高字节魔数，低字节为探针编号 */
#define BRK_INSN(id)    (0xD4200000U | ((BRK_MAGIC | (uint32_t)(id)) << 5))

struct brk_probe {
    int          used;
    unsigned int idx;          /* 观察点在原页的指令索引 */
    unsigned int ghost_idx;    /* BRK 覆盖位置（ghost 字索引） */
    unsigned int cleanup_idx;  /* 清扫槽起始（ghost 字索引） */
};

/* 单个 hook 槽位：对应一个被 UXN 武装的 4KB 目标页 */
struct hook_record {
    int             used;           /* 槽位占用标志（槽位管理用，fault 路径看 armed） */
    pid_t           pid;            /* 目标进程 tgid */
    unsigned long   target_page;    /* 目标页基址 */
    uint64_t        orig_pte;       /* 设 UXN 前的原始 PTE 值（做 ghost 模板用） */
    GhostMemoryData ghost;          /* ghost 页元数据（含 offsets 映射表） */
    bool            armed;          /* 武装标志：为 true 时 abort 路径才接管 */


    int             n_addrs;        /* 本页观察的函数入口数 */
    unsigned long   addrs[HOOK_ADDRS_PER_PAGE]; //	一页内会包含很多个函数，同一个页内被hook 的函数地址，这里记录的是原始函数的地址
    int             dbg_cnt;        /* 本槽位重定向日志限幅计数 */

    int             ghost_words;    /* ghost 已写入总字数（含收尾跳转与清扫槽） */
    int             trailer_idx;    /* 页尾收尾跳转的 ghost 字索引 */
    uint32_t        orig_page[DBI_TARGET_INSNS]; /* 原页指令备份（运行时加/删探针重定位用） */
    struct brk_probe probes[HOOK_ADDRS_PER_PAGE];
};

/* do_debug_exception kprobe 是否就位：未就位时不能打 BRK 探针
 * （否则 BRK 触发后无人接管，目标进程会吃 SIGTRAP 崩掉） */
static int g_brk_enabled;

void hook_manager_brk_enable(int enabled)
{
    g_brk_enabled = enabled;
}

/*
 * workqueue 请求项：kprobe 前置里分配（GFP_ATOMIC）并入队，
 * kworker 回调里 container_of 取回、用完后必须 kfree。
 * 注意：必须在使用 container_of 之前给出完整定义，
 * 否则报 "incomplete definition of type" 编译错误。
 */
struct bp_request {
    struct work_struct work;    /* 内嵌工作项 */
    int      op;                /* BP_OP_INSTALL / BP_OP_UNINSTALL */
    int      has_task;          /* 卸载时：1=按 t 卸指定地址，0=全部卸载 */
    HookTask t;                 /* 安装/卸载参数（按值拷贝，之后与用户态内存无关） */
};

static struct hook_record g_recs[MAX_RECORD];
static follow_pte_t     g_follow_pte;
static copy_from_user_nofault_t g_copy_from_user;
static struct workqueue_struct *bp_wq;

/* 重定向调试日志限幅（定位完问题可关） */
#define FAULT_DEBUG_MAX 32

void hook_manager_init(follow_pte_t follow, copy_from_user_nofault_t copy)
{
    g_follow_pte = follow;
    g_copy_from_user = copy;
}

/* 真正的安装/卸载逻辑（后面定义），先声明给 work 回调用 */
static void do_install(HookTask *task);
static void do_uninstall(HookTask *task);

/* ---------- 工作队列：原子上下文登记 → 进程上下文执行 ---------- */

int hook_manager_wq_init(void)
{
    /* WQ_MEM_RECLAIM：安装路径要做内存分配，防止内存压力下死锁 */
    bp_wq = alloc_workqueue("pte_hook_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!bp_wq)
        return -ENOMEM;
    return 0;
}

void hook_manager_wq_exit(void)
{
    if (!bp_wq)
        return;
    flush_workqueue(bp_wq);     /* 排队的请求做完再销毁 */
    destroy_workqueue(bp_wq);
    bp_wq = NULL;
}

/* work 回调：进程上下文，可睡眠；请求项用完必须 kfree，否则每次请求都泄漏 */
static void bp_work_fn(struct work_struct *work)
{
    struct bp_request *req = container_of(work, struct bp_request, work);

    if (req->op == BP_OP_INSTALL)
        do_install(&req->t);
    else if (req->op == BP_OP_UNINSTALL)
        do_uninstall(req->has_task ? &req->t : NULL);

    kfree(req);
}

/*
 * 安装入口（可运行于 kprobe 原子上下文）：
 * 只分配请求项并入队，真正的安装由 bp_work_fn 异步完成（结果看 dmesg）。
 */
int __nocfi install_hook(HookTask *task)
{
    struct bp_request *req;

    if (!bp_wq)
        return -ENODEV;

    /* GFP_ATOMIC：调用方在关中断的 BRK 异常上下文里，不能睡眠 */
    req = kmalloc(sizeof(*req), GFP_ATOMIC);
    if (!req)
        return -ENOMEM;
    req->op = BP_OP_INSTALL;
    req->has_task = 1;
    req->t  = *task;            /* 按值拷贝一份，req 生命周期独立于调用方 */
    INIT_WORK(&req->work, bp_work_fn);
    if (!queue_work(bp_wq, &req->work)) {
        kfree(req);
        return -EBUSY;
    }
    return 0;
}

/* 卸载请求（可运行于 kprobe 原子上下文），同样只入队异步执行 */
void hook_request_uninstall(HookTask *task)
{
    struct bp_request *req;

    if (!bp_wq)
        return;
    req = kmalloc(sizeof(*req), GFP_ATOMIC);
    if (!req)
        return;
    req->op = BP_OP_UNINSTALL;
    if (task) {
        req->t = *task;
        req->has_task = 1;
    } else {
        req->has_task = 0;      /* 全部卸载 */
    }
    INIT_WORK(&req->work, bp_work_fn);
    if (!queue_work(bp_wq, &req->work))
        kfree(req);
}

/* ---------- 工具函数 ---------- */

/* 去掉用户地址高位的 tag（MTE/TBI 场景） */
static inline unsigned long strip_user_tag(unsigned long addr)
{
    return addr & ((1UL << 48) - 1);
}

/* 设置 UXN（禁止用户态执行） */
static inline pte_t pte_set_uxn(pte_t pte)
{
    pte_val(pte) |= PTE_UXN;
    return pte;
}

/* 清除 UXN（恢复用户态执行） */
static inline pte_t pte_clear_uxn(pte_t pte)
{
    pte_val(pte) &= ~PTE_UXN;
    return pte;
}

/* 根据 pid 找 task_struct（增加引用计数，用毕需 put_task_struct） */
static struct task_struct *get_task_by_pid(pid_t pid)
{
    struct task_struct *task = NULL;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    return task;
}

/*
 * 把目标进程的一整页代码读到内核缓冲区，并返回原始 PTE 值。
 *
 * 注意不能用 copy_from_user：那是"当前进程"（下发命令的工具进程）
 * 的地址空间，而代码页属于目标进程。
 * 做法：follow_pte 命中后在页表锁内 get_page 钉住物理页，
 * 解锁后通过内核线性映射 kmap 直接拷贝，不受目标页用户态权限影响。
 *
 * 调用方需持有 mmap 读锁。
 */
static int __nocfi read_target_code(struct mm_struct *mm, unsigned long va,
                            uint64_t *pte_out, uint32_t *buf)
{
    struct vm_area_struct *vma;
    pte_t *ptep;
    spinlock_t *ptl;
    pte_t old;
    struct page *page;
    void *kaddr;
    int ret;

    vma = find_vma(mm, va);
    if (!vma || va < vma->vm_start)
        return -EFAULT;

    /* follow_pte 成功返回时持有 ptl 页表自旋锁 */
    ret = g_follow_pte(mm, va, &ptep, &ptl);
    if (ret)
        return ret;

    old = *ptep;
    if (!pte_present(old)) {
        spin_unlock(ptl);
        return -EFAULT;
    }
    page = pte_page(old);
    get_page(page);             /* 钉住，防止解锁后页被回收 */
    *pte_out = pte_val(old);
    spin_unlock(ptl);

    kaddr = kmap(page);
    memcpy(buf, kaddr, PAGE_SIZE);
    kunmap(page);
    put_page(page);
    return 0;
}

/* 设置或清除目标地址所在页的 UXN 位（进程上下文，可睡眠） */
static int __nocfi set_target_uxn(struct mm_struct *mm, unsigned long va, bool set)
{
    struct vm_area_struct *vma;
    pte_t *ptep;
    spinlock_t *ptl;
    int ret = 0;

    mmap_read_lock(mm);
    vma = find_vma(mm, va);
    if (!vma || va < vma->vm_start) {
        ret = -EFAULT;
        goto out;
    }
    ret = g_follow_pte(mm, va, &ptep, &ptl);
    if (ret)
        goto out;
    if (!pte_present(*ptep)) {
        spin_unlock(ptl);
        ret = -EFAULT;
        goto out;
    }
    /*
     * PTE_CONT 处理（关键，踩过的坑）：4K 页配置下一个 CONT 连续块是
     * 16 项（64KB）。.text 页经 readahead 批量映射时通常带 CONT 位。
     * 若只修改块内某一项的属性（比如单独给一页加 UXN），块内属性不一致，
     * 属架构未定义行为，个别核会 TLB conflict 直接挂死重启。
     * 做法：加 UXN 前先把整块 16 项的 CONT 位全部清掉（只动 present 项，
     * 各项原有属性保持不变），再改目标项，最后按整个 64KB 区间刷 TLB。
     */
    if (set && (pte_val(*ptep) & PTE_CONT)) {
        /*
         * 目标项处于连续块：改变 CONT 位（block size）属于
         * valid->valid 的属性变化，架构要求走 break-before-make，
         * 否则个别核会 TLB conflict 直接挂死重启。
         * 步骤：
         *   1) break：保存原值，把整块 present 项写成无效（0）；
         *   2) 刷掉整块 64KB 的旧 TLB（含旧的 CONT 表项）；
         *   3) make：写回清了 CONT 的值，目标项额外加 UXN；
         *   4) 再刷一次 TLB 让新表项立即生效。
         * flush_tlb_range 在 arm64 上只发 tlbi 广播、不睡眠，
         * 因此可以全程持有 ptl，消除"表项无效"的竞态窗口。
         */
        int i, base_idx = (int)((va >> PAGE_SHIFT) & (CONT_PTES - 1));
        pte_t *base = ptep - base_idx;
        unsigned long block_start = va & CONT_PTE_MASK;
        uint64_t saved[CONT_PTES];

        /* 1) break：保存原值并把 present 项写无效（swap 项不动，避免损坏偏移量） */
        for (i = 0; i < CONT_PTES; i++) {
            saved[i] = pte_val(base[i]);
            if (pte_present(base[i]))
                set_pte(&base[i], __pte(0));
        }

        /* 2) 刷掉整块旧 TLB */
        flush_tlb_range(vma, block_start, block_start + CONT_PTE_SIZE);

        /* 3) make：写回清 CONT 的值，目标项加 UXN */
        for (i = 0; i < CONT_PTES; i++) {
            pte_t old = __pte(saved[i]);
            uint64_t v = saved[i];

            if (!pte_present(old))
                continue;               /* 原本就不是 present 项，保持不动 */
            v &= ~PTE_CONT;
            if (&base[i] == ptep)
                v |= PTE_UXN;
            set_pte(&base[i], __pte(v));
        }
        spin_unlock(ptl);

        /* 4) make 之后再刷一次，保证清了 CONT / 加了 UXN 的新表项立即生效 */
        flush_tlb_range(vma, block_start, block_start + CONT_PTE_SIZE);
        ret = 0;
        goto out;
    }

    /* 卸载时只清 UXN 位而不是整体写回旧值：
     * 期间内核可能更新过 AF/DBM 等标志，整体回写会丢更新 */
    if (set)
        set_pte(ptep, pte_set_uxn(*ptep));
    else
        set_pte(ptep, pte_clear_uxn(*ptep));
    spin_unlock(ptl);
    flush_tlb_page(vma, va);
out:
    mmap_read_unlock(mm);
    return ret;
}

/* ---------- 槽位管理（仅进程上下文：kworker / exit 路径，天然串行） ---------- */

/*
	按照pid 和 页基址的方式查看是否已存在的记录
*/
static struct hook_record *find_slot_by_page(pid_t pid, unsigned long page)
{
    int i;

    for (i = 0; i < MAX_RECORD; i++)
        if (g_recs[i].used && g_recs[i].pid == pid &&
            g_recs[i].target_page == page)
            return &g_recs[i];
    return NULL;
}

static struct hook_record *find_free_slot(void)
{
    int i;

    for (i = 0; i < MAX_RECORD; i++)
        if (!g_recs[i].used)
            return &g_recs[i];
    return NULL;
}

/* 观察表中记录的就是真实地址，而且页基址是相同的，先进行记录。返回 1=新增，0=已存在或已满 */
static int slot_add_watch_addr(struct hook_record *rec, unsigned long va)
{
    int i;

    for (i = 0; i < rec->n_addrs; i++)
        if (rec->addrs[i] == va)
            return 0;                   /* 已存在 */
    if (rec->n_addrs >= HOOK_ADDRS_PER_PAGE) {
        pr_warn("pte_hook: watch addrs full on page 0x%lx\n",
                rec->target_page);
        return 0;
    }
    rec->addrs[rec->n_addrs++] = va;
    return 1;
}

/* 从观察表删除一个入口（与末尾交换压缩） */
static void slot_remove_watch_addr(struct hook_record *rec, unsigned long va)
{
    int i;

    for (i = 0; i < rec->n_addrs; i++) {
        if (rec->addrs[i] == va) {
            rec->addrs[i] = rec->addrs[rec->n_addrs - 1];
            rec->n_addrs--;
            return;
        }
    }
}

/* ---------- BRK 探针（ghost 内观察点） ---------- */

/* 该观察地址是否已有 BRK 探针（有则 fault 路径不再重复 dump） */
static int slot_has_probe(struct hook_record *rec, unsigned int idx)
{
    int j;

    for (j = 0; j < HOOK_ADDRS_PER_PAGE; j++)
        if (rec->probes[j].used && rec->probes[j].idx == idx)
            return 1;
    return 0;
}

/*
 * 从槽位数据重建一个反映当前 ghost 状态的临时 ctx
 * （运行时已武装页面上加/删探针用）。ghost_buf 由调用方提供
 * （DBI_GHOST_MAX_BYTES），返回的 ctx 用完需 kvfree。
 */
static struct dbi_page_ctx *slot_build_ctx(struct hook_record *rec,
                                           uint32_t *ghost_buf)
{
    struct dbi_page_ctx *ctx;
    int i;

    ctx = kvzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return NULL;

    ctx->target_page    = rec->target_page;
    ctx->ghost_page     = rec->ghost.vaddr;
    ctx->orig           = rec->orig_page;
    ctx->ghost          = ghost_buf;
    ctx->ghost_capacity = (int)(rec->ghost.alloc_size / 4);
    ctx->ghost_count    = rec->ghost_words;
    ctx->finalized      = 1;
    ctx->trailer_idx    = rec->trailer_idx;
    for (i = 0; i < DBI_TARGET_INSNS; i++)
        ctx->offset_map[i] = (uint16_t)rec->ghost.offsets[i];
    memcpy(ghost_buf, (void *)rec->ghost.kaddr, (size_t)rec->ghost_words * 4);
    return ctx;
}

/* 把临时 ctx 的改动写回 ghost 物理页并同步 i-cache */
static int __nocfi slot_commit_ctx(struct hook_record *rec,
                                   struct dbi_page_ctx *ctx)
{
    memcpy((void *)rec->ghost.kaddr, ctx->ghost, (size_t)ctx->ghost_count * 4);
    rec->ghost_words = ctx->ghost_count;
    return ghost_sync_icache(&rec->ghost, (unsigned long)ctx->ghost_count * 4);
}

/* 在 ctx 上为观察地址打探针的公共尾部：登记 probes[] 表 */
static void slot_probe_register(struct hook_record *rec, unsigned int idx,
                                unsigned int ghost_idx, int cleanup_idx, int id)
{
    rec->probes[id].used        = 1;
    rec->probes[id].idx         = idx;
    rec->probes[id].ghost_idx   = ghost_idx;
    rec->probes[id].cleanup_idx = (unsigned int)cleanup_idx;
}

/* 给观察地址打 BRK 探针（在已反映 ghost 状态的 ctx 上操作）。
 * 返回 0 成功；失败不影响主流程（退化为只在页入口 fault 时 dump）。 */
static int slot_probe_emit(struct hook_record *rec, struct dbi_page_ctx *ctx,
                           unsigned long va)
{
    unsigned int idx;
    int id, cleanup;

    if (!g_brk_enabled)
        return -ENODEV;
    /* 注意用 ctx->target_page：安装路径里此时 rec 字段还没填 */
    if (va < ctx->target_page)
        return -EINVAL;
    idx = (unsigned int)((va - ctx->target_page) >> 2);
    if (idx >= DBI_TARGET_INSNS)
        return -EINVAL;
    if (slot_has_probe(rec, idx))
        return 0;

    for (id = 0; id < HOOK_ADDRS_PER_PAGE; id++)
        if (!rec->probes[id].used)
            break;
    if (id == HOOK_ADDRS_PER_PAGE)
        return -ENOSPC;

    cleanup = dbi_emit_brk_probe(ctx, (int)idx, BRK_INSN(id));
    if (cleanup < 0)
        return -EINVAL;

    slot_probe_register(rec, idx, ctx->offset_map[idx], cleanup, id);
    pr_info("pte_hook: brk probe @0x%lx -> ghost off 0x%x, cleanup off 0x%x\n",
            va, ctx->offset_map[idx] * 4, cleanup * 4);
    return 0;
}

/* 运行时给已武装的槽位追加观察地址 + 打 BRK 探针（kworker 进程上下文） */
static void __nocfi slot_watch_add(struct hook_record *rec, unsigned long va)
{
    uint32_t *buf;
    struct dbi_page_ctx *ctx;

    if (!slot_add_watch_addr(rec, va)) {
        pr_info("pte_hook: 0x%lx already watched (or watch list full)\n", va);
        return;
    }
    pr_info("pte_hook: reuse slot, watch 0x%lx (page 0x%lx already armed)\n",
            va, rec->target_page);

    if (!g_brk_enabled)
        return;

    buf = kvzalloc(DBI_GHOST_MAX_BYTES, GFP_KERNEL);
    if (!buf)
        return;
    ctx = slot_build_ctx(rec, buf);
    if (!ctx) {
        kvfree(buf);
        return;
    }
    if (slot_probe_emit(rec, ctx, va) == 0) {
        if (slot_commit_ctx(rec, ctx))
            pr_err("pte_hook: brk probe commit fail (i-cache sync)\n");
    } else {
        pr_warn("pte_hook: brk probe emit fail for 0x%lx\n", va);
    }
    kvfree(ctx);
    kvfree(buf);
}

/* 拆除观察地址对应的 BRK 探针：把 BRK 位置恢复为原始指令序列 */
static void __nocfi slot_probe_remove(struct hook_record *rec, unsigned long va)
{
    unsigned int idx;
    uint32_t *buf;
    struct dbi_page_ctx *ctx;
    int j;

    if (va < rec->target_page)
        return;
    idx = (unsigned int)((va - rec->target_page) >> 2);
    if (idx >= DBI_TARGET_INSNS)
        return;

    for (j = 0; j < HOOK_ADDRS_PER_PAGE; j++) {
        if (rec->probes[j].used && rec->probes[j].idx == idx)
            break;
    }
    if (j == HOOK_ADDRS_PER_PAGE)
        return;                         /* 没有探针，无需恢复 */

    buf = kvzalloc(DBI_GHOST_MAX_BYTES, GFP_KERNEL);
    if (!buf)
        return;
    ctx = slot_build_ctx(rec, buf);
    if (ctx) {
        /* 在原位置重新生成该指令的展开序列（位置相同，产物逐字一致），
         * BRK 被覆盖回原指令；清扫槽成为死代码，无害 */
        if (dbi_remove_brk_probe(ctx, (int)idx) == 0)
            slot_commit_ctx(rec, ctx);
        kvfree(ctx);
    }
    kvfree(buf);
    rec->probes[j].used = 0;
}

/*
 * 拆除一个槽位：解除武装 → 恢复 PTE → 释放 ghost → 清空槽位。
 * 仅进程上下文调用（可睡眠）。
 *
 * 已知风险：拆除瞬间若目标线程正在 ghost 页内执行，
 * 释放物理页会让它崩溃。安全卸载（停线程 / 执行引用计数）
 * 属于后续加固内容。
 */
static void __nocfi slot_teardown(struct hook_record *rec)
{
    struct task_struct *target;
    struct mm_struct *mm = NULL;

    if (!rec->used)
        return;

    /* 先解除武装：fault 路径立刻停止接管本槽位，新 fault 交回内核原逻辑 */
    rec->armed = false;
    smp_wmb();

    target = get_task_by_pid(rec->pid);
    if (target) {
        mm = get_task_mm(target);
        put_task_struct(target);
    }

    if (mm && mm == rec->ghost.mm) {
        /* 进程还活着且地址空间没变：恢复目标页 PTE、释放 ghost */
        if (set_target_uxn(mm, rec->target_page, false))
            pr_warn("pte_hook: restore PTE fail (page may be swapped out)\n");
        ghost_free(&rec->ghost);
        mmput(mm);
    } else {
        /*
         * 进程已退出或 exec：用户页表已随 mm 销毁，无需恢复 PTE；
         * 但 ghost 物理页是 __get_free_pages 直接申请的，必须手动归还，
         * 否则永久泄漏。此时绝不能解引用 rec->ghost.mm（悬垂指针）。
         */
        if (mm)
            mmput(mm);
        ghost_release_phys(&rec->ghost);
    }

    rec->used = 0;
    rec->pid = 0;
    rec->target_page = 0;
    rec->n_addrs = 0;
    rec->ghost_words = 0;
    rec->trailer_idx = -1;
    memset(rec->probes, 0, sizeof(rec->probes));
}

/*
 * 收割目标进程已退出的槽位。
 * pid 复用时旧槽位可能"复活"错配（虽有 fault 路径的 mm 比较兜底），
 * 这里在安装新 hook 前顺手清理，同时归还 ghost 物理页。
 */
static void reap_dead_slots(void)
{
    int i;

    for (i = 0; i < MAX_RECORD; i++) {
        struct task_struct *t;

        if (!g_recs[i].used)
            continue;
        t = get_task_by_pid(g_recs[i].pid);
        if (t) {
            put_task_struct(t);
            continue;                   /* 进程还活着 */
        }
        pr_info("pte_hook: reap dead slot %d (pid was %d)\n",
                i, g_recs[i].pid);
        slot_teardown(&g_recs[i]);      /* 内部走 ghost_release_phys 分支 */
    }
}

/*
 * 真正的安装逻辑（仅由 bp_work_fn 在进程上下文调用，可以睡眠）。
 * 注意任何出错路径都要把已拿到的资源（task 引用、mm 引用、
 * 缓冲区、ghost 页）全部释放，否则泄漏。
 */
static void __nocfi do_install(HookTask *task)
{
    struct task_struct *target;
    struct mm_struct *mm;
    unsigned long va, page;
    uint32_t *orig = NULL, *ghost_code = NULL;
    struct dbi_page_ctx *ctx = NULL;
    struct hook_record *rec;
    bool ghost_installed = false;
    int ret = 0, i;

    if (!g_follow_pte)
        return;

    va   = strip_user_tag(task->address);
    page = va & PAGE_MASK;

    /* 0. 顺手收割目标进程已退出的槽位，避免槽位和物理页泄漏 */
    reap_dead_slots();

    /*
     * 同一个进程，而且页基址还相同，那么就可以复用之前的东西，否则卸载的时候会出现问题。
     */
    rec = find_slot_by_page(task->pid, page);
    if (rec) {
        /* 同页复用：登记观察地址并补打 BRK 探针（实时改 ghost + 刷 i-cache） */
        slot_watch_add(rec, va);
        return;
    }

    /* 2. 新页：找空槽位 */
    rec = find_free_slot();
    if (!rec) {
        pr_warn("pte_hook: no free slot (max %d)\n", MAX_RECORD);
        return;
    }
    /* 防御：清掉可能残留的上次安装痕迹（失败回滚路径可能留下探针标记） */
    memset(rec->probes, 0, sizeof(rec->probes));
    rec->ghost_words = 0;
    rec->trailer_idx = -1;

    target = get_task_by_pid(task->pid);
    if (!target) {
        pr_err("pte_hook: can't find task %d\n", task->pid);
        return;
    }
    mm = get_task_mm(target);
    if (!mm) {
        put_task_struct(target);
        pr_err("pte_hook: task %d don't have mm\n", task->pid);
        return;
    }

    orig = kmalloc(PAGE_SIZE, GFP_KERNEL);
    /*
     * 大块缓冲区一律用 kvzalloc（vmalloc 兜底）：
     * 32KB 的 kmalloc 是 order-3 高阶分配，内存紧张时会卡在
     * 直接回收/内存规整里。这两个只是重编译临时暂存，不需要物理连续。
     */
    ghost_code = kvzalloc(DBI_GHOST_MAX_BYTES, GFP_KERNEL);
    /* dbi_page_ctx 内含 2KB offset_map + 4KB pending 队列，不能放栈上 */
    ctx = kvzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!orig || !ghost_code || !ctx) {
        ret = -ENOMEM;
        goto out_free;
    }

    /* 1. 读原页内容与原 PTE（mmap 读锁内完成） */
    mmap_read_lock(mm);
    ret = read_target_code(mm, va, &rec->orig_pte, orig);
    mmap_read_unlock(mm);
    if (ret) {
        pr_err("pte_hook: read data 0x%lx fail\n", va);
        goto out_free;
    }

    /* 2. 在目标页附近找空洞并安装 ghost PTE。
     *    注意必须是 mmap 写锁：apply_to_page_range 会新建页表层级。
     *    此阶段绝不能持有 ptl 自旋锁调用本函数——ghost_alloc 里
     *    申请物理页（GFP_KERNEL）可能睡眠。 */
    mmap_write_lock(mm);
    ret = ghost_alloc(target, mm, page, HOOK_GHOST_RANGE,
                      rec->orig_pte, HOOK_GHOST_PAGES, &rec->ghost);
    mmap_write_unlock(mm);
    if (ret) {
        pr_err("pte_hook: ghost alloc fail %d\n", ret);
        goto out_free;
    }
    ghost_installed = true;

    /* 3. 重编译整页到临时缓冲区 */
    ctx->target_page    = page;
    ctx->ghost_page     = rec->ghost.vaddr;
    ctx->orig           = orig;
    ctx->ghost          = ghost_code;
    /* 输出容量必须和 ghost 实际页数匹配，防止写穿 ghost 物理页 */
    ctx->ghost_capacity = (HOOK_GHOST_PAGES * PAGE_SIZE) / 4;
    ret = dbi_recompile_page(ctx);
    pr_info("pte_hook: dbi count fixed=%d expanded=%d passthrough=%d "
            "intra=%d failed=%d out %d int \n",
            ctx->fixed, ctx->expanded, ctx->passthrough,
            ctx->intra_page_fixed, ctx->failed, ctx->ghost_count);
    if (ret || ctx->failed) {
        /* failed > 0 意味着有指令被降级成 NOP，执行必然出错，放弃安装 */
        pr_err("pte_hook: dbi fail \n");
        ret = ret ? ret : -EOPNOTSUPP;
        goto out_free;
    }

    /* 3.5 给观察地址打 BRK 探针：执行流路过 ghost 内该位置时陷入内核
     *    dump 寄存器。失败只降级为"页入口 dump"，不影响安装。 */
    if (slot_probe_emit(rec, ctx, va))
        pr_warn("pte_hook: brk probe unavailable for 0x%lx, entry-dump only\n",
                va);

    /* 双保险：输出（含探针清扫槽）不得超过 ghost 实际分配的字节数 */
    if ((size_t)ctx->ghost_count * 4 > rec->ghost.alloc_size) {
        pr_err("pte_hook: dbi out %d more than ghost %lu\n",
               ctx->ghost_count * 4, rec->ghost.alloc_size);
        ret = -E2BIG;
        goto out_free;
    }

    /* 4. 通过内核线性映射把重编译结果写入 ghost 物理页，并同步 i-cache。
     *    i-cache 同步失败（如 flush_dcache 符号未解析）会导致目标执行到
     *    陈旧/零指令而崩溃，必须放弃安装而不是带病武装。 */
    memcpy((void *)rec->ghost.kaddr, ghost_code,
           (size_t)ctx->ghost_count * 4);
    ret = ghost_sync_icache(&rec->ghost, (unsigned long)ctx->ghost_count * 4);
    if (ret) {
        pr_err("pte_hook: i-cache fail %d, uninstall \n", ret);
        goto out_free;
    }

    /* 5. 把指令映射表存进 ghost 元数据，abort 路径直接查表；
     *    同时保存原页副本与 ghost 元信息（运行时加/删探针要重建 ctx） */
    for (i = 0; i < DBI_TARGET_INSNS; i++)
        rec->ghost.offsets[i] = ctx->offset_map[i];
    rec->ghost_words = ctx->ghost_count;
    rec->trailer_idx = ctx->trailer_idx;
    memcpy(rec->orig_page, orig, PAGE_SIZE);

    /* 6. 先填写槽位并武装，再设 UXN（顺序关键）。
     *    若先设 UXN 后武装，两者之间的窗口里目标页一旦被取指，
     *    hook_handle_fault 因 armed==false 直接返回 0，原 do_mem_abort
     *    就会对 UXN 页发 SIGSEGV 杀掉目标进程。此时 ghost 页已就绪，
     *    提前武装是安全的：UXN 未设前目标页不会 fault，不会误接管。 */
    rec->pid         = task->pid;
    rec->target_page = page;
    rec->addrs[0]    = va;
    rec->n_addrs     = 1;
    rec->dbg_cnt     = 0;
    rec->used        = 1;
    smp_wmb();
    rec->armed = true;

    /* 7. 设置目标页 UXN（此后目标页取指才会 fault 并被接管） */
    ret = set_target_uxn(mm, va, true);
    if (ret) {
        pr_err("pte_hook: set UXN fail %d\n", ret);
        rec->armed = false;   /* 回滚武装，避免留下半安装状态 */
        smp_wmb();
        rec->used = 0;
        goto out_free;
    }

    pr_info("pte_hook: install hook success pid=%d addr=0x%lx ghost_va=0x%lx\n",
            rec->pid, va, rec->ghost.vaddr);

out_free:
    if (ret && ghost_installed)
        ghost_free(&rec->ghost);    /* 内部自取 mmap 写锁 */
    kvfree(ctx);
    kvfree(ghost_code);
    kfree(orig);
    put_task_struct(target);
    mmput(mm);
}

/* 卸载：task 非 NULL 卸指定 (pid,address)，NULL 卸全部（进程上下文） */
static void __nocfi do_uninstall(HookTask *task)
{
    unsigned long va, page;
    struct hook_record *rec;

    if (!task) {
        uninstall_all_hooks();
        return;
    }

    va   = strip_user_tag(task->address);
    page = va & PAGE_MASK;

    rec = find_slot_by_page(task->pid, page);
    if (!rec) {
        pr_warn("pte_hook: uninstall: no hook for pid=%d addr=0x%lx\n",
                task->pid, va);
        return;
    }

    slot_remove_watch_addr(rec, va);
    slot_probe_remove(rec, va);     /* 同步拆掉 BRK 探针，恢复 ghost 原指令 */
    if (rec->n_addrs > 0) {
        /* 本页还有其它观察地址：只摘这个函数，页保持武装 */
        pr_info("pte_hook: stop watching 0x%lx, page still armed (%d addrs left)\n",
                va, rec->n_addrs);
        return;
    }

    /* 本页没有观察对象了：整页拆除（恢复 PTE、释放 ghost） */
    slot_teardown(rec);
    pr_info("pte_hook: uninstall 0x%lx done\n", va);
}

void __nocfi uninstall_all_hooks(void)
{
    int i;

    for (i = 0; i < MAX_RECORD; i++)
        slot_teardown(&g_recs[i]);
    pr_info("pte_hook: uninstall all done\n");
}

/*
 * do_mem_abort 前置处理。
 * 返回 1：已接管（uregs->pc 已改写为 ghost 地址，调用方需跳过原函数）
 * 返回 0：与本 hook 无关
 *
 * 本函数运行在全系统每一次内存异常上，过滤顺序按最便宜的来：
 * 异常类型 → armed → pid → 页地址。
 */
int __nocfi hook_handle_fault(unsigned long far, unsigned long esr,
                              struct pt_regs *uregs)
{
    unsigned int ec = (esr >> 26) & 0x3F;
    unsigned int ifsc = esr & 0x3F;
    unsigned long far_va = strip_user_tag(far);
    unsigned long far_page = far_va & PAGE_MASK;
    int cur_pid;
    int i, j;

    /* 只接管 EL0 取指 + 权限错误（EC=0x20，IFSC=0b0011xx）；
     * 绝大多数异常（数据异常、换页等）从这里直接返回 */
    if (ec != 0x20 || (ifsc & 0x3C) != 0x0C)
        return 0;

    cur_pid = task_tgid_nr(current);

    for (i = 0; i < MAX_RECORD; i++) {
        struct hook_record *rec = &g_recs[i];
        unsigned int idx;

        if (!rec->armed)
            continue;
        smp_rmb();              /* 与安装侧的 smp_wmb 配对 */
        if (rec->pid != cur_pid)
            continue;
        if (rec->target_page != far_page)
            continue;
        /* UXN 只改在目标进程的页表上，别的进程理论上不会命中，
         * 这里再确认一次（仅比较指针，不解引用，mm 悬垂也安全） */
        if (current->mm != rec->ghost.mm)
            continue;
        if (!uregs)
            return 0;

        idx = (unsigned int)((far_va - far_page) >> 2);
        if (idx >= DBI_TARGET_INSNS)
            return 0;

        /*
         * UXN 以页为单位：目标页内任何地址 fault 都重定向到 ghost 页
         * 的对应位置。这正好解决了"同页其它函数先执行导致 hook 失效"
         * 的老问题——整页的执行都被搬到了 ghost 页。
         * 只有精确命中登记的函数入口时，x0..x7 才是该函数的入参。
         */
        for (j = 0; j < rec->n_addrs; j++) {
            if (rec->addrs[j] == far_va) {
                /* 已有 BRK 探针的地址由 ghost 内的探针负责 dump，
                 * 这里跳过避免重复打印 */
                if (!slot_has_probe(rec, (far_va - far_page) >> 2)) {
                    pr_info("pte_hook: hit fn 0x%lx tgid=%d slot=%d\n",
                            far_va, cur_pid, i);
                    dump_user_args(uregs, far_va);
                }
                break;
            }
        }

        uregs->pc = rec->ghost.vaddr +
                    (unsigned long)rec->ghost.offsets[idx] * 4;

        /* 调试（限幅）：确认重定向真的发生了，以及 ghost PC 是否落在合理范围 */
        // if (rec->dbg_cnt < FAULT_DEBUG_MAX) {
        //     rec->dbg_cnt++;
        //     pr_info("pte_hook: redirect far=0x%lx -> ghost_pc=0x%lx (slot=%d idx=%u)\n",
        //             far_va, uregs->pc, i, idx);
        // }
        return 1;
    }
    return 0;
}

/*
 * 用户态 BRK 钩子回调（main.c 经 register_user_break_hook 注册）。
 * 处理 ghost 页内 BRK 探针：dump 观察点的完整寄存器现场，
 * 然后把 pc 改到清扫槽（被覆盖指令的重生成副本 + 跳回正常后继）。
 * 返回 1：已接管（调用方返回 DBG_HOOK_HANDLED，目标进程不会收 SIGTRAP）
 * 返回 0：与本 hook 无关
 *
 * 本路径只会被用户态 BRK 指令异常触发（EC=0x3C），
 * 且内核已按 imm/mask 匹配过魔数；此时 uregs->pc = BRK 指令本身的地址。
 */
int __nocfi hook_handle_brk(struct pt_regs *uregs, unsigned int esr)
{
    unsigned int iss = esr & 0xFFFF;
    unsigned long far;
    int cur_pid;
    int i, j;

    /* 双保险：imm16 必须带我们的魔数（内核已按 imm/mask 匹配过一遍） */
    if ((iss & 0xFF00U) != BRK_MAGIC)
        return 0;
    if (!uregs)
        return 0;

    far = uregs->pc;            /* BRK 异常的 ELR = BRK 指令本身的地址 */
    cur_pid = task_tgid_nr(current);

    for (i = 0; i < MAX_RECORD; i++) {
        struct hook_record *rec = &g_recs[i];
        unsigned int g;

        if (!rec->armed)
            continue;
        smp_rmb();              /* 与安装侧的 smp_wmb 配对 */
        if (rec->pid != cur_pid)
            continue;
        if (current->mm != rec->ghost.mm)
            continue;
        if (far < rec->ghost.vaddr ||
            far >= rec->ghost.vaddr + (unsigned long)rec->ghost_words * 4)
            continue;

        g = (unsigned int)((far - rec->ghost.vaddr) >> 2);
        for (j = 0; j < HOOK_ADDRS_PER_PAGE; j++) {
            struct brk_probe *p = &rec->probes[j];

            if (p->used && p->ghost_idx == g) {
                unsigned long orig_va =
                    rec->target_page + (unsigned long)p->idx * 4;

                // pr_info("pte_hook: watch hit orig=0x%lx (ghost off 0x%x) "
                //         "tgid=%d slot=%d\n", orig_va, g * 4, cur_pid, i);
                dump_user_args(uregs, far);
                /* 去清扫槽执行被覆盖的原指令，随后自动跳回正常后继 */
                uregs->pc = rec->ghost.vaddr + (unsigned long)p->cleanup_idx * 4;
                return 1;
            }
        }
        return 0;   /* 在我们 ghost 范围内但不是探针：不接管（不应发生） */
    }
    return 0;
}
