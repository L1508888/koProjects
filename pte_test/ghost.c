/*
 * ghost.c —— "幽灵页"分配器
 *
 * 直接申请物理页，并手工把 PTE 安装进目标进程页表的空洞区域：
 *   - 不创建 VMA，/proc/<pid>/maps 里看不到这块映射；
 *   - 映射属性从目标代码页的原始 PTE 模板复制（清 UXN/GP，保证 EL0 可执行）；
 *   - 供 DBI 重编译后的代码栖身。
 *
 * 锁约定：
 *   ghost_alloc 需要调用方持有目标 mm 的 mmap 写锁
 *   （apply_to_page_range 会新建页表层级）；
 *   ghost_free 内部自取写锁，调用方不得持锁调用。
 */

#include "ghost.h"
#include <asm/barrier.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/module.h>

#define ARM64_PFN_MASK (0x0000FFFFFFFFF000UL) /* PFN 字段：bits [47:12] */

#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

/* 由 init_ghost() 注入的内核符号表 */
static GhostSymbolData *ghost_symbol_page;

void init_ghost(GhostSymbolData *ghostSymbol)
{
    ghost_symbol_page = ghostSymbol;
}

/* 页数向上取整为 2 的幂阶数 */
static int pages_to_order(int n)
{
    int order = 0;
    while ((1 << order) < n)
        order++;
    return order;
}

struct install_ctx {
    uint64_t pte_val;   /* 待写入的 PTE 值 */
    int      written;   /* 是否真正写入 */
};

static int install_pte_cb(pte_t *pte, unsigned long addr, void *data)
{
    struct install_ctx *c = (struct install_ctx *)data;
    uint64_t *p = (uint64_t *)pte;

    /* 只往空的 PTE 里写；已被占用则报错，交给上层回滚 */
    if (*p != 0 && (*p & PTE_VALID)) {
        return -EEXIST;
    }

    *p = c->pte_val;
    c->written = 1;
    return 0;
}

struct clear_ctx {
    int cleared;
};

static int clear_pte_cb(pte_t *pte, unsigned long addr, void *data)
{
    struct clear_ctx *c = (struct clear_ctx *)data;
    uint64_t *p = (uint64_t *)pte;
    *p = 0;
    c->cleared = 1;
    return 0;
}

/*
 * 检查虚拟地址是否已被占用（页表已建立且 present）。
 * 调用方需持有 mmap 锁。空洞区域的页表中间层级可能不存在，逐级判空。
 */
static bool vaddr_is_occupied(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return false;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return false;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return false;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return false;
    /* 大页（段映射）直接视为占用，本模块不拆分 */
    if (pmd_trans_huge(*pmd))
        return true;
    ptep = pte_offset_map(pmd, addr);
    if (!ptep)
        return false;
    return pte_present(*ptep);
}

/**
 * 在目标进程地址空间里找一块离 near 最近的空洞
 *
 * @param mm         目标进程的内存描述符
 * @param near       期望位置的"中心"地址，尽量在它附近找
 * @param range      搜索半径，最终区间为 [near_page - range, near_page + range)
 * @param num_pages  需要的页数
 * @return           找到的起始地址（页对齐），未找到返回 0
 */
static __nocfi unsigned long find_hole_near(struct mm_struct *mm,
                                            unsigned long near,
                                            unsigned long range,
                                            int num_pages)
{
    /* 需要的总字节数 */
    unsigned long need = (unsigned long)num_pages * 0x1000;
    unsigned long near_page = near & ~0xFFFUL;  /* near 向下页对齐 */
    /* lower / high 是搜索范围的下限和上限 */
    unsigned long lower = near_page > range ? near_page - range : 0;
    unsigned long high = near_page + range;

    unsigned long best = 0, best_dist = ~0UL;

    unsigned long addr = lower;
    struct vm_area_struct *vma;

    if (!ghost_symbol_page || !ghost_symbol_page->find_vma) {
        return 0;
    }
    if (num_pages <= 0) {
        return 0;
    }

    while (addr < high) {
        unsigned long gap_start, gap_end, cand, d;

        /* 找第一个满足 vm_end > addr 的 VMA */
        vma = ghost_symbol_page->find_vma(mm, addr);

        /*
         * VMA 为空：说明所有 VMA 的 vm_end 都小于等于 addr，
         * 从 addr 到 high 整体是空洞；
         * 或找到的 VMA 起始地址已超出搜索上限，同样整体是空洞。
         */
        if (!vma || vma->vm_start >= high) {
            gap_start = addr;
            gap_end = high;
        }
        /* VMA 与 addr 之间存在空洞，范围是 [addr, vm_start) */
        else if (vma->vm_start > addr) {
            gap_start = addr;
            gap_end = vma->vm_start;
        }
        /* addr 落在某个 VMA 内部：跳过这个 VMA 继续找 */
        else {
            addr = vma->vm_end;
            continue;
        }

        /* 空洞够大才考虑 */
        if (gap_end - gap_start >= need) {
            /* 空洞包含 near_page：直接用 near_page */
            if (near_page >= gap_start && near_page + need <= gap_end)
                cand = near_page;
            /* 空洞整体在 near_page 高侧：用空洞起点 */
            else if (near_page < gap_start)
                cand = gap_start;
            /* 空洞整体在 near_page 低侧：贴着空洞末尾放 */
            else
                cand = gap_end - need;

            d = (cand > near_page) ? cand - near_page : near_page - cand;
            if (d < best_dist && !vaddr_is_occupied(mm, cand)) {
                best_dist = d;
                best = cand;
            }
        }

        if (!vma || vma->vm_start >= high) {
            break;
        }
        addr = vma->vm_end;
    }
    return best;
}

/*
 * 分配 ghost 页并安装进目标进程页表。
 * 注意：调用方必须持有 mm 的 mmap 写锁。
 */
int __nocfi ghost_alloc(struct task_struct *task, struct mm_struct *mm,
                        unsigned long near, unsigned long range,
                        uint64_t pte_template, int num_pages,
                        GhostMemoryData *out)
{
    int order, i, j, ret;
    unsigned long kva;
    uint64_t pa_base;
    unsigned long vaddr;
    uint64_t new_pte = 0;
    struct install_ctx ictx;    /* 安装 PTE 的回调参数 */
    struct clear_ctx cctx;      /* 回滚时清 PTE 的回调参数 */
    uint64_t asid;

    if (!ghost_symbol_page || !mm || !out)
        return -EINVAL;

    order = pages_to_order(num_pages);

    /* 1. 直接申请连续物理页（返回内核线性映射地址） */
    kva = ghost_symbol_page->get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!kva) {
        return -ENOMEM;
    }

    pa_base = (uint64_t)virt_to_phys((void *)kva);

    /* 2. 在目标页附近寻找空洞 */
    vaddr = find_hole_near(mm, near, range, 1 << order);
    if (!vaddr) {
        ghost_symbol_page->free_pages(kva, order);
        return -ENOSPC;
    }

    /* 3. 逐页安装 PTE */
    for (i = 0; i < (1 << order); i++) {
        uint64_t page_pa = pa_base + (uint64_t)i * 0x1000;

        /* 保留模板 PTE 的所有属性位，仅替换物理页帧号（PFN）部分 */
        new_pte = (pte_template & ~ARM64_PFN_MASK) | (page_pa & ARM64_PFN_MASK);
        /* 确保页有效（VALID）、普通页类型（TYPE_PAGE）、
         * 访问标志置位（AF，避免首次访问触发缺页异常） */
        new_pte |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF;
        /* 清除 UXN：允许 EL0 执行（ghost 页存在的意义） */
        new_pte &= ~PTE_UXN;
        /* 清除 GP（Guarded Page）位：避免 BTI 检查拦截非落地垫跳转 */
        new_pte &= ~(1UL << 50);

        ictx.pte_val = new_pte;
        ictx.written = 0;
        ret = ghost_symbol_page->apply_to_page_range(mm,
                                                     vaddr + (unsigned long)i * 0x1000,
                                                     0x1000, install_pte_cb, &ictx);
        /* 安装失败则回滚：清掉已安装的 PTE、释放物理页 */
        if (ret || !ictx.written) {
            if (!ret)
                ret = -EEXIST;
            for (j = 0; j < i; j++) {
                cctx.cleared = 0;
                ghost_symbol_page->apply_to_page_range(mm,
                                                       vaddr + (unsigned long)j * 0x1000,
                                                       0x1000, clear_pte_cb, &cctx);
            }
            ghost_symbol_page->free_pages(kva, order);
            return ret;
        }
    }

    /* 4. 刷 TLB：精确失效，避免全局刷新 */
    asid = mm->context.id.counter & 0xFFFFUL;

    if (asid && (1 << order) > 8) {
        /* 页数较多时：按 ASID 刷新整个进程 */
        unsigned long arg = asid << 48;
        asm volatile("tlbi aside1is, %0\n\t"
                     "dsb ish\n\t"
                     "isb\n\t" ::"r"(arg)
                     : "memory");
    } else {
        /* 页数较少时：逐页精确刷新（All ASID, Last Level） */
        for (j = 0; j < (1 << order); j++) {
            unsigned long va = vaddr + (unsigned long)j * PAGE_SIZE;
            asm volatile("tlbi vaale1is, %0\n\t" ::"r"(va >> 12));
        }
        asm volatile("dsb ish\n\t"
                     "isb\n\t" ::
                         : "memory");
    }

    out->task = task;
    out->mm = mm;
    out->vaddr = vaddr;
    out->kaddr = kva;
    out->pfn = pa_base >> 12;
    out->installed_pte = new_pte;
    out->order = order;
    out->alloc_size = (unsigned long)(1 << order) * 0x1000;
    out->installed = 1;
    return 0;
}

/*
 * IPI 回调：迫使每个 CPU 走一遍异常入口。
 * 异常入口的硬件语义自带流水线冲刷（等效 isb），
 * 保证没有 CPU 还在执行即将释放的 ghost 页。
 */
static void ghost_drain_ipi(void *info)
{
    (void)info;
    isb();
}

/* 卸载 ghost 页：清 PTE、刷 TLB/i-cache、释放物理页 */
int __nocfi ghost_free(GhostMemoryData *ghostMemory)
{
    int page_count, i;
    uint64_t asid;
    struct mm_struct *mm;

    if (!ghostMemory || !ghostMemory->installed) {
        return 0;
    }
    if (!ghost_symbol_page) {
        return -ENODEV;
    }

    mm = ghostMemory->mm;
    if (!mm) {
        return -ESRCH;
    }

    /* ---------- 1. 生命周期保护 ---------- */
    /* mmget_not_zero：防止目标进程在此期间退出并释放 mm_struct */
    if (!mmget_not_zero(mm)) {
        return -ESRCH;
    }

    page_count = 1 << (ghostMemory->order);
    asid = mm->context.id.counter & 0xFFFFUL;

    /* ---------- 2. 页表锁 ---------- */
    /* apply_to_page_range 会修改页表，必须持有 mmap 写锁，
     * 与目标进程的 mmap/munmap 互斥 */
    mmap_write_lock(mm);

    /* ---------- 3. 逐页清除 PTE ---------- */
    for (i = 0; i < page_count; i++) {
        struct clear_ctx cctx;
        cctx.cleared = 0;
        ghost_symbol_page->apply_to_page_range(ghostMemory->mm,
                                               ghostMemory->vaddr + (unsigned long)i * 0x1000,
                                               0x1000, clear_pte_cb, &cctx);
    }

    /* ---------- 4. 精确 TLB 刷新 ---------- */
    if (asid && page_count > 8) {
        /* 页数较多：按 ASID 刷新整个进程，
         * 只影响该 mm 的映射，其他进程/内核 TLB 不受影响 */
        unsigned long asid_arg = asid << 48;
        asm volatile("tlbi aside1is, %0\n\t"
                     "dsb ish\n\t"
                     "isb\n\t" ::"r"(asid_arg)
                     : "memory");
    } else {
        /* 页数较少（或 ASID 未分配）：逐页 VA 刷新。
         * vaale1is = VA All ASID Last Level EL1 Inner Shareable，
         * 只刷这几页的最后一级 TLB（PTE），不碰中间层级的 walk cache */
        for (i = 0; i < page_count; i++) {
            unsigned long va = ghostMemory->vaddr + (unsigned long)i * PAGE_SIZE;
            asm volatile("tlbi vaale1is, %0" ::"r"(va >> 12));
        }
        asm volatile("dsb ish\n\t"
                     "isb\n\t" ::
                         : "memory");
    }

    /* ---------- 5. I-cache 失效（释放执行中代码页的必要措施） ---------- */
    /* ARM64 没有"按物理地址失效 I-cache"的指令，也没有 ic ivau 的广播版本。
     * 由于 ghost 页可能正被任意 CPU 执行，必须确保所有 CPU 的 I-cache
     * 中不再缓存这些物理地址的指令。ic ialluis 是 Inner Shareable 域内
     * 唯一能让远程 CPU 失效 I-cache 的广播指令。 */
    asm volatile(
        "ic ialluis\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    /* ---------- 6. IPI 排空：强制所有 CPU 冲刷流水线 ---------- */
    /* ic ialluis 只保证 I-cache 内容被清掉，不保证已进入流水线的
     * 指令被丢弃。IPI 强制所有 CPU 陷入异常入口，其硬件语义包含
     * 流水线冲刷（等效 isb）。此后没有任何 CPU 还能执行 ghost 页。 */
    ghost_symbol_page->on_each_cpu(ghost_drain_ipi, NULL, 1);

    mmap_write_unlock(mm);

    /* ---------- 7. 释放物理页 ---------- */
    ghost_symbol_page->free_pages(ghostMemory->kaddr, ghostMemory->order);

    /* ---------- 8. 清理元数据 ---------- */
    ghostMemory->installed = 0;
    ghostMemory->kaddr = 0;
    ghostMemory->vaddr = 0;
    ghostMemory->mm = NULL;
    ghostMemory->task = NULL;

    mmput(mm);
    return 0;
}

/*
 * 仅释放 ghost 物理页（目标进程已退出时使用）。
 * 此时 ghost->mm 是悬垂指针，绝不能解引用；
 * 用户页表已随进程销毁，PTE 无需清理。
 */
void __nocfi ghost_release_phys(GhostMemoryData *ghostMemory)
{
    if (!ghostMemory || !ghostMemory->installed || !ghost_symbol_page)
        return;

    ghost_symbol_page->free_pages(ghostMemory->kaddr, ghostMemory->order);

    ghostMemory->installed = 0;
    ghostMemory->kaddr = 0;
    ghostMemory->vaddr = 0;
    ghostMemory->mm = NULL;
    ghostMemory->task = NULL;
}

/*
 * 代码写入 ghost 页后同步指令缓存：
 *   1. __flush_dcache_area：把新写的指令从 D-cache 写回到 PoU
 *      （通过内核线性映射地址操作，按物理地址生效）；
 *   2. ic ialluis：广播失效所有 CPU 的 I-cache，保证用户态
 *      通过 ghost 虚拟地址取到的是新指令。
 * 必须在目标进程执行 ghost 代码之前调用。
 */
int __nocfi ghost_sync_icache(GhostMemoryData *ghostMemory, unsigned long code_bytes)
{
    if (!ghostMemory || !ghostMemory->installed ||
        !ghost_symbol_page || !ghost_symbol_page->flush_dcache_area)
        return -EINVAL;

    ghost_symbol_page->flush_dcache_area((void *)ghostMemory->kaddr, code_bytes);

    asm volatile("ic ialluis\n\t"
                 "dsb ish\n\t"
                 "isb\n\t"
                 ::: "memory");
    return 0;
}
