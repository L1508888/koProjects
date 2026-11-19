/*
 * javahook.c —— Java 层（ART 方法级）hook 内核实现
 *
 * 设计要点（完整说明见 docs/JavaHook.md）：
 *
 *   Java 方法最终都会落成一段 ARM64 机器码，入口地址记录在这两个地方
 *   之一：
 *     a) ArtMethod.entry_point_ 字段（8 字节，位于 .data/.bss）；
 *     b) 已编译代码本身的首地址（.text / .oat / .so 的可执行页）。
 *
 *   本模块对两者各提供一种策略：
 *
 *   [FIELD] 改写 ArtMethod.entry_point_ 字段
 *       把字段值换成本模块在目标进程里生成的 trampoline 地址。
 *       优点：不碰代码页、不碰 PTE，纯数据写，最简单也最稳。
 *       缺点：ART 内部若缓存了入口（少见），或目标方法在 JNI 快速
 *             调用路径上会被直接取 entry_point_ 时需要注意；
 *             修改对 ART 可见。
 *
 *   [UXN]   PTE 取指劫持（JH_FLAG_UXN）
 *       完全不动 ArtMethod：把入口所在 4KB 页的 PTE 置 UXN，
 *       由 hookManager 的 do_mem_abort 钩子把"精确命中入口"的取指
 *       异常重定向到 trampoline，"同页其它地址"的取指异常重定向到
 *       DBI 重编译副本。优点：ART 数据结构、代码页字节都保持原样，
 *       ART 侧的完整性校验无从发现。缺点：依赖 PTE 机制。
 *
 *   两种策略共用同一个 trampoline 生成器。trampoline 只是：
 *
 *       [brk #imm]                 ; 可选观察点
 *       movz/movk x17, #target     ; 目标的绝对地址
 *       br   x17                   ; 尾跳（tail jump）
 *
 *   它不压栈、不改 sp、不碰 x0..x7，所以对 ART 的方法调用 ABI
 *   （参数在 x0..x7、返回值在 x0/x1）完全透明，"调用原方法"也不会
 *   因为多一层跳转而出错。
 *
 *   trampoline 落在 ghost 页里：物理页由 __get_free_pages 直接申请，
 *   PTE 手工塞进目标进程地址空间的空洞，不创建 VMA，所以
 *   /proc/<pid>/maps 看不到它。
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/barrier.h>
#include <asm/pgtable.h>

#include "javahook.h"
#include "jh_tramp.h"
#include "ghost.h"
#include "hookManager.h"

#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

#define JH_MAX_SLOTS      24

/*
 * trampoline 页内布局：
 *
 *   +0x00  entry trampoline     （ART 直接调用的入口，可能带入口/出口观察点）
 *   +0x40  backup trampoline    （"调用原方法"用，纯尾跳，不带观察点）
 *
 * 单个 trampoline 的长度上限来自 jh_tramp.h 的 JH_TRAMP_MAX_WORDS
 * （唯一定义处，改了那里这里自动跟上）。
 */
#define JH_TRAMP_OFF       0x00
#define JH_BACKUP_OFF      0x40

/* 编译期保证两个 trampoline 不会重叠 */
static_assert(JH_TRAMP_MAX_WORDS * 4 <= JH_BACKUP_OFF,
              "trampoline 长度不得超过 backup 起始偏移");

/* BRK 魔数：高字节把事件路由到本模块，低字节区分入口/出口观察点 */
#define JH_BRK_MAGIC      0xBF00U

/* FOLL_* 缺失时的兜底（include/linux/mm.h 里已有，这里只做保险） */
#ifndef FOLL_WRITE
#define FOLL_WRITE  0x01
#endif
#ifndef FOLL_FORCE
#define FOLL_FORCE  0x10
#endif

struct java_hook_record {
    int            used;
    pid_t          pid;
    unsigned long  art_method;     /* ArtMethod*（目标进程用户地址） */
    unsigned int   entry_off;      /* 入口字段偏移 */
    unsigned long  orig_entry;     /* 入口字段原值，卸载时还原 */
    unsigned long  tramp;          /* trampoline 起始（ghost 内） */
    unsigned long  enter_brk;      /* 入口观察点地址（0 = 无） */
    unsigned long  exit_brk;       /* 返回值观察点地址（0 = 无） */
    unsigned long  backup;         /* "调用原方法"应使用的地址 */
    int            use_uxn;        /* 1 = UXN 策略（未改 ArtMethod） */
    int            skip_original;  /* trampoline 直接返回 ret_val */
    uint32_t       flags;          /* 生效的 JH_FLAG_* */
    struct JavaHookReq req;        /* 规则快照（观察点里要用） */
    GhostMemoryData ghost;         /* trampoline 所在 ghost 页 */
};

static struct java_hook_record g_jh[JH_MAX_SLOTS];

static jh_access_process_vm_t g_apv;
static jh_follow_pte_t        g_follow_pte;

/*
 * 槽位表串行化：安装/卸载都跑在进程上下文（/proc 写、javahook.c 同步接口），
 * 只有一处并发风险——多个进程同时写 /proc 控制文件。用互斥量串起来。
 */
static DEFINE_MUTEX(g_jh_lock);

void javahook_init(jh_access_process_vm_t apv, jh_follow_pte_t follow)
{
    g_apv        = apv;
    g_follow_pte = follow;
}

/* ---------- 目标进程内存访问 ---------- */

/*
 * 按 pid 找 task_struct（增加引用计数，用毕需 put_task_struct）。
 *
 * 为什么不只用 find_task_by_vpid：它查的是**当前调用者所在 pid namespace**
 * 里的编号。实践中遇到两个会失效的场景：
 *   1) 命令进程处于不同的 pid namespace（容器 / KernelSU 的 su 有时会这样）；
 *   2) 目标的 pid 是"用户态看到的全局编号"，而调用者在内层 namespace。
 * 此时 find_task_by_vpid 返回 NULL，虽然 /proc/<pid> 明明可访问。
 *
 * 回退方案：遍历全局进程列表，用 task_tgid_nr()（init namespace 视角的
 * 全局编号）匹配。这与用户态 ps / /proc 的编号语义一致，覆盖上面两种情况。
 */
static struct task_struct *jh_get_task(pid_t pid)
{
    struct task_struct *task = NULL;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    if (task)
        return task;

    /* 回退：按全局 tgid 扫描 */
    rcu_read_lock();
    for_each_process(task) {
        if (task_tgid_nr(task) == pid) {
            get_task_struct(task);
            rcu_read_unlock();
            pr_info("pte_java: pid %d resolved via global scan\n", pid);
            return task;
        }
    }
    rcu_read_unlock();

    pr_warn("pte_java: pid %d not found (vpid and global scan both failed)\n",
            pid);
    return NULL;
}

/* ---------- 按包名 / uid 定位目标进程 ---------- */

/*
 * 读目标 task 的进程名（comm）与 cmdline，用于和包名比对。
 *
 * 为什么两个都读：
 *   - comm（TASK_COMM_LEN=16）被截断，`com.example.someapp` 会变成
 *     `com.example.so`，所以不能只靠它；
 *   - cmdline 是完整的（zygote fork 出来的 App 进程 cmdline 就是包名），
 *     但它可能为空（内核线程、已退出、权限不足）。
 * 两个都取，任一匹配即算命中，覆盖得更全。
 *
 * 本函数运行在进程上下文（/proc 写、kworker），可以睡眠。
 */
static __nocfi void jh_task_names(struct task_struct *task, char *comm, int comm_len,
                          char *cmd, int cmd_len)
{
    struct mm_struct *mm;
    unsigned long arg_start, arg_end, arg_len;
    char *buf;

    /*
     * comm 必须用长度恰好为 TASK_COMM_LEN(16) 的缓冲区：
     * get_task_comm() 内部有 BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN)。
     * 所以这里用局部数组，再按调用方给的容量拷出去。
     */
    if (comm && comm_len > 0) {
        char tcomm[TASK_COMM_LEN];
        int n;

        get_task_comm(tcomm, task);
        tcomm[TASK_COMM_LEN - 1] = 0;
        n = (int)strlen(tcomm);
        if (n > comm_len - 1)
            n = comm_len - 1;
        memcpy(comm, tcomm, (size_t)n);
        comm[n] = 0;
    }
    if (cmd && cmd_len > 0)
        cmd[0] = 0;

    if (!cmd || cmd_len <= 0)
        return;

    /* cmdline 在用户态栈顶附近：读 mm->arg_start 处的一页 */
    mm = get_task_mm(task);
    if (!mm)
        return;

    buf = kmalloc(256, GFP_KERNEL);
    if (buf) {
        int n = 0;

        /*
         * arg_start/arg_end 要在 mmap 读锁内取：它们会随 exec / 栈扩展
         * 变化，锁外读是竞态的。取值后立刻放锁，读内存放到锁外
         * （access_process_vm 可能缺页睡眠，绝不能持锁调用）。
         */
        mmap_read_lock(mm);
        arg_start = mm->arg_start;
        arg_end   = mm->arg_end;
        mmap_read_unlock(mm);

        arg_len = arg_end > arg_start ? arg_end - arg_start : 0;
        if (arg_len > 0) {
            /*
             * 用 access_process_vm 读（kallsyms 注入的通道），
             * 比 kmap 物理页安全：它自己处理缺页与权限。
             * 注意这里是进程上下文（/proc 写路径），可以睡眠。
             */
            if (g_apv && arg_start) {
                int want = arg_len < 255 ? (int)arg_len : 255;

                n = g_apv(task, arg_start, buf, want, FOLL_FORCE);
                if (n < 0)
                    n = 0;
                if (n > want)
                    n = want;
            }
        }
        if (n > 0) {
            int i;

            /*
             * cmdline 是 NUL 分隔的参数列表。把 NUL 全部换成空格，
             * 得到一整行文本 —— 因为包名不一定在第一个参数里：
             *   - 真实 App（zygote fork）：argv[0] 就是包名
             *   - app_process 启动的进程：argv[0] 是 app_process，
             *     包名在后面（实测 /proc/<pid>/cmdline 形如
             *     "app_process / pte.javatest.JavaHookTest"）
             * 换成整行后，下面用"整行内包含包名"来匹配即可，两种都覆盖。
             */
            for (i = 0; i < n; i++) {
                if (buf[i] == 0)
                    buf[i] = ' ';
            }
            buf[n] = 0;
            if (n > cmd_len - 1)
                n = cmd_len - 1;
            memcpy(cmd, buf, (size_t)n);
            cmd[n] = 0;
        }
        kfree(buf);
    }
    mmput(mm);
}

/*
 * cmdline 的**第一个词**（argv[0] 的 basename）是否等于 pkg。
 *
 * 为什么不用 jh_cmdline_has_exact（"任意位置出现"）：会把父 shell 误判成目标。
 * 实测踩过：`sh -c "CLASSPATH=... app_process / pte.javatest.Foo"` 的
 * cmdline 里也包含包名，于是父 sh 被当成"主进程"，而它没有 mm
 * （get_task_mm 失败 → -ESRCH），hook 装不上。
 *
 * 真正的目标进程两种形态：
 *   - zygote fork 的 App：argv[0] 就是包名
 *   - app_process 启动： argv[0] 是 app_process，包名在后面的参数里
 * 所以判定顺序是：
 *   1) argv[0] 的 basename == pkg        （最优先，App 主进程）
 *   2) argv[0] 的 basename == app_process 且后面某参数 == pkg
 *   3) 其它位置出现 pkg（降级，只当兜底）
 */
static __nocfi int jh_cmdline_word_is(const char *cmdline, const char *pkg)
{
    const char *p, *base;

    if (!cmdline || !cmdline[0] || !pkg || !pkg[0])
        return 0;

    /* 取第一个词 */
    p = cmdline;
    while (*p == ' ')
        p++;
    base = p;
    while (*p && *p != ' ')
        p++;

    /* 去掉路径前缀：/system/bin/app_process -> app_process */
    {
        const char *slash = base;
        const char *q;

        for (q = base; q < p; q++)
            if (*q == '/')
                slash = q + 1;
        base = slash;
    }

    return (size_t)(p - base) == strlen(pkg) &&
           !strncmp(base, pkg, (size_t)(p - base));
}

/* cmdline 里是否有某个完整的词等于 pkg（任意位置） */
static __nocfi int jh_cmdline_has_word(const char *cmdline, const char *pkg)
{
    size_t plen;
    const char *p;

    if (!cmdline || !cmdline[0] || !pkg || !pkg[0])
        return 0;
    plen = strlen(pkg);

    for (p = cmdline; (p = strstr(p, pkg)) != NULL; p++) {
        char before = (p == cmdline) ? ' ' : p[-1];
        char after  = p[plen];

        if (before == ' ' && (after == 0 || after == ' '))
            return 1;
    }
    return 0;
}

/*
 * 名字匹配规则（pkg 可以出现在 name 的任意位置）：
 *
 *   1) 完全相同
 *   2) name 形如 "<pkg>:<suffix>"（Android 私有进程，如 com.foo:remote）
 *   3) name 是整行 cmdline 时，其中某个"以空格分隔的词"等于 pkg
 *      或形如 "<pkg>:<suffix>"
 *
 * 为什么允许出现在任意位置：App 进程的 cmdline 有两种形态 ——
 *   真实 App（zygote fork）：argv[0] = 包名
 *   app_process 启动：      "app_process / <包名>"
 * 两种都要能匹配，所以按"词"来比，而不是只比开头。
 *
 * 边界要求：pkg 后面必须是 '\0'、':'、' ' 之一，
 * 否则 "com.foo" 会误匹配 "com.foobar"。
 */
static __nocfi int jh_name_match(const char *name, const char *pkg)
{
    size_t plen;
    const char *p;

    if (!name || !name[0] || !pkg || !pkg[0])
        return 0;

    plen = strlen(pkg);

    /* 完全相同 */
    if (!strcmp(name, pkg))
        return 1;

    /* 在整行里找 pkg 的每一次出现，检查前后边界 */
    for (p = name; (p = strstr(p, pkg)) != NULL; p++) {
        char before = (p == name) ? ' ' : p[-1];
        char after  = p[plen];

        /* 前面必须是词边界（行首或空格） */
        if (before != ' ')
            continue;
        /* 后面必须是词尾、私有进程分隔符或参数分隔符 */
        if (after == 0 || after == ':' || after == ' ')
            return 1;
    }
    return 0;
}

/*
 * 按 pkg / uid 找目标进程。
 *
 *   pkg 非空 → 匹配进程名（comm 或 cmdline），取第一个命中的
 *   uid 非 0  → 匹配进程的 real uid（App 的 userId，如 10123）
 *   两者都给 → 必须同时满足
 *
 * 返回值：成功返回带引用的 task_struct（用毕 put_task_struct），失败 NULL。
 *
 * ⚠️ 实现上的三个硬约束（前两个都实测踩过，会直接 panic / 匹配失败）：
 *
 *  1) RCU 临界区（rcu_read_lock/for_each_process）里**绝不允许睡眠**。
 *     早期版本在锁内调 jh_task_names()（内部 get_task_mm / kmalloc /
 *     access_process_vm 全可能睡眠），结果在 do_mem_abort 里数据中止，
 *     设备直接重启。
 *     正确做法：RCU 内只做"读字段 + 收集候选 pid"，重量级操作放到锁外。
 *
 *  2) 候选集**不能设小上限**：Android 有 400+ 进程，只取前 N 个会漏掉
 *     目标（实测 32 个名额全被 init/system 进程占满，App 进程排在后面
 *     根本不进候选）。这里用两阶段：先只按 uid 收窄（App uid 命中数
 *     很少），只有"没给 uid"时才全量收集。
 *
 *  3) 候选 task 必须在锁外重新 find 一次再使用（cmdline 读取涉及目标
 *     mm，不能在 RCU 内做）。
 */
#define JH_MAX_CAND 512

/* 优先级：2 = argv[0] 就是包名；1 = app_process 且后面有包名；0 = 其它 */
static __nocfi int jh_match_rank(const char *comm, const char *cmd,
                                 const char *pkg)
{
    if (!strcmp(comm, pkg))
        return 3;               /* comm 直接就是包名 */
    if (jh_cmdline_word_is(cmd, pkg))
        return 2;               /* argv[0] 是包名 */
    if (jh_cmdline_word_is(cmd, "app_process") &&
        (jh_cmdline_has_word(cmd, pkg) || jh_name_match(cmd, pkg)))
        return 1;               /* app_process + 参数里的包名 */
    return 0;
}

/*
 * 按 pkg / uid 找目标进程。
 *
 *   pkg 非空 → 匹配进程名（comm 或 cmdline），取 rank 最高的
 *   uid 非 0  → 匹配进程的 real uid（App 的 userId，如 10123）
 *   两者都给 → 必须同时满足
 *
 * 返回值：成功返回带引用的 task_struct（用毕 put_task_struct），失败 NULL。
 *
 * ⚠️ 实现上踩过的三个坑（都会导致 panic 或选错进程）：
 *
 *  1) RCU 临界区（rcu_read_lock/for_each_process）里**绝不允许睡眠**。
 *     在锁内调 jh_task_names()（内部 get_task_mm / kmalloc /
 *     access_process_vm 全可能睡眠）会在 do_mem_abort 里数据中止，
 *     设备直接重启。→ RCU 内只读字段、收候选 pid，重量级操作放锁外。
 *
 *  2) 候选集**不能设小上限**。Android 有 400+ 进程，只取前 N 个会漏掉
 *     目标（实测 32 个名额全被 init/system 占满）。
 *
 *  3) 不能"第一个命中就采用"。父 shell 的 cmdline 里也可能包含包名
 *     （`sh -c "... app_process / com.foo.Bar"`），它没有 mm，
 *     选中它 hook 装不上。→ 用 rank 打分，取最高分。
 */
#define JH_MAX_CAND 512

static struct task_struct *jh_find_task_by_name(pid_t pid, u32 target_uid,
                                                bool has_uid, const char *pkg)
{
    struct task_struct *task = NULL, *hit = NULL;
    pid_t *cand;
    int ncand = 0, i;
    int best_rank = 0;
    bool need_name = (pkg && pkg[0]);

    /* pid 直接给了就先按 pid 找（找不到再退回名字匹配） */
    if (pid > 0) {
        task = jh_get_task(pid);
        if (task)
            return task;
    }
    if (!need_name && !has_uid)
        return NULL;

    /* 512 个 pid = 2KB，放内核栈太危险（栈只有 16KB） */
    cand = kmalloc_array(JH_MAX_CAND, sizeof(pid_t), GFP_KERNEL);
    if (!cand)
        return NULL;

    /* 第一轮：RCU 内只读字段，不碰 mm、不 kmalloc、不读用户内存 */
    rcu_read_lock();
    for_each_process(task) {
        const struct cred *cred;
        bool uid_ok = true;

        if (task->flags & PF_KTHREAD)
            continue;

        if (has_uid) {
            cred = __task_cred(task);
            uid_ok = (from_kuid(&init_user_ns, cred->uid) == target_uid);
        }
        if (!uid_ok)
            continue;

        cand[ncand++] = task_tgid_nr(task);
        if (ncand >= JH_MAX_CAND)
            break;
    }
    rcu_read_unlock();

    if (!ncand) {
        pr_warn("pte_java: no process matches pkg='%s' uid=%u\n",
                pkg ? pkg : "", target_uid);
        kfree(cand);
        return NULL;
    }
    pr_info("pte_java: scanning %d candidate(s) for pkg='%s' uid=%u\n",
            ncand, pkg ? pkg : "", target_uid);

    /* 第二轮：锁外做名字匹配（要读 cmdline，会睡眠）+ rank 打分 */
    for (i = 0; i < ncand; i++) {
        char comm[32], cmd[256];
        struct task_struct *t;
        struct mm_struct *m;
        int rank;

        t = jh_get_task(cand[i]);
        if (!t)
            continue;

        if (!need_name) {
            hit = t;                /* 只按 uid 过滤：第一个就是 */
            goto out;
        }

        /* 跳过没有 mm 的进程（shell / 内核线程 / 正在退出） */
        m = get_task_mm(t);
        if (!m) {
            put_task_struct(t);
            continue;
        }
        mmput(m);

        jh_task_names(t, comm, sizeof(comm), cmd, sizeof(cmd));
        rank = jh_match_rank(comm, cmd, pkg);

        if (rank > best_rank) {
            if (hit)
                put_task_struct(hit);   /* 让位给更高分 */
            hit = t;
            best_rank = rank;
            if (rank >= 3)
                break;                  /* 已是最优（comm 就是包名） */
            continue;
        }
        put_task_struct(t);
    }

out:
    kfree(cand);

    if (hit) {
        pr_info("pte_java: resolved pkg='%s' uid=%u -> pid %d (rank %d)\n",
                pkg ? pkg : "", target_uid, task_tgid_nr(hit), best_rank);
    } else {
        pr_warn("pte_java: no process name matches pkg='%s' (uid=%u, %d candidates)\n",
                pkg ? pkg : "", target_uid, ncand);
    }
    return hit;
}

/*
 * 读目标进程内存。返回 0 成功，负数 -errno。
 * 走 access_process_vm（kallsyms 注入）：它内部处理 COW 与权限，
 * 不会像 kmap 物理页那样改到共享页上。
 *
 * quiet=1 时不打错误日志（探测布局时会试多个候选偏移，失败很正常）。
 */
static int __nocfi jh_read_ex(struct task_struct *task, unsigned long addr,
                              void *buf, int len, int quiet)
{
    int r;

    if (!g_apv)
        return -ENODEV;
    r = g_apv(task, addr, buf, len, FOLL_FORCE);
    if (r != len) {
        if (!quiet)
            pr_err("pte_java: read 0x%lx len %d failed (%d)\n",
                   addr, len, r);
        return -EFAULT;
    }
    return 0;
}

static int __nocfi jh_read(struct task_struct *task, unsigned long addr,
                           void *buf, int len)
{
    return jh_read_ex(task, addr, buf, len, 0);
}

/* 写目标进程内存（FOLL_WRITE|FOLL_FORCE：只读页也能写，走 COW） */
static int __nocfi jh_write(struct task_struct *task, unsigned long addr,
                            const void *buf, int len)
{
    int r;

    if (!g_apv)
        return -ENODEV;
    r = g_apv(task, addr, (void *)buf, len, FOLL_WRITE | FOLL_FORCE);
    if (r != len) {
        pr_err("pte_java: write 0x%lx len %d failed (%d)\n", addr, len, r);
        return -EFAULT;
    }
    return 0;
}

/* ---------- 地址属性判定 ---------- */

/*
 * 判断用户地址是否落在"EL0 可取指"的页上。
 *
 * 只看 PTE：present 且未置 UXN。这样不必区分 .text / .oat / .so，
 * 也不用查 VMA 链，对 ART 的 AOT 代码、JIT 代码、解释器桩都成立。
 *
 * 例外：已经被本模块 UXN 武装的页（同页上先装了别的 hook）UXN 位是
 * 置位的，但取指异常会被我们接管并重定向，语义上仍然"可执行"，
 * 所以先查一次 hook_page_armed()。
 *
 * 锁顺序（重要）：hook_page_armed 会拿 g_install_lock，而安装路径
 * 是"先 g_install_lock 再 mmap 锁"；这里必须先查槽位、再取 mmap 锁，
 * 绝不能反过来，否则构成 ABBA 死锁。
 * 调用方不要持 mmap 锁。
 */
static int __nocfi jh_addr_is_exec(struct mm_struct *mm, pid_t pid,
                                   unsigned long addr)
{
    pte_t *ptep;
    spinlock_t *ptl;
    pte_t pte;
    int ret, ok = 0;

    if (!mm || !addr || !g_follow_pte)
        return 0;

    /* 已被本模块武装的页：UXN 位是我们自己置的，语义上仍可执行 */
    if (hook_page_armed(pid, addr))
        return 1;

    mmap_read_lock(mm);
    ret = g_follow_pte(mm, addr & PAGE_MASK, &ptep, &ptl);
    if (!ret) {
        pte = *ptep;
        if (pte_present(pte) && !(pte_val(pte) & PTE_UXN))
            ok = 1;
        spin_unlock(ptl);
    }
    mmap_read_unlock(mm);
    return ok;
}

/* 取某可执行页的 PTE 作为 ghost 页的属性模板（调用方不要持 mmap 锁） */
static int __nocfi jh_pte_template(struct mm_struct *mm, unsigned long addr,
                                   uint64_t *out)
{
    pte_t *ptep;
    spinlock_t *ptl;
    int ret;

    if (!g_follow_pte)
        return -ENODEV;

    mmap_read_lock(mm);
    ret = g_follow_pte(mm, addr & PAGE_MASK, &ptep, &ptl);
    if (!ret) {
        *out = pte_val(*ptep);
        spin_unlock(ptl);
    }
    mmap_read_unlock(mm);
    return ret;
}

/* ---------- trampoline 生成 ----------
 *
 * 指令编码与形态选择都放在 jh_tramp.c 里（纯计算，可用真实汇编器验证）。
 * 这里只负责决定"目标地址"和"观察点编号"，然后调生成器。
 */

/*
 * 观察点编号（BRK 的 imm16 低字节）：
 *   0 = 入口（参数）
 *   1 = 出口（返回值）
 * 高字节是 JH_BRK_MAGIC，用来把事件路由到本模块。
 */
#define JH_BRK_ENTER_ID  0
#define JH_BRK_EXIT_ID   1

/*
 * 在目标进程里分配一页 ghost，把 trampoline 写进去并同步 i-cache。
 * 返回 0 成功（ghost 已填充到 out），失败返回 -errno。
 *
 * 注意：ghost_alloc 内部会 apply_to_page_range 新建页表层级，
 * 必须持 mmap 写锁；这里自己取，调用方不要持锁。
 */
static int __nocfi jh_alloc_tramp_page(struct task_struct *task,
                                       struct mm_struct *mm,
                                       unsigned long near,
                                       uint64_t pte_template,
                                       GhostMemoryData *out,
                                       uint32_t *code, int words)
{
    /* 由近及远试探：先小范围（保持 B/BL 可达、地址空间干净），
     * 进程地址空间很密时再逐级放宽 */
    static const unsigned long ranges[] = {
        32UL << 20,     /* 32MB */
        512UL << 20,    /* 512MB */
        4UL << 30,      /* 4GB */
        48UL << 30,     /* 48GB：arm64 用户空间上限量级，兜底 */
    };
    unsigned int i;
    int ret = -ENOSPC;

    for (i = 0; i < ARRAY_SIZE(ranges); i++) {
        mmap_write_lock(mm);
        ret = ghost_alloc(task, mm, near & PAGE_MASK, ranges[i], pte_template,
                          1, out);
        mmap_write_unlock(mm);
        if (!ret)
            break;
        if (ret != -ENOSPC)
            return ret;
    }
    if (ret)
        return ret;

    memcpy((void *)out->kaddr, code, (size_t)words * 4);
    ret = ghost_sync_icache(out, (unsigned long)words * 4);
    if (ret) {
        ghost_free(out);
        return ret;
    }
    return 0;
}

/* ---------- ArtMethod 布局探测 ---------- */

/*
 * 候选偏移表（按 Android 版本演进排列，先试最常见的）：
 *
 *   Android 12/13 arm64（ART 13，64 位）：
 *     declaring_class_     0x00 (4B, GcRoot 压缩引用)
 *     access_flags_        0x04 (4B)
 *     dex_code_item_offset_ 0x08
 *     dex_method_index_    0x0C
 *     method_index_        0x10
 *     hotness_count_       0x12
 *     data_                0x18  (8B)
 *     entry_point_         0x20  (8B)   ← 默认
 *
 *   Android 8 ~ 11：同上（entry_point_ 也是 0x20）
 *   Android 5/6（部分机型）：entry_point_ 0x18
 *
 * 探测不靠版本号，而是靠"这个 8 字节值是否指向一张 EL0 可执行页"：
 * data_ 通常指向 ArtMethod* 或 profiling 数据（不可执行），
 * entry_point_ 必然可执行，所以判定相当可靠。
 */
/*
 * 候选偏移表（按实测命中率排序）。
 *
 * ⚠️ 这张表是**实测**得来的，不是从源码抄的：
 *   在 Pixel 6 / Android 13 (ART 13) 上 dump ArtMethod 内存看到：
 *     +0x00: declaring_class_ / access_flags_ 等打包字段
 *     +0x08: dex_code_item_offset_ / dex_method_index_ 等
 *     +0x10: data_ 指针（指向堆上的数据，**不可执行**）
 *     +0x18: entry_point_（指向 libart.so 的 r-x 段，**可执行**）← 实测
 *   相邻 ArtMethod 的间隔是 0x20 字节（add/greet/tick 相差正好 0x20），
 *   所以结构体本身只有 0x20 字节，0x20 已经是下一个方法的起始。
 *
 * 早期 Android（8~11）常见的是 entry_point_ = 0x20；Android 13 改到了
 * 0x18。这里把 0x18 放最前，同时保留其它候选做兼容 —— 判定标准仍是
 * "该 8 字节是不是指向一张 EL0 可取指的页"，所以顺序只影响速度。
 */
static const unsigned int jh_entry_candidates[] = { 0x18, 0x20, 0x10, 0x28 };

int java_probe_entry_off(pid_t pid, unsigned long art_method,
                         unsigned int *entry_off)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long val;
    unsigned int i;
    int ret = -ESRCH;

    if (!art_method || !entry_off)
        return -EINVAL;

    task = jh_get_task(pid);
    if (!task)
        return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) {
        pr_warn("pte_java: task %d has no mm (kernel thread or exiting)\n", pid);
        put_task_struct(task);
        return -ESRCH;
    }

    for (i = 0; i < ARRAY_SIZE(jh_entry_candidates); i++) {
        unsigned int off = jh_entry_candidates[i];

        if (jh_read_ex(task, art_method + off, &val, sizeof(val), 1))
            continue;
        if (!val)
            continue;
        if (!jh_addr_is_exec(mm, pid, val))
            continue;
        *entry_off = off;
        pr_info("pte_java: probe ArtMethod 0x%lx entry_off=0x%x entry=0x%lx\n",
                art_method, off, val);
        ret = 0;
        break;
    }

    if (ret)
        pr_warn("pte_java: probe ArtMethod 0x%lx failed (指定 entry_off 再试)\n",
                art_method);

    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* ---------- ArtMethod 字段读写（调试接口） ---------- */

int java_read_entry(pid_t pid, unsigned long art_method, unsigned int entry_off,
                    unsigned long *out)
{
    struct task_struct *task;
    int ret;

    if (!art_method || !out)
        return -EINVAL;

    task = jh_get_task(pid);
    if (!task)
        return -ESRCH;

    if (!entry_off) {
        /* 没给偏移就先探测，探测本身要读目标内存，所以放在拿到 task 之后 */
        ret = java_probe_entry_off(pid, art_method, &entry_off);
        if (ret) {
            put_task_struct(task);
            return ret;
        }
    }

    ret = jh_read(task, art_method + entry_off, out, sizeof(*out));
    put_task_struct(task);
    return ret;
}

int java_write_entry(pid_t pid, unsigned long art_method, unsigned int entry_off,
                     unsigned long value)
{
    struct task_struct *task;
    int ret;

    if (!art_method || !entry_off)
        return -EINVAL;

    task = jh_get_task(pid);
    if (!task)
        return -ESRCH;
    ret = jh_write(task, art_method + entry_off, &value, sizeof(value));
    put_task_struct(task);
    return ret;
}

/* ---------- 槽位管理 ---------- */

/*
 * 入口分类（仅诊断，便于判断 hook 是否落在预期位置）。
 *
 * ART 里 ArtMethod.entry_point_ 可能指向三类不同的东西：
 *   1) 该方法自己的 AOT/JIT 编译代码（各方法地址互不相同）
 *   2) libart.so 里的共享跳板：art_quick_invoke_stub、
 *      art_quick_generic_jni_trampoline、art_interpreted_method 等
 *      —— 所有方法共用同一地址，此时 Hook 入口本身没意义，
 *         必须配合"方法索引/参数"过滤（见文档 9.1 节）
 *
 * 判定依据用 VMA 而不是 PTE：
 *   - VMA 有 file 且是 r-x 映射   → 来自 .so/.oat，可能是共享跳板
 *   - VMA 无 file（匿名）且可执行 → JIT 生成的代码，方法独享
 *
 * 注意不能用 PTE_WRITE 判断：arm64 上 PTE_WRITE 就是 DBM 位，
 * 只反映"硬件可以自动置脏"，和页是否可写没关系。
 */
static void __nocfi jh_log_entry_hint(struct mm_struct *mm, unsigned long entry)
{
    struct vm_area_struct *vma;
    const char *kind;

    if (!mm || !entry)
        return;

    mmap_read_lock(mm);
    vma = find_vma(mm, entry);
    if (!vma || entry < vma->vm_start) {
        mmap_read_unlock(mm);
        pr_info("pte_java: entry 0x%lx 不在任何 VMA 内（异常）\n", entry);
        return;
    }
    if (!(vma->vm_flags & VM_EXEC)) {
        kind = "映射不可执行（偏移很可能错了）";
    } else if (vma->vm_file) {
        kind = "r-x 文件映射 → AOT 代码或 ART 共享跳板，需确认";
    } else {
        kind = "匿名可执行 → JIT 代码，方法独享，hook 立即生效";
    }
    pr_info("pte_java: entry 0x%lx -> %s\n", entry, kind);
    mmap_read_unlock(mm);
}
static struct java_hook_record *jh_find(pid_t pid, unsigned long art_method)
{
    int i;

    for (i = 0; i < JH_MAX_SLOTS; i++) {
        if (g_jh[i].used && g_jh[i].pid == pid &&
            g_jh[i].art_method == art_method)
            return &g_jh[i];
    }
    return NULL;
}

static struct java_hook_record *jh_find_free(void)
{
    int i;

    for (i = 0; i < JH_MAX_SLOTS; i++)
        if (!g_jh[i].used)
            return &g_jh[i];
    return NULL;
}

/* 槽位号：用于 BRK imm 与调试输出 */
static int jh_slot_id(const struct java_hook_record *rec)
{
    return (int)(rec - g_jh);
}

void javahook_reap(void)
{
    int i;

    for (i = 0; i < JH_MAX_SLOTS; i++) {
        struct java_hook_record *rec = &g_jh[i];
        struct task_struct *t;

        if (!rec->used)
            continue;
        t = jh_get_task(rec->pid);
        if (t) {
            put_task_struct(t);
            continue;
        }
        /*
         * 进程已退出：用户页表随 mm 销毁，不用碰 PTE；
         * 但 ghost 物理页是 __get_free_pages 直接申请的，必须归还，
         * 且此时 rec->ghost.mm 已悬垂，绝不能交给 ghost_free。
         */
        pr_info("pte_java: reap dead slot %d (pid was %d)\n", i, rec->pid);
        /* 先解除武装（BRK 路径据此停止匹配），再归还物理页 */
        rec->used = 0;
        smp_wmb();
        ghost_release_phys(&rec->ghost);
        memset(rec, 0, sizeof(*rec));
    }
}

/*
 * 拆除一个槽位。顺序很重要：
 *   1) 先撤掉入口劫持（字段写回 / 解除 UXN），此后新调用不再进入
 *      trampoline；
 *   2) 再释放 trampoline 所在 ghost 页。
 * 第 2 步与"正在 trampoline 里执行的线程"之间没有强同步
 * （ghost_free 内置 ic ialluis + IPI 排空是尽力而为），
 * 这与 hookManager 的已知限制一致，见文档"已知限制"一节。
 */
static void __nocfi jh_teardown(struct java_hook_record *rec)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    unsigned long enter = rec->enter_brk, exit = rec->exit_brk;

    if (!rec->used)
        return;

    /*
     * 0. 先"解除武装"，再动资源。
     *
     * javahook_handle_brk 跑在 BRK 异常上下文（关中断、不能拿锁），
     * 它靠 rec->used + 观察点地址来匹配。如果先释放 ghost 页再清
     * used，就会出现"页已归还、BRK 处理程序还在按旧地址匹配"的窗口。
     * 所以这里先把 used 清掉并加写屏障，与读侧的 smp_rmb 配对。
     * 这与 hookManager 的 armed 标志是同一套做法。
     */
    rec->used = 0;
    smp_wmb();

    task = jh_get_task(rec->pid);
    if (task)
        mm = get_task_mm(task);

    /* 1. 撤掉入口劫持 */
    if (rec->use_uxn) {
        /* PTE 策略：解除 UXN 武装（进程已退出时内部是幂等空操作） */
        hook_uninstall_sync(rec->pid, rec->orig_entry);
    } else if (mm && rec->orig_entry) {
        /* 字段策略：把 entry_point_ 写回原值 */
        if (jh_write(task, rec->art_method + rec->entry_off,
                     &rec->orig_entry, sizeof(rec->orig_entry)))
            pr_warn("pte_java: restore entry failed (pid %d)\n", rec->pid);
    }

    /* 2. 释放 trampoline 物理页 */
    if (mm && mm == rec->ghost.mm)
        ghost_free(&rec->ghost);      /* 页表还在，正常卸载映射 */
    else
        ghost_release_phys(&rec->ghost);  /* 进程已退出/exec：只归还物理页 */

    if (mm)
        mmput(mm);
    if (task)
        put_task_struct(task);

    pr_info("pte_java: teardown slot %d pid=%d method=0x%lx "
            "brk(enter=%lx exit=%lx)\n",
            jh_slot_id(rec), rec->pid, rec->art_method, enter, exit);
    memset(rec, 0, sizeof(*rec));
}

void javahook_release_all(void)
{
    int i;

    mutex_lock(&g_jh_lock);
    for (i = 0; i < JH_MAX_SLOTS; i++)
        jh_teardown(&g_jh[i]);
    mutex_unlock(&g_jh_lock);
    pr_info("pte_java: release all done\n");
}

/* ---------- 安装 ---------- */

/*
 * 把 trampoline 写进目标进程的 ghost 页，并算出两个观察点的 VA。
 *
 *   target —— 尾跳/调用的目标（replace ?: 原入口 ?: ghost 副本）
 *   out_tramp/out_enter_brk/out_exit_brk —— 返回地址（0 = 没有）
 *
 * 观察点编号写在 BRK 的 imm16 低字节里，高字节是 JH_BRK_MAGIC。
 * BRK 处理函数靠"pc 等于哪个观察点地址"来区分入口/出口，
 * 所以这里必须精确记下每个 BRK 落在 trampoline 的第几个字。
 */
static int __nocfi jh_emit_trampoline(struct task_struct *task,
                                      struct mm_struct *mm,
                                      const struct JavaHookReq *req,
                                      unsigned long near, uint64_t pte_tmpl,
                                      uint64_t target,
                                      GhostMemoryData *ghost,
                                      unsigned long *out_tramp,
                                      unsigned long *out_enter_brk,
                                      unsigned long *out_exit_brk)
{
    uint32_t code[16];
    int enter_idx = -1, exit_idx = -1;
    int words, ret;

    words = jh_build_tramp(code, ARRAY_SIZE(code), req, target,
                           jh_enc_brk(JH_BRK_MAGIC | JH_BRK_ENTER_ID),
                           jh_enc_brk(JH_BRK_MAGIC | JH_BRK_EXIT_ID),
                           &enter_idx, &exit_idx);
    if (words <= 0)
        return -EINVAL;

    ret = jh_alloc_tramp_page(task, mm, near, pte_tmpl, ghost, code, words);
    if (ret)
        return ret;

    *out_tramp = ghost->vaddr + JH_TRAMP_OFF;
    *out_enter_brk = enter_idx >= 0 ?
        *out_tramp + (unsigned long)enter_idx * 4 : 0;
    *out_exit_brk = exit_idx >= 0 ?
        *out_tramp + (unsigned long)exit_idx * 4 : 0;
    return 0;
}

/* 请求里是否有任何"要看/要改"的规则（否则整个 hook 没意义） */
static int jh_req_has_rules(const struct JavaHookReq *r)
{
    return jh_args_need_enter_brk(r) || jh_ret_needs_exit_brk(r);
}

int __nocfi java_hook_method(const struct JavaHookReq *req,
                             struct JavaHookResult *out)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct java_hook_record *rec;
    struct JavaHookReq r;
    uint64_t pte_tmpl = 0;
    unsigned long orig_entry = 0, tramp = 0, backup = 0;
    unsigned long enter_brk = 0, exit_brk = 0;
    unsigned int entry_off;
    pid_t tpid = 0;          /* 实际解析到的目标 pid（r.pid 可能为 0） */
    int ret = 0;
    int use_uxn, no_tramp, skip_orig;

    if (!req || !out)
        return -EINVAL;

    /*
     * 先把 out 清干净：后面任何一条失败路径都要让调用方看到 ret，
     * 否则用户态会把"未初始化的结构"当成结果。
     */
    memset(out, 0, sizeof(*out));
    out->seq = req->seq;

    if (req->magic != JAVA_HOOK_REQ_MAGIC ||
        req->version != JAVA_HOOK_REQ_VERSION) {
        out->ret = -EINVAL;
        return -EINVAL;
    }
    /*
     * 目标定位：pid 可以不给。没给时按 pkg / uid 解析（见
     * jh_find_task_by_name）。但 ArtMethod 地址必须给 —— 它无法
     * 仅凭"类名+方法名"在内核侧可靠地算出来（ART 内部结构逐版本变化），
     * 由用户态助手 pte_java_resolve 在目标进程里用 JNI 拿。
     */
    if (!req->art_method) {
        out->ret = -EINVAL;
        return -EINVAL;
    }
    if (!req->pid && !req->pkg[0] && !(req->flags & JH_FLAG_HAS_UID)) {
        out->ret = -EINVAL;
        return -EINVAL;
    }

    r = *req;
    /* pkg 字段要保证 NUL 结尾（用户态可能没填满） */
    r.pkg[JH_PKG_MAX - 1] = 0;
    use_uxn   = !!(r.flags & JH_FLAG_UXN);
    no_tramp  = !!(r.flags & JH_FLAG_NO_TRAMP);
    skip_orig = !!(r.flags & JH_FLAG_SKIP_ORIGINAL);

    if (no_tramp && !r.replace) {
        out->ret = -EOPNOTSUPP;
        return -EOPNOTSUPP;
    }
    /* raw（不生成 trampoline）与 skip（直接返回）是互斥语义 */
    if (no_tramp && skip_orig) {
        out->ret = -EINVAL;
        return -EINVAL;
    }
    /*
     * 规则校验：参数下标必须落在 x0..x7，op 必须是已知值。
     * 这些错误在安装期就报出来，比运行期崩在目标进程里好得多。
     */
    {
        unsigned int i, n = r.arg_cnt < JH_ARGS_MAX ? r.arg_cnt : JH_ARGS_MAX;

        for (i = 0; i < n; i++) {
            if (r.args[i].op > JH_OP_ADD) {
                out->ret = -EINVAL;
                return -EINVAL;
            }
            if (jh_rule_active(r.args[i].op) && r.args[i].idx >= JH_ARGS_MAX) {
                out->ret = -EINVAL;
                return -EINVAL;
            }
        }
        if (r.ret_op > JH_OP_ADD) {
            out->ret = -EINVAL;
            return -EINVAL;
        }
        if (r.ret_bits && r.ret_bits != 32 && r.ret_bits != 64) {
            out->ret = -EINVAL;
            return -EINVAL;
        }
    }
    /*
     * uxn 且没有任何规则、也没有 replace：装上之后方法行为毫无变化，
     * 还要让整页代码多走一遍异常路径，直接拒绝。
     */
    if (use_uxn && !no_tramp && !r.replace && !jh_req_has_rules(&r)) {
        out->ret = -EOPNOTSUPP;
        return -EOPNOTSUPP;
    }

    mutex_lock(&g_jh_lock);
    javahook_reap();

    /*
     * 1. 定位目标进程。
     *    pid 优先；没给（或已失效）时按 pkg / uid 解析。
     *    解析结果写进 tpid，后面所有步骤都用它 —— 不再用 r.pid，
     *    因为按名字定位时 r.pid 可能是 0。
     */
    task = jh_find_task_by_name(r.pid, r.target_uid,
                                !!(r.flags & JH_FLAG_HAS_UID), r.pkg);
    if (!task) {
        ret = -ESRCH;
        goto out_unlock;
    }
    tpid = task_tgid_nr(task);

    if (jh_find(tpid, r.art_method)) {
        ret = -EEXIST;
        put_task_struct(task);
        goto out_unlock;
    }

    rec = jh_find_free();
    if (!rec) {
        ret = -ENOSPC;
        put_task_struct(task);
        goto out_unlock;
    }

    mm = get_task_mm(task);
    if (!mm) {
        pr_warn("pte_java: task %d has no mm (kernel thread or exiting)\n",
                tpid);
        put_task_struct(task);
        ret = -ESRCH;
        goto out_unlock;
    }

    /* 1. 定位入口字段：显式指定优先，否则探测 */
    entry_off = r.entry_off;
    if (!entry_off) {
        ret = java_probe_entry_off(tpid, r.art_method, &entry_off);
        if (ret)
            goto out_put;
    }

    /* 2. 读原入口。这一步同时验证 (art_method + entry_off) 确实可读 */
    ret = jh_read(task, r.art_method + entry_off, &orig_entry,
                  sizeof(orig_entry));
    if (ret)
        goto out_put;

    if (!skip_orig && !jh_addr_is_exec(mm, tpid, orig_entry)) {
        pr_err("pte_java: entry 0x%lx of method 0x%lx is not executable "
               "(entry_off=0x%x 是否正确?)\n",
               orig_entry, r.art_method, entry_off);
        ret = -EINVAL;
        goto out_put;
    }

    /* 3. 取一张可执行页的 PTE 当 ghost 模板：属性/cache 策略与代码页一致 */
    ret = jh_pte_template(mm, orig_entry, &pte_tmpl);
    if (ret || !pte_tmpl) {
        ret = -EFAULT;
        goto out_put;
    }

    /* 只是诊断信息：告诉使用者入口落在哪种映射里，便于判断
     * 命中的是"每个方法独有的编译代码"还是"ART 的共享跳板" */
    jh_log_entry_hint(mm, orig_entry);

    /* 原入口是否被 UXN 武装，决定 jh_addr_is_exec 的判定结果 */
    (void)skip_orig;

    /*
     * ---- 策略 A：只改 ArtMethod.entry_point_ 字段 ----
     *
     *   ArtMethod.entry_point_ ──▶ trampoline(ghost) ──▶ 目标
     *
     * 目标 = replace（给了的话）否则原入口。原入口没被改动、原代码页
     * 没被改动，所以 backup 恒为 orig_entry，replace 可以随时跳它来
     * "调用原方法"。
     *
     * trampoline 完全构造好之后才写字段，切换是原子的（单次 8 字节
     * 对齐写，arm64 上不会撕裂）；已在旧入口上执行的调用照常完成。
     */
    if (!use_uxn) {
        unsigned long to_write;

        if (no_tramp) {
            /* 不做 trampoline：字段直接指向 replace */
            tramp    = r.replace;
            backup   = orig_entry;
            to_write = r.replace;
        } else {
            /* 给了 replace 就跳 replace，否则跳原入口 */
            unsigned long target = r.replace ? r.replace : orig_entry;

            ret = jh_emit_trampoline(task, mm, &r, orig_entry, pte_tmpl,
                                     target, &rec->ghost, &tramp,
                                     &enter_brk, &exit_brk);
            if (ret)
                goto out_put;

            backup   = orig_entry;
            to_write = tramp;

            /*
             * 独立的 backup trampoline：不带观察点、语义恒等于
             * "跳到原入口"。只在给了 replace 时才需要——没有 replace
             * 时 backup 就是原入口本身。
             */
            if (r.replace) {
                struct JavaHookReq plain = r;
                uint32_t bcode[16];
                int bwords;

                plain.flags &= ~(JH_FLAG_BRK | JH_FLAG_SKIP_ORIGINAL);
                plain.arg_cnt = 0;
                plain.ret_op  = JH_OP_NONE;
                bwords = jh_build_tramp(bcode, ARRAY_SIZE(bcode), &plain,
                                        orig_entry, 0, 0, NULL, NULL);
                if (bwords <= 0) {
                    ghost_free(&rec->ghost);
                    ret = -EINVAL;
                    goto out_put;
                }
                memcpy((void *)(rec->ghost.kaddr + JH_BACKUP_OFF), bcode,
                       (size_t)bwords * 4);
                ret = ghost_sync_icache(&rec->ghost,
                                        JH_BACKUP_OFF +
                                        (unsigned long)bwords * 4);
                if (ret) {
                    ghost_free(&rec->ghost);
                    goto out_put;
                }
                backup = rec->ghost.vaddr + JH_BACKUP_OFF;
            }
        }

        if (jh_write(task, r.art_method + entry_off, &to_write,
                     sizeof(to_write))) {
            if (rec->ghost.installed)
                ghost_free(&rec->ghost);
            ret = -EFAULT;
            goto out_put;
        }
        goto commit;
    }

    /*
     * ---- 策略 B：PTE/UXN 劫持代码入口 ----
     *
     * 完全不改 ArtMethod。分两步走，避免任何"trampoline 还是垃圾
     * 代码时就被调用"的窗口：
     *
     *   阶段 1：先以"观察"方式武装入口页（repl=0）。
     *           此后 orig_entry 的取指异常会重定向到 DBI 重编译副本，
     *           方法行为与原来完全一致（这就是 backup 的来源）。
     *   阶段 2：拿到 ghost 副本地址后，本地生成 trampoline，
     *           再用 repl=tramp 把同一个槽位升级为"替换"语义。
     *           切换只改一个指针，trampoline 这时已经写完并同步过
     *           i-cache。
     *
     * 注意 backup 必须是 ghost 副本而不是 orig_entry：直接跳 orig_entry
     * 会再次 UXN fault 并被重定向回 trampoline，形成死循环。
     */
    ret = hook_install_sync_ex(tpid, orig_entry, 0, 0);
    if (ret) {
        pr_err("pte_java: uxn arm failed %d\n", ret);
        goto out_put;
    }

    backup = hook_lookup_ghost_pc(tpid, orig_entry);
    if (!backup) {
        pr_err("pte_java: no ghost pc for 0x%lx\n", orig_entry);
        hook_uninstall_sync(tpid, orig_entry);
        ret = -EINVAL;
        goto out_put;
    }

    if (no_tramp) {
        ret = hook_install_sync_ex(tpid, orig_entry, r.replace, 0);
        if (ret) {
            hook_uninstall_sync(tpid, orig_entry);
            goto out_put;
        }
        tramp = r.replace;      /* 记录用，卸载时不写字段 */
        goto commit;
    }

    /* trampoline 跳到 ghost 重编译副本（不触发 UXN，即执行原逻辑） */
    ret = jh_emit_trampoline(task, mm, &r, orig_entry, pte_tmpl, backup,
                             &rec->ghost, &tramp, &enter_brk, &exit_brk);
    if (ret) {
        hook_uninstall_sync(tpid, orig_entry);
        goto out_put;
    }

    /* 升级为替换语义：精确命中 orig_entry 直接跳到 tramp。
     * probe=0：观察点已经放在 trampoline 里了，ghost 副本那边不需要
     * 再打一个（否则页内分支落到该位置时会重复触发）。 */
    ret = hook_install_sync_ex(tpid, orig_entry, tramp, 0);
    if (ret) {
        hook_uninstall_sync(tpid, orig_entry);
        ghost_free(&rec->ghost);
        goto out_put;
    }

commit:
    /*
     * 发布顺序（关键）：先把所有字段填完，最后才置 used 并加写屏障。
     * javahook_handle_brk 跑在 BRK 异常上下文，看到 used==1 就会去读
     * enter_brk/exit_brk/req 等字段；如果顺序反了，它可能匹配到一条
     * 只填了一半的记录，用错的规则去改寄存器。
     * 这与 hookManager 的 "填字段 → smp_wmb → armed=true" 是同一套做法。
     */
    rec->pid           = tpid;
    rec->art_method    = r.art_method;
    rec->entry_off     = entry_off;
    rec->orig_entry    = orig_entry;
    rec->tramp         = tramp;
    rec->enter_brk     = enter_brk;
    rec->exit_brk      = exit_brk;
    rec->backup        = backup;
    rec->use_uxn       = use_uxn;
    rec->skip_original = skip_orig;
    rec->flags         = r.flags;
    rec->req           = r;         /* 规则快照，观察点里要用 */
    rec->req.arg_cnt   = r.arg_cnt < JH_ARGS_MAX ? r.arg_cnt : JH_ARGS_MAX;

    smp_wmb();
    rec->used          = 1;         /* 最后发布 */

    out->trampoline = tramp;
    out->orig_entry = orig_entry;
    out->backup     = backup;
    out->enter_brk  = enter_brk;
    out->exit_brk   = exit_brk;
    out->entry_off  = entry_off;
    out->pid        = tpid;         /* 按 pkg/uid 定位时告诉调用方实际 pid */
    out->flags      = r.flags;
    out->ret        = 0;

    pr_info("pte_java: hook ok pid=%d method=0x%lx off=0x%x orig=0x%lx "
            "tramp=0x%lx backup=0x%lx enter_brk=0x%lx exit_brk=0x%lx "
            "strategy=%s\n",
            tpid, r.art_method, entry_off, orig_entry, tramp, backup,
            enter_brk, exit_brk, use_uxn ? "uxn" : "field");

out_put:
    if (ret) {
        out->ret = ret;
        pr_err("pte_java: hook failed %d (pid=%d method=0x%lx)\n",
               ret, tpid, r.art_method);
    }
    mmput(mm);
    put_task_struct(task);
out_unlock:
    if (ret && !out->ret)
        out->ret = ret;
    mutex_unlock(&g_jh_lock);
    return ret;
}

int __nocfi java_unhook_method(pid_t pid, unsigned long art_method,
                               unsigned int entry_off)
{
    struct java_hook_record *rec;

    (void)entry_off;   /* 已记录在槽位里，参数只为 ABI 完整 */

    mutex_lock(&g_jh_lock);
    rec = jh_find(pid, art_method);
    if (!rec) {
        mutex_unlock(&g_jh_lock);
        return 0;              /* 幂等 */
    }
    jh_teardown(rec);
    mutex_unlock(&g_jh_lock);
    return 0;
}

/* ======================================================================
 * 捕获环：参数 / 返回值的输出通道
 *
 * 观察点跑在 BRK 异常上下文（EL1，关中断，不可睡眠，不能拿 mutex）。
 * 在那里 printk 会：
 *   - 拖慢每次方法调用（高频方法会直接拖死系统）；
 *   - 把 dmesg 环形缓冲冲爆，看不到真正需要的信息。
 *
 * 所以 PRINT 动作只把寄存器快照写进一块预分配的定长数组，用户态用
 * "dump" 命令批量取走。写入路径无锁：
 *   - 每条记录有一个 seq（原子递增的序号）；
 *   - 写入者先填内容，再用 smp_wmb 把内容"发布"出去（atomic64_set 带
 *     release 语义），读取者只接受 seq 与预期一致的那条；
 * 多 CPU 同时写不会撕裂；读取者最多跳过一条正在写的记录。
 * ====================================================================== */

#define JH_CAP_SLOTS   512     /* 环形缓冲条数 */
#define JH_CAP_ARGS    8       /* 记录 x0..x7 */

#define JH_CAP_ENTER   1
#define JH_CAP_EXIT    2

struct jh_capture {
    atomic64_t seq;              /* 0 = 空；非 0 = 已发布的序号 */
    u64        stamp_ns;         /* 命中时刻，仅诊断用 */
    u32        pid;
    u32        slot;
    u32        kind;             /* JH_CAP_ENTER / JH_CAP_EXIT */
    u32        nargs;
    u64        method;           /* ArtMethod* */
    u64        regs[JH_CAP_ARGS];
    u64        x8;               /* 间接结果寄存器 */
};

static struct jh_capture *g_cap;
static atomic64_t g_cap_pub = ATOMIC64_INIT(0);   /* 已发布的最大序号 */
static u64 g_cap_read;                            /* 读取端游标 */
static int g_cap_on;

int javahook_capture_is_on(void)
{
    return g_cap_on;
}

int javahook_capture_enable(int on)
{
    int prev = g_cap_on;

    g_cap_on = on ? 1 : 0;
    return prev;
}

int javahook_capture_clear(void)
{
    int i;

    if (!g_cap)
        return -ENODEV;
    for (i = 0; i < JH_CAP_SLOTS; i++)
        atomic64_set(&g_cap[i].seq, 0);
    atomic64_set(&g_cap_pub, 0);
    g_cap_read = 0;
    return 0;
}

/* 分配环形缓冲（模块初始化时一次到位，避免在异常上下文里申请内存） */
int javahook_capture_init(void)
{
    static_assert(sizeof(struct jh_capture) * JH_CAP_SLOTS <= 128 * 1024,
                  "捕获环过大，请降低 JH_CAP_SLOTS");

    g_cap = kvzalloc(sizeof(*g_cap) * JH_CAP_SLOTS, GFP_KERNEL);
    if (!g_cap)
        return -ENOMEM;
    atomic64_set(&g_cap_pub, 0);
    g_cap_read = 0;
    g_cap_on = 1;               /* 默认开启：装 hook 就是为了看东西 */
    return 0;
}

void javahook_capture_exit(void)
{
    kvfree(g_cap);
    g_cap = NULL;
    g_cap_on = 0;
}

/*
 * 写入一条记录。**只能从 BRK 异常上下文调用**：
 * 无锁、无分配、无睡眠。失败（未分配）直接丢弃。
 */
static void __nocfi jh_cap_put(u32 kind, struct java_hook_record *rec,
                               const struct pt_regs *uregs)
{
    struct jh_capture *c;
    u64 seq;
    int i;

    if (!g_cap_on || !g_cap)
        return;

    seq = (u64)atomic64_inc_return(&g_cap_pub);
    c = &g_cap[(seq - 1) % JH_CAP_SLOTS];

    /* 先作废这条，再写内容，最后才发布 seq */
    atomic64_set(&c->seq, 0);
    smp_wmb();

    c->stamp_ns = ktime_get_ns();
    c->pid      = (u32)rec->pid;
    c->slot     = (u32)jh_slot_id(rec);
    c->kind     = kind;
    c->method   = rec->art_method;
    c->nargs    = JH_CAP_ARGS;
    for (i = 0; i < JH_CAP_ARGS; i++)
        c->regs[i] = uregs->regs[i];
    c->x8 = uregs->regs[8];

    smp_wmb();
    atomic64_set(&c->seq, (s64)seq);
}

/* 把一条记录格式化成一行文本 */
static int jh_cap_format(char *buf, int size, const struct jh_capture *c)
{
    int off = 0, i;

    off += scnprintf(buf + off, size - off,
                     "#%lld %s slot=%u pid=%u method=0x%llx",
                     (long long)atomic64_read(&c->seq),
                     c->kind == JH_CAP_EXIT ? "RET" : "ARG",
                     c->slot, c->pid, (unsigned long long)c->method);
    for (i = 0; i < JH_CAP_ARGS; i++)
        off += scnprintf(buf + off, size - off, " x%d=%llx",
                         i, (unsigned long long)c->regs[i]);
    off += scnprintf(buf + off, size - off, " x8=%llx\n",
                     (unsigned long long)c->x8);
    return off;
}

int javahook_capture_dump(char *buf, int size, int max)
{
    int off = 0, n = 0;
    u64 pub, seq;

    if (!buf || size <= 0)
        return 0;
    if (!g_cap)
        return scnprintf(buf, size, "(capture ring not allocated)\n");
    if (max <= 0 || max > JH_CAP_SLOTS)
        max = JH_CAP_SLOTS;

    pub = (u64)atomic64_read(&g_cap_pub);

    /* 生产者已经绕了好几圈：跳到"还能取到"的最早位置 */
    if (pub > (u64)JH_CAP_SLOTS && g_cap_read + JH_CAP_SLOTS < pub)
        g_cap_read = pub - JH_CAP_SLOTS;

    while (g_cap_read < pub && n < max) {
        struct jh_capture *c;
        s64 published;

        g_cap_read++;
        seq = g_cap_read;
        c = &g_cap[(seq - 1) % JH_CAP_SLOTS];

        /* 只有"内容已写完并发布"的记录才认，正被覆盖的跳过 */
        published = atomic64_read(&c->seq);
        smp_rmb();
        if ((u64)published != seq)
            continue;

        off += jh_cap_format(buf + off, size - off, c);
        n++;
        if (off >= size - 160)
            break;              /* 缓冲快满，剩下的下次再 dump */
    }

    if (n == 0)
        off += scnprintf(buf + off, size - off, "(no new records)\n");
    else
        off += scnprintf(buf + off, size - off,
                         "[%d records, total=%llu]\n", n,
                         (unsigned long long)pub);
    return off;
}

/* ======================================================================
 * BRK 观察点
 * ====================================================================== */

/*
 * trampoline 里的 BRK 以 EL0 BRK 异常进来。
 * uregs->pc 就是 BRK 指令本身（AArch64 对 BRK 的 preferred return
 * address 是 BRK 所在地址），所以处理完必须手动 pc += 4，
 * 否则会原地死循环。
 */

/* 规则里的下标检查：idx 必须落在 x0..x7 */
static int jh_rule_idx_ok(const struct JavaArgRule *r)
{
    return r->idx < JH_CAP_ARGS;
}

/*
 * 入口观察点：看 / 改参数。
 * 此刻 x0..x7 就是调用者传进来的原始值，直接改 uregs->regs[n]，
 * 原方法看到的就是改过的参数（trampoline 之后才跳/调原方法）。
 */
static void __nocfi jh_do_enter(struct pt_regs *uregs,
                                struct java_hook_record *rec)
{
    const struct JavaHookReq *r = &rec->req;
    unsigned int i, n;
    int cap_done = 0;

    /*
     * PRINT：先进捕获环（记录的是**修改前**的原始参数）。
     * 多个参数都标了 print 也只记一条——一条记录里就带全部 x0..x7，
     * 重复记录纯属浪费环形缓冲。
     */
    for (i = 0; i < r->arg_cnt && i < JH_ARGS_MAX; i++) {
        if (r->args[i].op == JH_OP_PRINT) {
            jh_cap_put(JH_CAP_ENTER, rec, uregs);
            cap_done = 1;
            break;
        }
    }
    /* JH_FLAG_BRK：额外打一份到 dmesg，给"临时看一眼"用 */
    if (rec->flags & JH_FLAG_BRK) {
        if (!cap_done)
            jh_cap_put(JH_CAP_ENTER, rec, uregs);
        pr_info("pte_java: hit method=0x%lx slot=%d pid=%d\n",
                rec->art_method, jh_slot_id(rec), rec->pid);
        pr_info("pte_java:   x0=%lx x1=%lx x2=%lx x3=%lx\n",
                uregs->regs[0], uregs->regs[1],
                uregs->regs[2], uregs->regs[3]);
    }

    /* 改写：按规则逐条作用到对应寄存器 */
    n = r->arg_cnt < JH_ARGS_MAX ? r->arg_cnt : JH_ARGS_MAX;
    for (i = 0; i < n; i++) {
        const struct JavaArgRule *a = &r->args[i];

        if (!jh_rule_active(a->op) || a->op == JH_OP_PRINT)
            continue;
        if (!jh_rule_idx_ok(a))
            continue;
        uregs->regs[a->idx] = jh_apply_op(a->op, uregs->regs[a->idx], a->val);
    }
}

/*
 * 出口观察点：看 / 改返回值。
 * 此刻刚从原方法 blr 回来，x0（以及 64 位值的 x1）就是返回值。
 *
 * 注意顺序：先记录再修改。这样捕获环里留下的是**原方法的真实返回值**，
 * 而不是被我们改过的值——排查问题时几乎总是想看前者。
 */
static void __nocfi jh_do_exit(struct pt_regs *uregs,
                               struct java_hook_record *rec)
{
    const struct JavaHookReq *r = &rec->req;
    int bits = (r->ret_bits == 32) ? 32 : 64;
    int want_print;

    /*
     * 什么时候记录：
     *   retop == PRINT     —— 用户就是要看返回值
     *   JH_FLAG_BRK        —— 调试开关，顺带看一眼
     * 修改动作本身不触发记录（用户只关心改成什么，不关心原来是什么时，
     * 少一条记录少一份噪声；想两者都要就同时给 retop=print 和一个修改
     * 规则——但 ret_op 只有一个字段，所以这里用 brk 标志做补充）。
     */
    want_print = (r->ret_op == JH_OP_PRINT) || (rec->flags & JH_FLAG_BRK);
    if (want_print)
        jh_cap_put(JH_CAP_EXIT, rec, uregs);

    if (!jh_rule_active(r->ret_op) || r->ret_op == JH_OP_PRINT)
        return;

    if (bits == 32) {
        /*
         * 32 位返回值（int/boolean/float 的位模式）：
         * 只改 w0 —— 写 x0 的低 32 位。ART 侧按 32 位读，高位无所谓，
         * 但保持高位不变更安全（有些路径会顺手当 64 位用）。
         */
        u32 cur = (u32)uregs->regs[0];

        uregs->regs[0] = (uregs->regs[0] & ~0xFFFFFFFFULL) |
                         (u64)(u32)jh_apply_op(r->ret_op, cur,
                                               (u32)r->ret_new);
    } else {
        uregs->regs[0] = jh_apply_op(r->ret_op, uregs->regs[0], r->ret_new);
    }
    /* x1 只有 128 位返回值（long/double 对）才用，规则不碰它 */
}

int __nocfi javahook_handle_brk(struct pt_regs *uregs, unsigned int esr)
{
    unsigned int iss = esr & 0xFFFF;
    unsigned long pc;
    int pid, i;

    if ((iss & 0xFF00U) != JH_BRK_MAGIC)
        return 0;
    if (!uregs)
        return 0;

    pc  = uregs->pc;
    pid = task_tgid_nr(current);

    for (i = 0; i < JH_MAX_SLOTS; i++) {
        struct java_hook_record *rec = &g_jh[i];

        if (!rec->used)
            continue;
        smp_rmb();              /* 与 jh_teardown 的 smp_wmb 配对 */
        if (rec->pid != pid)
            continue;
        if (current->mm != rec->ghost.mm)
            continue;

        if (pc == rec->enter_brk) {
            jh_do_enter(uregs, rec);
            uregs->pc = pc + 4;
            return 1;
        }
        if (pc == rec->exit_brk) {
            jh_do_exit(uregs, rec);
            uregs->pc = pc + 4;
            return 1;
        }
    }
    return 0;
}

/* ---------- 状态查询 ---------- */

/* 把参数规则渲染成 "arg1=print,arg2=add:0x10" 形式 */
static int jh_fmt_args(char *buf, int size, const struct JavaHookReq *r)
{
    static const char *opname[] = { "none", "print", "set", "or", "and", "add" };
    int off = 0;
    unsigned int i, n = r->arg_cnt < JH_ARGS_MAX ? r->arg_cnt : JH_ARGS_MAX;
    int first = 1;

    for (i = 0; i < n; i++) {
        const struct JavaArgRule *a = &r->args[i];

        if (!jh_rule_active(a->op))
            continue;
        off += scnprintf(buf + off, size - off, "%sx%u=%s",
                         first ? "" : ",", a->idx,
                         a->op <= JH_OP_ADD ? opname[a->op] : "?");
        first = 0;
        if (a->op == JH_OP_SET || a->op == JH_OP_OR ||
            a->op == JH_OP_AND || a->op == JH_OP_ADD)
            off += scnprintf(buf + off, size - off, ":0x%llx",
                             (unsigned long long)a->val);
    }
    if (jh_rule_active(r->ret_op)) {
        off += scnprintf(buf + off, size - off, "%sret=%s",
                         first ? "" : ",",
                         r->ret_op <= JH_OP_ADD ? opname[r->ret_op] : "?");
        if (r->ret_op != JH_OP_PRINT)
            off += scnprintf(buf + off, size - off, ":0x%llx",
                             (unsigned long long)r->ret_new);
    }
    if (first && !jh_rule_active(r->ret_op))
        off += scnprintf(buf + off, size - off, "-");
    return off;
}

int javahook_list(char *buf, int size)
{
    int off = 0, i, n = 0;

    off += scnprintf(buf + off, size - off,
                     "idx pid   method       entry_off tramp        backup       "
                     "brk(enter/exit) strat rules\n");
    mutex_lock(&g_jh_lock);
    for (i = 0; i < JH_MAX_SLOTS; i++) {
        struct java_hook_record *rec = &g_jh[i];
        char rules[128];
        int roff;

        if (!rec->used)
            continue;
        roff = jh_fmt_args(rules, sizeof(rules), &rec->req);
        rules[roff < (int)sizeof(rules) ? roff : (int)sizeof(rules) - 1] = 0;

        off += scnprintf(buf + off, size - off,
                         "%3d %5d 0x%08lx 0x%02x       0x%08lx   0x%08lx "
                         "%d/%d %5s %s\n",
                         i, rec->pid, rec->art_method, rec->entry_off,
                         rec->tramp, rec->backup,
                         rec->enter_brk ? 1 : 0, rec->exit_brk ? 1 : 0,
                         rec->use_uxn ? "uxn" : "field", rules);
        n++;
    }
    mutex_unlock(&g_jh_lock);
    off += scnprintf(buf + off, size - off, "[%d/%d slots used] capture=%s\n",
                     n, JH_MAX_SLOTS, g_cap_on ? "on" : "off");
    return off;
}
