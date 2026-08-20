#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/kprobes.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/smp.h>
#include <linux/printk.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/err.h>
#include <asm/hw_breakpoint.h>
#include <asm/debug-monitors.h>
#include <asm/sysreg.h>
#include <asm/ptrace.h>




/* Android 13 GKI 5.10 开了 CONFIG_CFI_CLANG=y 且 CONFIG_CFI_PERMISSIVE 没开。
 * 通过 kallsyms_lookup_name() 拿到的函数地址再用类型化函数指针去调用，
 * 编译器会在调用点插入 CFI hash 检查；模块自己算出的 type id 和 vmlinux
 * 里目标函数挂载的 type id 不一定一致，不一致就 __cfi_check_fail -> panic。
 * 解决：把任何"先 kallsyms 取地址再间接调用"的函数都标 __nocfi。 */
#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

MODULE_LICENSE("GPL");

#define PR_BASE_ID      0x05200000
#define PR_REGIS_HW_BP  (PR_BASE_ID + 1)
#define MY_SIG          36

/* 用户态传进来的请求。语义：
 *   - address != 0：在所有 CPU 上装一个 X 型硬件断点；
 *   - address == 0：把当前已装的断点卸掉；
 *   - pid  >  0 ：按 tgid 过滤，只对该进程的任意线程发信号；
 *   - pid  == 0 ：不过滤，任意 task 命中都发信号（调试 / 全局监控用）；
 *   - type      ：当前未解释，仅打日志，未来留作扩展。 */
struct my_task {
    unsigned int  type;
    unsigned long address;
    pid_t         pid;
};

/* ----- 设计说明 -----
 *
 * 这一版换成 CPU-wide 模式：
 *
 *   register_wide_hw_breakpoint(attr, bp_handle, NULL)
 *
 * 会在每个在线 CPU 上各创建一个 per-CPU perf_event，把 BVR/BCR 持久写入
 * 该 CPU 的调试寄存器。任何 task 调度到该 CPU 后只要 PC 走到 attr.bp_addr
 * 都会产生 EL1 debug exception，进入我们的 bp_handle。
 *
 * 过滤策略放在 bp_handle 里做：比较 current->tgid 与全局保存的 target_tgid，
 *   - 命中目标进程：发送信号 + 走单步恢复；
 *   - 非目标 task ：静默走单步恢复（不发信号、不破坏指令流）。
 *
 * 之所以 *始终* 要做单步恢复：BP 是在指令"将要执行"前触发的，要把那条
 * 指令真正跑过去，只能"关 BCR -> 单步 -> reinstall BCR"，不能直接改 PC
 * 跳过去（prologue 的 stp/sub sp 一跳就崩）。
 *
 * 一个已知的小瑕疵：toggle_bp_registers(BCR, EL0, 0) 只关掉了当前 CPU 的
 * BCR.E，单步完成后 reinstall_suspended_bps() 也只在 *当前 CPU* 重打开。
 * 如果 task 在"关掉 -> 单步完成"这个极窄窗口里被迁到别的 CPU，原 CPU 的
 * BCR 会停留在 disabled 直到再次有目标 task 在那个 CPU 上触发。实测里
 * 这种漏命中几乎不会出现，目前不做额外补偿；如果你后续观察到批量丢命中
 * 可以再加一个 task_work 在单步后用 smp_call_function_many 广播补一刀。
 */

static struct perf_event * __percpu *cpu_bp_events;   /* register_wide 的返回值 */
static unsigned long                 cpu_bp_address;   /* 当前装的地址，0 表示未装 */

/* target_tgid_atomic 同时承担"是否启用"和"过滤目标"两个语义：
 *   <  0 ：模块未装 / 正在拆，bp_handle 只做单步恢复，永不发信号；
 *   == 0 ：装好了，但用户不指定 tgid，任意 task 命中都发信号；
 *   >  0 ：装好了，只对该 tgid 下任意线程发信号。
 * 用 -1 作为"未装"哨兵而不是 0，是为了避开 release_bp() 期间的极短窗口：
 *   release_bp 先把 cpu_bp_events 摘下来再调 unregister_wide_hw_breakpoint
 *   等待 in-flight overflow handler 走完。如果用 0 表示"未装"，在拆除窗口里
 *   bp_handle 会把它解释成"不过滤"，给随便哪个无辜 task 发信号。 */
static atomic_t                      target_tgid_atomic = ATOMIC_INIT(-1);
static DEFINE_MUTEX(bp_lock);

/* ---- sigreturn-rehit 抑制（per-task） ----
 *
 * 命中流程：
 *   1) bp_handle 发送 MY_SIG -> exit-to-user 时分发 -> 用户 handler 运行
 *   2) handler return -> rt_sigreturn 把 PC 还原回断点地址
 *   3) CPU 再次执行该地址 -> BP 再次触发 -> bp_handle 又跑一次
 * 第 3 步那次必须只单步、不发信号，否则用户态死循环。
 *
 * 原来的版本（per-task BP）把 rehit 状态挂在 perf_event 的 ctx 上，
 * O(1)。CPU-wide 模式下整个进程共用一份 perf_event，必须按 task pid
 * 维度跟踪 rehit。这里用 64 槽固定大小哈希，pid 撞槽就线性探测，再
 * 撞就 LRU 顶掉最旧的。 */
#define REHIT_TIMEOUT_NS    (NSEC_PER_SEC)
#define REHIT_SLOTS         64

struct rehit_slot {
    pid_t pid;       /* 0 表示空槽 */
    u64   set_ns;
};

static struct rehit_slot rehit_slots[REHIT_SLOTS];
static DEFINE_SPINLOCK(rehit_lock);

/* 返回 true 表示这是一次 rehit，应该抑制信号；否则正常发信号。 */
static bool rehit_check(pid_t pid)
{
    int i, free_idx = -1, oldest_idx = 0;
    u64 now = ktime_get_ns();
    u64 oldest_ns;
    unsigned long flags;
    bool suppress = false;

    spin_lock_irqsave(&rehit_lock, flags);
    oldest_ns = rehit_slots[0].set_ns;

    for (i = 0; i < REHIT_SLOTS; i++) {
        if (rehit_slots[i].pid == pid) {
            if (now - rehit_slots[i].set_ns < REHIT_TIMEOUT_NS) {
                /* 找到状态机 -> 这次是 rehit，抑制并清槽 */
                rehit_slots[i].pid = 0;
                suppress = true;
            } else {
                /* 槽里残留了一个超时的旧记录：把它当成新的首次命中 */
                rehit_slots[i].set_ns = now;
            }
            goto out;
        }
        if (rehit_slots[i].pid == 0 && free_idx < 0)
            free_idx = i;
        if (rehit_slots[i].set_ns < oldest_ns) {
            oldest_idx = i;
            oldest_ns = rehit_slots[i].set_ns;
        }
    }

    /* 没找到该 pid，说明这是首次命中，登记一个状态机 */
    if (free_idx < 0)
        free_idx = oldest_idx;   /* 表满 -> LRU 顶掉最旧的 */
    rehit_slots[free_idx].pid = pid;
    rehit_slots[free_idx].set_ns = now;

out:
    spin_unlock_irqrestore(&rehit_lock, flags);
    return suppress;
}

static void rehit_clear_all(void)
{
    unsigned long flags;

    spin_lock_irqsave(&rehit_lock, flags);
    memset(rehit_slots, 0, sizeof(rehit_slots));
    spin_unlock_irqrestore(&rehit_lock, flags);
}

static struct kprobe kp;

/* ---- 通过 kallsyms 解析未导出符号 ---- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void (*toggle_bp_registers_t)(int reg, enum dbg_active_el el, int enable);
typedef void (*user_enable_single_step_t)(struct task_struct *task);
typedef struct perf_event * __percpu *
            (*register_wide_hw_breakpoint_t)(struct perf_event_attr *attr,
                                             perf_overflow_handler_t triggered,
                                             void *context);
typedef void (*unregister_wide_hw_breakpoint_t)(struct perf_event * __percpu *cpu_events);

static toggle_bp_registers_t         p_toggle_bp_registers;
static user_enable_single_step_t     p_user_enable_single_step;
static register_wide_hw_breakpoint_t  p_register_wide_hw_breakpoint;
static unregister_wide_hw_breakpoint_t p_unregister_wide_hw_breakpoint;


static unsigned long lookup_via_kprobe(const char *name)
{
    struct kprobe k;
    unsigned long addr = 0;

    memset(&k, 0, sizeof(k));
    k.symbol_name = name;
    if (register_kprobe(&k) == 0) {
        addr = (unsigned long)k.addr;
        unregister_kprobe(&k);
    }
    return addr;
}

static int __nocfi resolve_kernel_symbols(void)
{
    kallsyms_lookup_name_t kln;
    unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");

    if (!addr) {
        pr_err("break: cannot resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }
    kln = (kallsyms_lookup_name_t)addr;

    p_toggle_bp_registers =
        (toggle_bp_registers_t)kln("toggle_bp_registers");
    p_user_enable_single_step =
        (user_enable_single_step_t)kln("user_enable_single_step");
    p_register_wide_hw_breakpoint =
        (register_wide_hw_breakpoint_t)kln("register_wide_hw_breakpoint");
    p_unregister_wide_hw_breakpoint =
        (unregister_wide_hw_breakpoint_t)kln("unregister_wide_hw_breakpoint");

    if (!p_toggle_bp_registers || !p_user_enable_single_step ||
        !p_register_wide_hw_breakpoint || !p_unregister_wide_hw_breakpoint) {
        pr_err("break: missing symbols toggle_bp_registers=%px "
               "user_enable_single_step=%px register_wide_hw_breakpoint=%px "
               "unregister_wide_hw_breakpoint=%px\n",
               p_toggle_bp_registers, p_user_enable_single_step,
               p_register_wide_hw_breakpoint, p_unregister_wide_hw_breakpoint);
        return -ENOENT;
    }
    return 0;
}


/* ---------- 硬件断点命中回调（在 EL1 调试异常上下文，原子）----------
 *
 * 单步恢复路径每次都要走：
 *   1. 关 BCR + di->bps_disabled=1 让硬件 BP 立刻失效；
 *   2. 开 single-step，让那条指令以单步方式跑完，避免直接改 PC
 *      跳过破坏栈帧；
 *   3. 单步走完后 single_step_handler -> reinstall_suspended_bps
 *      自动把 BCR 再次打开，后续再次命中。
 *   4. 信号到达 -> 用户处理 -> sigreturn 还原 PC 引起一次 re-hit，
 *      靠 rehit_check 抑制掉这次。
 *
 * 过滤目标 task：与全局 target_tgid 不匹配的就只走单步路径放行，
 * 不发信号、不触发 rehit 状态机。
 */
static void __nocfi bp_handle(struct perf_event *bp_event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    struct kernel_siginfo info;
    struct debug_info *di;
    int want_tgid;
    bool is_target;

    if (!current || !current->mm || !user_mode(regs))
        return;

    di = &current->thread.debug;

    /* 不管是不是目标 task，先无条件做单步恢复，让指令能跑过去。 */
    di->bps_disabled = 1;
    p_toggle_bp_registers(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL0, 0);
    if (test_thread_flag(TIF_SINGLESTEP))
        di->suspended_step = 1;
    else
        p_user_enable_single_step(current);

    /* 过滤目标 task：
     *   want_tgid <  0：模块没装或正在拆，单步放行不发信号；
     *   want_tgid == 0：不过滤，所有 task 命中都发信号；
     *   want_tgid >  0：只对该 tgid 下的任意线程发信号。 */
    want_tgid = atomic_read(&target_tgid_atomic);
    if (want_tgid < 0)
        return;
    is_target = (want_tgid == 0) || (current->tgid == want_tgid);
    if (!is_target)
        return;

    /* sigreturn-rehit 抑制 */
    if (rehit_check(current->pid))
        return;

    memset(&info, 0, sizeof(info));
    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr   = (void __user *)(uintptr_t)bp_event->attr.bp_addr;
    send_sig_info(MY_SIG, &info, current);
    pr_info("break: send signal tgid=%d tid=%d addr=0x%llx\n",
            current->tgid, current->pid,
            (unsigned long long)bp_event->attr.bp_addr);
}


/* ---------- 卸载当前 BP ---------- *
 * unregister_wide_hw_breakpoint 内部会等所有正在执行的 overflow handler
 * 走完才返回，所以释放后调用 bp_handle 不会有 use-after-free。 */
static void __nocfi release_bp(void)
{
    struct perf_event * __percpu *evs;

    mutex_lock(&bp_lock);
    evs = cpu_bp_events;
    cpu_bp_events = NULL;
    cpu_bp_address = 0;
    /* 先把 target_tgid 标记为 -1 (off)，再去 unregister。这样 unregister
     * 等待 in-flight overflow handler 时，那些 handler 看到 -1 会自动跳过
     * 发信号，不会误伤无辜 task。 */
    atomic_set(&target_tgid_atomic, -1);
    mutex_unlock(&bp_lock);

    if (evs)
        p_unregister_wide_hw_breakpoint(evs);

    rehit_clear_all();
}


/* ---------- 在内核线程上下文里真正去注册硬件断点 ---------- *
 *
 * 走 workqueue 而不是 task_work，原因有二：
 *
 *   1. kprobe pre-handler 是原子上下文（IRQ disabled），而
 *      register_wide_hw_breakpoint 会 sleep（要在所有 CPU 上做 IPI/install），
 *      不能直接在那里跑，必须挪到可调度上下文。
 *
 *   2. register_wide_hw_breakpoint 注册的是 CPU-scoped perf_event，
 *      find_get_context() 对 CPU 维度 event 会强制 perf_allow_cpu() 检查：
 *      perf_event_paranoid > 0 且 !capable(CAP_PERFMON) 直接返回 -EACCES。
 *      task_work 跑在「调用 prctl 的那个无特权用户进程」上下文里，capable()
 *      用的是它的 cred，必然失败。改用 workqueue 后回调跑在内核 worker
 *      线程（init_cred）上下文，capable(CAP_PERFMON) 为真，直接放行。
 *
 * 用 alloc_ordered_workqueue 建的有序队列，保证 install/uninstall 串行执行，
 * 不会有两个请求并发改 cpu_bp_events。
 */
static struct workqueue_struct *bp_wq;

struct bp_request {
    struct work_struct work;
    struct my_task     t;
};

static void __nocfi bp_install_work(struct work_struct *work)
{
    struct bp_request *req = container_of(work, struct bp_request, work);
    struct my_task t = req->t;
    struct perf_event_attr attr;
    struct perf_event * __percpu *evs;

    pr_info("break: install (work): type=%u addr=0x%lx target_tgid=%d\n",
            t.type, t.address, t.pid);

    /* uninstall：address == 0 时卸掉当前 BP */
    if (t.address == 0) {
        release_bp();
        pr_info("break: bp uninstalled\n");
        goto out_free;
    }

    /* install：覆盖语义，先撤旧的再装新的 */
    release_bp();

    hw_breakpoint_init(&attr);
    attr.bp_addr        = t.address;
    attr.bp_len         = HW_BREAKPOINT_LEN_4;
    attr.bp_type        = HW_BREAKPOINT_X;
    attr.exclude_kernel = 1;

    evs = p_register_wide_hw_breakpoint(&attr, bp_handle, NULL);
    if (IS_ERR_OR_NULL(evs)) {
        pr_err("break: register_wide_hw_breakpoint failed: %ld\n",
               evs ? PTR_ERR(evs) : -ENOMEM);
        goto out_free;
    }

    mutex_lock(&bp_lock);
    cpu_bp_events  = evs;
    cpu_bp_address = t.address;
    /* t.pid < 0 一律按"无过滤"处理；>=0 直接透传到原子变量。 */
    atomic_set(&target_tgid_atomic, t.pid > 0 ? t.pid : 0);
    mutex_unlock(&bp_lock);

    pr_info("break: bp installed cpu-wide at 0x%lx, target tgid=%d%s\n",
            t.address, t.pid,
            t.pid > 0 ? "" : " (no filter, all tasks)");

out_free:
    kfree(req);
}


/* ---------- kprobe 回调：只采集数据，挂 workqueue ----------
 *
 * kprobe pre handler 是原子上下文（IRQ disabled），只做 copy_from_user +
 * 入队，真正会 sleep 的注册动作丢给 bp_wq 的 worker 线程跑。 */
static int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
    struct pt_regs *uregs;
    int option;
    unsigned long arg2;
    struct bp_request *req;
    struct my_task t;
    unsigned long left;

    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs)
        return 0;

    option = (int)uregs->regs[0];
    if (option != PR_REGIS_HW_BP)
        return 0;

    arg2 = (unsigned long)uregs->regs[1];
    if (!arg2)
        return 0;

    pagefault_disable();
    left = copy_from_user(&t, (void __user *)arg2, sizeof(t));
    pagefault_enable();
    if (left) {
        pr_err("break: copy_from_user failed, %lu bytes left\n", left);
        return 0;
    }

    req = kmalloc(sizeof(*req), GFP_ATOMIC);
    if (!req)
        return 0;

    req->t = t;
    INIT_WORK(&req->work, bp_install_work);

    if (!queue_work(bp_wq, &req->work)) {
        pr_err("break: queue_work failed (tgid=%d tid=%d), req already queued\n",
               current->tgid, current->pid);
        kfree(req);
    }

    return 0;
}

/* ---------- 模块初始化 / 退出 ---------- */
static int __init init_mod(void)
{
    int ret;

    ret = resolve_kernel_symbols();
    if (ret)
        return ret;

    /* 有序队列：保证 install/uninstall 请求按提交顺序串行执行 */
    bp_wq = alloc_ordered_workqueue("break_bp_wq", 0);
    if (!bp_wq) {
        pr_err("break: alloc_ordered_workqueue failed\n");
        return -ENOMEM;
    }

    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("break: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
        destroy_workqueue(bp_wq);
        return ret;
    }

    pr_info("break: module loaded (cpu-wide mode)\n");
    return 0;
}

static void __nocfi __exit exit_mod(void)
{
    /* 先摘 kprobe，确保不再有新的 req 入队；
     * 再 flush 把队列里在途的 install/uninstall 跑完，避免 release_bp 之后
     * 还有 worker 引用已释放的资源；最后销毁队列。 */
    unregister_kprobe(&kp);
    flush_workqueue(bp_wq);
    release_bp();
    destroy_workqueue(bp_wq);
    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);
