#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
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
#include <linux/task_work.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
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

struct my_task {
    unsigned int  type;
    unsigned long address;
    pid_t         pid;   /* 目标线程的 vpid；为 0 时表示调用线程自己 */
};

/* ----- 全局状态 ----- *
 *
 * 现在按"用户态指定的 pid"精确地装一份 hw_breakpoint，每个 install 请求
 * 对应一个 bp_entry，串在 bp_list 里。ARM64 的硬件断点寄存器是 per-thread
 * 的，所以这里指定的"pid"就是真正会命中 BP 的线程。
 *
 * 同一进程/线程多次 install 走"覆盖"语义：每次 install 之前会把已有的
 * 所有 entry 撤干净（见 bp_install_twork 开头的 release_all_bp_entries）。
 *
 * perf 子系统会在目标线程退出时自动 detach 该事件，我们持有的 perf_event
 * ref 仍然有效，最终在 release 时统一 drop。
 */
struct bp_entry {
    struct list_head    list;
    struct perf_event  *bp;
    struct task_struct *task;
    /* per-entry 的 sigreturn-rehit 状态机，避免多线程互相踩到 */
    bool                rehit_expected;
    u64                 rehit_set_ns;
    spinlock_t          rehit_lock;
};

static LIST_HEAD(bp_list);
static DEFINE_MUTEX(bp_lock);

/* sigreturn-rehit 抑制
 * ----------------------
 * 详细原理见 bp_handle 上方注释。这里只定义超时常量。 */
#define REHIT_TIMEOUT_NS    (NSEC_PER_SEC)

static struct kprobe kp;

/* ---- 通过 kallsyms 解析未导出符号 ---- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void (*toggle_bp_registers_t)(int reg, enum dbg_active_el el, int enable);
typedef void (*user_enable_single_step_t)(struct task_struct *task);
typedef struct perf_event *(*register_user_hw_breakpoint_t)(struct perf_event_attr *attr,
                            perf_overflow_handler_t triggered,
                            void *context,
                            struct task_struct *tsk);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef int (*task_work_add_t)(struct task_struct *task,
                               struct callback_head *twork,
                               enum task_work_notify_mode mode);

static toggle_bp_registers_t      p_toggle_bp_registers;
static user_enable_single_step_t  p_user_enable_single_step;
static register_user_hw_breakpoint_t p_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t p_unregister_hw_breakpoint;
static task_work_add_t            p_task_work_add;


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
    p_register_user_hw_breakpoint =
        (register_user_hw_breakpoint_t)kln("register_user_hw_breakpoint");
    p_unregister_hw_breakpoint =
        (unregister_hw_breakpoint_t)kln("unregister_hw_breakpoint");
    p_task_work_add =
        (task_work_add_t)kln("task_work_add");

    if (!p_toggle_bp_registers || !p_user_enable_single_step ||
        !p_register_user_hw_breakpoint || !p_unregister_hw_breakpoint ||
        !p_task_work_add) {
        pr_err("break: missing symbols toggle_bp_registers=%px "
               "user_enable_single_step=%px register_user_hw_breakpoint=%px "
               "unregister_hw_breakpoint=%px task_work_add=%px\n",
               p_toggle_bp_registers, p_user_enable_single_step,
               p_register_user_hw_breakpoint, p_unregister_hw_breakpoint,
               p_task_work_add);
        return -ENOENT;
    }
    return 0;
}


/* ---------- 硬件断点命中回调（在 EL1 调试异常上下文，原子）----------
 *
 * 持久模式：每次命中都禁 BP -> 单步 -> 内核自动 reinstall BP -> 继续。
 *   1. 关 BCR + 设 di->bps_disabled=1：让硬件 BP 立刻失效；
 *   2. 开 single-step：让那一条断点指令以单步方式走完，避免破坏函数
 *      栈帧（不能直接修改 PC 跳过它，prologue 的 stp/sub sp 跳过会崩）；
 *   3. 单步走完后 arch/arm64/kernel/debug-monitors.c 的 single_step_handler
 *      会走 reinstall_suspended_bps，自动把 BCR 重新打开、清 bps_disabled，
 *      后续再次走到 X 又能命中。**不需要用户态配合**。
 *   4. sigreturn 会把 PC 还原到 X 引起一次额外的 re-hit；这一次只单步
 *      不发信号（rehit 状态机）。
 *
 * per-entry 状态：通过 perf_event->overflow_handler_context 直接拿到，
 * 不用查链表，避免在原子上下文里走 mutex/RCU。
 */
static void __nocfi bp_handle(struct perf_event *bp_event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    struct bp_entry *e = bp_event->overflow_handler_context;
    struct kernel_siginfo info;
    struct debug_info *di;
    bool suppress = false;
    u64 now;
    unsigned long flags;

    if (!current || !current->mm || !user_mode(regs))
        return;

    di = &current->thread.debug;

    /* 始终：关 BCR + 开单步。单步完成后内核自动把 BCR 再打开。 */
    di->bps_disabled = 1;
    p_toggle_bp_registers(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL0, 0);
    if (test_thread_flag(TIF_SINGLESTEP))
        di->suspended_step = 1;
    else
        p_user_enable_single_step(current);

    /* sigreturn-rehit 抑制 */
    if (e) {
        now = ktime_get_ns();
        spin_lock_irqsave(&e->rehit_lock, flags);
        if (e->rehit_expected && (now - e->rehit_set_ns) < REHIT_TIMEOUT_NS) {
            e->rehit_expected = false;
            suppress = true;
        } else {
            e->rehit_expected = true;
            e->rehit_set_ns = now;
        }
        spin_unlock_irqrestore(&e->rehit_lock, flags);
    }

    if (suppress)
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


/* ---------- 卸载所有 bp_entry ---------- *
 * 把链表整个截下来放锁，再慢慢 unregister + put_task + kfree。
 * unregister_hw_breakpoint 内部会等所有正在执行的 overflow handler 走完，
 * 之后我们 kfree(e) 是安全的，不会有 use-after-free。 */
static void __nocfi release_all_bp_entries(void)
{
    LIST_HEAD(reap);
    struct bp_entry *e, *tmp;

    mutex_lock(&bp_lock);
    list_splice_init(&bp_list, &reap);
    mutex_unlock(&bp_lock);

    list_for_each_entry_safe(e, tmp, &reap, list) {
        list_del(&e->list);
        if (e->bp)
            p_unregister_hw_breakpoint(e->bp);
        if (e->task)
            put_task_struct(e->task);
        kfree(e);
    }
}


/* ---------- 在进程上下文里真正去注册硬件断点 ---------- *
 *
 * 仍然走 task_work：kprobe pre-handler 是原子上下文（IRQ disabled），而
 * register_user_hw_breakpoint 会 sleep，不能直接在那里跑。
 *
 * task_work_add(current, ..., TWA_RESUME) 把回调挂到调用线程的
 * TIF_NOTIFY_RESUME 链上，prctl 系统调用返回用户态前在「调用线程自己」
 * 可调度的上下文里执行。这样调用线程一定还活着、不会 PF_EXITING；目标
 * 线程（t.pid 指向的那个）则在我们 get_task_struct 拿到 ref 之后单独检
 * 查 PF_EXITING，避开 perf core 里的 -ESRCH。
 */
struct bp_request {
    struct callback_head cbh;
    struct my_task       t;
};

static void __nocfi bp_install_twork(struct callback_head *head)
{
    struct bp_request *req = container_of(head, struct bp_request, cbh);
    struct my_task t = req->t;
    struct perf_event_attr attr;
    struct task_struct *target = NULL;
    struct perf_event *new_bp;
    struct bp_entry *e = NULL;

    pr_info("break: install request (twork): caller_tgid=%d caller_tid=%d "
            "type=%u addr=0x%lx target_pid=%d\n",
            current->tgid, current->pid, t.type, t.address, t.pid);

    if (!t.address) {
        pr_err("break: invalid breakpoint address 0\n");
        goto out_free_req;
    }

    /* 先把上次装的全部撤掉（覆盖语义） */
    release_all_bp_entries();

    /* 解析目标线程：pid==0 表示调用线程自己，其他情况按用户态 vpid 查找。
     * 用 RCU 保护 pid_task 的访问，get_task_struct 之后再放 RCU。 */
    if (t.pid == 0) {
        target = current;
        get_task_struct(target);
    } else {
        rcu_read_lock();
        target = pid_task(find_vpid(t.pid), PIDTYPE_PID);
        if (target)
            get_task_struct(target);
        rcu_read_unlock();
    }

    if (!target) {
        pr_err("break: target pid=%d not found\n", t.pid);
        goto out_free_req;
    }

    if (target->flags & PF_EXITING) {
        pr_err("break: target pid=%d is exiting\n", t.pid);
        put_task_struct(target);
        goto out_free_req;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = t.address;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.exclude_kernel = 1;

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        put_task_struct(target);
        goto out_free_req;
    }
    spin_lock_init(&e->rehit_lock);
    e->task = target;

    /* 把 e 作为 overflow_handler_context 传进去，bp_handle 里就能 O(1)
     * 拿到 per-entry 状态。 */
    new_bp = p_register_user_hw_breakpoint(&attr, bp_handle, e, target);
    if (IS_ERR(new_bp)) {
        pr_warn("break: register failed for tid=%d: %ld\n",
                target->pid, PTR_ERR(new_bp));
        put_task_struct(target);
        kfree(e);
        goto out_free_req;
    }
    e->bp = new_bp;

    mutex_lock(&bp_lock);
    list_add_tail(&e->list, &bp_list);
    mutex_unlock(&bp_lock);

    pr_info("break: bp installed on tid=%d (tgid=%d) at 0x%lx (persistent)\n",
            target->pid, target->tgid, t.address);

out_free_req:
    kfree(req);
}


/* ---------- kprobe 回调：只采集数据，挂 task_work ----------
 *
 * 必须标 __nocfi：内部要通过 kallsyms 解析出来的函数指针 p_task_work_add()
 * 做间接调用，CFI hash 对不上会 BUG()/panic，且发生在 atomic 上下文里
 * （kprobe pre handler IRQ disabled），日志根本来不及刷，表现就是"机器
 *  瞬间没了"。 */
static int __nocfi handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
    struct pt_regs *uregs;
    int option, ret;
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
    init_task_work(&req->cbh, bp_install_twork);

    /* TWA_RESUME：仅在返回用户态时唤醒，不会中断当前系统调用语义 */
    ret = p_task_work_add(current, &req->cbh, TWA_RESUME);
    if (ret) {
        pr_err("break: task_work_add(tgid=%d tid=%d) failed: %d\n",
               current->tgid, current->pid, ret);
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

    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("break: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
        return ret;
    }

    pr_info("break: module loaded (persistent mode)\n");
    return 0;
}

static void __nocfi __exit exit_mod(void)
{
    unregister_kprobe(&kp);
    release_all_bp_entries();
    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);
