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
#include <linux/smp.h>
#include <linux/printk.h>
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
    unsigned int type;
    unsigned long address;
};

/* ----- 全局状态 ----- */
static struct perf_event *bp;
static struct task_struct *bp_task;
static DEFINE_MUTEX(bp_lock);

/* one-shot 防死循环：第一次命中后置 1，调度 unreg work 把 perf_event
 * 撤销；后续命中（来自 sigreturn 回到原指令、或者 reinstall 把 BCR
 * 重开后再次命中）只把 BCR 关掉就返回，不刷日志、不重复发信号，等
 * unreg work 跑完就彻底干净。每次成功 install 一个新 bp 时清 0。 */
static atomic_t bp_one_shot = ATOMIC_INIT(0);

static struct kprobe kp;
static struct workqueue_struct *bp_wq;
static struct work_struct bp_unreg_work;

/* ---- 通过 kallsyms 解析未导出符号 ---- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void (*toggle_bp_registers_t)(int reg, enum dbg_active_el el, int enable);
typedef void (*user_enable_single_step_t)(struct task_struct *task);
typedef struct perf_event *(*register_user_hw_breakpoint_t)(struct perf_event_attr *attr,
                            perf_overflow_handler_t triggered,
                            void *context,
                            struct task_struct *tsk);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);

static toggle_bp_registers_t      p_toggle_bp_registers;
static user_enable_single_step_t  p_user_enable_single_step;
static register_user_hw_breakpoint_t p_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t p_unregister_hw_breakpoint;


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

    if (!p_toggle_bp_registers || !p_user_enable_single_step ||
        !p_register_user_hw_breakpoint || !p_unregister_hw_breakpoint) {
        pr_err("break: missing symbols toggle_bp_registers=%px "
               "user_enable_single_step=%px register_user_hw_breakpoint=%px "
               "unregister_hw_breakpoint=%px\n",
               p_toggle_bp_registers, p_user_enable_single_step,
               p_register_user_hw_breakpoint, p_unregister_hw_breakpoint);
        return -ENOENT;
    }
    return 0;
}


/* ---------- 异步：撤销当前已装的硬件断点 ---------- */
static void __nocfi bp_unreg_work_fn(struct work_struct *w)
{
    struct perf_event *to_release = NULL;
    struct task_struct *task_to_put = NULL;

    mutex_lock(&bp_lock);
    if (bp) {
        to_release = bp;
        bp = NULL;
    }
    if (bp_task) {
        task_to_put = bp_task;
        bp_task = NULL;
    }
    mutex_unlock(&bp_lock);

    if (to_release)
        p_unregister_hw_breakpoint(to_release);
    if (task_to_put)
        put_task_struct(task_to_put);
}


/* ---------- 硬件断点命中回调（在 EL1 调试异常上下文，原子）----------
 *
 * 设计要点（one-shot）：
 *   1. 关 BCR + 设 di->bps_disabled=1：让硬件 BP 立刻失效；
 *   2. 开 single-step：让那一条断点指令以单步方式走完，避免破坏函数
 *      栈帧（不能直接修改 PC 跳过它，prologue 的 stp/sub sp 跳过会崩）；
 *   3. 单步走完后内核默认走 reinstall_suspended_bps，会重新打开 BCR
 *      和清 bps_disabled —— 这本身没问题；
 *   4. 但是 sigaction handler 跑完 sigreturn 会把 PC 恢复到断点指令
 *      本身，又会再次命中 BP —— 所以**第一次命中后立刻调度 unreg work
 *      把整个 perf_event 撤销**，让后续命中（直到 unreg work 跑完）
 *      只关 BCR 不发信号。
 *
 * 用户态希望"每次都命中"的话，需要在 sigaction handler 里再调一次
 * prctl 把 BP 重新装回去（call_back.c 里的 func_callback 增加几行）。
 */
static void __nocfi bp_handle(struct perf_event *bp_event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    struct kernel_siginfo info;
    struct debug_info *di;
    int first_hit;

    if (!current || !current->mm || !user_mode(regs))
        return;

    di = &current->thread.debug;

    /* 始终先关 BP + 开单步，无论是不是第一次命中 */
    di->bps_disabled = 1;
    p_toggle_bp_registers(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL0, 0);
    if (test_thread_flag(TIF_SINGLESTEP))
        di->suspended_step = 1;
    else
        p_user_enable_single_step(current);

    /* 一次性：仅首次命中发信号 + 调度 unreg work。 */
    first_hit = atomic_xchg(&bp_one_shot, 1) == 0;
    if (!first_hit)
        return;

    memset(&info, 0, sizeof(info));
    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr   = (void __user *)(uintptr_t)bp_event->attr.bp_addr;
    send_sig_info(MY_SIG, &info, current);

    if (bp_wq)
        queue_work(bp_wq, &bp_unreg_work);
}


/* ---------- 在进程上下文里真正去注册硬件断点 ---------- */
struct bp_request {
    struct work_struct work;
    struct task_struct *task;
    struct my_task t;
};

static void __nocfi bp_install_work(struct work_struct *w)
{
    struct bp_request *req = container_of(w, struct bp_request, work);
    struct perf_event_attr attr;
    struct perf_event *new_bp;
    struct my_task t = req->t;

    pr_info("break: install request: pid=%d type=%u addr=0x%lx\n",
            req->task->pid, t.type, t.address);

    if (!t.address) {
        pr_err("break: invalid breakpoint address 0\n");
        goto out_put;
    }

    mutex_lock(&bp_lock);

    if (bp) {
        p_unregister_hw_breakpoint(bp);
        bp = NULL;
    }
    if (bp_task) {
        put_task_struct(bp_task);
        bp_task = NULL;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = t.address;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.exclude_kernel = 1;

    new_bp = p_register_user_hw_breakpoint(&attr, bp_handle, NULL, req->task);
    if (IS_ERR(new_bp)) {
        pr_err("break: register_user_hw_breakpoint failed: %ld\n",
               PTR_ERR(new_bp));
        new_bp = NULL;
    } else {
        bp = new_bp;
        get_task_struct(req->task);
        bp_task = req->task;
        /* 重新装好后才允许命中：清 one-shot flag */
        atomic_set(&bp_one_shot, 0);
        pr_info("break: bp registered for pid=%d at 0x%lx\n",
                req->task->pid, t.address);
    }

    mutex_unlock(&bp_lock);

out_put:
    put_task_struct(req->task);
    kfree(req);
}


/* ---------- kprobe 回调：只采集数据，调度 work ---------- */
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

    get_task_struct(current);
    req->task = current;
    req->t = t;
    INIT_WORK(&req->work, bp_install_work);

    if (!queue_work(bp_wq, &req->work)) {
        put_task_struct(current);
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

    bp_wq = alloc_ordered_workqueue("break_wq", 0);
    if (!bp_wq) {
        pr_err("break: alloc_ordered_workqueue failed\n");
        return -ENOMEM;
    }

    INIT_WORK(&bp_unreg_work, bp_unreg_work_fn);

    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("break: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
        destroy_workqueue(bp_wq);
        bp_wq = NULL;
        return ret;
    }

    pr_info("break: module loaded (one-shot mode)\n");
    return 0;
}

static void __nocfi __exit exit_mod(void)
{
    unregister_kprobe(&kp);

    if (bp_wq) {
        flush_workqueue(bp_wq);
        destroy_workqueue(bp_wq);
        bp_wq = NULL;
    }

    mutex_lock(&bp_lock);
    if (bp) {
        p_unregister_hw_breakpoint(bp);
        bp = NULL;
    }
    if (bp_task) {
        put_task_struct(bp_task);
        bp_task = NULL;
    }
    mutex_unlock(&bp_lock);

    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);
