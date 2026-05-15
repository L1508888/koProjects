#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/kprobes.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/printk.h>
#include <asm/hw_breakpoint.h>
#include <asm/debug-monitors.h>
#include <asm/sysreg.h>



MODULE_LICENSE("GPL");

#define PR_BASE_ID      0x05200000
#define PR_REGIS_HW_BP  (PR_BASE_ID + 1)
#define MY_SIG          36

struct my_task {
    unsigned int type;
    unsigned long address;
};



static struct perf_event *bp;
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



static toggle_bp_registers_t      p_toggle_bp_registers;
static user_enable_single_step_t  p_user_enable_single_step;
static register_user_hw_breakpoint_t p_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t p_unregister_hw_breakpoint;


/* register_kprobe 内部会用 kallsyms 把 symbol_name 转成 addr，
 * 借此把 kallsyms_lookup_name 自己掏出来。 */
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

static int resolve_kernel_symbols(void)
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

    if (!p_toggle_bp_registers || !p_user_enable_single_step) {
        pr_err("break: missing symbols toggle_bp_registers=%px "
               "user_enable_single_step=%px register_user_hw_breakpoint=%px "
               "unregister_hw_breakpoint=%px\n",
               p_toggle_bp_registers, p_user_enable_single_step,
               p_register_user_hw_breakpoint, p_unregister_hw_breakpoint);
        return -ENOENT;
    }
    return 0;
}
// static pid_t              bp_tgid;
// static unsigned long      bp_addr;


// 函数原型
// void toggle_bp_registers(int reg, enum dbg_active_el el, int enable)
// typedef void(*toggle_bp_registers_t)(int reg, enum dbg_active_el el, int enable);



// 函数原型
// void user_enable_single_step(struct task_struct *child)
// typedef void (*user_enable_single_step_t)(struct task_struct *child);




/* ---------- 硬件断点命中回调（仍在原子上下文） ---------- */
static void bp_handle(struct perf_event *bp_event,
                      struct perf_sample_data *data,
                      struct pt_regs *regs)
{
    struct kernel_siginfo info;
    struct debug_info *di = &current->thread.debug;

    pr_info("breakpoint hit at 0x%llx, PC=0x%llx\n",
            bp_event->attr.bp_addr, regs->pc);

    /*
     * 关键：ARM64 的 HW_BREAKPOINT_X 是 before-execute，PC 仍指向
     * 断点指令。因为我们用了自定义 overflow_handler，
     * uses_default_overflow_handler() 返回 false，
     * arch/arm64/kernel/hw_breakpoint.c::breakpoint_handler() 不会替我们
     * 关 BP + 单步，所以必须在这里手工补上，否则返回用户态会立刻再次命中。
     *
     * 这里复用内核自带的 single_step_handler/reinstall_suspended_bps()
     * 机制：单步过完那一条指令后，BP 会被它自动重新装回。
     */
    di->bps_disabled = 1;
    p_toggle_bp_registers(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL0, 0);
    if (test_thread_flag(TIF_SINGLESTEP))
        di->suspended_step = 1;
    else
        p_user_enable_single_step(current);

    /* 通知用户态。注意此时 PC 仍 == bp_addr，用户 handler 看到的
     * x0..x7 就是函数入口的实参。 */
    memset(&info, 0, sizeof(info));
    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr   = (void __user *)bp_event->attr.bp_addr;
    send_sig_info(MY_SIG, &info, current);
}





static void set_bp(int pid, struct my_task* target_task)
{
    struct task_struct *task;
    struct perf_event_attr attr;

    pr_info("break prepare install breakpoint at %lx \n", target_task->address);
    task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        pr_err("break: target task %d not found\n", pid);
        return;
    }

    /* 创建新断点 */
    hw_breakpoint_init(&attr);
    attr.bp_addr = target_task->address;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.exclude_kernel = 1;

    bp = p_register_user_hw_breakpoint(&attr, bp_handle, NULL, task);
    if (IS_ERR(bp)) {
        pr_err("break: register_user_hw_breakpoint failed\n");
        bp = NULL;
    } else {
        pr_info("break: bp re-registered for task %d at 0x%lx\n", pid, target_task->address);
    }

    put_task_struct(task);
}



/* ---------- kprobe 回调：只收集数据，调度工作 ---------- */
static int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
    struct pt_regs *uregs;
    int option, pid;
    unsigned long arg2;
    struct my_task t;

    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs) {
        pr_err("break: get uregs failed\n");
        return 0;
    }

    option = (int)uregs->regs[0];

    if (option == PR_REGIS_HW_BP) {
        arg2   = (unsigned long)uregs->regs[1];
        pr_info("break: prctl pid=%d comm=%s option=0x%x arg2=0x%lx\n",
                current->pid, current->comm, option, arg2);

        if (copy_from_user(&t, (void __user *)arg2, sizeof(t))) {
            pr_err("break: copy_from_user failed\n");
            return 0;
        }

        pid = current->pid;
        set_bp(pid, &t);
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
        pr_err("break: register_kprobe failed %d\n", ret);
        return ret;
    }

    pr_info("break: module loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{

    if (bp) {
        p_unregister_hw_breakpoint(bp);
        bp = NULL;
    }
    // 注销 kprobe，避免新的工作被调度
    unregister_kprobe(&kp);
    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);