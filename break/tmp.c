#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <asm/debug-monitors.h>
#include <asm/hw_breakpoint.h>
#include <asm/ptrace.h>



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
static pid_t              bp_tgid;
static unsigned long      bp_addr;


// 函数原型
// void toggle_bp_registers(int reg, enum dbg_active_el el, int enable)
// typedef void(*toggle_bp_registers_t)(int reg, enum dbg_active_el el, int enable);



// 函数原型
// void user_enable_single_step(struct task_struct *child)
// typedef void (*user_enable_single_step_t)(struct task_struct *child);


/* ---------- 通过 kprobe 拿到未导出符号 ---------- */
typedef int  (*arch_install_hw_breakpoint_t)(struct perf_event *bp);
typedef void (*arch_uninstall_hw_breakpoint_t)(struct perf_event *bp);
typedef void (*user_enable_single_step_t)(struct task_struct *task);
typedef void (*user_disable_single_step_t)(struct task_struct *task);
typedef void (*register_user_step_hook_t)(struct step_hook *hook);
typedef void (*unregister_user_step_hook_t)(struct step_hook *hook);

static arch_install_hw_breakpoint_t   p_arch_install_bp;
static arch_uninstall_hw_breakpoint_t p_arch_uninstall_bp;
static user_enable_single_step_t      p_user_enable_ss;
static user_disable_single_step_t     p_user_disable_ss;
static register_user_step_hook_t      p_reg_step;
static unregister_user_step_hook_t    p_unreg_step;



static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}


/* ---------- 单步异常 hook：把 BP 重新装回去 ---------- */
static int my_step_fn(struct pt_regs *regs, unsigned int esr)
{
    /* 只处理我们关心的进程；其它人的单步直接放行 */
    if (!current || current->tgid != bp_tgid)
        return DBG_HOOK_ERROR;

    if (bp && p_arch_install_bp)
        p_arch_install_bp(bp);          /* 重写 BVR/BCR，E 位置 1 */

    if (p_user_disable_ss)
        p_user_disable_ss(current);     /* 清 TIF_SINGLESTEP */
    /* 兜底：把 SPSR.SS 位也清掉，免得回到用户态又触发一次 */
    regs->pstate &= ~DBG_SPSR_SS;

    pr_info("break [STEP] re-armed bp at 0x%lx, pid=%d, pc=0x%lx\n",
            bp_addr, current->pid, instruction_pointer(regs));

    return DBG_HOOK_HANDLED;
}

static struct step_hook my_step_hook = {
    .fn = my_step_fn,
};



/* ---------- 硬件断点命中回调（仍在原子上下文） ---------- */
static void bp_handle(struct perf_event *bp_event,
                      struct perf_sample_data *data,
                      struct pt_regs *regs)
{
    struct kernel_siginfo info;
    // struct debug_info   *di;
    pr_info("breakpoint hit at 0x%llx, PC=0x%llx\n",
            bp_event->attr.bp_addr, regs->pc);

    // 发送信号给用户态（send_sig_info 在原子上下文安全）

    memset(&info, 0, sizeof(info));
    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr   = (void __user *)bp_event->attr.bp_addr; // 可选
    send_sig_info(MY_SIG, &info, current);
     if (p_arch_uninstall_bp)
        p_arch_uninstall_bp(bp_event);

    /* 3. 打开 PSTATE.SS + TIF_SINGLESTEP，让 ERET 后立刻进入单步异常 */
    if (p_user_enable_ss)
        p_user_enable_ss(current);
    else
        regs->pstate |= DBG_SPSR_SS; 
    return;
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

    bp = register_user_hw_breakpoint(&attr, bp_handle, NULL, task);
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
    // struct bp_work *work;

    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs) {
        pr_err("break: get uregs failed\n");
        return 0;
    }

     option = (int)         uregs->regs[0];

    if (option == PR_REGIS_HW_BP) {
        arg2   = (unsigned long)uregs->regs[1];
        // arg3   = (unsigned long)uregs->regs[2];
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
    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("break: register_kprobe failed %d\n", ret);
        return ret;
    }

    p_arch_install_bp   = (void *)lookup_name("arch_install_hw_breakpoint");
    p_arch_uninstall_bp = (void *)lookup_name("arch_uninstall_hw_breakpoint");
    p_user_enable_ss    = (void *)lookup_name("user_enable_single_step");
    p_user_disable_ss   = (void *)lookup_name("user_disable_single_step");
    p_reg_step          = (void *)lookup_name("register_user_step_hook");
    p_unreg_step        = (void *)lookup_name("unregister_user_step_hook");

      pr_info("break: syms install=%px uninstall=%px ss_en=%px ss_dis=%px reg=%px unreg=%px\n",
            p_arch_install_bp, p_arch_uninstall_bp,
            p_user_enable_ss, p_user_disable_ss,
            p_reg_step, p_unreg_step);

    p_reg_step(&my_step_hook);
    pr_info("break: module loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{

    if (bp) {
        unregister_hw_breakpoint(bp);
        bp = NULL;
    }
    // 注销 kprobe，避免新的工作被调度
    unregister_kprobe(&kp);
    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);