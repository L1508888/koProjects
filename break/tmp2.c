#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/slab.h>        // kmalloc/kfree

MODULE_LICENSE("GPL");

#define PR_BASE_ID      0x05200000
#define PR_REGIS_HW_BP  (PR_BASE_ID + 1)
#define MY_SIG          36

struct my_task {
    unsigned int pid;
    unsigned int type;
    unsigned long address;

};




// 这两个静态变量在后续会继续使用
static struct perf_event *bp;
static struct my_task target_task;

/* ---------- 硬件断点命中回调 ---------- */
static void bp_handle(struct perf_event *bp_event,
                      struct perf_sample_data *data,
                      struct pt_regs *regs)
{
    struct kernel_siginfo info;

    /* 先安全卸载旧断点（此时已经在进程上下文） */
    if (bp) {
        unregister_hw_breakpoint(bp);
        bp = NULL;
    }
    
    /* 2. 发送信号给用户态 */
    memset(&info, 0, sizeof(info));
    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr   = (void *)bp_event->attr.bp_addr;
    send_sig_info(MY_SIG, &info, current->group_leader);
    
}


static void set_bp(struct my_task* target_task)
{
    struct task_struct *task;
    struct perf_event_attr attr;
    
    pr_info("break prepare install breakpoint at %lx \n", target_task->address);
    task = get_pid_task(find_vpid(target_task->pid), PIDTYPE_PID);
    if (!task) {
        pr_err("break: target task %d not found\n", target_task->pid);
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
        pr_info("break: bp re-registered for task %d at 0x%lx\n", target_task->pid, target_task->address);
    }

    put_task_struct(task);
}

/* ---------- kprobe 回调 ---------- */
static int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
    struct pt_regs *uregs;
    int option;
    unsigned long arg2, arg3, arg4, arg5;
    
    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs) {
        pr_err("break: get uregs failed\n");
        return 0;
    }

    option = (int)         uregs->regs[0];
    arg2   = (unsigned long)uregs->regs[1];
    arg3   = (unsigned long)uregs->regs[2];
    arg4   = (unsigned long)uregs->regs[3];
    arg5   = (unsigned long)uregs->regs[4];

    if (option == PR_REGIS_HW_BP) {
        pr_info("break: prctl pid=%d comm=%s option=0x%x arg2=0x%lx\n",
                current->pid, current->comm, option, arg2);

        if (copy_from_user(&target_task, (void __user *)arg2, sizeof(target_task))) {
            pr_err("break: copy_from_user failed\n");
            return 0;
        }
        target_task.pid = current->pid;
        set_bp(&target_task);
    }
    return 0;
}

static struct kprobe kp;

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

    pr_info("break: module loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{
    if (bp) {
        unregister_hw_breakpoint(bp);
        bp = NULL;
    }
    unregister_kprobe(&kp);
    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);