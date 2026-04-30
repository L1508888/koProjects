#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/eventfd.h>
#include <linux/sched.h>


MODULE_LICENSE("GPL");

// #define PR_BASE_ID    0x05200000
// #define PR_REGIS_HW_BP (PR_BASE_ID+1)
// #define MY_SIG 36

// struct my_task {
//     unsigned int type;
//     unsigned long address;
// };


static struct perf_event *bp;

// static void bp_handle(struct perf_event *bp,
//                       struct perf_sample_data *data,
//                       struct pt_regs *regs)
// {
//     struct kernel_siginfo info;
//     int signal_info_res;
//     printk(KERN_ERR "[HWBP] hit pid=%d\n", current->pid);
//     memset(&info, 0, sizeof(info));

//     info.si_signo = MY_SIG;
//     info.si_code  = SI_QUEUE;
//     info.si_ptr = (void*)bp->attr.bp_addr;
//     signal_info_res = send_sig_info(MY_SIG, &info, current->group_leader);
//     printk(KERN_ERR "send_sig_info ret %d\n", signal_info_res);
// }



/* 注册断点 */
// static int set_bp(pid_t pid, struct my_task *t)
// {
//     struct perf_event_attr attr;
//     struct task_struct *task;

//     task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
//     if (!task) return -1;

//     hw_breakpoint_init(&attr);
//     attr.bp_addr = t->address;
//     attr.bp_len  = HW_BREAKPOINT_LEN_4;
//     attr.bp_type = HW_BREAKPOINT_X;
//     attr.exclude_kernel = 1;


//     printk("SIGRTMIN = %d, MY_SIG = %d\n", SIGRTMIN, MY_SIG);
//     bp = register_user_hw_breakpoint(&attr, bp_handle, NULL, task);

//     if (IS_ERR(bp)) {
//         printk(KERN_ERR "register bp failed\n");
//         return -1;
//     }

//     printk(KERN_INFO "set bp addr=%lx\n", t->address);
//     return 0;
// }





static int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
     struct pt_regs *uregs;
     int            option;
     unsigned long  arg2, arg3, arg4, arg5;
    // struct my_task t;
    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs){
        printk("get uregs fail \n");
        return 0;

    }
    option = (int)         uregs->regs[0];
    arg2   = (unsigned long)uregs->regs[1];
    arg3   = (unsigned long)uregs->regs[2];
    arg4   = (unsigned long)uregs->regs[3];
    arg5   = (unsigned long)uregs->regs[4];


    pr_info("[prctl] pid=%d comm=%s option=0x%x arg2=0x%lx arg3=0x%lx arg4=0x%lx arg5=0x%lx\n",
            current->pid, current->comm,
            option, arg2, arg3, arg4, arg5);

    // if (option != PR_REGIS_HW_BP)
    //     return 0;

    

    // if (copy_from_user(&t, (void __user *)arg2, sizeof(t))) {
    //     printk(KERN_ERR "copy_from_user failed\n");
    //     return 0;
    // }
    // set_bp(current->pid, &t);
    return 0;
}


static struct kprobe kp;


static int __init init_mod(void)
{
    int ret;
    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe fail %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "module loaded\n");
    return 0;
}


static void __exit exit_mod(void)
{
    if (bp)
        unregister_hw_breakpoint(bp);

    unregister_kprobe(&kp);

    printk(KERN_INFO "module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);