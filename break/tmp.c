#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
// #include <linux/eventfd.h>
#include <linux/sched.h>
#include <linux/workqueue.h>


MODULE_LICENSE("GPL");

#define PR_BASE_ID    0x05200000
#define PR_REGIS_HW_BP (PR_BASE_ID+1)
#define MY_SIG 36



struct my_task {
    unsigned int type;
    unsigned long address;
};


struct bp_reg_work {
    struct work_struct work;
    pid_t pid;
    unsigned long addr;
};


static struct perf_event *bp;
static struct work_struct bp_unreg_work;




static void bp_unreg_work_handler(struct work_struct *w)
{
    if (bp) {
        // 安全卸载（此时处于进程上下文）
        unregister_hw_breakpoint(bp);   // 或 perf_event_release_kernel(bp);
        bp = NULL;
        pr_info("bp unregistered by work\n");
    }
}



/*
    注册硬件断点的回调，这个回调中只会发送信号，然后将取消注册硬件断点的逻辑进行调度
*/
static void bp_handle(struct perf_event *bp_event,
                      struct perf_sample_data *data,
                      struct pt_regs *regs)
{
    struct kernel_siginfo info;
    int signal_info_res;


    printk(KERN_ERR "break [HWBP] hit pid=%d\n", current->pid);
    memset(&info, 0, sizeof(info));

    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr = (void*)bp_event->attr.bp_addr;
    signal_info_res = send_sig_info(MY_SIG, &info, current->group_leader);
    printk(KERN_INFO "bp hit & single-step started for pid=%d\n", current->pid);

    schedule_work(&bp_unreg_work);
}



static void bp_reg_work_handler(struct work_struct *w){
    struct bp_reg_work *bpw = container_of(w, struct bp_reg_work, work);
    struct task_struct *task;
    struct perf_event_attr attr;

    // 此时已经是进程上下文，可以睡眠
    task = get_pid_task(find_vpid(bpw->pid), PIDTYPE_PID);
    if (!task) {
        pr_err("break target task %d not found\n", bpw->pid);
        return;
    }

     // 先清理可能残留的断点
    if (bp) {
        unregister_hw_breakpoint(bp);
        bp = NULL;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = bpw->addr;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.exclude_kernel = 1;

    bp = register_user_hw_breakpoint(&attr, bp_handle, NULL, task);
    if (IS_ERR(bp)) {
        pr_err("break register_user_hw_breakpoint failed\n");
    } else {
        pr_info("break registered for task %d\n", bpw->pid);
    }

    put_task_struct(task);
    kfree(bpw);
}



/*
    kprobe 的回调函数，
*/
static int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
     struct pt_regs *uregs;
     int            option;
     unsigned long  arg2, arg3, arg4, arg5;
    struct my_task t;
    struct bp_reg_work *bpw;
    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs){
        printk("break get uregs fail \n");
        return 0;
    }
    option = (int)         uregs->regs[0];
    arg2   = (unsigned long)uregs->regs[1];
    arg3   = (unsigned long)uregs->regs[2];
    arg4   = (unsigned long)uregs->regs[3];
    arg5   = (unsigned long)uregs->regs[4];


    if (option == PR_REGIS_HW_BP){
        printk("break prctl pid=%d comm=%s option=0x%x arg2=0x%lx arg3=0x%lx arg4=0x%lx arg5=0x%lx\n",
            current->pid, current->comm, option, arg2, arg3, arg4, arg5);

        if (copy_from_user(&t, (void __user *)arg2, sizeof(t))) {
            printk(KERN_ERR "copy_from_user failed\n");
            return 0;
        }
        // printk("break copy_from_user success\n");
        // printk("break target function address %lx \n", t.address);


        bpw = kmalloc(sizeof(*bpw), GFP_ATOMIC);
        bpw->pid = current->pid;
        bpw->addr = t.address;
        INIT_WORK(&bpw->work, bp_reg_work_handler);
        schedule_work(&bpw->work);

        // set_bp(current->pid, &t);
        return 0;
    }
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
        printk(KERN_ERR "break register_kprobe fail %d\n", ret);
        return ret;
    }

    INIT_WORK(&bp_unreg_work, bp_unreg_work_handler);
    printk(KERN_INFO "break module loaded\n");
    return 0;
}


static void __exit exit_mod(void)
{

    // 取消可能残留的工作队列（flush/cancel）
    cancel_work_sync(&bp_unreg_work);
    if (bp)
        unregister_hw_breakpoint(bp);

    unregister_kprobe(&kp);
    printk(KERN_INFO "break module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);