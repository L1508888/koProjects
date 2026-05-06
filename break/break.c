#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#define PR_BASE_ID      0x05200000
#define PR_REGIS_HW_BP  (PR_BASE_ID + 1)
#define MY_SIG          36

struct my_task {
    unsigned int type;
    unsigned long address;
};

/* ---------- 工作队列结构 ---------- */
struct bp_work {
    struct work_struct work;
    struct task_struct *target_task;  // 已增加引用的目标进程
    unsigned long addr;
};

static struct perf_event *bp;
static struct kprobe kp;


/* ---------- 硬件断点命中回调（仍在原子上下文） ---------- */
static void bp_handle(struct perf_event *bp_event,
                      struct perf_sample_data *data,
                      struct pt_regs *regs)
{
    struct kernel_siginfo info;
    pr_info("breakpoint hit at 0x%llx, PC=0x%llx\n",
            bp_event->attr.bp_addr, regs->pc);

    // 发送信号给用户态（send_sig_info 在原子上下文安全）
    
    memset(&info, 0, sizeof(info));
    info.si_signo = MY_SIG;
    info.si_code  = SI_QUEUE;
    info.si_ptr   = (void __user *)bp_event->attr.bp_addr; // 可选
    send_sig_info(MY_SIG, &info, current);

    // 在原子上下文中安全地禁用断点
    // perf_event_disable_inatomic(bp_event);
}




/* ---------- 工作处理：实际注册硬件断点 ---------- */
static void bp_register_work(struct work_struct *work)
{
    struct bp_work *w = container_of(work, struct bp_work, work);
    struct perf_event_attr attr;
    struct perf_event *new_bp;

    pr_info("break: work installing bp for pid %d at 0x%lx\n",
            w->target_task->pid, w->addr);

    /* 初始化断点属性（不使用 hw_breakpoint_init 更可控） */
    memset(&attr, 0, sizeof(attr));
    attr.size        = sizeof(attr);
    attr.type        = PERF_TYPE_BREAKPOINT;
    attr.bp_addr     = w->addr;
    attr.bp_len      = HW_BREAKPOINT_LEN_4;  // ARM64 指令 4 字节
    attr.bp_type     = HW_BREAKPOINT_X;      // 执行断点
    attr.exclude_kernel = 1;
    attr.disabled    = 0;                    // 直接启用

    /* 这里可以安全睡眠 */
    new_bp = register_user_hw_breakpoint(
                                    &attr, bp_handle,
                                    NULL, w->target_task);
    if (IS_ERR(new_bp)) {
        pr_err("break: register failed: %ld\n", PTR_ERR(new_bp));
    } else {
        pr_info("break: register success\n");
        bp = new_bp;
    }

    put_task_struct(w->target_task);  // 释放在 kprobe 中增加的引用
    kfree(w);
}



/* ---------- kprobe 回调：只收集数据，调度工作 ---------- */
static int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
    struct pt_regs *uregs;
    int option;
    unsigned long arg2;
    struct my_task t;
    struct bp_work *work;

    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs) {
        pr_err("break: get uregs failed\n");
        return 0;
    }

    option = (int)uregs->regs[0];
    if (option == PR_REGIS_HW_BP) {
        arg2 = (unsigned long)uregs->regs[1];
        if (copy_from_user(&t, (void __user *)arg2, sizeof(t))) {
            pr_err("break: copy_from_user failed\n");
            return 0;
        }

        /* 原子上下文中分配 work，使用 GFP_ATOMIC */
        work = kmalloc(sizeof(*work), GFP_ATOMIC);
        if (!work) {
            pr_err("break: no memory for work\n");
            return 0;
        }

        INIT_WORK(&work->work, bp_register_work);
        // 为 work 增加任务引用，防止 work 执行前进程退出
        get_task_struct(current);
        work->target_task = current;
        work->addr = t.address;

        schedule_work(&work->work);   // 可在原子上下文调用
        pr_info("break: scheduled work for pid %d\n", current->pid);
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
    pr_info("break: module loaded\n");
    return 0;
}

static void __exit exit_mod(void)
{
    // 注销 kprobe，避免新的工作被调度
    unregister_kprobe(&kp);
    // 等待所有已调度的工作完成（如果有）
    flush_scheduled_work();
    // 释放硬件断点
    // if (!IS_ERR_OR_NULL(bp)) {
    //     unregister_user_hw_breakpoint(bp);
    //     bp = NULL;
    // }
    pr_info("break: module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);