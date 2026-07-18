#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kprobes.h>


#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif


typedef struct {
    
    unsigned long address;
    pid_t         pid;
}hookTask;


static struct kprobe kp;



static int handler_pre(struct kprobe *p, struct pt_regs *kregs){
    struct pt_regs *uregs;
    unsigned long arg2;
    hookTask myTask;
    unsigned long left;
    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs)
        return 0;

    
    arg2 = (unsigned long)uregs->regs[1];
    if (!arg2)
        return 0;


    left = copy_from_user(&myTask, (void __user *)arg2, sizeof(myTask));
}


/* ---------- 模块初始化 / 退出 ---------- */
static int __init init_mod(void){
    int ret;


    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("break: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
        return ret;
    }

    ret = resolve_kernel_symbols();
    if (ret)
        return ret;
    pr_info("pte_test: module loaded");
    return 0;
}

static void __exit exit_mod(void){
    unregister_kprobe(&kp);
    pr_info("pte_test: module exit");
}


MODULE_LICENSE("GPL");

module_init(init_mod);
module_exit(exit_mod);
