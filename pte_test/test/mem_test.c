#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kprobes.h>


#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif


// static struct kprobe g_mem_abort_kp;
static struct kprobe kp;

int ptehook_handle_abort(unsigned long far, unsigned long esr, void *regs_vp){
    unsigned int ec, ifsc;
    unsigned long far_page;
    int i;
    //  解析 esr，得到具体是因为什么导致的异常。ec == 0x20 表示正是 UXN 为1 的异常
    ec = (esr >> 26) & 0x3F;
    ifsc = esr & 0x3F;

    far_page = far & ~0xFFFUL;
    pr_info("pte_test: error ec %d \n", ec);
    pr_info("pte_test: error ifsc %d \n", ifsc);
    pr_info("pte_test: error address %p \n", far_page);

    for (i=0; i < 32; i++) {
        pr_info("pte_test: %d arg is %p ", i, (regs_vp + i));
    }
    return 0;
}




static int mem_abort_pre(struct kprobe *p, struct pt_regs *regs)
{
    //  Fault Address Register、触发异常的虚拟地址
    unsigned long far = regs->regs[0];
    //  Exception Syndrome Register、包含详细的异常信息
    unsigned long esr = regs->regs[1];
    //  异常发生时的 CPU 寄存器快照
    void *user_regs = (void *)regs->regs[2];

    if (ptehook_handle_abort(far, esr, user_regs)) {
        regs->pc = regs->regs[30];   /* return to caller (LR) */
        return 1;                    /* skip single-step of do_mem_abort */
    }
    return 0;
}


static int resolve_kernel_symbols(void)
{
    int ret;
    
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "do_mem_abort";
    kp.pre_handler = mem_abort_pre;
    ret = register_kprobe(&kp);
    if(ret < 0){
        pr_err("pte_test: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
        return ret;
    }
    return 0;
}



/* ---------- 模块初始化 / 退出 ---------- */
static int __init init_mod(void){
    int ret;

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

