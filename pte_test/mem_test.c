#include <linux/module.h>



#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif


static struct kprobe g_mem_abort_kp;

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
    struct kprobe g_mem_abort_kp;
    memset(&g_mem_abort_kp, 0, sizeof(g_mem_abort_kp));
    g_mem_abort_kp.symbol_name = "do_mem_abort";
    g_mem_abort_kp.pre_handler = mem_abort_pre;
    ret = register_kprobe(&g_mem_abort_kp);
    if(ret < 0){
        pr_err("break: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
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

    
}

static void __exit exit_mod(void){

}


module_init(init_mod);
module_exit(exit_mod);

