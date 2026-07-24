
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kprobes.h>

static struct kretprobe ptrace_kp;

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    pr_info("hook_test: enter entry_handler");
    return 0;
}


static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    pr_info("hook_test: enter ret_handler");
    return 0;
}

static int install_hook(){
    int ret;

	memset(&ptrace_kp, 0, sizeof(ptrace_kp));
	ptrace_kp.kp.symbol_name = "__arm64_sys_prctl";
	ptrace_kp.entry_handler  = entry_handler;
	ptrace_kp.handler = ret_handler;
	ret = register_kretprobe(&ptrace_kp);
	if (ret < 0) {
		pr_err("hook_test: register_kprobe(ptrace) failed %d\n", ret);
		return ret;
	}
	pr_info("hook_test: ptrace hooked\n");
	return 0;
}


static int __init init_mod(void)
{
	
    install_hook();
	pr_info("hook_test: module loaded\n");
	return 0;
}

static void __exit exit_mod(void)
{
	
	pr_info("hook_test: module exit\n");
}

MODULE_LICENSE("GPL");
module_init(init_mod);
module_exit(exit_mod);