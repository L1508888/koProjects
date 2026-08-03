
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>


#include "func_help.h"

#define MAGIC_PRCTL_OPTION  0xDEADBEEF



typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);




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

static __nocfi int resolve_kernel_symbols(void)
{
	kallsyms_lookup_name_t kln;
	unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");

	if (!addr) {
		pr_err("pte_test: cannot resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}
	kln = (kallsyms_lookup_name_t)addr;

	follow_pte_ptr = (follow_pte_t)kln("follow_pte");
	if (!follow_pte_ptr) {
		pr_err("pte_test: follow_pte not found\n");
		return -ENOENT;
	}
	pr_info("pte_test: follow_pte=%px\n", follow_pte_ptr);
	return 0;
}



static __nocfi int handler_pre(struct kprobe *p, struct pt_regs *kregs)
{
	struct pt_regs *uregs;
	unsigned long arg2, left;
	HookTask myTask;
	int option;

	uregs = (struct pt_regs *)kregs->regs[0];
	if (!uregs)
		return 0;

	option = (int)uregs->regs[0];
	if (option != MAGIC_PRCTL_OPTION)
		return 0;

	arg2 = (unsigned long)uregs->regs[1];
	if (!arg2)
		return 0;

	left = copy_from_user(&myTask, (void __user *)arg2, sizeof(myTask));
	if (left) {
		pr_err("pte_test: copy_from_user failed, %lu left\n", left);
		return 0;
	}

	modify_process_pte(&myTask);
	return 0;
}

//  用于hook ptrcl 函数
static struct kprobe kp;
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
		pr_err("pte_test: register_kprobe(prctl) failed %d\n", ret);
		return ret;
	}
	pr_info("pte_test: module loaded\n");
	return 0;
}

static void __exit exit_mod(void)
{
	unregister_kprobe(&kp);
	pr_info("pte_test: module exit\n");
}

MODULE_LICENSE("GPL");
module_init(init_mod);
module_exit(exit_mod);