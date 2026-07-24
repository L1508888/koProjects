

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>







#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif



typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static kallsyms_lookup_name_t kln;
#define MAX_DUMP_LEN		256


struct binder_txn_data {
	union {
		__u32 handle;
		__u64 ptr;
	} target;
	__u64 cookie;
	__u32 code;
	__u32 flags;
	__s32 sender_pid;
	__u32 sender_euid;
	__u64 data_size;
	__u64 offsets_size;
	union {
		struct {
			__u64 buffer;
			__u64 offsets;
		} ptr;
		__u8 buf[8];
	} data;
};


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

	unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");

	if (!addr) {
		pr_err("binder_test: cannot resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}
	kln = (kallsyms_lookup_name_t)addr;
	return 0;
}



static struct kprobe kp_binder;
// static struct kprobe mem_abort_kp;

static void dump_txn(int reply, const struct binder_txn_data *tr){
    u8 buf[MAX_DUMP_LEN];
	size_t n, want;
	unsigned long user_buf;

	
	
	want = MAX_DUMP_LEN;

	pr_info("binder_test: tgid=%d pid=%d reply=%d code=%u flags=0x%x "
		"handle=%u data=%llu offs=%llu sender_pid=%d euid=%u\n",
		task_tgid_nr(current), task_pid_nr(current), reply,
		tr->code, tr->flags, tr->target.handle,
		(unsigned long long)tr->data_size,
		(unsigned long long)tr->offsets_size,
		tr->sender_pid, tr->sender_euid);

	if (!tr->data_size || !tr->data.ptr.buffer || !want)
		return;

	user_buf = (unsigned long)tr->data.ptr.buffer;
	n = tr->data_size < want ? (size_t)tr->data_size : want;

	memset(buf, 0, sizeof(buf));
	if (copy_from_user(buf, (const void __user *)user_buf, n)) {
		pr_info("binder_test: copy_from_user payload failed "
			"(buf=0x%lx len=%zu)\n", user_buf, n);
		return;
	}

	print_hex_dump(KERN_INFO, "binder_test parcel: ", DUMP_PREFIX_OFFSET,
		       16, 1, buf, n, true);
}

static int binder_txn_pre(struct kprobe *p, struct pt_regs *regs){
    struct binder_txn_data tr;
	int reply;
	long ret;

	reply = (int)regs->regs[3];
    ret = copy_from_kernel_nofault(&tr, (const void *)regs->regs[2],
				       sizeof(tr));
	if (ret)
		return 0;

	// if (!should_capture(reply, &tr))
	// 	return 0;

	dump_txn(reply, &tr);
	return 0;
}

static int install_binder_hook(void){
    int ret;
    unsigned long addr;
    //  register_kprobe 可能会拿不到 binder_transaction 的地址
    memset(&kp_binder, 0, sizeof(kp_binder));
	kp_binder.symbol_name = "binder_transaction";
	kp_binder.pre_handler = binder_txn_pre;
	ret = register_kprobe(&kp_binder);
	if (!ret) {
		pr_info("binder_test: hooked binder_transaction via symbol\n");
		return 0;
	}


    addr = kln("binder_transaction");
	if (!addr) {
		pr_err("binder_test: binder_transaction not in kallsyms (%d)\n",
		       ret);
		return -ENOENT;
	}

	memset(&kp_binder, 0, sizeof(kp_binder));
	kp_binder.addr = (kprobe_opcode_t *)addr;
	kp_binder.pre_handler = binder_txn_pre;
	ret = register_kprobe(&kp_binder);
	if (ret) {
		pr_err("binder_test: register_kprobe(addr) failed %d\n", ret);
		return ret;
	}
    pr_info("binder_test: hooked binder_transaction at %px\n",
		(void *)addr);
    return 0;

}



static int __init init_mod(void)
{
	int ret;

	ret = resolve_kernel_symbols();
	if (ret)
		return ret;

	
	ret = install_binder_hook();
	if (ret) {
		unregister_kprobe(&kp_binder);
		return ret;
	}

	pr_info("binder_test: module loaded\n");
	return 0;
}

static void __exit exit_mod(void)
{
	unregister_kprobe(&kp_binder);
	pr_info("binder_test: module exit\n");
}

MODULE_LICENSE("GPL");
module_init(init_mod);
module_exit(exit_mod);