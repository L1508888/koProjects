
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <asm/ptrace.h>


#include "break_pass.h"

#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif


#define MY_PTRACE_GETREGSET	0x4204
#define MY_PTRACE_SETREGSET	0x4205

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif

#define MAX_XPS 6           //  硬件断点最大数量
#define MAX_WRPS 6          //  读写硬件断点最大数量
#define HW_MAX   16



#define HW_DBG_REGS_MAX 16
// static LIST_HEAD(bp_list);
// static DEFINE_SPINLOCK(bp_lock);


/* 与 uapi asm/ptrace.h::user_hwdebug_state 一致 */
struct my_user_hwdebug_state {
	__u32 dbg_info;
	__u32 pad;
	struct {
		__u64 addr;
		__u32 ctrl;
		__u32 pad;
	} dbg_regs[HW_DBG_REGS_MAX];
};

struct hw_reg_state {
	__u64 addr;
	__u32 ctrl;
};


typedef struct{
    long request;
    pid_t pid;
    unsigned long addr;
    unsigned long data;
    bool interested;
}HookPtraceContext;




static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    // struct task_struct *child;
	long request;
	unsigned long data, addr;
    pid_t pid;
    HookPtraceContext* ctx = (HookPtraceContext*)ri->data;
    struct pt_regs *sregs;
    pr_info("pte_test: enter  entry_handler \n");

    sregs = (struct pt_regs *)regs->regs[0];
    if (!sregs)
        return 0;

    request = (long)sregs->regs[0];
	pid     = (long)sregs->regs[1];
	addr    = (long)sregs->regs[2];
	data    = sregs->regs[3];

    ctx->request = request;
    ctx->pid = pid;
    ctx->addr = addr;
    ctx->data = data;
    ctx->interested = false;
    if (request != MY_PTRACE_GETREGSET && request != MY_PTRACE_SETREGSET) {
        return 0;
    }
    if (addr != NT_ARM_HW_BREAK && addr != NT_ARM_HW_WATCH){
            return 0;
    }

    ctx->interested = true;
	return 0;
}

struct user_bp_stat {
	pid_t tid;
	int break_count;
	int watch_count;
	struct hw_reg_state break_regs[MAX_XPS];
	struct hw_reg_state watch_regs[MAX_WRPS];
	struct list_head list;
};

static struct user_bp_stat *find_or_create(pid_t tid)
{
	struct user_bp_stat *s;

	spin_lock(&bp_lock);
	list_for_each_entry(s, &bp_list, list) {
		if (s->tid == tid) {
			spin_unlock(&bp_lock);
			return s;
		}
	}
	spin_unlock(&bp_lock);

	s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s)
		return NULL;
	s->tid = tid;
	INIT_LIST_HEAD(&s->list);

	spin_lock(&bp_lock);
	list_add(&s->list, &bp_list);
	spin_unlock(&bp_lock);
	return s;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    bool set_break = false;
    struct iovec iov;
    struct user_bp_stat *stat;
    int *count, max_count, i, n, new_count;
    struct my_user_hwdebug_state hw;
    struct hw_reg_state *cur;
    size_t hdr, copy_len;
    int ret;
    HookPtraceContext* ctx = (HookPtraceContext*)ri->data;
    if (!ctx->interested) {
        return 0;
    }
    pr_info("pte_test: enter  ret_handler \n");

    if (ctx->addr == NT_ARM_HW_BREAK) {
        set_break = true;
    }
    if (set_break) {
        max_count = MAX_XPS;
    }

    if (copy_from_user(&iov, (void __user *)ctx->data, sizeof(iov))){
        return 0;
    }

    stat = find_or_create(ctx->pid);
	if (!stat){
        return 0;
    }

    count = set_break ? &stat->break_count : &stat->watch_count;
	cur   = set_break ? stat->break_regs : stat->watch_regs;
	hdr   = offsetof(struct my_user_hwdebug_state, dbg_regs);
    

    if (ctx->request == MY_PTRACE_SETREGSET) {
        memset(&hw, 0, sizeof(hw));
        copy_len = iov.iov_len;
        if (copy_len > sizeof(hw)){
            copy_len = sizeof(hw);
        }
		if (copy_from_user(&hw, iov.iov_base, copy_len)){
            return 0;
        }

        //  因为是一个变长数组，所以这里需要计算数组的长度
        n = 0;
		if (copy_len > hdr){
            n = (int)((copy_len - hdr) / sizeof(hw.dbg_regs[0]));
        }
		if (n > HW_MAX){
            n = HW_MAX;
        }


        //  用于进行记录，
        new_count = 0;
		for (i = 0; i < n && i < max_count; i++) {
			cur[i].addr = hw.dbg_regs[i].addr;
			cur[i].ctrl = hw.dbg_regs[i].ctrl;
			if (cur[i].addr){
                new_count++;
            }
		}
		*count = new_count;

        //  如果设定的长度大于最大长度，直接返回错误，否则返回0
        if (n > max_count) {
            ret = -ENOSPC;
        }else {
            ret = 0;
        }
		regs_set_return_value(regs, ret);
		pr_info("pte_test: SET %s tid=%d n=%d -> %ld\n",
			set_break ? "BRK" : "WAT", ctx->pid, n, ret);
		return 0;
    }

    if (ctx->request == MY_PTRACE_GETREGSET) {
        memset(&hw, 0, sizeof(hw));
        hw.dbg_info = max_count;

        for (i = 0; i < *count && i < max_count; i++) {
			hw.dbg_regs[i].addr = cur[i].addr;
			hw.dbg_regs[i].ctrl = cur[i].ctrl;
		}

        copy_len = iov.iov_len;
		if (copy_len > sizeof(hw))
			copy_len = sizeof(hw);
		if (copy_to_user(iov.iov_base, &hw, copy_len))
			return 0;

		regs_set_return_value(regs, 0);
		pr_info("pte_test: GET %s tid=%d count=%d\n",
			set_break ? "BRK" : "WAT", ctx->pid, *count);
    }
    return 0;
}




extern int install_hook_ptrace(void){
    int ret;

	memset(&ptrace_kp, 0, sizeof(ptrace_kp));
	ptrace_kp.kp.symbol_name = "__arm64_sys_ptrace";
	ptrace_kp.entry_handler  = entry_handler;
	ptrace_kp.handler = ret_handler;
    ptrace_kp.data_size = sizeof(HookPtraceContext);
	ret = register_kretprobe(&ptrace_kp);
	if (ret < 0) {
		pr_err("pte_test: register_kretprobe(ptrace) failed %d\n", ret);
		return ret;
	}
	pr_info("pte_test: ptrace hooked\n");
	return ret;
}


 extern int uninstall_hook_ptrace(void){
    struct user_bp_stat *s, *n;
    unregister_kretprobe(&ptrace_kp);
	spin_lock(&bp_lock);
	list_for_each_entry_safe(s, n, &bp_list, list) {
		list_del(&s->list);
		kfree(s);
	}
	spin_unlock(&bp_lock);
	pr_info("pte_test: unloaded\n");
    return 0;
}

MODULE_LICENSE("GPL");