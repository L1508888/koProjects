


//  __maybe_unused int install_hook_ptrace(void);
//  __maybe_unused int uninstall_hook_ptrace(void);



 #ifndef HWBP_BREAK_PASS_H
 #define HWBP_BREAK_PASS_H

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>


static LIST_HEAD(bp_list);
static DEFINE_SPINLOCK(bp_lock);

 typedef struct{
    long request;
    pid_t pid;
    unsigned long addr;
    unsigned long data;
    bool interested;
}HookPtraceContext;


static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
 #endif