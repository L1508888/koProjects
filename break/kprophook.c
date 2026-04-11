#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

static struct kprobe kp;



int handler_pre(struct kprobe* p, struct pt_regs *regs){
    char comm[TASK_COMM_LEN] = {0};
    char fname[256] = {0};
    const char __user *filename = (const char __user *)regs->regs[1];

    get_task_comm(comm, current);
    if (filename) {
        strncpy_from_user(fname, filename, sizeof(fname)-1);
    }
    if (strstr(fname, "data/secret")) {
        printk("kprobe get path %s \n", fname);
    }
    return 0;
}


// 模块加载时执行的初始化函数
static int __init kp_init(void){
    int ret;
     kp.symbol_name = "__arm64_sys_openat";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "kprobe registered at %p\n", kp.addr);
    return 0;
}


// 模块卸载时执行的清理函数
static void __exit kp_exit(void){
unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe unregistered\n");
}


// 注册模块的入口和出口函数
module_init(kp_init);
module_exit(kp_exit);

// 模块的许可证信息，GPL 是必须的
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Hello World kernel module for Android");