

#include "ftracehook.h"

int fh_reslove_func_address(struct ftrace_hook *hook) {
  hook->address = kallsyms_lookup_name(hook->name);
  if (!hook->address) {
    printf("%s address is null \n", hook->name);
    return -1;
  }
  *((unsigned long *)hook->orig) = hook->address;
  return 0;
}


/*
    这个方法其实就是用来保存参数，并且替换pc 指针

*/
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs) {

  //已知结构体中某个成员的地址 → 求整个结构体的起始地址。
  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
}

int fh_install_hooks(struct ftrace_hook *hook, size_t count) {
  printk("ftrace hook %s \n", hook->name);
  int err;
  err = fh_reslove_func_address(hook);
  if (err != 0) {
    return err;
  }
  hook->ops.func = fh_ftrace_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION_SAFE
                    | FTRACE_OPS_FL_IPMODIFY;
  return 0;
}

int fh_remove_hooks(struct ftrace_hook *hook, size_t count) { return 0; }

// 模块加载时执行的初始化函数
static int __init hook_init(void) {

  printk("openat hook init \n");

  return 0;
}

// 模块卸载时执行的清理函数
static void __exit hook_exit(void) {}

// 注册模块的入口和出口函数
module_init(hook_init);
module_exit(hook_exit);

// 模块的许可证信息，GPL 是必须的
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Hello World kernel module for Android");