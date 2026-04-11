// ftrace_openat_hook.c

#include <linux/ftrace.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("ftrace hook openat");

// ========================
// 原始函数指针
// ========================
static asmlinkage long (*orig_openat)(int dfd, const char __user *filename,
                                      int flags, umode_t mode);

// ========================
// 我们的hook函数
// ========================
static asmlinkage long my_openat(int dfd, const char __user *filename,
                                 int flags, umode_t mode) {
  char comm[TASK_COMM_LEN] = {0};
  char fname[256] = {0};

  // 当前进程名
  get_task_comm(comm, current);

  // 从用户态拷贝路径
  if (filename) {
    strncpy_from_user(fname, filename, sizeof(fname) - 1);
  }

  // 过滤目标进程
  if (strcmp(comm, "target_app") == 0) {

    printk(KERN_INFO "[HOOK] %s openat: %s\n", comm, fname);

    // ===== 自定义逻辑 =====
    if (strstr(fname, "/data/secret")) {
      printk(KERN_INFO "[HOOK] blocked!\n");
      return -ENOENT;
    }
  }

  return orig_openat(dfd, filename, flags, mode);
}

//
// ========================
// ftrace hook 结构体
// ========================
struct ftrace_hook {
  const char *name;
  void *function;
  void *original;

  unsigned long address;
  struct ftrace_ops ops;
};

//
// ========================
// ftrace 回调（关键）
// ========================
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct pt_regs *regs) {
  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if defined(CONFIG_ARM64)
  regs->regs[0] = regs->regs[0]; // 保持结构完整（占位）
  regs->pc = (unsigned long)hook->function;
#else
  regs->ip = (unsigned long)hook->function;
#endif
}

//
// ========================
// 解析符号地址
// ========================
static int fh_resolve_hook_address(struct ftrace_hook *hook) {
  hook->address = kallsyms_lookup_name(hook->name);

  if (!hook->address) {
    printk(KERN_ERR "unresolved symbol: %s\n", hook->name);
    return -ENOENT;
  }

  *((unsigned long *)hook->original) = hook->address;

  return 0;
}

//
// ========================
// 安装 hook
// ========================
static int fh_install_hook(struct ftrace_hook *hook) {
  int err;

  err = fh_resolve_hook_address(hook);
  if (err)
    return err;

  hook->ops.func = fh_ftrace_thunk;
  // hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
  //                 | FTRACE_OPS_FL_RECURSION_SAFE
  //                 | FTRACE_OPS_FL_IPMODIFY;

  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED |
                    FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
  if (err)
    return err;

  err = register_ftrace_function(&hook->ops);
  if (err)
    return err;

  return 0;
}

//
// ========================
// 卸载 hook
// ========================
static void fh_remove_hook(struct ftrace_hook *hook) {
  unregister_ftrace_function(&hook->ops);
  ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

//
// ========================
// 定义 hook
// ========================
static struct ftrace_hook openat_hook = {
    .name = "__arm64_sys_openat",
    .function = my_openat,
    .original = &orig_openat,
};

//
// ========================
// 模块入口
// ========================
static int __init hook_init(void) {
  int ret;

  printk(KERN_INFO "openat hook init\n");

  ret = fh_install_hook(&openat_hook);
  if (ret) {
    printk(KERN_ERR "hook install failed\n");
    return ret;
  }

  return 0;
}

//
// ========================
// 模块退出
// ========================
static void __exit hook_exit(void) {
  fh_remove_hook(&openat_hook);
  printk(KERN_INFO "openat hook exit\n");
}

module_init(hook_init);
module_exit(hook_exit);