#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

// 模块加载时执行的初始化函数
static int __init hello_init(void) {
  printk("hello, android kernel \n");
  printk("enter current pid=%d, commom=%s \n", current->pid, current->comm);
  // printk(KERN_INFO "Hello, Android Kernel World!\n");
  return 0; // 返回 0 表示初始化成功
}

// 模块卸载时执行的清理函数
static void __exit hello_exit(void) {
  printk("byebye, android kernel \n");
  printk("exit current pid=%d, commom=%s \n", current->pid, current->comm);
  // printk(KERN_INFO "Goodbye, Android Kernel World!\n");
}

// 注册模块的入口和出口函数
module_init(hello_init);
module_exit(hello_exit);

// 模块的许可证信息，GPL 是必须的
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Hello World kernel module for Android");

// #include <linux/module.h>

// static int __init hello_init(void){
//     pr_info("Hello, kernel!\n");
//     return 0;
// }

// static void __exit hello_exit(void){
//     pr_info("Googbye, kernel!\n");
// }

// module_init(hello_init);
// module_exit(hello_exit);

// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("nuoen");
// MODULE_DESCRIPTION("Simple hello module");