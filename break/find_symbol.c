// break.c -- Android 13 / Pixel 6 (oriole) GKI
//
// 使用步骤:
//   adb root
//   adb shell 'echo 0 > /proc/sys/kernel/kptr_restrict'
//   adb push break.ko /data/local/tmp/
//   adb shell '
//     ADDR=$(grep " T kallsyms_lookup_name$" /proc/kallsyms | awk "{print \"0x\"\$1}")
//     insmod /data/local/tmp/break.ko kln_addr=$ADDR
//   '
//   adb shell 'dmesg | tail -20'
//
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/hw_breakpoint.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Author");
MODULE_DESCRIPTION("HW breakpoint via prctl on Android GKI");



/* 待检查的符号；NULL 结束。
 * 想加什么自己往里塞就行，名字必须和 /proc/kallsyms 完全一致。 */
static const char * const sym_list[] = {
    /* kprobe 子系统 */
    "register_kprobe",
    "unregister_kprobe",
    "enable_kprobe",
    "disable_kprobe",
    "register_kretprobe",
    "unregister_kretprobe",

    /* 硬件断点 / perf */
    "register_user_hw_breakpoint",
    "unregister_hw_breakpoint",
    "modify_user_hw_breakpoint",
    "register_wide_hw_breakpoint",
    "unregister_wide_hw_breakpoint",
    "perf_event_create_kernel_counter",
    "perf_event_release_kernel",

    /* 信号 / 任务 */
    "send_sig_info",
    "find_vpid",
    "find_get_pid",
    "get_pid_task",
    "pid_task",

    /* 用户空间拷贝 */
    "_copy_from_user",
    "_copy_to_user",

    /* eventfd（tmp.c 里用到了） */
    "eventfd_ctx_fdget",
    "eventfd_ctx_put",
    "eventfd_signal",

    /* 系统调用入口（arm64 是 __arm64_sys_xxx 而不是 __x64_sys_xxx） */
    "__arm64_sys_prctl",
    "__arm64_sys_ptrace",
    "__do_sys_prctl",

    /* 通常 GKI 不再导出，列在这里就是为了证明它"找得到地址但用不了" */
    "kallsyms_lookup_name",
    "kallsyms_on_each_symbol",

    NULL,
};


/* 用 kprobe 解析符号地址：
 *   register_kprobe 内部会调用 kallsyms 把 symbol_name 翻译成 kp.addr，
 *   注册成功后我们读出 addr，然后立刻 unregister。
 * 解析失败时 register_kprobe 通常返回 -EINVAL / -ENOENT。 */
static unsigned long lookup_sym(const char *name)
{
    struct kprobe kp;
    unsigned long addr = 0;
    int ret;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = name;

    ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    } else {
        pr_debug("[CHK] register_kprobe(%s) ret=%d\n", name, ret);
    }
    return addr;
}





static int __init init_mod(void) {
    int i, ok = 0, fail = 0;

    pr_info("[CHK] ===== symbol availability check (arm64 GKI) =====\n");

    for (i = 0; sym_list[i]; i++) {
        unsigned long addr = lookup_sym(sym_list[i]);

        if (addr) {
            pr_info("[CHK] %-36s = 0x%016lx  [OK]\n",
                    sym_list[i], addr);
            ok++;
        } else {
            pr_warn("[CHK] %-36s = %-18s  [FAIL]\n",
                    sym_list[i], "(not found)");
            fail++;
        }
    }

    pr_info("[CHK] summary: %d found, %d not found\n", ok, fail);

    pr_info("[HWBP] module loaded\n");

    /* 这些是「直接拿地址」的方式：模块能加载到这里说明它们都被
     * EXPORT_SYMBOL[_GPL]，可以直接当函数指针用而不仅仅是知道地址。
     * 用 %px 打印真实地址，避开 kptr_restrict 的哈希。 */
    pr_info("[CHK] direct &register_kprobe              = %px\n",
            (void *)register_kprobe);
    pr_info("[CHK] direct &unregister_kprobe            = %px\n",
            (void *)unregister_kprobe);
    pr_info("[CHK] direct &unregister_hw_breakpoint     = %px\n",
            (void *)unregister_hw_breakpoint);
    pr_info("[CHK] direct &send_sig_info                = %px\n",
            (void *)send_sig_info);

    /* 这个模块只是探测一次，没必要常驻；返回 0 让它留着以便 rmmod。
     * 也可以直接 return -ECANCELED 让 insmod 顺便卸载，但那样 dmesg 会
     * 多一行报错，看起来不优雅。 */
    return 0;
}


static void __exit exit_mod(void)
{
    
    pr_info("[HWBP] module exit\n");
}

module_init(init_mod);
module_exit(exit_mod);
