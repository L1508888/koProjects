



#include <linux/printk.h>
#include <linux/ptrace.h>

#include "callback.h"

/*
 * 打印命中时的用户态参数（开发辅助）。
 *
 * AArch64 AAPCS 约定：整型/指针参数前 8 个在 x0..x7，
 * 对应 uregs->regs[0..7]；第 9 个起在用户栈上（uregs->sp）。
 * 浮点参数在 v0..v7，需要 fpsimd 状态，暂不处理。
 */
void dump_user_args(struct pt_regs *uregs, unsigned long far)
{
    if (!uregs) {
        pr_err("pte_hook: uregs 为空，异常情况\n");
        return;
    }

    pr_info("pte_hook: args@0x%lx pc=0x%lx lr=0x%lx sp=0x%lx\n",
            far, uregs->pc, uregs->regs[30], uregs->sp);
    pr_info("pte_hook: x0=%lx x1=%lx x2=%lx x3=%lx\n",
            uregs->regs[0], uregs->regs[1],
            uregs->regs[2], uregs->regs[3]);
    pr_info("pte_hook: x4=%lx x5=%lx x6=%lx x7=%lx\n",
            uregs->regs[4], uregs->regs[5],
            uregs->regs[6], uregs->regs[7]);

    /* 载荷 dump（x1 指针的前 0x40 字节）暂时关闭：
     * 本函数运行在 kprobe 原子上下文，读用户内存需要 kallsyms 解析注入
     * copy_from_user_nofault（当前版本未接入），现在只打寄存器。
     * 要恢复载荷 dump 请先把 hook_read_user 加回来。 */
}