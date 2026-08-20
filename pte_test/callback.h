#ifndef PTE_CALLBACK_H
#define PTE_CALLBACK_H

struct pt_regs;

/*
 * 命中时的用户态回调（当前实现：dump 参数寄存器，见 callback.c）。
 * 注意：不能加 static —— 定义在 callback.c，经本头文件跨编译单元引用。
 */
void dump_user_args(struct pt_regs *uregs, unsigned long far);

#endif /* PTE_CALLBACK_H */
