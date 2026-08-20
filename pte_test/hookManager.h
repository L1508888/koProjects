#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <linux/types.h>
#include <linux/mm.h>
#include "dbi.h"
#include "ghost.h"



/* hook 请求（内部传递用；用户态 ABI 见 main.c 头部注释） */
typedef struct {
    unsigned long address;   /* 目标函数的精确地址（不要求页对齐） */
    pid_t         pid;       /* 目标进程 pid */
} HookTask;

/* follow_pte 函数指针类型（main.c 解析后注入） */
typedef int (*follow_pte_t)(struct mm_struct *mm, unsigned long address,
                            pte_t **ptepp, spinlock_t **ptlp);

/*
 * copy_from_user_nofault 函数指针类型。
 * 5.10 GKI 没有 EXPORT 这个符号（直接调用会在 modpost 报 undefined），
 * 但它存在于 kallsyms 中，由 main.c 解析后注入。
 */
typedef long (*copy_from_user_nofault_t)(void *dst, const void __user *src,
                                         size_t size);

/* main.c 解析出内核符号后通过此函数注入 */
void hook_manager_init(follow_pte_t follow, copy_from_user_nofault_t copy);

/*
 * 请求入队接口（可运行于 kprobe 原子上下文）：
 * kprobe 前置处理运行在 BRK 异常上下文（关中断、禁睡眠），
 * 安装/卸载里全是可睡眠操作，所以这两个入口只分配请求项并入队，
 * 由 kworker 进程上下文执行真正的安装/卸载逻辑（异步，结果看 dmesg）。
 */
int  install_hook(HookTask *task);

/*
 * 卸载请求（可运行于 kprobe 原子上下文），同样只入队异步执行。
 *   task 非 NULL：卸载指定的 (pid, address)；若该页还有其它观察地址，
 *                 只摘除这个地址，页保持武装，地址表空了就整页拆除。
 *   task == NULL：卸载全部 hook。
 */
void hook_request_uninstall(HookTask *task);

/* 工作队列初始化 / 销毁（main.c 在模块加载 / 卸载时调用） */
int  hook_manager_wq_init(void);
void hook_manager_wq_exit(void);

/* 卸载所有 hook：逐槽位解除武装 → 恢复原 PTE → 释放 ghost 页 */
void uninstall_all_hooks(void);

/*
 * do_mem_abort 前置处理（main.c 的 kprobe 回调里调用）。
 * 返回 1：已接管（uregs->pc 已改写为 ghost 地址，调用方需跳过原 do_mem_abort）
 * 返回 0：与本 hook 无关，原函数照常执行
 */
struct pt_regs;
int hook_handle_fault(unsigned long far, unsigned long esr,
                      struct pt_regs *uregs);

#endif /* HOOK_MANAGER_H */
