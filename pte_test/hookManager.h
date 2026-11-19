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

/*
 * 用户态 BRK 钩子回调（main.c 经 register_user_break_hook 注册）。
 * 处理 ghost 页内 BRK 探针：dump 观察点寄存器现场，pc 改到清扫槽。
 * uregs 直接是用户态寄存器快照，且 uregs->pc = BRK 指令本身的地址。
 * 返回 1：已接管；返回 0：与本 hook 无关
 */
struct pt_regs;
int hook_handle_brk(struct pt_regs *uregs, unsigned int esr);

/*
 * BRK 探针总开关：main.c 在 register_user_break_hook 注册成功后置 1。
 * 未启用时安装路径不会打 BRK 探针（否则 BRK 触发无人接管，
 * 目标进程会收 SIGTRAP 崩掉），退化为"页入口 dump"。
 */
void hook_manager_brk_enable(int enabled);

/* ======================================================================
 * 扩展接口（Java 层 hook 用，见 javahook.c / docs/JavaHook.md）
 * ====================================================================== */

/*
 * 同步安装：给 (pid, address) 安装 hook。
 *
 * replace 语义：
 *   0  —— 传统"观察"语义：页被 UXN 武装后，任何地址的取指异常都
 *         重定向到 ghost 里对应的重编译副本，原函数照常执行；
 *         精确命中 address 时额外 dump 一次参数。
 *   非 0 —— "替换"语义：只有精确命中 address 的取指异常会把用户态
 *          pc 直接改成 replace（Java 层 trampoline），该页其它地址
 *          （以及经 ghost 内部跳转回到本页的流程）仍走 ghost 副本。
 *
 * 仅可在进程上下文调用（内部会申请内存、拿 mmap 锁、可能睡眠）。
 * 返回 0 表示成功，负值为 -errno。
 */
int  hook_install_sync(pid_t pid, unsigned long address, unsigned long replace);

/*
 * 同上，但可控制是否给该地址打 ghost 内 BRK 探针（probe=0 关闭）。
 * Java 层 UXN 策略的第一步用它：以"观察"方式武装页面取得 ghost 副本
 * 地址，之后再升级成替换语义，期间不需要探针。
 */
int  hook_install_sync_ex(pid_t pid, unsigned long address,
                          unsigned long replace, int probe);

/*
 * 同步卸载指定地址（进程上下文）。若该页还有其它地址，只摘除这个地址，
 * 页保持武装；地址表空了才整页拆除（恢复 PTE、释放 ghost）。
 */
int  hook_uninstall_sync(pid_t pid, unsigned long address);

/*
 * 查询目标地址在 ghost 中的重编译副本 PC。
 * Java 层 strategy-B（UXN 替换）把"调用原方法"的 backup 指向这里：
 * 直接跳到 ghost 副本不会再次触发 UXN 异常，从而执行原始逻辑。
 * 未安装 / 该页未武装时返回 0。
 */
unsigned long hook_lookup_ghost_pc(pid_t pid, unsigned long address);

/* 目标地址是否已被登记（任一槽位的地址表里） */
int  hook_is_watched(pid_t pid, unsigned long address);

/*
 * 目标地址所在页是否已被本模块 UXN 武装（同一页的其它函数入口）。
 * Java 层判断"入口是否可执行"时要用它：已被武装的页 UXN 位是置位的，
 * 单看 PTE 会误判为"不可执行"，但实际上取指异常会被我们接管。
 */
int  hook_page_armed(pid_t pid, unsigned long address);

#endif /* HOOK_MANAGER_H */
