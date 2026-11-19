#ifndef PTE_JH_TRAMP_H
#define PTE_JH_TRAMP_H

/*
 * jh_tramp.h —— trampoline 生成器（纯计算，可在用户态编译验证）
 *
 * 这里只依赖 linux/types.h 与 linux/string.h（后者仅为 memset/memcpy），
 * 不碰任何内核运行时 API，所以 tools/tramp_selftest.c 能直接把它
 * 编到用户态、用真实汇编器核对每条指令的编码。
 */

#include <linux/types.h>
#include "javahook.h"

/*
 * trampoline 最坏长度（字）——唯一定义处。
 *  调用形态：brk(1) + stp(1) + mov64(4) + blr(1) + brk(1) + ldp(1) + ret(1) = 10
 *  skip 形态：brk(1) + mov64(4) + movz(1) + brk(1) + ret(1) = 8
 * 返回值 0 时 mov64 只发 1 条；全 0xFFFF 时发 4 条，取较大者。
 *
 * javahook.c 的 ghost 页布局直接用它算偏移，改这里两边自动一致。
 */
#define JH_TRAMP_MAX_WORDS 12

/* BRK #imm16 指令编码 */
uint32_t jh_enc_brk(uint16_t imm16);

/* 规则是否生效（op != NONE） */
int jh_rule_active(uint32_t op);

/* 是否需要入口观察点（有任何一个参数规则生效） */
int jh_args_need_enter_brk(const struct JavaHookReq *req);
/* 是否需要出口观察点（返回值规则生效） */
int jh_ret_needs_exit_brk(const struct JavaHookReq *req);

/*
 * 生成 trampoline。
 *   target     —— 尾跳/调用的目标地址（replace ?: 原入口 ?: ghost 副本）
 *   enter_brk  —— 入口观察点指令（BRK #imm）
 *   exit_brk   —— 出口观察点指令（BRK #imm）
 *   out_enter/out_exit —— 返回两条 BRK 在 code[] 中的**字下标**
 *                        （没有则为 -1）。调用方据此算出观察点的 VA，
 *                        BRK 处理里靠地址精确匹配是入口还是出口。
 * 返回写入的字数，失败 -1。
 */
int jh_build_tramp(uint32_t *code, int cap, const struct JavaHookReq *req,
                   uint64_t target, uint32_t enter_brk, uint32_t exit_brk,
                   int *out_enter, int *out_exit);

/* trampoline 最坏长度（字） */
int jh_tramp_max_words(void);

/* 按 op 把规则作用到 cur 上 */
uint64_t jh_apply_op(uint32_t op, uint64_t cur, uint64_t val);

#endif /* PTE_JH_TRAMP_H */
