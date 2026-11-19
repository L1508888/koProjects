/*
 * jh_tramp.c —— Java hook 的 ARM64 trampoline 生成器（纯计算，无内核依赖）
 *
 * 从 javahook.c 里拆出来单独成文件，原因有二：
 *   1. 它只是"输入规则 → 输出指令数组"的纯函数，可以拿到用户态
 *      用真实汇编器逐字节验证（见 tools/tramp_selftest.c + compare.sh）；
 *   2. javahook.c 里混着大量内核 API 调用，不利于审查这段
 *      对正确性要求最高的代码。
 *
 * 完整说明见 docs/JavaHook.md 第 4 节。
 */

#include <linux/types.h>

#include "jh_tramp.h"

/* ---------- 小指令编码器 ---------- */

/*
 * 把 64 位立即数装载进 rd：
 *   MOVZ  rd, #chunk0, lsl #0      （首条，其余段先归零）
 *   MOVK  rd, #chunkN, lsl #(16N)  （只发非零段，省指令）
 * 返回写入的指令条数，至少 1 条。
 */
static int emit_mov64(uint32_t *out, uint32_t rd, uint64_t imm)
{
    int n = 0, shift, first = 1;

    for (shift = 0; shift < 64; shift += 16) {
        uint32_t chunk = (uint32_t)((imm >> shift) & 0xFFFFU);
        uint32_t hw = (uint32_t)(shift / 16);

        if (first) {
            out[n++] = 0xD2800000U | (hw << 21) | (chunk << 5) | (rd & 0x1FU);
            first = 0;
        } else if (chunk) {
            out[n++] = 0xF2800000U | (hw << 21) | (chunk << 5) | (rd & 0x1FU);
        }
    }
    return n;
}

/* MOVZ Xd, #imm16, LSL #hw —— 单独发一条（用于 0 也照发的场合） */
static uint32_t enc_movz(uint32_t rd, uint32_t imm16, uint32_t hw)
{
    return 0xD2800000U | ((hw & 3U) << 21) | ((imm16 & 0xFFFFU) << 5) |
           (rd & 0x1FU);
}

/* BR  Xn —— 无条件远跳，不返回 */
static uint32_t enc_br(uint32_t rn)
{
    return 0xD61F0000U | ((rn & 0x1FU) << 5);
}

/* BLR Xn —— 带链接的调用，返回地址写入 x30 */
static uint32_t enc_blr(uint32_t rn)
{
    return 0xD63F0000U | ((rn & 0x1FU) << 5);
}

/* RET */
static uint32_t enc_ret(void)
{
    return 0xD65F03C0U;
}

/*
 * STP x29, x30, [sp, #-16]!
 *   A9BF7BFD：64 位 STP，pre-index -16，Rt=29(x29) Rt2=30(x30) Rn=31(sp)
 * LDP x29, x30, [sp], #16
 *   A8C17BFD：post-index +16
 *
 * 这两条只为"调用后还要回来"的形态准备：blr 会覆盖 x30，
 * 不保存的话原方法的返回值就回不到调用者了。
 * 顺带保存 x29 让栈回溯链保持完整（调试友好）。
 */
#define INSN_STP_X29_X30_PRE16  0xA9BF7BFDU
#define INSN_LDP_X29_X30_POST16 0xA8C17BFDU

/* BRK #imm16 */
uint32_t jh_enc_brk(uint16_t imm16)
{
    return 0xD4200000U | ((uint32_t)imm16 << 5);
}

/* ---------- 规则判定 ---------- */

int jh_rule_active(uint32_t op)
{
    return op != JH_OP_NONE;
}

int jh_args_need_enter_brk(const struct JavaHookReq *req)
{
    unsigned int i, n;

    /* JH_FLAG_BRK：只是想在 dmesg 里看一眼参数，也需要入口观察点 */
    if (req->flags & JH_FLAG_BRK)
        return 1;

    n = req->arg_cnt < JH_ARGS_MAX ? req->arg_cnt : JH_ARGS_MAX;
    for (i = 0; i < n; i++)
        if (jh_rule_active(req->args[i].op))
            return 1;
    return 0;
}

int jh_ret_needs_exit_brk(const struct JavaHookReq *req)
{
    /* 只有"要看/要改返回值"才需要用 blr 形态 + 出口观察点 */
    return jh_rule_active(req->ret_op);
}

/* ---------- trampoline 生成 ---------- */

/*
 * 两种形态：
 *
 *   need_exit == 0  → 尾跳（不保存任何东西，最快，完全不改变栈）
 *       [brk enter]                 ; 需要看/改参数时
 *       [movz/movk x17, target]     ; target = replace ?: orig
 *       [br x17]                    ; 原方法直接返回给调用者
 *
 *   need_exit == 1  → 调用（原方法返回后还能再插手）
 *       [brk enter]                 ; 需要看/改参数时
 *       stp  x29, x30, [sp, #-16]!  ; blr 会覆盖 x30，必须自己保
 *       [movz/movk x17, target]     ; x17(IP1) 是 ABI 允许破坏的临时寄存器
 *       blr  x17                    ; 调用原方法，返回值落在 x0/x1
 *       brk  exit                   ; 此刻 x0/x1 就是返回值
 *       ldp  x29, x30, [sp], #16
 *       ret                         ; 把（可能被改过的）返回值交回调用者
 *
 * 为什么不额外保存 x0..x7：尾跳与调用都不改参数寄存器，原方法自己
 * 会保存它要用的参数。只有在调用形态下 x0/x1 被返回值占用——那正是
 * 我们要观察的东西。x19..x28（被调用者保存）由原方法自己保护。
 */
int jh_build_tramp(uint32_t *code, int cap, const struct JavaHookReq *req,
                   uint64_t target, uint32_t enter_brk, uint32_t exit_brk,
                   int *out_enter, int *out_exit)
{
    int n = 0;
    int need_enter = jh_args_need_enter_brk(req);
    int need_exit  = jh_ret_needs_exit_brk(req);

    if (out_enter)
        *out_enter = -1;
    if (out_exit)
        *out_exit = -1;

#define EMIT(x) do { if (n >= cap) return -1; code[n++] = (x); } while (0)
#define EMIT_MOV64(rd, imm) do {                                        \
        if (n + 4 > cap) return -1;                                     \
        n += emit_mov64(code + n, (rd), (imm));                         \
    } while (0)

    /* ---- 1. 入口观察点：此时 x0..x7 就是调用者传来的原始参数 ---- */
    if (need_enter) {
        if (out_enter)
            *out_enter = n;
        EMIT(enter_brk);
    }

    if (req->flags & JH_FLAG_SKIP_ORIGINAL) {
        /* ---- 不调原方法：摆好返回值，让出口观察点能看见/改它 ---- */
        EMIT_MOV64(0, req->ret_val);
        /* long / double 的第二个八字节清零：漏了它 32 位 int 返回值的
         * 高位会是垃圾，ART 侧按 64 位读就会算错 */
        EMIT(enc_movz(1, 0, 0));
        if (need_exit) {
            if (out_exit)
                *out_exit = n;
            EMIT(exit_brk);
        }
        EMIT(enc_ret());
        return n;
    }

    /* ---- 2. 调用原方法 ---- */
    if (need_exit) {
        EMIT(INSN_STP_X29_X30_PRE16);
        EMIT_MOV64(17, target);
        EMIT(enc_blr(17));
        /* ---- 3. 出口观察点：此刻 x0/x1 就是原方法的返回值 ---- */
        if (out_exit)
            *out_exit = n;
        EMIT(exit_brk);
        EMIT(INSN_LDP_X29_X30_POST16);
        EMIT(enc_ret());
    } else {
        EMIT_MOV64(17, target);
        EMIT(enc_br(17));
    }

#undef EMIT
#undef EMIT_MOV64
    return n;
}

/*
 * 最坏长度（字）见 jh_tramp.h 的 JH_TRAMP_MAX_WORDS（唯一定义处）。
 * 这里只导出成函数，供不 include jh_tramp.h 的调用方使用。
 */
int jh_tramp_max_words(void)
{
    return JH_TRAMP_MAX_WORDS;
}

/* ---------- 参数 / 返回值规则运算 ---------- */

uint64_t jh_apply_op(uint32_t op, uint64_t cur, uint64_t val)
{
    switch (op) {
    case JH_OP_SET: return val;
    case JH_OP_OR:  return cur | val;
    case JH_OP_AND: return cur & val;
    case JH_OP_ADD: return cur + val;
    default:        return cur;
    }
}
