/*
 * simtest.c —— 在用户态模拟 jh_do_enter / jh_do_exit 的规则应用，
 *              配合 trampoline 的形状检查语义是否自洽。
 *
 * 目的：把"规则 → 寄存器变化"这段纯逻辑在 PC 上跑一遍，确认：
 *   1. print 只看不改；
 *   2. set/or/and/add 的位运算符合预期；
 *   3. bits32 只动低 32 位；
 *   4. skip 模式下出口观察点看到的是 ret_val。
 *
 * 编译运行：
 *   gcc -I.. -o /tmp/simtest simtest.c ../jh_tramp.c && /tmp/simtest
 */
#include <stdio.h>
#include <string.h>
#include "jh_tramp.h"

static int fails;

#define CHECK(cond, msg) do {                                        \
    if (!(cond)) { printf("  [FAIL] %s\n", msg); fails++; }           \
    else          printf("  [ OK ] %s\n", msg);                       \
} while (0)

/* 复刻 jh_do_enter 的改写部分（不涉及捕获环） */
static void apply_enter(const struct JavaHookReq *r, uint64_t *regs)
{
    unsigned int i, n = r->arg_cnt < JH_ARGS_MAX ? r->arg_cnt : JH_ARGS_MAX;

    for (i = 0; i < n; i++) {
        const struct JavaArgRule *a = &r->args[i];

        if (!jh_rule_active(a->op) || a->op == JH_OP_PRINT)
            continue;
        if (a->idx >= JH_ARGS_MAX)
            continue;
        regs[a->idx] = jh_apply_op(a->op, regs[a->idx], a->val);
    }
}

/* 复刻 jh_do_exit 的改写部分 */
static void apply_exit(const struct JavaHookReq *r, uint64_t *regs)
{
    int bits = (r->ret_bits == 32) ? 32 : 64;

    if (!jh_rule_active(r->ret_op) || r->ret_op == JH_OP_PRINT)
        return;
    if (bits == 32) {
        uint32_t cur = (uint32_t)regs[0];
        regs[0] = (regs[0] & ~0xFFFFFFFFULL) |
                  (uint64_t)(uint32_t)jh_apply_op(r->ret_op, cur,
                                                  (uint32_t)r->ret_new);
    } else {
        regs[0] = jh_apply_op(r->ret_op, regs[0], r->ret_new);
    }
}

int main(void)
{
    struct JavaHookReq r;
    uint64_t regs[9];

    printf("== 参数改写 ==\n");

    /* add：把 x1 从 3 改成 19 */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[1] = 3;
    r.arg_cnt = 1;
    r.args[0].idx = 1; r.args[0].op = JH_OP_ADD; r.args[0].val = 16;
    apply_enter(&r, regs);
    CHECK(regs[1] == 19, "arg1=add:0x10 -> 3+16=19");
    CHECK(regs[0] == 0, "x0 未被牵连");

    /* set */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[2] = 0xABCD;
    r.arg_cnt = 1;
    r.args[0].idx = 2; r.args[0].op = JH_OP_SET; r.args[0].val = 0x64;
    apply_enter(&r, regs);
    CHECK(regs[2] == 0x64, "arg2=set:0x64 -> 0x64");

    /* or / and 叠加 */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[3] = 0xF0;
    r.arg_cnt = 2;
    r.args[0].idx = 3; r.args[0].op = JH_OP_OR;  r.args[0].val = 0x0F;
    r.args[1].idx = 3; r.args[1].op = JH_OP_AND; r.args[1].val = 0xFC;
    apply_enter(&r, regs);
    CHECK(regs[3] == 0xFC, "(0xF0|0x0F)&0xFC = 0xFC（规则按顺序叠加）");

    /* print 不改 */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[1] = 0x1234;
    r.arg_cnt = 1;
    r.args[0].idx = 1; r.args[0].op = JH_OP_PRINT;
    apply_enter(&r, regs);
    CHECK(regs[1] == 0x1234, "arg1=print 不改变参数");

    printf("\n== 返回值改写 ==\n");

    /* 64 位 add */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[0] = 7;
    r.ret_op = JH_OP_ADD; r.ret_new = 1; r.ret_bits = 64;
    apply_exit(&r, regs);
    CHECK(regs[0] == 8, "retop=add:1 bits64 -> 7+1=8");

    /* 32 位 set：高位保持不变 */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[0] = 0xDEADBEEF00000007ULL;
    r.ret_op = JH_OP_SET; r.ret_new = 0x64; r.ret_bits = 32;
    apply_exit(&r, regs);
    CHECK(regs[0] == 0xDEADBEEF00000064ULL,
          "retop=set:0x64 bits32 -> 只改低 32 位，高位保留");

    /* 32 位 add 的进位不会溢出到高位 */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[0] = 0xAAAAAAAAFFFFFFFEULL;
    r.ret_op = JH_OP_ADD; r.ret_new = 1; r.ret_bits = 32;
    apply_exit(&r, regs);
    CHECK(regs[0] == 0xAAAAAAAAFFFFFFFFULL,
          "bits32 下 w0=0xFFFFFFFE +1 = 0xFFFFFFFF，不向高位进位");

    /* retop=print 不修改 */
    memset(&r, 0, sizeof(r));
    memset(regs, 0, sizeof(regs));
    regs[0] = 0x42;
    r.ret_op = JH_OP_PRINT;
    apply_exit(&r, regs);
    CHECK(regs[0] == 0x42, "retop=print 不改变返回值");

    printf("\n== trampoline 形态与规则的一致性 ==\n");
    {
        uint32_t code[32];
        int n, enter_idx, exit_idx;
        uint64_t regs2[9];

        /* 只改参数：应当是尾跳形态（不保存 x30） */
        memset(&r, 0, sizeof(r));
        r.arg_cnt = 1;
        r.args[0].idx = 1; r.args[0].op = JH_OP_SET; r.args[0].val = 1;
        n = jh_build_tramp(code, 32, &r, 0x1234,
                           jh_enc_brk(0xBF00), jh_enc_brk(0xBF01),
                           &enter_idx, &exit_idx);
        CHECK(n > 0 && enter_idx == 0 && exit_idx == -1,
              "只有参数规则 -> 入口观察点 @0，无出口观察点");
        CHECK(code[n - 1] == 0xD61F0220U, "最后一个字是 br x17（尾跳）");

        /* 有返回值规则：必须是调用形态，且最后是 ret */
        memset(&r, 0, sizeof(r));
        r.ret_op = JH_OP_PRINT;
        n = jh_build_tramp(code, 32, &r, 0x1234,
                           jh_enc_brk(0xBF00), jh_enc_brk(0xBF01),
                           &enter_idx, &exit_idx);
        CHECK(n > 0 && enter_idx == -1 && exit_idx >= 0,
              "只有返回值规则 -> 无入口观察点，有出口观察点");
        CHECK(code[0] == 0xA9BF7BFDU, "首字是 stp x29,x30（保存返回地址）");
        CHECK(code[n - 1] == 0xD65F03C0U, "末字是 ret");
        CHECK(exit_idx > 0 && code[exit_idx - 1] == 0xD63F0220U,
              "出口观察点紧跟在 blr x17 之后");

        /* skip：出口观察点看到的是 ret_val */
        memset(&r, 0, sizeof(r));
        r.flags = JH_FLAG_SKIP_ORIGINAL;
        r.ret_val = 0x64;
        r.ret_op = JH_OP_ADD;
        r.ret_new = 1;
        n = jh_build_tramp(code, 32, &r, 0,
                           jh_enc_brk(0xBF00), jh_enc_brk(0xBF01),
                           &enter_idx, &exit_idx);
        regs2[0] = r.ret_val;   /* 模拟 trampoline 已经把返回值摆进 x0 */
        apply_exit(&r, regs2);
        CHECK(regs2[0] == 0x65,
              "skip + retop=add:1 -> 出口看到 ret_val(0x64) 并改成 0x65");
        CHECK(exit_idx > 0 && code[exit_idx - 1] != 0xD63F0220U,
              "skip 形态没有 blr（不调用原方法）");
        (void)n;
    }

    printf("\n%s (%d failures)\n", fails ? "存在问题" : "全部通过", fails);
    return fails ? 1 : 0;
}
