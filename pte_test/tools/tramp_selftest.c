/*
 * tramp_selftest.c —— trampoline 生成器的用户态自测
 *
 * 作用：把 jh_tramp.c 生成出的每条指令打成十六进制，
 * 配合 compare.sh 交给真实汇编器核对（确认位域没写错）。
 * 这样在没有设备的情况下也能验证这段最关键的代码。
 *
 * 编译运行：
 *   gcc -I.. -o /tmp/selftest tramp_selftest.c ../jh_tramp.c && /tmp/selftest
 */
#include <stdio.h>
#include <string.h>
#include "jh_tramp.h"

/* BRK imm16：低字节是观察点编号（0=入口，1=出口） */
#define BRK_ENTER 0xBF00U
#define BRK_EXIT  0xBF01U

static void run(const char *name, const struct JavaHookReq *req, uint64_t target)
{
    uint32_t code[32];
    int enter_idx, exit_idx;
    int n = jh_build_tramp(code, 32, req, target,
                           jh_enc_brk(BRK_ENTER), jh_enc_brk(BRK_EXIT),
                           &enter_idx, &exit_idx);
    int i;

    if (n < 0) {
        printf("%s: BUILD FAILED\n", name);
        return;
    }
    printf("%-20s words=%d enter@%d exit@%d:", name, n, enter_idx, exit_idx);
    for (i = 0; i < n; i++)
        printf(" %08x", code[i]);
    printf("\n");
}

int main(void)
{
    struct JavaHookReq r;

    /* 1. 纯尾跳（最基础形态，不带任何观察点） */
    memset(&r, 0, sizeof(r));
    run("tail_only", &r, 0x1234ULL);

    /* 2. 尾跳 + 入口观察点（打印参数） */
    memset(&r, 0, sizeof(r));
    r.arg_cnt = 1; r.args[0].idx = 1; r.args[0].op = JH_OP_PRINT;
    run("tail_enter", &r, 0x1234ULL);

    /* 3. 调用形态：入口 + 出口观察点 */
    memset(&r, 0, sizeof(r));
    r.arg_cnt = 1; r.args[0].idx = 1; r.args[0].op = JH_OP_PRINT;
    r.ret_op = JH_OP_PRINT;
    run("call_enter_exit", &r, 0x1234ULL);

    /* 4. 只观察返回值（无入口观察点） */
    memset(&r, 0, sizeof(r));
    r.ret_op = JH_OP_PRINT;
    run("call_exit_only", &r, 0x1234ULL);

    /* 5. skip：直接返回常量 0x64 */
    memset(&r, 0, sizeof(r));
    r.flags = JH_FLAG_SKIP_ORIGINAL;
    r.ret_val = 0x64;
    run("skip_ret", &r, 0);

    /* 6. skip + 返回值观察点 */
    memset(&r, 0, sizeof(r));
    r.flags = JH_FLAG_SKIP_ORIGINAL;
    r.ret_val = 0xFFFFFFFFFFFFFFFFULL;
    r.ret_op = JH_OP_SET;
    run("skip_ret_brk", &r, 0);

    /* 7. 64 位大地址（四段 MOVZ/MOVK 全用上） */
    memset(&r, 0, sizeof(r));
    run("tail_bigaddr", &r, 0x7fff12345678ULL);

    /* 8. JH_FLAG_BRK：只要 dmesg 打一眼参数 */
    memset(&r, 0, sizeof(r));
    r.flags = JH_FLAG_BRK;
    run("flag_brk_only", &r, 0x1234ULL);

    return 0;
}
