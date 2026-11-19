// SPDX-License-Identifier: GPL-2.0
/*
 * test_insn.c - 针对 ecapctl.c 里指令可探测性判断的单元测试
 *
 * 【为什么要 include .c 文件】
 * a64_check_probeable() 是 static 函数，外部链接不进来。而把它改成
 * 非 static 只为测试并不值得（会污染全局符号，也削弱了封装）。
 *
 * 直接用 #include 把整个翻译单元拉进来，static 函数就成了本文件的
 * 内部函数，可以直接调用。同时用 -Dmain=ecapctl_main 把 ecapctl 的
 * main 改名，避免与本文件的 main 冲突。
 *
 * 【测试用例的来源】
 * 期望值不是我自己推的，而是逐条对照内核源码
 *   arch/arm64/kernel/probes/decode-insn.c : aarch64_insn_is_steppable()
 *   arch/arm64/include/asm/insn.h          : __AARCH64_INSN_FUNCS(...)
 * 得出的。每条用例都标注了依据。
 *
 * 编译运行：
 *   cc -O2 -Wall -Iinclude -Dmain=ecapctl_main \
 *      -o /tmp/test_insn tests/test_insn.c && /tmp/test_insn
 */

#include <stdio.h>
#include <string.h>

/* 把 ecapctl 的 main 改名，避免符号冲突 */
#define main ecapctl_main
#include "../user/ecapctl.c"
#undef main

struct insn_case {
	uint32_t insn;
	const char *name;
	int want; /* 0 = 可探测，-1 = 内核会拒绝 */
	const char *basis;
};

static const struct insn_case cases[] = {
	/* ---- 典型函数序言：必须可探测，否则整个工具没法用 ---- */
	{ 0xD503233F, "paciasp", 0, "HINT 白名单 (0x19<<5)" },
	{ 0xD503245F, "bti c", 0, "HINT 白名单 (0x22<<5)" },
	{ 0xD503201F, "nop", 0, "HINT 白名单 (0x0<<5)" },
	{ 0xD503249F, "bti j", 0, "HINT 白名单 (0x24<<5)" },
	{ 0xA9BF7BFD, "stp x29,x30,[sp,#-16]!", 0, "普通存储，steppable" },
	{ 0xD10083FF, "sub sp,sp,#0x20", 0, "普通算术，steppable" },
	{ 0xB9400BE0, "ldr w0,[sp,#8]", 0, "非 literal load，steppable" },

	/* ---- 分支：内核用 simulate_* 模拟，可以探测 ---- */
	{ 0xD65F03C0, "ret", 0, "INSN_GOOD_NO_SLOT: simulate_br_blr_ret" },
	{ 0x94000010, "bl", 0, "INSN_GOOD_NO_SLOT: simulate_b_bl" },
	{ 0x17FFFFF0, "b", 0, "INSN_GOOD_NO_SLOT: simulate_b_bl" },
	{ 0xB4000100, "cbz x0", 0, "INSN_GOOD_NO_SLOT: simulate_cbz_cbnz" },
	{ 0x54000040, "b.eq", 0, "INSN_GOOD_NO_SLOT: simulate_b_cond" },

	/* ---- PC 相对字面量加载：INSN_REJECTED ---- */
	{ 0x58000120, "ldr x0, literal", -1, "uses_literal -> INSN_REJECTED" },
	{ 0x18000120, "ldr w0, literal", -1, "uses_literal -> INSN_REJECTED" },
	{ 0x98000120, "ldrsw x0, literal", -1, "uses_literal -> INSN_REJECTED" },

	/* ---- 独占访问：INSN_REJECTED ---- */
	{ 0xC85F7C20, "ldaxr x0,[x1]", -1, "is_exclusive -> INSN_REJECTED" },
	{ 0xC89FFC20, "stlxr wzr,x0,[x1]", -1, "is_exclusive -> INSN_REJECTED" },

	/* ---- MSR：INSN_REJECTED（imm / reg 两种形式） ---- */
	{ 0xD51B4200, "msr nzcv, x0", -1, "is_msr_reg" },
	{ 0xD50340DF, "msr daifset,#2", -1, "is_msr_imm" },

	/* ---- MRS：只有 DAIF 例外 ---- */
	{ 0xD5384100, "mrs x0, nzcv", -1, "MRS 非 DAIF -> 拒绝" },
	/*
	 * mrs x0, daif 的编码核对过程：
	 *   spclreg = (insn & 0x1FFFE0) >> 5
	 *   0xD53B4220 -> 0xDA11 == AARCH64_INSN_SPCLREG_DAIF  ✓
	 * 注意 0xD53B4200 的 spclreg 是 0xDA10，那是 nzcv 而不是 daif。
	 */
	{ 0xD53B4220, "mrs x0, daif", 0, "MRS DAIF 是唯一例外 (0xDA11)" },

	/* ---- 异常产生：INSN_REJECTED ---- */
	{ 0xD4000001, "svc #0", -1, "is_exception" },
	{ 0xD4200000, "brk #0", -1, "is_exception" },

	/* ---- ERET ---- */
	{ 0xD69F03E0, "eret", -1, "is_eret (全 32 位精确)" },
	{ 0xD69F0BFF, "eretaa", -1, "is_eret_auth" },

	/* ---- 不在白名单的 HINT ---- */
	{ 0xD503205F, "wfe", -1, "HINT 不在白名单" },
	{ 0xD503203F, "yield", -1, "HINT 不在白名单" },
	{ 0xD503209F, "sev", -1, "HINT 不在白名单" },

	/*
	 * ---- ISB / DSB ----
	 * 这两个容易误判。它们属于 AARCH64_INSN_CLS_BR_SYS，但
	 * aarch64_insn_is_hint() 对它们返回 false（掩码 0xFFFFF01F 不匹配
	 * 0xD503201F），也不匹配 branch/msr/exception/eret/mrs 中任何一条，
	 * 于是 aarch64_insn_is_steppable() 走到最后的 return true。
	 * 结论：它们是**可探测**的。
	 */
	{ 0xD5033FDF, "isb", 0, "BR_SYS 但不在任何拒绝列表 -> steppable" },
	{ 0xD5033F9F, "dsb sy", 0, "BR_SYS 但不在任何拒绝列表 -> steppable" },
};

int main(void)
{
	unsigned int i;
	int fails = 0;

	printf("== a64_check_probeable() unit test ==\n\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct insn_case *c = &cases[i];
		const char *why = NULL;
		int got = a64_check_probeable(c->insn, &why);
		int ok = (got == c->want);

		if (!ok)
			fails++;

		printf("%s  %-26s 0x%08X  got=%2d want=%2d   %s\n",
		       ok ? "OK  " : "FAIL", c->name, c->insn, got, c->want,
		       c->basis);

		if (!ok && why)
			printf("                                    reason: %s\n",
			       why);
	}

	printf("\n%d failure(s) out of %zu case(s)\n", fails,
	       sizeof(cases) / sizeof(cases[0]));

	return fails ? 1 : 0;
}
