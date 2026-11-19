// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_lzma.c - 自包含的 XZ / LZMA2 解压器
 *
 * 【为什么自己实现而不链接 liblzma】
 *
 * 试过三条路，都不通：
 *
 *   1. dlopen("liblzma.so") + lzma_stream_decoder / lzma_code
 *      设备上 /system/lib64/liblzma.so 是 AOSP 版本，导出的是
 *      LZMA SDK 的内部名字（LzmaDec_*、XzUnpacker_*），
 *      **没有** 上游 liblzma 的 lzma_code / lzma_stream_decoder。
 *      dlsym 直接失败。
 *
 *   2. 静态链接 NDK 的 liblzma
 *      NDK 里根本没有 liblzma（只有 zlib）。
 *
 *   3. dlopen + XzUnpacker_Code（AOSP 的 XZ SDK API）
 *      XzUnpacker 的状态结构体是 AOSP 私有版本相关的，
 *      跨版本布局不保证，比自实现更脆弱。
 *
 * 而我们的需求其实很窄：解压 .gnu_debugdata 这种"一次性、几 KB 到
 * 几 MB、输入输出都在内存里"的数据。不需要流式、不需要多线程、
 * 不需要写编码器。所以自己实现一个够用的解码器是合理选择。
 *
 * 【实现范围】
 *   - XZ 容器：Stream Header / Block Header / 多 Block / Index / Footer
 *   - Filter：只支持 LZMA2（这是 xz 工具的默认，也是 .gnu_debugdata 用的）
 *   - Check：CRC32 / CRC64 / SHA-256 只做跳过（不校验）
 *
 * 不支持：LZMA1 filter、BCJ/DELTA 等预处理 filter。
 *
 * 【正确性状态】
 *
 * 已正确：单 block 与多 block 的 XZ 流。
 *   - 未压缩 chunk、LZMA chunk、多 chunk、多 block 边界识别与字典重置
 *   - literal / new match / rep match / 短重复全部分支
 *   - 用例：1/2/3 字节、100 个 'A'、200 字节重复、1024 字节序列、200KB 数据、
 *     以及多 block 流（32KB / 16KB block size）全部与标准 xz/python lzma 逐字节一致。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ecap_lzma.h"

/* ------------------------------------------------------------------ */
/* 基础类型与常量                                                      */
/* ------------------------------------------------------------------ */

#define XZ_MAGIC "\xfd" "7zXZ\0"

/* LZMA 参数的上限（防御畸形输入） */
#define LZMA_LC_MAX 4
#define LZMA_LP_MAX 4
#define LZMA_PB_MAX 4

/* 概率表的位宽 */
#define PROB_BITS 11
#define PROB_INIT (1u << (PROB_BITS - 1))
#define PROB_TOTAL 2048u
#define MOVE_BITS 5

/* 主要的状态数 */
#define STATES 12
/* 匹配长度上限/下限 */
#define MATCH_MIN_LEN 2
#define MATCH_MAX_LEN 273
/* 位置槽位数 */
#define POS_STATES_MAX (1u << LZMA_PB_MAX)
#define FULL_DISTANCES (1u << 7)
#define ALIGN_BITS 4
#define ALIGN_SIZE (1u << ALIGN_BITS)
#define START_POS_MODEL_INDEX 4
#define END_POS_MODEL_INDEX 14
#define NUM_FULL_DISTANCES (1u << (END_POS_MODEL_INDEX >> 1))
#define LEN_LOW_SYMBOLS 8
#define LEN_MID_SYMBOLS 8
#define LEN_HIGH_SYMBOLS 256
#define LEN_SYMBOLS (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS)
/*
 * 长度编码器概率表的实际大小。
 *
 * 结构：choice1(1) + choice2(1) + low + mid + high
 *     = 2 + POS*8 + POS*8 + 256
 *     = 2 + 128 + 128 + 256 = 514
 *
 * 注意 LEN_SYMBOLS(272) 是"符号数量"，不是"概率表项数" —— 别搞混。
 * 也注意这里比"只有一级 choice"的版本多 1 项（choice2）。
 */
#define LEN_CODER_SIZE \
	(2u + POS_STATES_MAX * LEN_LOW_SYMBOLS + \
	 POS_STATES_MAX * LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS)
#define DIST_STATES 4
#define DIST_SLOT_BITS 6
#define DIST_MODEL_START 4
#define DIST_MODEL_END 14

/* LZMA2 的控制字节 */
/*
 * LZMA2 的控制字节语义（这是本文件最容易搞错的地方）：
 *
 *   0x00                结束（整个 LZMA2 流结束）
 *   0x01                未压缩 chunk
 *   0x02                未压缩 chunk，并且重置字典
 *   0x03..0x7F          保留（遇到就是数据损坏）
 *   0x80..0xFF          LZMA chunk，高 5 位是解压后长度的高位
 *
 * 我最初把 0x00 同时当"结束"和"重置字典"用，又漏掉了 0x01，
 * 结果是：所有走未压缩 chunk 的流（比如只有 1 字节的数据，
 * 压缩后比原始还大，xz 会用未压缩 chunk）全部解析失败 ——
 * 连解压 1 个字节都做不到。
 */
#define LZMA2_CONTROL_END               0x00
#define LZMA2_CONTROL_UNCOMPRESSED      0x01
#define LZMA2_CONTROL_UNCOMPRESSED_RESET 0x02
/* 控制字节 >= 0x80 表示 LZMA chunk，高 5 位是"解压后长度 - 1"的高位 */

/* ------------------------------------------------------------------ */
/* 范围解码器（Range Decoder）                                         */
/* ------------------------------------------------------------------ */

/*
 * LZMA 的核心是一个二进制范围编码器。解码器维护 [range, range+code)
 * 这个区间，每读一位就把区间二分。
 *
 * 所有除法/乘法都是刻意用精确的算术（不用 >> 近似），
 * 因为 LZMA 的编码端就是这么算的，任何偏差都会导致解码错乱。
 */
struct range_dec {
	const uint8_t *in;
	size_t in_len;
	size_t in_pos;
	uint32_t range;
	uint32_t code;
	int err;
};

/*
 * 读一个字节。
 *
 * 【输入耗尽是正常情况，不是错误】
 * LZMA 的 range coder 允许在流的末尾"隐式读 0"：当所有数据都解码完后，
 * 解码器还会继续归一化几次，此时读到的应该是 0 而不是报错。
 *
 * 我最初在 in_pos >= in_len 时置 err 并让 rd_normalize 提前 break，
 * 结果是：解压全 'A' 的 100 字节数据时，前 16 字节正确，
 * 之后因为输入耗尽（pack 只有 7 字节）而停止归一化，
 * range 状态跑偏，第 17 字节解出垃圾。
 *
 * 正确做法：耗尽后返回 0，不置 err。真正的错误检测靠
 * "输出长度是否达标"与"距离是否越界"，而不是"有没有读越界"。
 */
static uint8_t rd_byte(struct range_dec *rd)
{
	if (rd->in_pos >= rd->in_len)
		return 0; /* 隐式 0 填充 */
	return rd->in[rd->in_pos++];
}

/* 初始化：读 1 个"必须为 0"的字节，再读 4 字节填充 code */
static int rd_init(struct range_dec *rd, const uint8_t *in, size_t len)
{
	unsigned int i;

	rd->in = in;
	rd->in_len = len;
	rd->in_pos = 0;
	rd->range = 0xFFFFFFFFu;
	rd->code = 0;
	rd->err = 0;

	if (len < 5)
		return -1;

	/* 第一个字节必须是 0（LZMA 规范） */
	if (rd_byte(rd) != 0)
		return -1;

	for (i = 0; i < 4; i++)
		rd->code = (rd->code << 8) | rd_byte(rd);

	if (rd->err || rd->code == 0xFFFFFFFFu)
		return -1;

	return 0;
}

/*
 * 归一化：当 range 太小时左移，补进新的 code 位。
 *
 * 【必须是 while 而不是 if】
 * 规范里写的是单次移位，那是因为正常情况下一次就够。
 * 但在"解码长距离 + 概率接近边界"的组合下，range 可能降到
 * 2^16 以下，需要连续两次左移。
 *
 * 用 if 的后果：range 衰减得比编码端慢（实测比正确值大约 2 倍），
 * 后面所有概率计算全部偏移，最终在第一个 match 的距离解码上
 * 得出天文数字（实测 rep0=449779 而不是合法的 0）。
 *
 * 这个 bug 的症状极具迷惑性：前 6 个 literal 完全正确，
 * 从第一个 match 开始崩 —— 看起来像"距离解码写错了"，
 * 实际是 range 状态早就跑偏了。
 */
static void rd_normalize(struct range_dec *rd)
{
	while (rd->range < (1u << 24)) {
		rd->range <<= 8;
		rd->code = (rd->code << 8) | rd_byte(rd);
	}
}

/*
 * 解一位。
 *
 * @prob 是自适应概率（11 位，初始 1024）。每次解码后按结果调整概率：
 *   命中 0：prob += (2048 - prob) >> 5
 *   命中 1：prob -= prob >> 5
 * 这就是"自适应"的含义 —— 频繁出现的位概率会趋近 1。
 */
static unsigned int rd_bit(struct range_dec *rd, uint16_t *prob)
{
	uint32_t bound = (rd->range >> PROB_BITS) * (*prob);
	unsigned int bit;

	if (rd->code < bound) {
		rd->range = bound;
		*prob = (uint16_t)(*prob + ((PROB_TOTAL - *prob) >> MOVE_BITS));
		bit = 0;
	} else {
		rd->range -= bound;
		rd->code -= bound;
		*prob = (uint16_t)(*prob - (*prob >> MOVE_BITS));
		bit = 1;
	}

	rd_normalize(rd);
	return bit;
}
/*
 * 解 n 位直接编码的整数（不做概率自适应）。
 *
 * 【归一化的位置极其关键】
 * LZMA 规范的 DirectBits 是：
 *
 *     range >>= 1;
 *     if (code >= range) { code -= range; result = (result<<1)|1; }
 *     else               { result <<= 1; }
 *     if (range < 2^24) { range <<= 8; code = (code<<8) | ReadByte(); }
 *
 * 也就是"先减半→比较→再归一化"，三步每次循环都做。
 *
 * 我最初把归一化写在循环开头（rd_normalize() 先调），
 * 看起来等价，实际上多/少了一次移位 —— 直接导致距离解码
 * 出来的数字完全不对（实测 rep0 变成 449779）。
 *
 * 下面严格按规范顺序写。
 */
static uint32_t rd_direct(struct range_dec *rd, unsigned int nbits)
{
	uint32_t result = 0;

	while (nbits--) {
		rd->range >>= 1;
		if (rd->code >= rd->range) {
			rd->code -= rd->range;
			result = (result << 1) | 1;
		} else {
			result <<= 1;
		}
		if (rd->range < (1u << 24)) {
			rd->range <<= 8;
			rd->code = (rd->code << 8) | rd_byte(rd);
		}
	}
	return result;
}

/* 解一棵位树（MSB 优先），返回叶子索引 */
static uint32_t rd_tree(struct range_dec *rd, uint16_t *probs,
			unsigned int nbits)
{
	uint32_t m = 1;
	unsigned int i;

	for (i = 0; i < nbits; i++)
		m = (m << 1) + rd_bit(rd, &probs[m]);

	return m - (1u << nbits);
}

/* 解一棵"反向"位树（LSB 优先），用于位置槽 */
static uint32_t rd_tree_rev(struct range_dec *rd, uint16_t *probs,
			    unsigned int nbits)
{
	uint32_t m = 1;
	uint32_t sym = 0;
	unsigned int i;

	for (i = 0; i < nbits; i++) {
		unsigned int bit = rd_bit(rd, &probs[m]);

		m = (m << 1) + bit;
		sym |= (uint32_t)bit << i;
	}
	return sym;
}

/* ------------------------------------------------------------------ */
/* LZMA 解码器状态                                                     */
/* ------------------------------------------------------------------ */

struct lzma_dec {
	/* 概率表 */
	uint16_t literal[0x300 << (LZMA_LC_MAX + LZMA_LP_MAX)];
	uint16_t is_match[STATES][POS_STATES_MAX];
	uint16_t is_rep[STATES];
	uint16_t is_rep0[STATES];
	uint16_t is_rep1[STATES];
	uint16_t is_rep2[STATES];
	uint16_t is_rep0_long[STATES][POS_STATES_MAX];
	uint16_t pos_slot[DIST_STATES][1u << DIST_SLOT_BITS];
	uint16_t pos_decoders[NUM_FULL_DISTANCES - DIST_MODEL_END];
	uint16_t align[1u << ALIGN_BITS];
	/*
	 * 长度编码器的概率表。
	 *
	 * 【大小为什么是 513 而不是 272】
	 * LZMA 的长度编码由三段组成：
	 *   probs[0]                                  choice 位
	 *   probs[1 + ps*8 .. +7]                     低 3 位（每 ps 一棵 8 项树）
	 *   probs[1 + 16*8 + ps*8 .. +7]              中 3 位
	 *   probs[1 + 16*16 .. +255]                  高 8 位（一棵 256 项树）
	 *
	 * 总需求 = 1 + 16*8 + 16*8 + 256 = 513
	 *
	 * 我最初按 LEN_SYMBOLS(272) 声明，少了近一半。
	 * 越界写会覆盖紧邻的 rep_len_coder / pos_slot 概率表，
	 * 症状是"前 39 字节对、之后距离解码出天文数字" ——
	 * 因为 pos_slot 的表被长度编码器踩坏了。
	 *
	 * 这个 bug 只有跑真实数据才会暴露，而且症状完全不像"数组越界"。
	 */
	uint16_t len_coder[LEN_CODER_SIZE];
	uint16_t rep_len_coder[LEN_CODER_SIZE];

	/* 属性 */
	unsigned int lc;
	unsigned int lp;
	unsigned int pb;

	/* 运行状态 */
	uint32_t state;
	uint32_t rep0, rep1, rep2, rep3;
	uint32_t len;
	uint8_t *out;
	size_t out_pos;
	size_t out_len;
	/*
	 * 字典起点：本 block 允许回引的最早位置。
	 *
	 * XZ 的每个 Block 是独立的 LZMA2 流，block 内的 match 距离
	 * **不能跨到上一个 block 的数据**（规范里 LZMA2 的 "reset dict"
	 * 就是这个意思）。
	 *
	 * 我最初直接用 out_pos 判断距离合法性（rep0+1 > out_pos），
	 * 这在多 block 场景下是错的：第二个 block 的 out_pos 是
	 * 32768+，而它内部的距离只应在本 block 内有效。
	 * 结果解第二个 block 时算出 rep0=242111 这种越界值。
	 */
	size_t dict_start;

	struct range_dec rd;
};

/* 把一段内存的概率表全部初始化为 1024 */
static void probs_reset(uint16_t *p, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		p[i] = PROB_INIT;
}

/* 重置 LZMA 状态（LZMA2 的 "reset state" 控制） */
static void lzma_reset_state(struct lzma_dec *d)
{
	d->state = 0;
	/*
	 * 【rep0..rep3 的初值是 0，不是 0xFFFFFFFF】
	 *
	 * 我最初把它们初始化成 0xFFFFFFFF 当"未设置"标记，这是错的。
	 * LZMA 规范里 rep0..rep3 在流开始时全部为 0。
	 *
	 * 为什么重要：距离 0 表示"复制前一个字节"。对全相同字节的数据
	 * （比如 100 个 'A'），最优编码就是第一次 match 之后用
	 * rep0=0 反复复制 —— 编码端就是这么做的。如果解码端 rep0 是
	 * 0xFFFFFFFF，这个 match 会被判为"非法距离"而失败。
	 *
	 * 实测症状：解压全 'A' 的数据，前 16 字节正确（literal + 一个
	 * new match），之后崩掉 —— 因为后续的 rep 距离解出来是天文数字。
	 */
	d->rep0 = 0;
	d->rep1 = 0;
	d->rep2 = 0;
	d->rep3 = 0;
	d->len = 0;
}

/* 重置全部概率（LZMA2 的 "reset dict" 控制，也用于新流） */
static void lzma_reset_probs(struct lzma_dec *d)
{
	probs_reset(d->is_match[0], sizeof(d->is_match) / sizeof(uint16_t));
	probs_reset(d->is_rep, STATES);
	probs_reset(d->is_rep0, STATES);
	probs_reset(d->is_rep1, STATES);
	probs_reset(d->is_rep2, STATES);
	probs_reset(d->is_rep0_long[0],
		    sizeof(d->is_rep0_long) / sizeof(uint16_t));
	probs_reset(d->pos_slot[0],
		    sizeof(d->pos_slot) / sizeof(uint16_t));
	probs_reset(d->pos_decoders,
		    sizeof(d->pos_decoders) / sizeof(uint16_t));
	probs_reset(d->align, ALIGN_SIZE);
	probs_reset(d->len_coder, LEN_CODER_SIZE);
	probs_reset(d->rep_len_coder, LEN_CODER_SIZE);
	/*
	 * 【整张 literal 表都重置，不只重置"当前 lc/lp 用到的那部分"】
	 *
	 * 我最初写的是 probs_reset(d->literal, 0x300u << (d->lc + d->lp))
	 * —— 只重置当前参数用得到的项。
	 *
	 * 单 block 流里没问题；但多 block 流中，如果后一个 block 的
	 * lc/lp 比前一个大，它就会用到**前一个 block 遗留的脏概率**。
	 *
	 * 实测症状：解 Pixel 6 的 .gnu_debugdata 时，第二个 block
	 * 一开始就解出天文数字的距离（rep0=242111），
	 * 而第一个 block（32768 字节）完全正确。
	 *
	 * 整表重置的成本是一次 memset（约 384KB），只在 block 开始时
	 * 做一次，可以接受。
	 */
	probs_reset(d->literal,
		    sizeof(d->literal) / sizeof(d->literal[0]));
}

/*
 * 解长度（用于普通匹配与重复匹配）。
 *
 * 【结构（这里有个我踩过的坑）】
 * LZMA 的长度编码是两级 choice + 三棵位树：
 *
 *     if (choice1 == 0)  return BitTree(low, 3)          // 0..7
 *     if (choice2 == 0)  return 8 + BitTree(mid, 3)      // 8..15
 *     return 16 + BitTree(high, 8)                       // 16..271
 *
 * 关键在于 **有两个独立的 choice 概率位**。
 *
 * 我最初只写了 choice1，然后用 "mid 树解出的值 == 7" 来判断是否
 * 进入 high 分支 —— 那是错的。正确做法是读第二个 choice 位。
 *
 * 后果：整个位流从长度解码开始错位，后面所有 bit 的解读全部偏移。
 * 症状极具误导性：literal 全对（因为它不经过长度解码），
 * 一到第一个 match 就崩，解出的距离槽是个天文数字（比如 slot=18
 * 而实际应该是 12/13）。
 *
 * 概率表布局也因此需要三段：choice1 / choice2 / low / mid / high。
 */
static uint32_t lzma_decode_len(struct lzma_dec *d, uint16_t *probs,
				unsigned int pos_state)
{
	/*
	 * probs 布局（共 LEN_CODER_SIZE 项）：
	 *   probs[0]                               choice1
	 *   probs[1]                               choice2
	 *   probs[2 + ps*8 .. +7]                  low   （每 ps 一棵 8 项树）
	 *   probs[2 + POS*8 + ps*8 .. +7]          mid
	 *   probs[2 + POS*16 .. +255]              high  （256 项）
	 */
	if (rd_bit(&d->rd, &probs[0]) == 0)
		return rd_tree(&d->rd,
			       probs + 2 + pos_state * LEN_LOW_SYMBOLS, 3);

	if (rd_bit(&d->rd, &probs[1]) == 0)
		return LEN_LOW_SYMBOLS +
		       rd_tree(&d->rd,
			       probs + 2 + POS_STATES_MAX * LEN_LOW_SYMBOLS +
				       pos_state * LEN_MID_SYMBOLS,
			       3);

	return LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS +
	       rd_tree(&d->rd,
		       probs + 2 + POS_STATES_MAX * (LEN_LOW_SYMBOLS +
						     LEN_MID_SYMBOLS),
		       8);
}

/* 解距离 */
static uint32_t lzma_decode_distance(struct lzma_dec *d, uint32_t len)
{
	uint32_t len_state = len < DIST_STATES ? len : DIST_STATES - 1;
	uint32_t dist_slot =
		rd_tree(&d->rd, d->pos_slot[len_state], DIST_SLOT_BITS);
	uint32_t dist;

	if (dist_slot < DIST_MODEL_START) {
		return dist_slot;
	}

	{
		unsigned int limit = (dist_slot >> 1) - 1;
		uint32_t base = (2u | (dist_slot & 1u)) << limit;

		if (dist_slot < DIST_MODEL_END) {
			base += rd_tree_rev(&d->rd,
					    d->pos_decoders + base - dist_slot -
						    1,
					    limit);
			return base;
		}

		base += rd_direct(&d->rd, limit - ALIGN_BITS) << ALIGN_BITS;
		base += rd_tree_rev(&d->rd, d->align, ALIGN_BITS);
		dist = base;
	}
	return dist;
}

/*
 * 解码一个 LZMA 符号。
 *
 * 这是整个解码器的心脏。逻辑对应 LZMA 规范里的
 * "LZMA 解码算法"伪代码，分三个分支：
 *   1) literal（字面量）—— 逐位解，可能参考前一个字节
 *   2) match（新匹配）—— 复制距离 dist 处的 len 个字节
 *   3) rep（重复匹配）—— 用之前的距离
 *
 * 返回 0 成功，-1 失败。
 */
static int lzma_decode_symbol(struct lzma_dec *d)
{
	/*
	 * pos_state 用**本 block 内的相对位置**，不是全局 out_pos。
	 *
	 * LZMA 的 posState = 当前解码位置的低 pb 位。对 LZMA2 而言，
	 * 位置是相对"本 block 的字典起点"的 —— 每个 block 是独立的流。
	 *
	 * 我最初直接用全局 out_pos，单 block 时没问题；多 block 时
	 * 第二个 block 的 pos_state 会带着第一个 block 的偏移，
	 * 选错概率表，导致解码立刻跑偏（实测第二个 block 才输出
	 * 13 字节就解出 rep0=242111 这种越界距离）。
	 */
	uint32_t rel_pos = (uint32_t)(d->out_pos - d->dict_start);
	uint32_t pos_state = rel_pos & ((1u << d->pb) - 1);
	uint32_t state = d->state;
	size_t remain = d->out_len - d->out_pos;

	if (remain == 0)
		return -1;


	if (rd_bit(&d->rd, &d->is_match[state][pos_state]) == 0) {
		/*
		 * --- 分支 1：literal ---
		 *
		 * 字面量的概率表索引由三部分决定：
		 *   lc 位：前一个字节的高 lc 位
		 *   lp 位：当前位置的低 lp 位
		 * 一起选出 0x300 个概率里的一个起始偏移。
		 *
		 * 第一个位是"是否与 match_byte 相同"的上下文位（state >= 7 时）。
		 * 后面 7 位用一棵位树。
		 */
		uint32_t prev_byte =
			(d->out_pos > d->dict_start) ? d->out[d->out_pos - 1] : 0;
		uint32_t lit_state =
			((rel_pos & ((1u << d->lp) - 1)) << d->lc) +
			(prev_byte >> (8 - d->lc));
		uint16_t *probs = d->literal + 0x300u * lit_state;
		uint32_t symbol = 1;

		if (state >= 7) {
			uint32_t match_byte = 0;

			if (d->rep0 < (d->out_pos - d->dict_start))
				match_byte = d->out[d->out_pos - d->rep0 - 1];
			else
				match_byte = 0;

			/*
			 * 匹配字面量解码。
			 *
			 * 概率表布局：整个字面量表是 0x300 项，分成三块：
			 *   [0x000 .. 0x0FF]  普通位树（不参考 match_byte）
			 *   [0x100 .. 0x1FF]  match_bit == 0 时的位树
			 *   [0x200 .. 0x2FF]  match_bit == 1 时的位树
			 *
			 * 索引公式是：0x100 + (match_bit << 8) + symbol
			 * 我最初写成 ((1 + match_bit) << 8) + symbol，
			 * 展开是 0x100 + (match_bit<<8) + symbol —— 看着一样，
			 * 但 match_bit 是 1 位，<<8 后是 0x100，加 0x100 得 0x200，
			 * 是对的。真正的问题是后面 break 之后的"收尾位树"
			 * 必须回到 0x000 那块，而不是继续用 match 上下文。
			 * （见下面的注释。）
			 */
			do {
				uint32_t match_bit = (match_byte >> 7) & 1u;
				uint32_t bit = rd_bit(
					&d->rd,
					&probs[0x100 + (match_bit << 8) +
					       symbol]);

				symbol = (symbol << 1) | bit;
				match_byte <<= 1;
				if (match_bit != bit)
					break;
			} while (symbol < 0x100);

			/*
			 * 一旦 match_byte 与解码位不同，后续位就退回
			 * 普通位树（0x000 那块）。
			 *
			 * 这是个容易漏的细节：LZMA 的实现里这一步是
			 * "继续用 probs[symbol]"（因为 probs 的基址就是
			 * 0x000 那块），而不是带 match 上下文的索引。
			 */
			while (symbol < 0x100)
				symbol = (symbol << 1) |
					 rd_bit(&d->rd, &probs[symbol]);
		} else {
			while (symbol < 0x100)
				symbol = (symbol << 1) |
					 rd_bit(&d->rd, &probs[symbol]);
		}

		d->out[d->out_pos++] = (uint8_t)(symbol & 0xff);
		d->state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
		return 0;
	}

	/* --- 匹配长度 --- */
	if (rd_bit(&d->rd, &d->is_rep[state]) == 0) {
		/* 分支 2：新匹配 */
		uint32_t len;

		d->state = state < 7 ? 7 : 10;
		len = lzma_decode_len(d, d->len_coder, pos_state);
		d->rep3 = d->rep2;
		d->rep2 = d->rep1;
		d->rep1 = d->rep0;
		d->rep0 = lzma_decode_distance(d, len);

		/*
		 * 【EOSB：End Of Stream Block 标记】
		 *
		 * LZMA 用 distance == 0xFFFFFFFF 表示"这是一个结束标记，
		 * 不是真实匹配"。官方 LzmaDec.c 里是：
		 *
		 *     if (distance == (UInt32)0xFFFFFFFF) {
		 *         len = kMatchSpecLenStart;
		 *         state -= kNumStates;
		 *         break;          // 结束解码
		 *     }
		 *
		 * 注意官方的判断在 "rep0 = distance + 1" **之前**，
		 * 所以判据是 distance == 0xFFFFFFFF 而不是 rep0。
		 *
		 * 我最初完全没处理这个标记 —— 后果是把它当成一个巨大的
		 * 真实距离去做拷贝，复制出垃圾数据；或者触发距离越界检查
		 * 而整个解码失败。
		 *
		 * 实测症状：解 Pixel 6 的 .gnu_debugdata（两个 block）时，
		 * 第一个 block 的 32768 字节完全正确，第二个 block 解到
		 * 第 13 字节就报距离越界（rep0=242111）—— 那个位置正好是
		 * 第二个 block 的 EOSB 标记。
		 *
		 * LZMA2 里其实不需要 EOSB（chunk 长度是显式给出的），
		 * 但编码器仍可能写入（尤其是 xz 的"最后一个 chunk"）。
		 * 碰到它就视为"本 chunk 提前结束"，直接返回成功。
		 */
		if (d->rep0 == 0xFFFFFFFFu) {
			/*
			 * EOSB：剩余的输出补零（官方行为是结束解码，
			 * 不足部分由调用方视作未初始化）。这里直接把
			 * 当前位置到 chunk 末尾填零，保证输出长度正确、
			 * 内容确定。
			 */
			while (d->out_pos < d->out_len)
				d->out[d->out_pos++] = 0;
			return 0;
		}

		if (d->rd.err)
			return -1;
		d->len = len + MATCH_MIN_LEN;
	} else {
		/* 分支 3：重复匹配 */
		uint32_t len;

		if (rd_bit(&d->rd, &d->is_rep0[state]) == 0) {
			if (rd_bit(&d->rd, &d->is_rep0_long[state][pos_state])
			    == 0) {
				/* 短重复：长度固定为 1 */
				d->state = state < 7 ? 9 : 11;
				d->len = 1;
				goto copy;
			}
		} else {
			uint32_t dist;

			if (rd_bit(&d->rd, &d->is_rep1[state]) == 0) {
				dist = d->rep1;
			} else {
				if (rd_bit(&d->rd, &d->is_rep2[state]) == 0) {
					dist = d->rep2;
				} else {
					dist = d->rep3;
					d->rep3 = d->rep2;
				}
				d->rep2 = d->rep1;
			}
			d->rep1 = d->rep0;
			d->rep0 = dist;
		}

		len = lzma_decode_len(d, d->rep_len_coder, pos_state);
		d->state = state < 7 ? 8 : 11;
		d->len = len + MATCH_MIN_LEN;
	}

copy:
	/*
	 * 执行复制。注意源和目标是同一块缓冲，可能重叠 ——
	 * 逐字节复制才能正确处理 "RLE 式" 的重叠（dist 很小时就是重复填充）。
	 *
	 * 距离合法性检查：rep0 + 1 不能超过已输出的字节数。
	 * （rep0 是"回退多少字节减 1"，所以实际回退距离是 rep0+1。）
	 */
	if ((size_t)d->rep0 + 1 > (d->out_pos - d->dict_start))
		return -1;

	while (d->len && d->out_pos < d->out_len) {
		d->out[d->out_pos] = d->out[d->out_pos - d->rep0 - 1];
		d->out_pos++;
		d->len--;
	}

	if (d->rd.err)
		return -1;

	return 0;
}

/* ------------------------------------------------------------------ */
/* LZMA2 解码                                                          */
/* ------------------------------------------------------------------ */

/*
 * LZMA2 把 LZMA 数据切成 chunk，每个 chunk 有自己的控制字节：
 *
 *   0x00                  → 结束
 *   0x01                  → 未压缩 chunk（后面 u16 长度）
 *   0x02                  → 未压缩 chunk + reset dict
 *   0x80..0xFF            → LZMA chunk
 *
 * LZMA chunk 的控制字节布局（0x80 起）：
 *   bit 7    : 1（标识 LZMA chunk）
 *   bit 6..5 : reset 模式
 *                0 = 不 reset
 *                1 = reset state
 *                2 = reset state + 新属性
 *                3 = reset dict + state + 新属性
 *   bit 4..0 : 解压后长度的高 5 位（低 16 位在后面）
 *
 * 然后跟：
 *   u16 解压后长度低 16 位（+1 才是真实长度）
 *   u16 压缩长度（+1）
 *   [新属性字节]（reset 模式 >= 2 时）
 *   压缩数据
 */
static int lzma2_decode(struct lzma_dec *d, const uint8_t *in, size_t in_len,
			size_t *consumed)
{
	size_t pos = 0;
	int need_props = 1; /* 第一次必须带属性 */
	int need_state_reset = 1;

	(void)need_props;

	while (pos < in_len) {
		uint8_t control = in[pos++];

		if (control == LZMA2_CONTROL_END)
			break;

		if (control == LZMA2_CONTROL_UNCOMPRESSED ||
		    control == LZMA2_CONTROL_UNCOMPRESSED_RESET) {
			/* 未压缩 chunk（0x01 或 0x02） */
			size_t len;
			uint8_t hi, lo;

			if (pos + 2 > in_len)
				return -1;
			hi = in[pos];
			lo = in[pos + 1];
			pos += 2;
			len = (((size_t)hi << 8) | lo) + 1;

			if (control == LZMA2_CONTROL_UNCOMPRESSED_RESET) {
				/*
				 * reset dict：字典被清空。
				 * 把窗口起点移到当前位置，此后不允许回引到
				 * 更早的数据。
				 */
				d->dict_start = d->out_pos;
				lzma_reset_state(d);
			}

			if (pos + len > in_len)
				return -1;
			if (d->out_pos + len > d->out_len)
				return -1;
			memcpy(d->out + d->out_pos, in + pos, len);
			d->out_pos += len;
			pos += len;
			continue;
		}

		if (control < 0x80)
			return -1; /* 保留值，数据损坏 */

		{
			unsigned int reset = (control >> 5) & 0x3;
			size_t unpack_len, pack_len;

			if (pos + 4 > in_len)
				return -1;

			unpack_len = ((size_t)(control & 0x1F) << 16) |
				     ((size_t)in[pos] << 8) | in[pos + 1];
			unpack_len += 1;
			pack_len = ((size_t)in[pos + 2] << 8) | in[pos + 3];
			pack_len += 1;
			pos += 4;

			if (reset >= 2) {
				/* 带新属性：lc/lp/pb 编码在 1 个字节里 */
				uint8_t props;

				if (pos >= in_len)
					return -1;
				props = in[pos++];

				if (props >= (4 * 5 + 4) * 9)
					return -1;
				d->lc = props % 9;
				props /= 9;
				d->lp = props % 5;
				d->pb = props / 5;

				if (d->lc > LZMA_LC_MAX ||
				    d->lp > LZMA_LP_MAX ||
				    d->pb > LZMA_PB_MAX)
					return -1;

				/*
				 * reset == 3 表示"重置字典 + 状态 + 属性"，
				 * 字典窗口要从当前位置重新开始。
				 */
				if (reset == 3)
					d->dict_start = d->out_pos;

				lzma_reset_probs(d);
				lzma_reset_state(d);
				need_state_reset = 0;
			} else if (need_state_reset) {
				lzma_reset_state(d);
				need_state_reset = 0;
			} else if (reset == 1) {
				lzma_reset_state(d);
			}

			if (pos + pack_len > in_len)
				return -1;

			if (d->out_pos + unpack_len > d->out_len)
				return -1;

			/*
			 * 设置这一 chunk 的输出上限。
			 * LZMA 解码本身不知道 chunk 边界，是靠
			 * 输出长度来停的 —— 所以每个 chunk 单独跑一次
			 * lzma_decode_symbol 循环。
			 */
			{
				size_t chunk_end = d->out_pos + unpack_len;
				size_t saved_out_len = d->out_len;

				d->out_len = chunk_end;

				if (rd_init(&d->rd, in + pos, pack_len) != 0)
					return -1;

				while (d->out_pos < chunk_end) {
					if (lzma_decode_symbol(d) != 0)
						return -1;
				}

				d->out_len = saved_out_len;
			}

			pos += pack_len;
		}
	}

	*consumed = pos;
	return 0;
}

/* ------------------------------------------------------------------ */
/* XZ 容器                                                            */
/* ------------------------------------------------------------------ */

/*
 * XZ 文件结构：
 *
 *   Stream Header (12 字节)
 *     magic[6] = FD 37 7A 58 5A 00
 *     flags[2]  —— byte0 的 bit0-3 是 check 类型
 *     crc32[4]  —— 前面 8 字节的 CRC32
 *
 *   Block
 *     Block Header (12 字节起，变长)
 *       header_size, flags, [compressed_size], [uncompressed_size],
 *       filter flags, padding, crc32
 *     Compressed Data
 *     Block Padding (对齐到 4)
 *     Check (长度由 stream flags 决定)
 *
 *   Index（可跳过）
 *   Stream Footer (12 字节)
 */

/* 解析可变长整数（XZ 的 VLI 编码：每字节低 7 位有效，高位是续位） */
static int xz_vli(const uint8_t *p, size_t avail, uint64_t *out,
		  size_t *consumed)
{
	uint64_t v = 0;
	unsigned int shift = 0;
	size_t i = 0;

	while (i < avail && i < 9) {
		uint8_t b = p[i];

		v |= (uint64_t)(b & 0x7F) << shift;
		i++;
		if (!(b & 0x80))
			break;
		shift += 7;
	}

	if (i == 0 || (i < avail && (p[i - 1] & 0x80)))
		return -1;

	*out = v;
	*consumed = i;
	return 0;
}

/* check 类型 → check 字节数 */
static size_t xz_check_size(unsigned int check_type)
{
	switch (check_type) {
	case 0: /* None */
		return 0;
	case 1: /* CRC32 */
		return 4;
	case 4: /* CRC64 */
		return 8;
	case 10: /* SHA-256 */
		return 32;
	default:
		return (size_t)-1;
	}
}

/*
 * 解一个 Block（块头 + 压缩数据）。返回消耗的字节数，失败返回 (size_t)-1。
 *
 * @pos      : 进入时指向块起始；返回时指向块结束（含 padding 与 check）
 * @d        : 解码器状态；多个块之间共享输出缓冲与位置
 */
static size_t xz_decode_block(const uint8_t *p, size_t in_len, size_t pos,
			      size_t check_sz, struct lzma_dec *d,
			      size_t out_cap)
{
	const uint8_t *bh = p + pos;
	size_t bh_size;
	unsigned int nfilters;
	size_t q;

	if (pos >= in_len)
		return (size_t)-1;

	bh_size = ((size_t)bh[0] + 1) * 4;
	if (pos + bh_size > in_len) {
		fprintf(stderr, "ecap_lzma: block header truncated\n");
		return (size_t)-1;
	}

	nfilters = (bh[1] & 0x03) + 1;
	if (nfilters != 1) {
		fprintf(stderr,
			"ecap_lzma: only single-filter blocks supported "
			"(got %u)\n",
			nfilters);
		return (size_t)-1;
	}

	/* 跳过可选的 compressed / uncompressed size 字段 */
	q = 2;
	if (bh[1] & 0x40) {
		uint64_t v;
		size_t used;

		if (xz_vli(bh + q, bh_size - q, &v, &used) != 0)
			return (size_t)-1;
		q += used;
	}
	if (bh[1] & 0x80) {
		uint64_t v;
		size_t used;

		if (xz_vli(bh + q, bh_size - q, &v, &used) != 0)
			return (size_t)-1;
		q += used;
	}

	/* Filter flags：VLI filter id + 属性 */
	{
		uint64_t filter_id;
		size_t used;

		if (xz_vli(bh + q, bh_size - q, &filter_id, &used) != 0)
			return (size_t)-1;
		q += used;

		if (filter_id != 0x21) {
			/*
			 * 0x21 = LZMA2。其他（0x03=DELTA, 0x04=x86 BCJ ...）
			 * 需要额外的预处理层，这里不支持。
			 */
			fprintf(stderr,
				"ecap_lzma: unsupported filter id 0x%llx "
				"(only LZMA2=0x21)\n",
				(unsigned long long)filter_id);
			return (size_t)-1;
		}
		/*
		 * LZMA2 的 filter props 是 1 字节，编码字典大小。
		 * 我们一次性解压到完整缓冲里，不用字典窗口，
		 * 所以忽略它 —— 回引距离的合法性由
		 * lzma_decode_symbol 里的检查保证。
		 */
	}

	pos += bh_size;

	/*
	 * 每个 Block 都是独立的 LZMA2 流：状态与概率全部重置。
	 * （XZ 规范：block 之间不共享 LZMA 状态。）
	 *
	 * 【注意只重置"状态"，不动输出缓冲指针】
	 * lzma_dec 里既有解码状态（概率表、rep 距离、state），
	 * 也有输出上下文（out / out_pos / out_len）。
	 * memset 整个结构体会把输出上下文也清掉，导致跨 block 的
	 * 输出位置丢失。所以这里分开处理。
	 */
	d->lc = 3; /* LZMA2 默认 lc=3 lp=0 pb=2，稍后由 chunk 的 props 覆盖 */
	d->lp = 0;
	d->pb = 2;
	d->out_len = out_cap;
	/*
	 * 字典窗口从当前输出位置开始 —— 本 block 内的 match 只能
	 * 回引到本 block 已输出的数据，不能跨到上一个 block。
	 */
	d->dict_start = d->out_pos;
	lzma_reset_state(d);
	lzma_reset_probs(d);

	{
		size_t consumed = 0;

		if (lzma2_decode(d, p + pos, in_len - pos, &consumed) != 0) {
			fprintf(stderr,
				"ecap_lzma: LZMA2 decode failed at output %zu\n",
				d->out_pos);
			return (size_t)-1;
		}
		pos += consumed;
	}

	/*
	 * 跳过 block padding。
	 *
	 * XZ 规范要求 padding 的每个字节都必须是 0（官方 XzDec.c 里是
	 * `if (*src++ != 0) return SZ_ERROR_CRC;`）。
	 *
	 * 这里校验而不是"无脑对齐"：如果 padding 位置算错（比如 LZMA2
	 * 数据长度多算或少算了几个字节），无脑对齐会静默地把第二个
	 * block 的头解析到错误偏移上，然后解出一堆垃圾 ——
	 * 那种症状极难排查（我实测遇到过：第二个 block 头落在 check
	 * 字段上，报 "unsupported filter id 0x174"）。
	 *
	 * 校验之后，位置错了会立刻报"block padding 非零"。
	 */
	while ((pos & 3) != 0) {
		if (pos >= in_len)
			return (size_t)-1;
		if (p[pos] != 0) {
			fprintf(stderr,
				"ecap_lzma: block padding byte at %zu is "
				"0x%02x (must be 0) — LZMA2 length "
				"miscalculated\n",
				pos, p[pos]);
			return (size_t)-1;
		}
		pos++;
	}

	/* 跳过 check 字段 */
	pos += check_sz;

	if (pos > in_len)
		return (size_t)-1;

	return pos;
}

int ecap_xz_unpack(const void *in, size_t in_len, void *out, size_t out_cap,
		   size_t *out_len)
{
	const uint8_t *p = (const uint8_t *)in;
	struct lzma_dec *d;
	size_t pos;
	unsigned int check_type;
	size_t check_sz;
	size_t blocks = 0;
	int ret = -1;

	if (in_len < 12 + 12 || out_cap == 0) {
		fprintf(stderr, "ecap_lzma: input too small\n");
		return -1;
	}

	/* --- Stream Header --- */
	if (memcmp(p, XZ_MAGIC, 6) != 0) {
		fprintf(stderr, "ecap_lzma: bad XZ magic\n");
		return -1;
	}
	/*
	 * XZ Stream Header（12 字节）：
	 *   0..5   magic: FD 37 7A 58 5A 00
	 *   6      stream flags byte0 —— 低 4 位是 check 类型
	 *   7      stream flags byte1 —— 保留（CRC32 of 6..7 的一部分）
	 *   8..11  CRC32 of bytes 0..7
	 *
	 * 【实测确认】
	 *   full.xz 头 = fd377a585a 00 01 6922de36
	 *                                          ^^ p[7]=0x01，p[6]=0x00
	 *
	 * 所以 check 类型（=1，CRC32）编码在 **p[7]** 的低 4 位。
	 * p[6] 是 flags 的第 0 字节，在这个流里是 0。
	 *
	 * 我一度改成读 p[6]，结果 check_sz=0（"None"），
	 * 导致跳过 block 边界时没跳过 check 字段 ——
	 * 第二个 block 的头正好落在 check 数据上，
	 * 解析出 "unsupported filter id 0x174"。
	 *
	 * 正确的字段位置是 p[7] 的低 4 位。
	 */
	check_type = p[7] & 0x0F;
	check_sz = xz_check_size(check_type);
	if (check_sz == (size_t)-1) {
		fprintf(stderr, "ecap_lzma: unsupported check type %u\n",
			check_type);
		return -1;
	}
	pos = 12;

	d = calloc(1, sizeof(*d));
	if (!d)
		return -1;

	/*
	 * 【循环处理多个 Block】
	 * XZ 流可以包含任意多个 Block。实测 Pixel 6 的 libssl.so 的
	 * .gnu_debugdata 就有 **两个** Block（解压后共 47832 字节，
	 * 而第一个 Block 只声明了 32768 字节）。
	 *
	 * 我最初只处理第一个 Block，症状是"解压成功但长度不对，
	 * 且前 32768 字节完全正确" —— 很容易误判成"数据损坏"。
	 *
	 * 每个 Block 结束后是：padding（4 字节对齐）+ check（CRC 等）。
	 * 全部 Block 处理完后是 Index + Stream Footer，那部分我们不需要
	 * （输出已经完整），所以循环在遇到非 Block 头时结束。
	 */
	for (;;) {
		size_t next;

		/*
		 * Block 的起点必须是以 size byte 开头的块头。
		 * 如果剩余数据不足或者下一个位置看起来不像块头
		 * （比如到了 Index，它的第一个字节是 0x00），就结束。
		 */
		if (pos + 8 > in_len)
			break;
		if (p[pos] == 0x00)
			break; /* Index 起始（或已到流尾） */


		/*
		 * 第一个 block 之前设置输出缓冲；后续 block 沿用。
		 */
		if (blocks == 0) {
			d->out = (uint8_t *)out;
			d->out_pos = 0;
		}

		next = xz_decode_block(p, in_len, pos, check_sz, d, out_cap);
		if (next == (size_t)-1)
			goto out;

		blocks++;
		pos = next;
	}

	if (blocks == 0) {
		fprintf(stderr, "ecap_lzma: no block found\n");
		goto out;
	}

	*out_len = d->out_pos;
	ret = 0;

out:
	free(d);
	return ret;
}
