// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_xz.c - 解压 .gnu_debugdata（XZ 压缩的 mini debug info）
 *
 * 【为什么需要它】
 * Android 系统 libssl.so 是 strip 过的，SSL_write / SSL_read 这类导出符号
 * 还在 .dynsym 里，但 bssl::ssl_log_secret 是**内部函数**（C++ mangled name
 * _ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE），只存在于
 * .gnu_debugdata 节里。
 *
 * 那个节的内容是 XZ 压缩的"迷你符号表"ELF：
 *   .gnu_debugdata  = LZMA/XZ 压缩的  <一个只有符号表的 ELF>
 *
 * 实测 Pixel 6 的 conscrypt libssl.so：
 *   .gnu_debugdata 节 0x2638 字节 → 解压后 47832 字节
 *   里面有 _ZN4bssl14ssl_log_secret... @ 0x3ecd0
 *
 * 【两条解压路径 —— 这是本文件最重要的设计】
 *
 * 路径 A（首选）：运行时 dlopen 上游 liblzma，用 lzma_stream_decoder
 *   在宿主机和部分设备上可用。速度快、久经验证。
 *
 * 路径 B（兜底）：自带的 ecap_xz_unpack（见 ecap_lzma.c）
 *   **Android 设备上必须走这条**。原因：
 *     /system/lib64/liblzma.so 是 AOSP 版本，导出的是 LZMA SDK 的
 *     内部名字（LzmaDec_*、XzUnpacker_*、AesCbc_Decode ...），
 *     **没有** 上游 liblzma 的 lzma_code / lzma_stream_decoder。
 *
 *     实测确认（Pixel 6 / Android 13）：
 *       $ nm -D /system/lib64/liblzma.so | grep lzma_code
 *       （无输出）
 *       $ nm -D /system/lib64/liblzma.so | grep -c LzmaDec_
 *       16
 *
 *   所以只看"liblzma.so 存在"是不够的，必须验证符号是否真能解析。
 *
 * 这样设计的好处：主机上跑得快、设备上也能跑，且不引入第三方依赖。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>

#include "ecap_xz.h"
#include "ecap_lzma.h"

/*
 * liblzma 的 ABI。
 *
 * 只声明我们用到的两个函数，避免依赖 lzma.h（NDK 里没有）。
 *
 * lzma_stream 是一个很大的结构体（约 136 字节），但我们只需要把它的
 * 地址传进去 —— liblzma 会自己填。为了避免布局不匹配，这里用一个
 * 足够大的字节数组来占位，并保证对齐。
 */
#define LZMA_STREAM_SIZE 256

union lzma_stream_wrap {
	unsigned char raw[LZMA_STREAM_SIZE];
	unsigned long align;
};

/* lzma_ret 与 lzma_action 的取值（来自 lzma/base.h） */
#define LZMA_OK             0
#define LZMA_STREAM_END     1
#define LZMA_BUF_ERROR      10
#define LZMA_FINISH         3

typedef int (*fn_lzma_stream_decoder)(void *strm, unsigned long long memlimit,
				      unsigned int flags);
typedef int (*fn_lzma_code)(void *strm, int action);

static struct {
	void *handle;
	fn_lzma_stream_decoder stream_decoder;
	fn_lzma_code code;
} g_lzma;

static const char *const lzma_paths[] = {
	"liblzma.so",               /* 让 linker 走系统搜索路径 */
	"/system/lib64/liblzma.so", /* Android 设备上的绝对路径 */
	NULL,
};

int ecap_xz_init(void)
{
	const char *const *p;

	if (g_lzma.handle)
		return 0;

	for (p = lzma_paths; *p; p++) {
		g_lzma.handle = dlopen(*p, RTLD_NOW | RTLD_LOCAL);
		if (g_lzma.handle)
			break;
	}

	if (!g_lzma.handle) {
		/*
		 * 这不是错误。设备上的 liblzma.so 是 AOSP 版本，
		 * 根本不含上游 API。我们会退回自带实现。
		 */
		return -1;
	}

	g_lzma.stream_decoder = (fn_lzma_stream_decoder)dlsym(
		g_lzma.handle, "lzma_stream_decoder");
	g_lzma.code = (fn_lzma_code)dlsym(g_lzma.handle, "lzma_code");

	if (!g_lzma.stream_decoder || !g_lzma.code) {
		/*
		 * 找到了 liblzma.so 但没有上游 API —— 正是 Android 的情况。
		 * 关掉句柄，让 ecap_xz_decompress 走自带实现。
		 */
		dlclose(g_lzma.handle);
		memset(&g_lzma, 0, sizeof(g_lzma));
		return -1;
	}

	return 0;
}

void ecap_xz_exit(void)
{
	if (g_lzma.handle) {
		dlclose(g_lzma.handle);
		memset(&g_lzma, 0, sizeof(g_lzma));
	}
}

/*
 * 是否可以解压。
 *
 * 永远返回 true —— 因为自带实现不依赖任何外部库。
 * 这个语义与 M2 时代的"liblzma 可用吗"不同，注释里说明一下，
 * 免得将来看到这个函数困惑。
 */
bool ecap_xz_available(void)
{
	return true;
}

/* 用上游 liblzma 解压。成功返回 0。 */
static int xz_via_liblzma(const void *in, size_t in_len, void *out,
			  size_t out_cap, size_t *out_len)
{
	union lzma_stream_wrap strm;
	struct lzma_stream_prefix {
		const unsigned char *next_in;
		size_t avail_in;
		unsigned long long total_in;
		unsigned char *next_out;
		size_t avail_out;
		unsigned long long total_out;
	} *s = (struct lzma_stream_prefix *)strm.raw;
	int ret;

	if (!g_lzma.handle)
		return -1;

	memset(strm.raw, 0, sizeof(strm.raw));

	ret = g_lzma.stream_decoder(strm.raw, ~0ULL, 0);
	if (ret != LZMA_OK)
		return -1;

	s->next_in = (const unsigned char *)in;
	s->avail_in = in_len;
	s->next_out = (unsigned char *)out;
	s->avail_out = out_cap;

	ret = g_lzma.code(strm.raw, LZMA_FINISH);
	if (ret != LZMA_STREAM_END)
		return -1;

	*out_len = (size_t)s->total_out;
	return 0;
}

int ecap_xz_decompress(const void *in, size_t in_len, void *out,
		       size_t out_cap, size_t *out_len)
{
	if (!in || !out || in_len == 0 || out_cap == 0)
		return -EINVAL;

	/*
	 * 先试上游 liblzma（如果可用），失败则用自带实现。
	 *
	 * 顺序是刻意的：liblzma 经过大量验证，能覆盖各种边界情况；
	 * 自带实现范围较窄（只支持单 block + LZMA2），但足以处理
	 * .gnu_debugdata。
	 */
	if (g_lzma.handle) {
		if (xz_via_liblzma(in, in_len, out, out_cap, out_len) == 0)
			return 0;
		/* 不打印错误：可能是这个流有 liblzma 也搞不定的特性，
		 * 先让自带实现试一次，两个都失败才算失败。 */
	}

	if (ecap_xz_unpack(in, in_len, out, out_cap, out_len) == 0)
		return 0;

	return -EIO;
}
