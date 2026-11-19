// SPDX-License-Identifier: GPL-2.0
/*
 * test_lzma.c - 自实现 XZ 解压器的单元测试
 *
 * 【怎么用】
 * 这个测试不内嵌压缩数据，而是接受外部生成的 .xz 文件：
 *
 *   python3 -c "import lzma; open('/tmp/t.xz','wb').write(lzma.compress(b'A'*100))"
 *   ./test_lzma /tmp/t.xz
 *
 * 程序会解压并把结果写到 stdout 的校验摘要里，用 python 的 lzma
 * 模块作为参照比对。
 *
 * 【更实用的用法：一键跑全部用例】
 *   make test-lzma
 *
 * 该目标会生成一组覆盖不同路径的 xz 文件（未压缩 chunk、纯 literal、
 * 重复数据、多 chunk、多 block），逐个解压并逐字节比对。
 *
 * 【为什么不用内嵌数据】
 * 内嵌 xz 字节流会让测试文件变得不可读、也无法人工检查。
 * 现生成 + 现比对，既保证覆盖，又保持源码干净。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ecap_lzma.h"

#define MAX_IN (16u << 20)
#define MAX_OUT (32u << 20)

static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *f;
	long n;
	uint8_t *buf;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "test_lzma: cannot open %s\n", path);
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	n = ftell(f);
	if (n <= 0 || (unsigned long)n > MAX_IN) {
		fclose(f);
		return NULL;
	}
	rewind(f);

	buf = malloc((size_t)n);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);

	*out_len = (size_t)n;
	return buf;
}

int main(int argc, char **argv)
{
	uint8_t *in, *out;
	size_t in_len = 0, out_len = 0;
	int r;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <file.xz>\n", argv[0]);
		return 2;
	}

	in = read_file(argv[1], &in_len);
	if (!in) {
		fprintf(stderr, "test_lzma: failed to read input\n");
		return 2;
	}

	out = malloc(MAX_OUT);
	if (!out) {
		free(in);
		return 2;
	}

	r = ecap_xz_unpack(in, in_len, out, MAX_OUT, &out_len);
	if (r != 0) {
		fprintf(stderr, "test_lzma: %s -> FAIL\n", argv[1]);
		free(in);
		free(out);
		return 1;
	}

	/*
	 * 把解压结果写到 stdout，由调用方（make test-lzma 的 python 部分）
	 * 与 lzma.decompress() 的输出做逐字节比对。
	 */
	if (fwrite(out, 1, out_len, stdout) != out_len) {
		free(in);
		free(out);
		return 2;
	}

	free(in);
	free(out);
	return 0;
}
