/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_xz.h - .gnu_debugdata 的 XZ 解压（运行时 dlopen liblzma）
 */
#ifndef _ECAP_XZ_H_
#define _ECAP_XZ_H_

#include <stddef.h>
#include <stdbool.h>

/* 加载 liblzma。返回 0 成功，-1 不可用（后续调用会返回 -ENOSYS）。 */
int ecap_xz_init(void);

/* 释放句柄 */
void ecap_xz_exit(void);

/* 是否可用 */
bool ecap_xz_available(void);

/*
 * 解压 XZ 数据。
 *
 * 返回 0 成功并回填 *out_len；负值为错误码（-ENOSYS 表示 liblzma 不可用）。
 * 输出缓冲不够时返回 -EIO 并在 stderr 打印需要的尺寸。
 */
int ecap_xz_decompress(const void *in, size_t in_len, void *out,
		       size_t out_cap, size_t *out_len);

#endif /* _ECAP_XZ_H_ */
