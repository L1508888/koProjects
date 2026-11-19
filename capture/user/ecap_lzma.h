/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_lzma.h - 自包含的 XZ / LZMA2 解压器
 */
#ifndef _ECAP_LZMA_H_
#define _ECAP_LZMA_H_

#include <stddef.h>

/*
 * 解压一个 XZ 流。
 *
 * @in/@in_len : 压缩数据（完整的 .xz 流）
 * @out        : 输出缓冲（调用方分配）
 * @out_cap    : 输出缓冲容量
 * @out_len    : 实际解压出的字节数
 *
 * 返回 0 成功，-1 失败（原因已打印到 stderr）。
 *
 * 只支持单 block、单 filter（LZMA2）的流 —— .gnu_debugdata 都是这种。
 * 不支持 BCJ/DELTA 预处理 filter。
 */
int ecap_xz_unpack(const void *in, size_t in_len, void *out, size_t out_cap,
		   size_t *out_len);

#endif /* _ECAP_LZMA_H_ */
