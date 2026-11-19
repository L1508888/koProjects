/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_elf.h - ELF 符号查找（支持 .dynsym 与 .gnu_debugdata）
 */
#ifndef _ECAP_ELF_H_
#define _ECAP_ELF_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * 在目标 .so 里查找符号的文件偏移。
 *
 * 查找顺序：
 *   1. .dynsym         —— 动态符号表（导出符号，如 SSL_write）
 *   2. .gnu_debugdata  —— XZ 压缩的 mini debug info（内部符号，
 *                         如 bssl::ssl_log_secret）
 *
 * @path        : 目标 .so 路径
 * @symname     : 要查的符号名（C 名字或 C++ mangled 名字）
 * @out_offset  : 成功时回填文件字节偏移
 * @out_found   : 成功时回填实际匹配到的符号名
 * @found_len   : out_found 的容量
 * @out_from    : 成功时回填 "dynsym" 或 "debugdata"，说明符号从哪来
 *
 * 返回 0 成功，-1 失败（已打印原因）。
 */
int ecap_elf_find_symbol(const char *path, const char *symname,
			 uint64_t *out_offset, char *out_found,
			 size_t found_len, const char **out_from);

/* 判断文件是否 aarch64 ELF */
bool ecap_elf_is_aarch64(const char *path);

#endif /* _ECAP_ELF_H_ */
