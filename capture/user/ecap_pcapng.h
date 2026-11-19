/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_pcapng.h - pcapng 输出（EPB + DSB）
 */
#ifndef _ECAP_PCAPNG_H_
#define _ECAP_PCAPNG_H_

#include <stdbool.h>
#include <stdint.h>

/* 抓包链路类型。DST_RAW = 原始 IP 包（没有以太网头） */
#define ECAP_LINKTYPE_RAW 101

struct ecap_pcapng;

/*
 * 创建 pcapng 文件。
 *
 * @path        : 输出文件路径
 * @linktype    : 链路类型（见上）
 * @snaplen     : 单帧最大长度
 *
 * 返回 NULL 表示失败（已打印原因）。
 *
 * 创建时立即写入 SHB（Section Header Block）+ IDB（Interface Description
 * Block），所以即使后面什么都不写，文件也是合法的 pcapng。
 */
struct ecap_pcapng *ecap_pcapng_open(const char *path, uint32_t linktype,
				     uint32_t snaplen);

/* 关闭并 flush */
void ecap_pcapng_close(struct ecap_pcapng *p);

/*
 * 写一个增强包块（EPB，Enhanced Packet Block）。
 *
 * @ts_ns       : 单调时钟纳秒（内核 ktime_get_mono_fast_ns 的值）
 * @if_id       : 接口编号，我们只有一个接口，固定 0
 * @data/@len   : 帧数据
 *
 * 返回 0 成功。
 */
int ecap_pcapng_write_epb(struct ecap_pcapng *p, uint64_t ts_ns,
			  uint32_t if_id, const void *data, uint32_t caplen,
			  uint32_t origlen);

/*
 * 写一个解密密钥块（DSB，Decryption Secrets Block）。
 *
 * @secrets_type : 例如 ECAP_DSB_TLS_KEY_LOG
 * @data/@len    : 密钥数据（SSLKEYLOG 格式的文本）
 *
 * 返回 0 成功。
 *
 * 【为什么需要这个块】
 * Wireshark 拿到 pcapng 后，会自己读 DSB 里的密钥，
 * 用 client_random 把密钥匹配到对应连接，然后解密 payload。
 * 这样用户不需要手工在 Wireshark 里配 SSLKEYLOGFILE —— 一个文件搞定。
 */
int ecap_pcapng_write_dsb(struct ecap_pcapng *p, uint32_t secrets_type,
			  const void *data, uint32_t len);

/*
 * DSB secrets type：TLS Key Log。
 *
 * 【这个数值是怎么定的 —— 有个容易搞反的地方】
 * pcapng 里所有多字节字段都是小端序。而规范给这些"类型"用的是
 * **ASCII 4 字符**，写进文件时按小端存放 —— 也就是说文件里的字节
 * 顺序应该正好是 'T','L','S','K'（0x54 0x4C 0x53 0x4B）。
 *
 * 要让 put_u32(0x????????) 在文件里写出 54 4C 53 4B，
 * 那个 u32 的值必须是 0x4B534C54（第 1 个字节是最低位）。
 *
 * 我最初写的是 0x544C534B，结果文件里是 4B 53 4C 54 = "KSLT" ——
 * 反了。用 Python 解出来才发现的（`struct.pack('<I', 0x544C534B)` → b'KSLT'）。
 *
 * Wireshark 对 secrets type 是**不分大小写地按数值比较**的，
 * 所以写反了不会报错，只会表现为"DSB 块存在但密钥没被用上"，
 * 极难排查。这里显式写成 0x4B534C54 并注明。
 */
#define ECAP_DSB_TLS_KEY_LOG 0x4B534C54u /* 文件里是 "TLSK" */

/* 统计 */
uint64_t ecap_pcapng_blocks_written(struct ecap_pcapng *p);
uint64_t ecap_pcapng_bytes_written(struct ecap_pcapng *p);

#endif /* _ECAP_PCAPNG_H_ */
