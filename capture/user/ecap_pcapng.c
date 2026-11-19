// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_pcapng.c - pcapng 文件输出
 *
 * 【pcapng 是什么】
 * pcap 的下一代格式（PCAP Next Generation）。相比经典 pcap，它支持：
 *   - 多个接口（一个文件里混合多种链路类型）
 *   - 纳秒级时间戳精度
 *   - 任意元数据块（注释、统计、解密密钥）
 *
 * 我们要用的块类型只有三种：
 *
 *   SHB  Section Header Block     —— 文件头，必须有且只有开头一个
 *   IDB  Interface Description    —— 描述"抓包接口"（链路类型、快照长度）
 *   EPB  Enhanced Packet          —— 一个包
 *   DSB  Decryption Secrets Block —— TLS 密钥（让 Wireshark 自动解密）
 *
 * 【所有块的结构都一样】
 *
 *   +----------------+  4 字节：块类型（Block Type）
 *   +----------------+  4 字节：块总长度（Block Total Length）
 *   |  块体（Body）  |
 *   +----------------+  4 字节：块总长度（重复一遍，用于反向遍历）
 *
 * 所有多字节字段都是**小端序**。块体长度必须按 4 字节对齐（用填充补齐）。
 *
 * 【为什么总长度要写两遍】
 * pcapng 设计时考虑了两个方向遍历：从文件头往后读（用第一份），
 * 或从文件尾往前读（用最后一份）。最后一份必须等于第一份，
 * 否则 Wireshark 会报 "corrupted file"。
 *
 * 【时间戳精度】
 * IDB 里有一个 if_tsresol 选项，默认值是 6，表示时间戳单位是 10^-6 秒
 * （微秒）。我们内核给的是纳秒（10^-9），所以显式把 if_tsresol 设成 9。
 * 这样 EPB 里可以直接放纳秒值，不用做换算 —— 少一次精度损失。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "ecap_pcapng.h"

/* 块类型常量（pcapng 规范） */
#define BT_SHB 0x0A0D0D0Au
#define BT_IDB 0x00000001u
#define BT_EPB 0x00000006u
#define BT_DSB 0x0000000Au

/* 字节序标记（SHB 里的 magic，固定值 0x1A2B3C4D） */
#define SHB_MAGIC 0x1A2B3C4Du
/* 版本 1.0 */
#define PCAPNG_VERSION_MAJOR 1u
#define PCAPNG_VERSION_MINOR 0u
/* section 长度未知 */
#define SECTION_LEN_UNKNOWN 0xFFFFFFFFFFFFFFFFull

/* 选项码 */
#define OPT_ENDOFOPT 0u
#define OPT_COMMENT  1u
/* IDB 专有选项 */
#define IDB_OPT_IF_NAME    2u
#define IDB_OPT_IF_TSRESOL 9u
/* EPB 专有选项 */
#define EPB_OPT_EPB_FLAGS  2u
/* DSB 专有选项 */
#define DSB_OPT_SECRETS_TYPE 1u

struct ecap_pcapng {
	FILE *fp;
	uint32_t linktype;
	uint32_t snaplen;
	uint64_t blocks;
	uint64_t bytes;
	int err;
};

/* ------------------------------------------------------------------ */
/* 小端序写入                                                          */
/* ------------------------------------------------------------------ */

/*
 * 直接把小端序字节写进一块内存，再一次性 fwrite。
 *
 * 【为什么不用 fwrite 逐字段写】
 * pcapng 的块需要一个"总长度"写在开头，而这个长度取决于块体内容。
 * 如果逐字段写，就得先算长度再回头改 —— 需要 ftell/fseek。
 * 先拼到内存里，算好长度再一次写出，逻辑简单得多，也不会有
 * 文件位置错乱的风险。
 */

static void put_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void put_u64(uint8_t *p, uint64_t v)
{
	put_u32(p, (uint32_t)(v & 0xffffffffu));
	put_u32(p + 4, (uint32_t)(v >> 32));
}

/* 4 字节对齐：返回补齐到 4 的倍数后的长度 */
static uint32_t pad4(uint32_t n)
{
	return (n + 3u) & ~3u;
}

/* ------------------------------------------------------------------ */
/* 块写入                                                              */
/* ------------------------------------------------------------------ */

/*
 * 写一个"类型 + 体"的块。
 *
 * @bt   : 块类型
 * @body : 块体（不含长度字段）
 * @blen : 块体长度（会被补齐到 4 字节）
 *
 * 内部负责：补齐、写两份总长度。
 */
static int write_block(struct ecap_pcapng *p, uint32_t bt, const void *body,
		       uint32_t blen)
{
	uint8_t hdr[8];
	uint8_t tail[4];
	static const uint8_t zeros[4] = { 0, 0, 0, 0 };
	uint32_t padded = pad4(blen);
	uint32_t total = 8u + padded + 4u;
	uint32_t padbytes = padded - blen;

	if (p->err)
		return -1;

	put_u32(hdr, bt);
	put_u32(hdr + 4, total);
	put_u32(tail, total);

	if (fwrite(hdr, 1, sizeof(hdr), p->fp) != sizeof(hdr))
		goto ioerr;
	if (blen && fwrite(body, 1, blen, p->fp) != blen)
		goto ioerr;
	if (padbytes && fwrite(zeros, 1, padbytes, p->fp) != padbytes)
		goto ioerr;
	if (fwrite(tail, 1, sizeof(tail), p->fp) != sizeof(tail))
		goto ioerr;

	p->blocks++;
	p->bytes += total;
	return 0;

ioerr:
	p->err = errno ? errno : EIO;
	return -1;
}

/*
 * 写选项列表。
 *
 * 每个选项：code(u16) len(u16) value[len] padding
 * 列表以 code=0, len=0 结束。
 *
 * 返回写入的字节数（不含结尾的 endofopt，由调用方决定是否需要）。
 * 为了简单，这里调用方自己在 body 里预留空间并给出指针。
 */
static uint32_t put_option(uint8_t *buf, uint16_t code, uint16_t len,
			   const void *val)
{
	uint32_t padded = pad4(len);

	put_u16(buf, code);
	put_u16(buf + 2, len);
	if (len && val)
		memcpy(buf + 4, val, len);
	if (padded > len)
		memset(buf + 4 + len, 0, padded - len);

	return 4u + padded;
}

/* ------------------------------------------------------------------ */
/* SHB / IDB                                                           */
/* ------------------------------------------------------------------ */

static int write_shb(struct ecap_pcapng *p)
{
	/*
	 * SHB 块体：
	 *   0  u32 byte-order magic (0x1A2B3C4D)
	 *   4  u16 major version
	 *   6  u16 minor version
	 *   8  i64 section length (-1 = 未知)
	 *  16  options...
	 */
	uint8_t body[16 + 4 + 64];
	static const char comment[] = "ecap_tls LKM TLS capture";
	uint32_t off = 0;
	uint32_t n;

	put_u32(body + 0, SHB_MAGIC);
	put_u16(body + 4, PCAPNG_VERSION_MAJOR);
	put_u16(body + 6, PCAPNG_VERSION_MINOR);
	put_u64(body + 8, SECTION_LEN_UNKNOWN);
	off = 16;

	/*
	 * 【坑】长度必须用 strlen，不能手数。
	 * 一开始我写了 30（数错），结果 put_option 里的 memcpy 会越界
	 * 读 5 个字节 —— 编译器的 -Wstringop-overflow 抓到了这个问题。
	 * 这类"字符串字面量 + 手写长度"的组合是经典错误来源，
	 * 一律改成 strlen(x) 或 sizeof(x)-1。
	 */
	n = put_option(body + off, OPT_COMMENT,
		       (uint16_t)(sizeof(comment) - 1), comment);
	off += n;
	/* endofopt */
	put_u16(body + off, OPT_ENDOFOPT);
	put_u16(body + off + 2, 0);
	off += 4;

	return write_block(p, BT_SHB, body, off);
}

static int write_idb(struct ecap_pcapng *p)
{
	/*
	 * IDB 块体：
	 *   0  u16 linktype
	 *   2  u16 reserved
	 *   4  u32 snaplen
	 *   8  options...
	 */
	uint8_t body[8 + 4 + 64];
	uint32_t off = 0;
	uint32_t n;
	uint8_t tsresol = 9; /* 纳秒 */
	const char *name = "ecap_tls";

	put_u16(body + 0, (uint16_t)p->linktype);
	put_u16(body + 2, 0);
	put_u32(body + 4, p->snaplen);
	off = 8;

	/* 接口名，纯粹为了在 Wireshark 里好看 */
	n = put_option(body + off, IDB_OPT_IF_NAME, (uint16_t)strlen(name),
		       name);
	off += n;

	/*
	 * if_tsresol = 9：时间戳单位是 10^-9 秒。
	 * 默认是 6（微秒），我们必须显式声明成纳秒，
	 * 否则内核给的纳秒值会被当成微秒解释，时间戳差 1000 倍。
	 */
	n = put_option(body + off, IDB_OPT_IF_TSRESOL, 1, &tsresol);
	off += n;

	put_u16(body + off, OPT_ENDOFOPT);
	put_u16(body + off + 2, 0);
	off += 4;

	return write_block(p, BT_IDB, body, off);
}

/* ------------------------------------------------------------------ */
/* 公开接口                                                            */
/* ------------------------------------------------------------------ */

struct ecap_pcapng *ecap_pcapng_open(const char *path, uint32_t linktype,
				     uint32_t snaplen)
{
	struct ecap_pcapng *p;

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;

	p->fp = fopen(path, "wb");
	if (!p->fp) {
		fprintf(stderr, "ecapctl: cannot create %s: %s\n", path,
			strerror(errno));
		free(p);
		return NULL;
	}

	/*
	 * 用全缓冲（默认 4KB 太小）。抓包会写大量小 EPB，
	 * 大缓冲能显著减少 write 系统调用次数。
	 */
	setvbuf(p->fp, NULL, _IOFBF, 1 << 20);

	p->linktype = linktype;
	p->snaplen = snaplen;

	/* SHB 与 IDB 必须最先写，顺序不能反 */
	if (write_shb(p) != 0 || write_idb(p) != 0) {
		fclose(p->fp);
		free(p);
		return NULL;
	}

	/*
	 * 立刻落盘。
	 * 这样即使进程马上被杀，文件也是一个合法的（空的）pcapng，
	 * 而不是 0 字节的垃圾 —— Wireshark 打开后者会报错。
	 */
	fflush(p->fp);

	return p;
}

void ecap_pcapng_close(struct ecap_pcapng *p)
{
	if (!p)
		return;
	if (p->fp) {
		fflush(p->fp);
		fclose(p->fp);
	}
	free(p);
}

int ecap_pcapng_write_epb(struct ecap_pcapng *p, uint64_t ts_ns,
			  uint32_t if_id, const void *data, uint32_t len,
			  uint32_t origlen)
{
	/*
	 * EPB 块体：
	 *   0   u32 interface id
	 *   4   u32 timestamp high   （时间戳高 32 位，单位由 if_tsresol 决定）
	 *   8   u32 timestamp low
	 *  12   u32 captured length
	 *  16   u32 original length
	 *  20   帧数据（补齐到 4 字节）
	 *       options...
	 */
	uint8_t *body;
	uint32_t padded_len = pad4(len);
	uint32_t blen = 20u + padded_len;
	int ret;

	body = calloc(1, blen);
	if (!body)
		return -1;

	put_u32(body + 0, if_id);
	put_u32(body + 4, (uint32_t)(ts_ns >> 32));
	put_u32(body + 8, (uint32_t)(ts_ns & 0xffffffffu));
	put_u32(body + 12, len);
	put_u32(body + 16, origlen >= len ? origlen : len);
	if (len)
		memcpy(body + 20, data, len);

	ret = write_block(p, BT_EPB, body, blen);
	free(body);

	/*
	 * 每写一个包就 flush。
	 *
	 * 【为什么不依赖缓冲区自动 flush】
	 * 抓包进程通常是被 kill / 断电结束的，不会走到 ecap_pcapng_close。
	 * 1MB 的用户态缓冲意味着**已经抓到的包会全部丢掉** ——
	 * 实测就是这个问题：统计显示 pkt_pushed=30，但 pcapng 文件是 0 字节。
	 *
	 * 代价是每包一次 write 系统调用。对抓包工具来说这个开销
	 * 完全可以接受（相对于 copy_from_user + 入队的成本）。
	 */
	if (!p->err)
		fflush(p->fp);

	return ret;
}

int ecap_pcapng_write_dsb(struct ecap_pcapng *p, uint32_t secrets_type,
			  const void *data, uint32_t len)
{
	/*
	 * DSB 块体：
	 *   0  u32 secrets type
	 *   4  u32 secrets length
	 *   8  secrets data（补齐到 4 字节）
	 *
	 * 【secrets type 的作用】
	 * 它告诉 Wireshark "这段数据怎么解释"。
	 * 0x544C534B ("TLSK") = TLS Key Log，内容是 SSLKEYLOG 文本格式：
	 *
	 *     CLIENT_RANDOM <32字节hex> <48字节hex>
	 *     或 TLS 1.3 的：
	 *     CLIENT_TRAFFIC_SECRET_0 <32字节hex> <32字节hex>
	 *     SERVER_TRAFFIC_SECRET_0 <32字节hex> <32字节hex>
	 *
	 * 每行一条，行尾 \n。
	 */
	uint8_t *body;
	uint32_t padded_len = pad4(len);
	uint32_t blen = 8u + padded_len;
	int ret;

	body = calloc(1, blen);
	if (!body)
		return -1;

	put_u32(body + 0, secrets_type);
	put_u32(body + 4, len);
	if (len)
		memcpy(body + 8, data, len);

	ret = write_block(p, BT_DSB, body, blen);
	free(body);

	/* 同 EPB：立刻落盘，防止进程被 kill 时丢失密钥块。
	 * 密钥只写一次，开销可忽略。 */
	if (!p->err)
		fflush(p->fp);

	return ret;
}

uint64_t ecap_pcapng_blocks_written(struct ecap_pcapng *p)
{
	return p ? p->blocks : 0;
}

uint64_t ecap_pcapng_bytes_written(struct ecap_pcapng *p)
{
	return p ? p->bytes : 0;
}
