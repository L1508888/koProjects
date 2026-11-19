// SPDX-License-Identifier: GPL-2.0
/*
 * ecapctl.c - ecap_tls.ko 的用户态控制端（M2 阶段）
 *
 * 【它做三件事】
 *   1. version  握手：确认 .ko 与 ecapctl 是同一次编译产物
 *   2. ping     验证 /dev/ecap_tls 的 poll/read/事件编解码链路
 *   3. capture  解析目标 .so 的 ELF，拿到 SSL_write 的文件偏移，
 *               通过 ioctl 下发给内核，然后循环 read 打印明文
 *
 * 【为什么偏移解析放在用户态】
 * 内核里解析 ELF 需要读文件、解压 XZ（.gnu_debugdata）、处理 reloc/动态符号，
 * 代码量大、容易出错，而且一旦出错就是内核 panic。
 * 用户态有完整工具链，解析失败只是返回个错误码，安全性完全不同。
 * 内核只接受一个"文件字节偏移"，职责极简。
 *
 * 【编译】
 *   NDK:  aarch64-linux-android29-clang -O2 -Iinclude -o ecapctl ecapctl.c
 *   本机: cc -O2 -Iinclude -o ecapctl_host ecapctl.c
 *
 * 【用法】
 *   ecapctl version
 *   ecapctl ping -n 16
 *   ecapctl capture --lib /apex/com.android.conscrypt/lib64/libssl.so
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <elf.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ecap_uapi.h"
#include "ecap_elf.h"
#include "ecap_xz.h"
#include "ecap_pcapng.h"

#define DEV_PATH "/dev/ecap_tls"

/*
 * bssl::ssl_log_secret 的 C++ mangled 名字。
 *
 * 【这个名字是怎么得到的】
 * 不是猜的 —— 从解压后的 .gnu_debugdata 里用 nm 查出来的：
 *
 *     $ python3 -c "解压 .gnu_debugdata" ; nm /tmp/mini_debuginfo.so | grep secret
 *     T _ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE
 *
 * 逐段拆解：
 *     _Z   N4bssl14ssl_log_secretE  PK6ssl_st  PKc  NS_4SpanIKhEE
 *     │    │  └ bssl::ssl_log_secret  │          │    └ bssl::Span<unsigned char const>
 *     │    └ 命名空间定界            │          └ char const*
 *     └ mangled 前缀                 └ ssl_st const*
 *
 * 【为什么硬编码而不是运行时构造】
 * mangled 名字的具体形式由 Itanium ABI 决定，理论上稳定；但不同
 * 编译器/版本可能生成带不同 cv 修饰的形式。硬编码至少能让"找不到"
 * 立刻暴露（而不是静默地挂错位置）。如果换设备后 keylog 解析失败，
 * 第一件事就是重新用 nm 确认这个名字。
 *
 * 实测环境（Pixel 6 / Android 13 / conscrypt）：存在且 st_value = 0x3ecd0
 */
#define ECAP_KEYLOG_SYMBOL \
	"_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE"

/* ==================================================================== */
/* 小工具                                                               */
/* ==================================================================== */

static void die(const char *msg)
{
	fprintf(stderr, "ecapctl: %s: %s\n", msg, strerror(errno));
	exit(1);
}

static void die_msg(const char *msg)
{
	fprintf(stderr, "ecapctl: %s\n", msg);
	exit(1);
}

static int open_dev(void)
{
	int fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		die("cannot open " DEV_PATH " (insmod ecap_tls.ko first?)");
	return fd;
}

/* 事件类型 -> 人类可读名字 */
static const char *ev_type_name(uint32_t t)
{
	switch (t) {
	case ECAP_EV_NONE:
		return "NONE";
	case ECAP_EV_PING:
		return "PING";
	case ECAP_EV_SSL_DATA:
		return "SSL_DATA";
	case ECAP_EV_KEYLOG:
		return "KEYLOG";
	case ECAP_EV_PACKET:
		return "PACKET";
	default:
		return "UNKNOWN";
	}
}

/*
 * 打印 payload。
 *
 * 用两种形式同时输出：
 *   - 文本视图：把可打印 ASCII 原样显示，其他字节显示成 '.'
 *   - 十六进制：前 64 字节，方便核对二进制内容（比如 TLS record 头）
 *
 * 真实的抓包工具会在这里做协议解析（HTTP/2 帧、gRPC 等），
 * M2 阶段先保证数据正确。
 *
 * 注意：这里输出的是**原始明文**，其中可能包含 Authorization、
 * Cookie 等凭据。事件日志应视为敏感数据，不要提交到仓库或贴进
 * 聊天记录。
 */
static void dump_payload(const uint8_t *p, uint32_t len, bool hex)
{
	uint32_t i;

	fprintf(stderr, "  text: ");
	for (i = 0; i < len; i++) {
		unsigned char c = p[i];
		fputc((c >= 0x20 && c < 0x7f) ? c : '.', stderr);
	}
	fputc('\n', stderr);

	if (!hex)
		return;

	fprintf(stderr, "  hex : ");
	for (i = 0; i < len && i < 64; i++)
		fprintf(stderr, "%02x", p[i]);
	if (len > 64)
		fprintf(stderr, "... (%u bytes total)", len);
	fputc('\n', stderr);
}

/* 把 ktime_get_mono_fast_ns() 的纳秒数换算成相对启动的时间 */
static void fmt_ns(uint64_t ts_ns, char *buf, size_t n)
{
	uint64_t sec = ts_ns / 1000000000ull;
	uint64_t ms = (ts_ns % 1000000000ull) / 1000000ull;

	snprintf(buf, n, "%llu.%03llus", (unsigned long long)sec,
		 (unsigned long long)ms);
}

/* ==================================================================== */
/* 子命令：version                                                      */
/* ==================================================================== */

static int cmd_version(void)
{
	int fd = open_dev();
	uint32_t ver = 0;

	if (ioctl(fd, ECAP_IOC_VERSION, &ver) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		die("ECAP_IOC_VERSION failed");
	}
	close(fd);

	printf("kernel ABI version : %u\n", ver);
	printf("userland ABI version: %u\n", (unsigned)ECAP_ABI_VERSION);

	if (ver != ECAP_ABI_VERSION) {
		fprintf(stderr,
			"ecapctl: ABI mismatch! .ko and ecapctl were built from "
			"different sources.\n");
		return 1;
	}
	printf("OK\n");
	return 0;
}

/* ==================================================================== */
/* 子命令：ping                                                         */
/* ==================================================================== */

static int cmd_ping(unsigned int count, unsigned int len, uint32_t pattern)
{
	int fd = open_dev();
	struct ecap_ping p = { .len = len, .pattern = pattern };
	struct ecap_event ev;
	unsigned int i;
	int rc = 0;

	if (len > ECAP_PAYLOAD_MAX)
		die_msg("ping length exceeds payload capacity");

	for (i = 0; i < count; i++) {
		if (ioctl(fd, ECAP_IOC_PING, &p) < 0) {
			/* -ENOSPC 说明队列满了。这不算失败：
			 * 抓包工具的设计就是满则丢弃。 */
			if (errno == ENOSPC) {
				fprintf(stderr, "ping: kernel queue full, "
						"dropping (expected under load)\n");
				continue;
			}
			fprintf(stderr, "ping: ioctl failed at #%u: %s\n",
				i, strerror(errno));
			rc = 1;
			break;
		}
	}

	/* 把队列里的事件全部读出来并校验内容 */
	{
		unsigned int got = 0, bad = 0;

		while (1) {
			ssize_t n;
			struct pollfd pfd = { .fd = fd, .events = POLLIN };

			if (poll(&pfd, 1, 200) <= 0)
				break;

			n = read(fd, &ev, sizeof(ev));
			if (n < 0) {
				if (errno == EAGAIN)
					break;
				fprintf(stderr, "ping: read failed: %s\n",
					strerror(errno));
				rc = 1;
				break;
			}
			if (n == 0)
				break;
			if (n != (ssize_t)sizeof(ev)) {
				fprintf(stderr,
					"ping: short read %zd (expected %zu)\n",
					n, sizeof(ev));
				rc = 1;
				break;
			}

			got++;

			if (ev.hdr.type != ECAP_EV_PING) {
				fprintf(stderr, "ping: unexpected type %u\n",
					ev.hdr.type);
				bad++;
				continue;
			}
			if (ev.hdr.len != len) {
				fprintf(stderr,
					"ping: len mismatch %u != %u\n",
					ev.hdr.len, len);
				bad++;
				continue;
			}
			/* 逐字节校验 pattern：能抓出"内核侧串包/覆盖"类 bug */
			for (i = 0; i < len; i++) {
				if (ev.payload[i] != (uint8_t)(pattern + i)) {
					fprintf(stderr,
						"ping: payload corrupted at %u "
						"(got %02x want %02x)\n",
						i, ev.payload[i],
						(uint8_t)(pattern + i));
					bad++;
					break;
				}
			}
		}

		printf("ping: sent %u, received %u, corrupt %u\n", count, got,
		       bad);
		if (bad)
			rc = 1;
	}

	/* 顺带打一下内核统计，验证计数器也在工作 */
	{
		struct ecap_stats st;

		if (ioctl(fd, ECAP_IOC_GET_STATS, &st) == 0) {
			printf("stats: pushed=%llu dropped=%llu reads=%llu "
			       "queued=%u/%u\n",
			       (unsigned long long)st.pushed,
			       (unsigned long long)st.dropped,
			       (unsigned long long)st.reads, st.queued,
			       st.slots);
		}
	}

	close(fd);
	return rc;
}

/* ==================================================================== */
/* 子命令：stats                                                        */
/* ==================================================================== */

static int cmd_stats(void)
{
	int fd = open_dev();
	struct ecap_stats st;

	if (ioctl(fd, ECAP_IOC_GET_STATS, &st) < 0)
		die("ECAP_IOC_GET_STATS failed");
	close(fd);

	printf("pushed       : %llu\n", (unsigned long long)st.pushed);
	printf("dropped      : %llu\n", (unsigned long long)st.dropped);
	printf("reads        : %llu\n", (unsigned long long)st.reads);
	printf("ioctls       : %llu\n", (unsigned long long)st.ioctls);
	printf("uprobe_hits  : %llu\n", (unsigned long long)st.uprobe_hits);
	printf("copy_fail    : %llu\n", (unsigned long long)st.copy_fail);
	/* M3 */
	printf("filtered     : %llu\n", (unsigned long long)st.filtered);
	printf("read_empty   : %llu\n", (unsigned long long)st.read_hits);
	printf("pending_miss : %llu\n", (unsigned long long)st.pending_miss);
	printf("pending      : %u/%u\n", st.pending, st.pending_max);
	/* M4 */
	printf("keylog_hits  : %llu\n", (unsigned long long)st.keylog_hits);
	printf("keylog_bad   : %llu\n", (unsigned long long)st.keylog_bad);
	printf("pkt_seen     : %llu\n", (unsigned long long)st.pkt_seen);
	printf("pkt_pushed   : %llu\n", (unsigned long long)st.pkt_pushed);
	printf("pkt_skipped  : %llu\n", (unsigned long long)st.pkt_skipped);
	printf("queued       : %u bytes\n", st.queued);
	printf("capacity     : %u bytes\n", st.slots);
	return 0;
}

/* ==================================================================== */
/* ELF 符号查找                                                         */
/* ==================================================================== */

/*
 * 符号解析的实现在 user/ecap_elf.c 里，这里只是一层薄封装。
 *
 * 【为什么要拆出去】
 * M2 时它只有 .dynsym 一条查找路径，混在本文件里还能接受。
 * M4 加了 .gnu_debugdata（XZ 解压 + 二级 ELF 解析）之后，
 * 代码量翻了一倍多，而且和"抓包主流程"完全无关。
 * 拆开后本文件专注在"设备交互 + 事件循环"上。
 *
 * 想了解偏移换算、两级符号查找、mini debug info 的处理，
 * 见 ecap_elf.c 与 ecap_xz.c 的文件头注释。
 */


/*
 * arm64 指令可探测性判断。
 *
 * 【为什么需要精确判断，不能只查"非零"】
 * arm64 的 arch_uprobe_analyze_insn() 会对它不支持的指令返回 -EINVAL，
 * 于是 uprobe_register 直接失败。但内核日志里只会看到
 *
 *     ecap_tls: uprobe_register(SSL_write @0x...) failed: -22
 *
 * 到底是"符号找错了"、"偏移算错了"，还是"这条指令恰好不支持探测"？
 * 光看 -EINVAL 完全分不出来。所以在用户态先把这件事查清楚。
 *
 * 【判断依据】
 * 直接照抄内核 arch/arm64/kernel/probes/decode-insn.c 的 arm_probe_decode_insn()。
 * 它能处理三类指令：
 *   1) 可单步执行（steppable）—— 绝大多数普通指令
 *   2) 可模拟（simulate）—— b/bl/br/blr/ret, b.cond, cbz/cbnz, tbz/tbnz, adr/adrp
 *   3) 其他 -> INSN_REJECTED
 *
 * 实际会被拒的是这几类：
 *   - PC 相对字面量加载：LDR (literal) / LDRSW (literal)
 *   - 独占访问：LDXR/STXR/LDAXR/STLXR 等
 *   - MSR（读写系统寄存器）
 *   - 产生异常：SVC/HVC/SMC/BRK/HLT
 *   - ERET
 *   - 不在白名单的 HINT：DSB/DMB/ISB/YIELD/WFE/SEV/AUTIASP/AUTIAZ ...
 *
 * 【好消息】
 * 函数序言几乎总是能探测的：
 *     bti c          -> 0xd503245f  （白名单里的）
 *     paciasp        -> 0xd503233f  （白名单里的）
 *     stp x29, x30   -> 普通存储指令，steppable
 *     sub sp, sp, #N -> 普通算术指令，steppable
 * 所以正常找到符号入口时，这个检查基本不会误报。
 */

/* HINT 指令的编码掩码与基准值：1101 0101 0000 0011 0010 CRm op2 11111 */
#define A64_HINT_MASK 0xFFFFF01Fu
#define A64_HINT_BASE 0xD503201Fu
/* switch (insn & 0xFE0) 用到的字段掩码 */
#define A64_HINT_FIELD_MASK 0xFE0u

/* 白名单 HINT（与内核 aarch64_insn_is_steppable_hint 完全一致） */
#define A64_HINT_NOP       0x000u
#define A64_HINT_XPACLRI   0x0E0u
#define A64_HINT_PACIA1716 0x100u
#define A64_HINT_PACIB1716 0x140u
#define A64_HINT_PACIAZ    0x300u
#define A64_HINT_PACIASP   0x320u
#define A64_HINT_PACIBZ    0x340u
#define A64_HINT_PACIBSP   0x360u
#define A64_HINT_BTI       0x400u
#define A64_HINT_BTIC      0x440u
#define A64_HINT_BTIJ      0x480u
#define A64_HINT_BTIJC     0x4C0u

static bool a64_is_hint(uint32_t insn)
{
	return (insn & A64_HINT_MASK) == A64_HINT_BASE;
}

static bool a64_hint_steppable(uint32_t insn)
{
	switch (insn & A64_HINT_FIELD_MASK) {
	case A64_HINT_NOP:
	case A64_HINT_XPACLRI:
	case A64_HINT_PACIA1716:
	case A64_HINT_PACIB1716:
	case A64_HINT_PACIAZ:
	case A64_HINT_PACIASP:
	case A64_HINT_PACIBZ:
	case A64_HINT_PACIBSP:
	case A64_HINT_BTI:
	case A64_HINT_BTIC:
	case A64_HINT_BTIJ:
	case A64_HINT_BTIJC:
		return true;
	default:
		return false;
	}
}

/*
 * 返回 0 表示"这条指令大概率能被 uprobe 探测"，非 0 表示已知不能。
 *
 * 这个函数刻意"宁松勿严"：只有当能明确判定为内核会拒绝时才报错。
 * 因为误报（把能探测的判成不能）会让用户白白放弃一个可用的抓包点，
 * 而漏报（把不能探测的放过去）最多只是 register 失败，行为退化到
 * "没有这个检查"的水平 —— 后者代价更小。
 */
static int a64_check_probeable(uint32_t insn, const char **why)
{
	uint32_t op24 = (insn >> 24) & 0x3Fu;

	/*
	 * HINT 类（含 NOP/BTI/PAC*）：只有白名单里的能单步执行。
	 * 像 AUTIASP / DSB / DMB / ISB / YIELD / WFE / SEV 都会被拒。
	 */
	if (a64_is_hint(insn)) {
		if (a64_hint_steppable(insn))
			return 0;
		*why = "unsupported HINT instruction (AUTIASP/DSB/ISB/YIELD...)";
		return -1;
	}

	/*
	 * PC 相对字面量加载：LDR (literal) / LDRSW (literal) / PRFM (literal)。
	 *
	 * 编码上 bits[29:27] == 0b011，bits[25:24] == 0b00。
	 * 等价于（含 size 位 bits[31:30]）bits[29:24] 取值为
	 *   0x18 (LDR W) / 0x58 (LDR X) / 0x98 (LDRSW) / 0xD8 (PRFM)
	 *
	 * 内核 aarch64_insn_uses_literal() 会把这些判为不可单步、也无模拟器，
	 * 于是 arm_probe_decode_insn 返回 INSN_REJECTED。
	 *
	 * 这是最容易踩的一类：编译器常把常量表访问写成 "ldr x0, =const"，
	 * 而函数的第一个基本块就可能用到它。
	 */
	if (op24 == 0x18u || op24 == 0x58u || op24 == 0x98u || op24 == 0xD8u) {
		*why = "PC-relative literal load (LDR/LDRSW/PRFM literal)";
		return -1;
	}

	/*
	 * 独占访问（LDXR/STXR/LDAXR/STLXR/LDXP/STXP ...）。
	 * 单步执行会把一个原子的 read-modify-write 拆开，内核直接拒绝。
	 * 编码：bits[29:24] 落在 0x08..0x0F。
	 */
	if (op24 >= 0x08u && op24 <= 0x0Fu) {
		*why = "exclusive load/store (LDXR/STXR family)";
		return -1;
	}

	/*
	 * MSR（写系统寄存器）。内核两个形式都拒绝：
	 *     msr_imm : mask 0xFFF8F01F, value 0xD500401F
	 *     msr_reg : mask 0xFFF00000, value 0xD5100000
	 * 定义见 arch/arm64/include/asm/insn.h。
	 */
	if ((insn & 0xFFF8F01Fu) == 0xD500401Fu ||
	    (insn & 0xFFF00000u) == 0xD5100000u) {
		*why = "MSR (system register write)";
		return -1;
	}

	/*
	 * MRS（读系统寄存器）。内核默认也拒绝，理由写在 decode-insn.c 里：
	 *   "The MRS instruction may not return a correct value when executing
	 *    in the single-stepping environment. We do make one exception, for
	 *    reading the DAIF bits."
	 *
	 * 也就是说：只有 mrs <Xt>, daif 能单步执行，其余一律拒绝。
	 *
	 * 系统寄存器编号的提取方式必须与内核完全一致：
	 *     aarch64_insn_extract_system_reg(): (insn & 0x1FFFE0) >> 5
	 * 是 19 位掩码，不是我只取低 11 位 —— 那样会把 0xD53B4200
	 * (mrs x0, daif) 误判成非 DAIF。
	 * DAIF 的编号是 0xDA11（AARCH64_INSN_SPCLREG_DAIF）。
	 */
	if ((insn & 0xFFF00000u) == 0xD5300000u) {
		unsigned int spclreg = (insn & 0x1FFFE0u) >> 5;

		if (spclreg != 0xDA11u) {
			*why = "MRS of a system register other than DAIF";
			return -1;
		}
	}

	/*
	 * 异常产生指令。内核用 exception 的粗粒度掩码：
	 *     exception: mask 0xFF000000, value 0xD4000000
	 * 这一条覆盖了 SVC/HVC/SMC/BRK/HLT 以及所有同类编码，
	 * 比逐条枚举更可靠（我之前逐条匹配 op2 的写法漏掉了部分变体）。
	 */
	if ((insn & 0xFF000000u) == 0xD4000000u) {
		*why = "exception-generating instruction (SVC/HVC/SMC/BRK/HLT)";
		return -1;
	}

	/*
	 * ERET 与 ERETAA/ERETAB。
	 * 内核里的定义（arch/arm64/include/asm/insn.h）：
	 *     __AARCH64_INSN_FUNCS(eret,      0xFFFFFFFF, 0xD69F03E0)
	 *     __AARCH64_INSN_FUNCS(eret_auth, 0xFFFFFBFF, 0xD69F0BFF)
	 * 注意 eret 是全 32 位精确匹配，eret_auth 只放开 bit10（A/B 选择位）。
	 */
	if (insn == 0xD69F03E0u || (insn & 0xFFFFFBFFu) == 0xD69F0BFFu) {
		*why = "ERET";
		return -1;
	}

	return 0;
}

/*
 * 检查目标偏移处的指令能否被 uprobe 探测。
 *
 * 返回 0 表示通过，-1 表示明确不能探测（已打印原因）。
 */
static int precheck_target_insn(const char *path, uint64_t offset)
{
	const char *why = NULL;
	int fd;
	uint32_t insn = 0;

	if (offset & 0x3) {
		fprintf(stderr,
			"ecapctl: offset 0x%llx is not 4-byte aligned; "
			"arm64 uprobe requires alignment\n",
			(unsigned long long)offset);
		return -1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (pread(fd, &insn, 4, (off_t)offset) != 4) {
		close(fd);
		fprintf(stderr, "ecapctl: cannot read instruction at 0x%llx\n",
			(unsigned long long)offset);
		return -1;
	}
	close(fd);

	/*
	 * 全零不是合法的 arm64 指令（0x00000000 是 UDF #0，但通常意味着
	 * 偏移落在填充区或者算错了）。单独报错，给出更明确的提示。
	 */
	if (insn == 0) {
		fprintf(stderr,
			"ecapctl: instruction at 0x%llx is 0x00000000 — "
			"the offset is probably wrong\n",
			(unsigned long long)offset);
		return -1;
	}

	printf("target insn @0x%llx = 0x%08x\n", (unsigned long long)offset,
	       insn);

	/*
	 * 精确检查。
	 *
	 * 【只在目标确实是 aarch64 时才检查】
	 * 开发者可能在 x86 主机上拿本机 .so 试跑（比如验证 ELF 解析逻辑），
	 * 这时指令编码完全不是 arm64，按 arm64 规则判断会误报。
	 * 所以先看 ELF 的 e_machine，只有 EM_AARCH64 才做这套检查。
	 */
	if (ecap_elf_is_aarch64(path)) {
		if (a64_check_probeable(insn, &why) != 0) {
			fprintf(stderr,
				"ecapctl: this instruction cannot be probed by "
				"arm64 uprobe: %s\n"
				"         (kernel would reject it with -EINVAL; "
				"pick another offset, e.g. the caller or a "
				"different symbol)\n",
				why ? why : "unknown reason");
			return -1;
		}
		printf("instruction looks probeable\n");
	}

	return 0;
}

/* ==================================================================== */
/* 子命令：capture                                                      */
/* ==================================================================== */

/*
 * 全局"收到终止信号"标志。
 *
 * 【为什么需要它 —— 这是个真实的健壮性缺陷】
 * Ctrl-C 会让 poll() 返回 EINTR，我的循环能捕获并正常跳到 cleanup。
 * 但 `kill`/`killall`（SIGTERM）的默认动作是**直接终止进程**，
 * 不会走任何清理代码。
 *
 * 后果很严重：DEL_PAIR / DEL_PROBE 都不会执行，探测点永久泄漏在
 * 内核模块里。下次再启动 capture 就会遇到
 *     ECAP_IOC_ADD_PAIR failed: File exists
 * 而且用户完全不知道原因 —— 实测就踩到了这个坑。
 *
 * 所以必须显式捕获 SIGTERM/SIGINT/SIGHUP，把"终止"变成"跳出循环"。
 *
 * 用 sig_atomic_t 是信号处理函数的硬性要求：只有这个类型能保证
 * 在信号上下文里读写不会撕裂。
 */
static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void install_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	/*
	 * 不设 SA_RESTART：让 poll() 被信号打断时返回 EINTR，
	 * 这样我们能在循环里检查 g_stop 并尽快退出。
	 */
	sigemptyset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
}

#define ECAP_MAX_EXTRA_KEYLOG 8

struct capture_opts {
	const char *lib;
	bool hex;
	bool stats;
	/* M3 */
	bool no_read;    /* 只抓 SSL_write */
	bool no_write;   /* 只抓 SSL_read */
	uint32_t tgid;   /* 进程过滤，0 = 不过滤 */
	uint32_t uid;    /* uid 过滤，0 = 不过滤 */
	/* M4 */
	const char *pcap_path;   /* pcapng 输出路径，NULL = 不写 */
	const char *keylog_path; /* SSLKEYLOGFILE 输出路径，NULL = 不写 */
	bool pkt;                /* 是否同时抓网络包 */
	uint32_t pkt_port;       /* 包端口过滤，0 = 不过滤 */
	bool keylog;             /* 是否提取 TLS 密钥 */
	const char *extra_keylogs[ECAP_MAX_EXTRA_KEYLOG];
	int num_extra_keylogs;
};

/* 事件方向的名字，用于输出前缀 */
static const char *dir_name(uint8_t dir)
{
	switch (dir) {
	case ECAP_DIR_WRITE:
		return "W";
	case ECAP_DIR_READ:
		return "R";
	default:
		return "?";
	}
}

/*
 * 解析一个符号并在失败时给出可操作的诊断。
 *
 * 返回 0 成功。*out_off 为文件偏移。
 *
 * 【M4 变化】
 * 改用 ecap_elf_find_symbol，它会先查 .dynsym，再查 .gnu_debugdata。
 * 后者是 bssl::ssl_log_secret 的唯一来源（内部函数不导出）。
 * out_from 会告诉我们符号是从哪个节找到的，打印出来方便排查。
 */
static int resolve_symbol(const char *lib, const char *sym, uint64_t *out_off,
			  const char *what)
{
	char found[128] = { 0 };
	const char *from = NULL;

	if (ecap_elf_find_symbol(lib, sym, out_off, found, sizeof(found),
				 &from) < 0) {
		fprintf(stderr, "ecapctl: failed to locate %s (%s) in %s\n",
			sym, what, lib);
		return -1;
	}

	printf("found %-10s (%s) at file offset 0x%llx  [via %s]\n", found, what,
	       (unsigned long long)*out_off, from ? from : "?");

	if (precheck_target_insn(lib, *out_off) < 0)
		return -1;

	return 0;
}

/*
 * 把 keylog 事件转换成 SSLKEYLOG 文本行并写进 pcapng 的 DSB 块。
 *
 * SSLKEYLOG 格式（NSS Key Log Format）：
 *
 *     <LABEL> <client_random_hex> <secret_hex>
 *
 * 例如：
 *     CLIENT_TRAFFIC_SECRET_0 1a2b3c... 9f8e7d...
 *
 * 【为什么用文本而不是二进制】
 * 这是 NSS/Wireshark 的标准格式，人类可读、方便和 SSLKEYLOGFILE 对照。
 * 每行一条，所以可以累积一批再写一个 DSB —— 那样块更少、文件更紧凑。
 *
 * 【client_random 全零怎么办】
 * 说明内核的 BoringSSL 结构体偏移不适用（版本变了）。
 * 这时把 32 字节写成全零 —— 但 Wireshark 无法据此匹配连接，
 * 该密钥等于无效。
 *
 * 所以我们干脆跳过这种行并计数，而不是写出有害的垃圾数据。
 * 用户看到 "keylog: N skipped (no client_random)" 就知道该升级偏移了。
 */
static bool keylog_to_line(const struct ecap_keylog_payload *kl,
			   uint8_t secret_len_hint, char *out, size_t out_cap)
{
	static const char hex[] = "0123456789abcdef";
	char crhex[ECAP_CLIENT_RANDOM_LEN * 2 + 1];
	char sechex[ECAP_KEYLOG_SECRET_MAX * 2 + 1];
	char label[ECAP_KEYLOG_LABEL_MAX + 1];
	bool cr_valid = false;
	size_t i, slen;
	int n;

	/* label 必须是以 NUL 结尾的字符串 */
	memcpy(label, kl->label, ECAP_KEYLOG_LABEL_MAX);
	label[ECAP_KEYLOG_LABEL_MAX] = '\0';
	if (label[0] == '\0')
		return false;

	/* client_random 是否有效（不全零） */
	for (i = 0; i < ECAP_CLIENT_RANDOM_LEN; i++) {
		if (kl->client_random[i] != 0) {
			cr_valid = true;
			break;
		}
	}
	if (!cr_valid)
		return false;

	/*
	 * 优先使用内核通过 hdr.dir 传来的精确长度；
	 * 仅在旧版内核未填（为 0）时退化为去尾部零字节。
	 */
	if (secret_len_hint > 0 && secret_len_hint <= ECAP_KEYLOG_SECRET_MAX) {
		slen = secret_len_hint;
	} else {
		slen = ECAP_KEYLOG_SECRET_MAX;
		while (slen > 0 && kl->secret[slen - 1] == 0)
			slen--;
	}
	if (slen == 0)
		return false;

	for (i = 0; i < ECAP_CLIENT_RANDOM_LEN; i++) {
		crhex[i * 2] = hex[(kl->client_random[i] >> 4) & 0xf];
		crhex[i * 2 + 1] = hex[kl->client_random[i] & 0xf];
	}
	crhex[sizeof(crhex) - 1] = '\0';

	for (i = 0; i < slen; i++) {
		sechex[i * 2] = hex[(kl->secret[i] >> 4) & 0xf];
		sechex[i * 2 + 1] = hex[kl->secret[i] & 0xf];
	}
	sechex[slen * 2] = '\0';

	n = snprintf(out, out_cap, "%s %s %s\n", label, crhex, sechex);
	if (n < 0 || (size_t)n >= out_cap)
		return false;

	return true;
}

static int parse_extra_keylog(const char *spec, char *path_out, size_t path_cap,
			      uint64_t *off_out)
{
	const char *colon = strrchr(spec, ':');

	if (colon && colon[1] != '\0') {
		char *endp = NULL;
		uint64_t off = strtoull(colon + 1, &endp, 0);

		if (endp && *endp == '\0' && off != 0) {
			size_t plen = (size_t)(colon - spec);

			if (plen == 0 || plen >= path_cap) {
				fprintf(stderr, "ecapctl: invalid path in %s\n",
					spec);
				return -1;
			}
			memcpy(path_out, spec, plen);
			path_out[plen] = '\0';
			*off_out = off;
			printf("using explicit keylog offset 0x%llx in %s\n",
			       (unsigned long long)off, path_out);
			return precheck_target_insn(path_out, off);
		}
	}

	if (strlen(spec) >= path_cap) {
		fprintf(stderr, "ecapctl: path too long: %s\n", spec);
		return -1;
	}
	snprintf(path_out, path_cap, "%s", spec);
	return resolve_symbol(path_out, ECAP_KEYLOG_SYMBOL, off_out,
			      "extra-keylog");
}

static int cmd_capture(const struct capture_opts *o)
{
	uint64_t w_off = 0, r_off = 0, k_off = 0;
	int devfd, libfd, rc = 0;
	struct ecap_probe_pair pair;
	struct ecap_probe_req kreq;
	struct ecap_event *ev;
	struct ecap_pcapng *pcap = NULL;
	FILE *keylog_fp = NULL;
	int want_write, want_read, want_keylog;
	bool pair_added = false;
	bool keylog_probe_added = false;
	bool nf_enabled = false;
	uint64_t keylog_lines = 0, keylog_skipped = 0;
	char extra_paths[ECAP_MAX_EXTRA_KEYLOG][512];
	uint64_t extra_offs[ECAP_MAX_EXTRA_KEYLOG];
	int extra_fds[ECAP_MAX_EXTRA_KEYLOG];
	bool extra_added[ECAP_MAX_EXTRA_KEYLOG];
	int i;

	for (i = 0; i < ECAP_MAX_EXTRA_KEYLOG; i++) {
		extra_fds[i] = -1;
		extra_offs[i] = 0;
		extra_added[i] = false;
	}

	/*
	 * 安装信号处理器。
	 *
	 * 必须在安装任何探测点之前 —— 否则在"探测点已挂上、但信号
	 * 还是默认动作"的窗口期里被 kill，探测点就会泄漏在内核里。
	 */
	install_signal_handlers();

	/* --- 1) 解析符号偏移 --- */
	want_write = !o->no_write;
	want_read = !o->no_read;
	/*
	 * keylog 只在用户明确要求时才挂；如果指定了 --keylog-file，也自动开启。
	 */
	want_keylog = o->keylog || (o->keylog_path != NULL);

	if (!want_write && !want_read && !want_keylog && !o->pkt &&
	    o->num_extra_keylogs == 0) {
		fprintf(stderr,
			"ecapctl: --no-write 和 --no-read 同时使用时，"
			"至少需要启用 --keylog 或 --packet\n");
		return 1;
	}

	if ((want_keylog || o->num_extra_keylogs > 0) &&
	    !o->pcap_path && !o->keylog_path) {
		fprintf(stderr,
			"warning: 已启用 --keylog 但未指定 --pcap 或 "
			"--keylog-file，提取的密钥不会落盘\n");
	}

	printf("parsing %s ...\n", o->lib);

	if ((want_keylog || o->num_extra_keylogs > 0) && !ecap_xz_available())
		ecap_xz_init(); /* 失败也让下面自己报错，这里只是尽力 */

	if (want_write &&
	    resolve_symbol(o->lib, "SSL_write", &w_off, "write") < 0)
		return 1;
	if (want_read && resolve_symbol(o->lib, "SSL_read", &r_off, "read") < 0)
		return 1;

	if (want_keylog) {
		/*
		 * C++ mangled name。用 nm 从 .gnu_debugdata 里查到的完整符号。
		 * 直接硬编码而不是在运行时构造，是因为 mangled name 的
		 * 具体形式（是否带参数类型）随编译器/ABI 变化，
		 * 硬编码至少能让"找不到"这件事立刻暴露，而不是静默失效。
		 */
		if (resolve_symbol(o->lib, ECAP_KEYLOG_SYMBOL, &k_off,
				   "keylog") < 0) {
			if (!want_write && !want_read &&
			    o->num_extra_keylogs == 0) {
				fprintf(stderr,
					"ecapctl: keylog 探测点解析失败，"
					"无法继续（纯路径 B 模式）\n");
				return 1;
			}
			fprintf(stderr,
				"ecapctl: keylog 探测点解析失败，"
				"继续抓明文（--keylog 已忽略）\n");
			want_keylog = 0;
		}
	}

	for (i = 0; i < o->num_extra_keylogs; i++) {
		if (parse_extra_keylog(o->extra_keylogs[i], extra_paths[i],
				       sizeof(extra_paths[i]),
				       &extra_offs[i]) < 0)
			return 1;
	}

	/* --- 2) 打开 pcapng / keylog 文件（如果要求） --- */
	if (o->pcap_path) {
		/*
		 * 链路类型用 DST_RAW(101)：我们抓的是原始 IP 包，
		 * 没有以太网头（Netfilter 的 LOCAL_IN/OUT 看到的就是 L3）。
		 * 用 Ethernet 类型会让 Wireshark 把 IP 头当成 MAC 头解析。
		 */
		pcap = ecap_pcapng_open(o->pcap_path, ECAP_LINKTYPE_RAW,
					ECAP_PKT_SNAPLEN);
		if (!pcap) {
			fprintf(stderr, "ecapctl: 无法创建 %s，"
					"继续只打印到终端\n", o->pcap_path);
		} else {
			fprintf(stderr,
				"pcapng: %s (linktype=RAW, snaplen=%u)\n",
				o->pcap_path, ECAP_PKT_SNAPLEN);
		}
	}

	if (o->keylog_path) {
		keylog_fp = fopen(o->keylog_path, "w");
		if (!keylog_fp) {
			fprintf(stderr, "ecapctl: 无法创建 keylog 文件 %s: %s\n",
				o->keylog_path, strerror(errno));
			ecap_pcapng_close(pcap);
			return 1;
		}
		fprintf(stderr, "keylog file: %s\n", o->keylog_path);
	}

	/* --- 3) 打开目标库，把 fd 交给内核 --- */
	libfd = open(o->lib, O_RDONLY | O_CLOEXEC);
	if (libfd < 0) {
		fprintf(stderr, "ecapctl: open(%s): %s\n", o->lib,
			strerror(errno));
		if (keylog_fp)
			fclose(keylog_fp);
		ecap_pcapng_close(pcap);
		return 1;
	}

	devfd = open_dev();

	/* --- 4) 校验 ABI --- */
	{
		uint32_t ver = 0;

		if (ioctl(devfd, ECAP_IOC_VERSION, &ver) < 0 ||
		    ver != ECAP_ABI_VERSION) {
			fprintf(stderr,
				"ecapctl: ABI mismatch (kernel=%u user=%u)\n",
				ver, (unsigned)ECAP_ABI_VERSION);
			close(devfd);
			close(libfd);
			if (keylog_fp)
				fclose(keylog_fp);
			ecap_pcapng_close(pcap);
			return 1;
		}
	}

	/* --- 5) 下发过滤规则 --- */
	if (o->tgid || o->uid) {
		struct ecap_filter flt;

		memset(&flt, 0, sizeof(flt));
		flt.tgid = o->tgid;
		flt.uid = o->uid;
		flt.include_all = 0;

		if (ioctl(devfd, ECAP_IOC_SET_FILTER, &flt) < 0)
			fprintf(stderr, "warning: SET_FILTER failed: %s "
					"(will capture everything)\n",
				strerror(errno));
		else
			printf("filter: tgid=%u uid=%u\n", o->tgid, o->uid);
	}

	/* --- 6) 成对下发明文探测点（仅路径 A 需要） --- */
	memset(&pair, 0, sizeof(pair));
	if (want_write || want_read) {
		pair.fd = (uint32_t)libfd;
		pair.write_offset = w_off;
		pair.read_offset = r_off;

		if (ioctl(devfd, ECAP_IOC_ADD_PAIR, &pair) < 0) {
			int e = errno;
			close(devfd);
			close(libfd);
			if (keylog_fp)
				fclose(keylog_fp);
			ecap_pcapng_close(pcap);
			errno = e;
			die("ECAP_IOC_ADD_PAIR failed (see dmesg)");
		}
		pair_added = true;
	}

	/* --- 7) 下发 keylog 探测点（单独一个 ioctl，因为它不是 pair） --- */
	if (want_keylog) {
		memset(&kreq, 0, sizeof(kreq));
		kreq.fd = (uint32_t)libfd;
		kreq.kind = ECAP_PROBE_KEYLOG;
		kreq.offset = k_off;

		if (ioctl(devfd, ECAP_IOC_ADD_PROBE, &kreq) < 0) {
			fprintf(stderr,
				"warning: keylog 探测点注册失败: %s\n",
				strerror(errno));
			want_keylog = 0;
		} else {
			keylog_probe_added = true;
		}
	}

	for (i = 0; i < o->num_extra_keylogs; i++) {
		extra_fds[i] = open(extra_paths[i], O_RDONLY | O_CLOEXEC);
		if (extra_fds[i] < 0) {
			fprintf(stderr, "warning: open(%s): %s\n",
				extra_paths[i], strerror(errno));
			continue;
		}
		memset(&kreq, 0, sizeof(kreq));
		kreq.fd = (uint32_t)extra_fds[i];
		kreq.kind = ECAP_PROBE_KEYLOG;
		kreq.offset = extra_offs[i];
		if (ioctl(devfd, ECAP_IOC_ADD_PROBE, &kreq) < 0) {
			fprintf(stderr,
				"warning: extra keylog 探测点注册失败 (%s): %s\n",
				extra_paths[i], strerror(errno));
			close(extra_fds[i]);
			extra_fds[i] = -1;
		} else {
			extra_added[i] = true;
			printf("extra keylog probe installed: %s @0x%llx\n",
			       extra_paths[i],
			       (unsigned long long)extra_offs[i]);
		}
	}

	/* --- 8) 启用网络包抓取（如果要求） --- */
	if (o->pkt) {
		uint32_t port = o->pkt_port;
		int r;

		if ((r = ioctl(devfd, ECAP_IOC_ENABLE_NF, &port)) < 0) {
			fprintf(stderr, "warning: ENABLE_NF failed: %s "
					"(继续只抓应用层明文)\n",
				strerror(errno));
		} else {
			nf_enabled = true;
			printf("netfilter capture enabled (port=%u)\n", port);
		}
	}

	printf("probes installed (%s%s%s%s%s%s). waiting ... (Ctrl-C to stop)\n",
	       want_write ? "SSL_write" : "",
	       (want_write && want_read) ? " + " : "",
	       want_read ? "SSL_read" : "",
	       ((want_write || want_read) && keylog_probe_added) ? " + " : "",
	       keylog_probe_added ? "keylog" : "",
	       (!want_write && !want_read && !keylog_probe_added && nf_enabled)
		       ? "netfilter-only"
		       : "");

	/* --- 9) 事件循环 --- */
	ev = malloc(sizeof(*ev));
	if (!ev) {
		rc = 1;
		goto cleanup;
	}

	for (;;) {
		struct pollfd pfd = { .fd = devfd, .events = POLLIN };
		ssize_t n;
		char tsbuf[32];

		/*
		 * 每轮循环都检查终止标志。
		 * 信号处理器只负责置位，真正的清理在主循环退出后做 ——
		 * 信号处理函数里不能调用 ioctl/free 这类非异步安全函数。
		 */
		if (g_stop) {
			fprintf(stderr, "\n收到终止信号，正在清理...\n");
			break;
		}

		if (poll(&pfd, 1, 500) < 0) {
			if (errno == EINTR)
				break; /* 信号打断（Ctrl-C 或 SIGTERM） */
			fprintf(stderr, "poll: %s\n", strerror(errno));
			rc = 1;
			break;
		}
		if (pfd.revents & (POLLERR | POLLHUP)) {
			fprintf(stderr, "device error/hangup\n");
			rc = 1;
			break;
		}
		if (!(pfd.revents & POLLIN))
			continue;

		n = read(devfd, ev, sizeof(*ev));
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			fprintf(stderr, "read: %s\n", strerror(errno));
			rc = 1;
			break;
		}
		if (n == 0)
			continue;
		if (n != (ssize_t)sizeof(*ev)) {
			fprintf(stderr, "short read %zd\n", n);
			rc = 1;
			break;
		}

		switch (ev->hdr.type) {
		case ECAP_EV_SSL_DATA: {
			fmt_ns(ev->hdr.ts_ns, tsbuf, sizeof(tsbuf));
			fprintf(stderr,
				"[%s] %s pid=%u tid=%u uid=%u len=%u%s\n",
				tsbuf, dir_name(ev->hdr.dir), ev->hdr.tgid,
				ev->hdr.tid, ev->hdr.uid, ev->hdr.len,
				(ev->hdr.flags & ECAP_EV_FLAG_TRUNC) ? " TRUNC"
								     : "");
			dump_payload(ev->payload, ev->hdr.len, o->hex);
			fputc('\n', stderr);
			break;
		}

		case ECAP_EV_KEYLOG: {
			const struct ecap_keylog_payload *kl =
				(const struct ecap_keylog_payload *)ev->payload;
			char line[512];

			if (ev->hdr.len < ECAP_KEYLOG_PAYLOAD_LEN) {
				fprintf(stderr, "[keylog] malformed payload "
						"(%u < %zu)\n", ev->hdr.len,
					ECAP_KEYLOG_PAYLOAD_LEN);
				break;
			}

			/*
			 * keylog 事件**不打印到终端**。密钥出现在终端回滚
			 * 缓冲/shell 历史里是实打实的凭据泄露风险。
			 * 只写进 pcapng DSB / keylog 文件。
			 */
			if (keylog_to_line(kl, ev->hdr.dir, line,
					   sizeof(line))) {
				keylog_lines++;
				if (keylog_fp) {
					fputs(line, keylog_fp);
					fflush(keylog_fp);
				}
				if (pcap) {
					if (ecap_pcapng_write_dsb(
						    pcap,
						    ECAP_DSB_TLS_KEY_LOG, line,
						    (uint32_t)strlen(line)) != 0)
						fprintf(stderr,
							"warning: DSB write "
							"failed\n");
				}
			} else {
				keylog_skipped++;
			}
			break;
		}

		case ECAP_EV_PACKET: {
			const struct ecap_pkt_meta *m =
				(const struct ecap_pkt_meta *)ev->payload;
			uint32_t payload_len;

			if (ev->hdr.len < ECAP_PKT_META_LEN) {
				fprintf(stderr, "[pkt] malformed payload\n");
				break;
			}
			payload_len = ev->hdr.len - (uint32_t)ECAP_PKT_META_LEN;

			if (pcap) {
				if (ecap_pcapng_write_epb(
					    pcap, ev->hdr.ts_ns, 0,
					    ev->payload + ECAP_PKT_META_LEN,
					    payload_len, m->origlen) != 0)
					fprintf(stderr,
						"warning: EPB write failed\n");
			}

			/* 包事件的终端输出只在 --hex 时才有意义（数据是二进制），
			 * 否则只打一行摘要，避免刷屏。 */
			if (o->hex) {
				char sstr[INET6_ADDRSTRLEN] = "?";
				char dstr[INET6_ADDRSTRLEN] = "?";

				if (m->ip_version == 4) {
					inet_ntop(AF_INET, &m->saddr4, sstr,
						  sizeof(sstr));
					inet_ntop(AF_INET, &m->daddr4, dstr,
						  sizeof(dstr));
				} else if (m->ip_version == 6) {
					inet_ntop(AF_INET6, m->saddr6, sstr,
						  sizeof(sstr));
					inet_ntop(AF_INET6, m->daddr6, dstr,
						  sizeof(dstr));
				}

				fmt_ns(ev->hdr.ts_ns, tsbuf, sizeof(tsbuf));
				fprintf(stderr,
					"[%s] PKT %s pid=%u %s:%u -> "
					"%s:%u %s cap=%u orig=%u\n",
					tsbuf,
					m->direction == ECAP_PKT_OUT ? "OUT"
								    : "IN",
					ev->hdr.tgid, sstr, m->sport, dstr,
					m->dport, m->proto == 6 ? "TCP" : "UDP",
					m->caplen, m->origlen);
			}
			break;
		}

		default:
			fprintf(stderr, "[skip] unknown event type %u (%s)\n",
				ev->hdr.type, ev_type_name(ev->hdr.type));
			break;
		}
	}

cleanup:
	/* --- 10) 收尾：严格按启用顺序的逆序停 --- */
	if (nf_enabled)
		ioctl(devfd, ECAP_IOC_DISABLE_NF);

	for (i = 0; i < o->num_extra_keylogs; i++) {
		if (extra_added[i]) {
			struct ecap_probe_del kdel;

			memset(&kdel, 0, sizeof(kdel));
			kdel.fd = (uint32_t)extra_fds[i];
			kdel.kind = ECAP_PROBE_KEYLOG;
			kdel.offset = extra_offs[i];
			if (ioctl(devfd, ECAP_IOC_DEL_PROBE, &kdel) < 0)
				fprintf(stderr,
					"warning: DEL extra keylog probe failed: %s\n",
					strerror(errno));
		}
		if (extra_fds[i] >= 0)
			close(extra_fds[i]);
	}

	if (keylog_probe_added) {
		struct ecap_probe_del kdel;

		memset(&kdel, 0, sizeof(kdel));
		kdel.fd = (uint32_t)libfd;
		kdel.kind = ECAP_PROBE_KEYLOG;
		kdel.offset = k_off;
		if (ioctl(devfd, ECAP_IOC_DEL_PROBE, &kdel) < 0)
			fprintf(stderr, "warning: DEL keylog probe failed: %s\n",
				strerror(errno));
	}

	if (pair_added && ioctl(devfd, ECAP_IOC_DEL_PAIR, &pair) < 0)
		fprintf(stderr, "warning: DEL_PAIR failed: %s\n",
			strerror(errno));

	if (o->stats) {
		struct ecap_stats st;

		if (ioctl(devfd, ECAP_IOC_GET_STATS, &st) == 0) {
			fprintf(stderr,
				"stats: hits=%llu pushed=%llu dropped=%llu "
				"copy_fail=%llu\n",
				(unsigned long long)st.uprobe_hits,
				(unsigned long long)st.pushed,
				(unsigned long long)st.dropped,
				(unsigned long long)st.copy_fail);
			fprintf(stderr,
				"       filtered=%llu read_empty=%llu "
				"pending_miss=%llu pending=%u/%u\n",
				(unsigned long long)st.filtered,
				(unsigned long long)st.read_hits,
				(unsigned long long)st.pending_miss, st.pending,
				st.pending_max);
			fprintf(stderr,
				"       keylog_hits=%llu keylog_bad=%llu\n",
				(unsigned long long)st.keylog_hits,
				(unsigned long long)st.keylog_bad);
			fprintf(stderr,
				"       pkt_seen=%llu pkt_pushed=%llu "
				"pkt_skipped=%llu\n",
				(unsigned long long)st.pkt_seen,
				(unsigned long long)st.pkt_pushed,
				(unsigned long long)st.pkt_skipped);
		}
		if (keylog_lines || keylog_skipped)
			fprintf(stderr,
				"       keylog written=%llu skipped=%llu "
				"(skipped 通常意味着 client_random 偏移不适用)\n",
				(unsigned long long)keylog_lines,
				(unsigned long long)keylog_skipped);
		if (pcap)
			fprintf(stderr, "       pcapng blocks=%llu bytes=%llu\n",
				(unsigned long long)
					ecap_pcapng_blocks_written(pcap),
				(unsigned long long)
					ecap_pcapng_bytes_written(pcap));
	}

	free(ev);
	if (keylog_fp)
		fclose(keylog_fp);
	ecap_pcapng_close(pcap);
	close(devfd);
	close(libfd);

	printf("stopped.\n");
	return rc;
}

/* ==================================================================== */
/* main                                                                 */
/* ==================================================================== */

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s <command> [options]\n"
		"\n"
		"commands:\n"
		"  version            握手，校验内核与用户态的 ABI 版本\n"
		"  ping [-n COUNT] [-l LEN] [-p PATTERN]\n"
		"                     验证事件通道（poll/read/编解码）\n"
		"  stats              读取内核统计计数\n"
		"  capture --lib PATH [options]\n"
		"                     同时挂 SSL_write 与 SSL_read 并打印明文\n"
		"\n"
		"capture options:\n"
		"  -l, --lib PATH     目标 TLS 库（必填）\n"
		"  -h, --hex          额外输出前 64 字节的十六进制\n"
		"  -v, --stats        结束时打印统计（默认开启）\n"
		"  -W, --no-read      只抓 SSL_write（不挂 SSL_read）\n"
		"  -R, --no-write     只抓 SSL_read（不挂 SSL_write）\n"
		"  -p, --tgid PID     只抓这个进程（0 = 不过滤）\n"
		"  -u, --uid UID      只抓这个 uid（0 = 不过滤）\n"
		"  -w, --pcap PATH    同时写 pcapng 文件（可用 Wireshark 打开）\n"
		"  -k, --keylog       提取 TLS 密钥并写进 pcapng（需 --pcap 或 -K）\n"
		"  -K, --keylog-file PATH\n"
		"                     额外把密钥以 SSLKEYLOGFILE 格式写入文件\n"
		"  -X, --extra-keylog PATH[:OFFSET]\n"
		"                     额外挂载其他库（如 App 自带 libssl）的 ssl_log_secret\n"
		"  -P, --packet       同时抓网络包（Netfilter，路径 B）\n"
		"  -o, --port PORT    包端口过滤（默认 443，0 = 不过滤）\n"
		"\n"
		"输出里每行开头的 W / R 表示方向：\n"
		"  W = SSL_write，App 发出去的明文\n"
		"  R = SSL_read， App 收回来的明文\n"
		"\n"
		"examples:\n"
		"  %s ping -n 32 -l 64\n"
		"  %s capture --lib "
		"/apex/com.android.conscrypt/lib64/libssl.so --hex\n"
		"  %s capture --lib ... --tgid 14027        # 只抓 Play 商店\n"
		"  %s capture --lib ... -W -R -k -P -w /sdcard/t.pcapng\n"
		"      └ 纯路径 B：仅 Hook ssl_log_secret + Netfilter 抓包\n",
		argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	/*
	 * 尽早尝试加载 liblzma。
	 *
	 * 它是 .gnu_debugdata（keylog 符号的唯一来源）的必需依赖。
	 * 这里先试一次，cmd_capture 里会根据 ecap_xz_available() 的
	 * 结果决定 keylog 功能是否可用 —— 不可用也不影响明文抓包。
	 *
	 * 放在 main 开头而不是 cmd_capture 里，是因为它对所有子命令
	 * 都可能有意义（将来 stats 也可能展示 xz 状态）。
	 */
	ecap_xz_init();

	if (strcmp(argv[1], "version") == 0) {
		if (argc != 2) {
			usage(argv[0]);
			return 1;
		}
		return cmd_version();
	}

	if (strcmp(argv[1], "stats") == 0) {
		if (argc != 2) {
			usage(argv[0]);
			return 1;
		}
		return cmd_stats();
	}

	if (strcmp(argv[1], "ping") == 0) {
		unsigned int count = 8, len = 32;
		uint32_t pattern = 0x41;
		int c;

		/* 把 argv[0] 跳过去，让 getopt 从 argv[2] 开始解析 */
		optind = 2;
		while ((c = getopt(argc, argv, "n:l:p:")) != -1) {
			switch (c) {
			case 'n':
				count = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'l':
				len = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'p':
				pattern = (uint32_t)strtoul(optarg, NULL, 0);
				break;
			default:
				usage(argv[0]);
				return 1;
			}
		}
		if (count == 0 || len == 0) {
			fprintf(stderr, "ping: count and len must be > 0\n");
			return 1;
		}
		return cmd_ping(count, len, pattern);
	}

	if (strcmp(argv[1], "capture") == 0) {
		static const struct option longopts[] = {
			{ "lib", required_argument, NULL, 'l' },
			{ "hex", no_argument, NULL, 'h' },
			{ "stats", no_argument, NULL, 'v' },
			/* M3 */
			{ "no-read", no_argument, NULL, 'W' },
			{ "no-write", no_argument, NULL, 'R' },
			{ "tgid", required_argument, NULL, 'p' },
			{ "uid", required_argument, NULL, 'u' },
			/* M4 */
			{ "pcap", required_argument, NULL, 'w' },
			{ "keylog", no_argument, NULL, 'k' },
			{ "keylog-file", required_argument, NULL, 'K' },
			{ "extra-keylog", required_argument, NULL, 'X' },
			{ "packet", no_argument, NULL, 'P' },
			{ "port", required_argument, NULL, 'o' },
			{ NULL, 0, NULL, 0 },
		};
		struct capture_opts o = {
			.lib = NULL,
			.hex = false,
			.stats = true,
			.no_read = false,
			.no_write = false,
			.tgid = 0,
			.uid = 0,
			.pcap_path = NULL,
			.keylog_path = NULL,
			.pkt = false,
			.pkt_port = 443,
			.keylog = false,
			.num_extra_keylogs = 0,
		};
		int c;

		optind = 2;
		while ((c = getopt_long(argc, argv, "l:hvWRp:u:w:kK:X:Po:",
					longopts, NULL)) != -1) {
			switch (c) {
			case 'l':
				o.lib = optarg;
				break;
			case 'h':
				o.hex = true;
				break;
			case 'v':
				o.stats = true;
				break;
			case 'W':
				o.no_read = true;
				break;
			case 'R':
				o.no_write = true;
				break;
			case 'p':
				o.tgid = (uint32_t)strtoul(optarg, NULL, 0);
				break;
			case 'u':
				o.uid = (uint32_t)strtoul(optarg, NULL, 0);
				break;
			/* --- M4 --- */
			case 'w':
				o.pcap_path = optarg;
				break;
			case 'k':
				o.keylog = true;
				break;
			case 'K':
				o.keylog_path = optarg;
				break;
			case 'X':
				if (o.num_extra_keylogs >=
				    ECAP_MAX_EXTRA_KEYLOG) {
					fprintf(stderr,
						"capture: too many --extra-keylog (max %d)\n",
						ECAP_MAX_EXTRA_KEYLOG);
					return 1;
				}
				o.extra_keylogs[o.num_extra_keylogs++] = optarg;
				break;
			case 'P':
				o.pkt = true;
				break;
			case 'o':
				o.pkt_port = (uint32_t)strtoul(optarg, NULL, 0);
				break;
			default:
				usage(argv[0]);
				return 1;
			}
		}
		if (!o.lib) {
			fprintf(stderr,
				"capture: --lib is required\n"
				"example: %s capture --lib "
				"/apex/com.android.conscrypt/lib64/libssl.so\n",
				argv[0]);
			return 1;
		}
		return cmd_capture(&o);
	}

	usage(argv[0]);
	return 1;
}
