/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_uapi.h - 内核模块与用户态程序共享的 ABI 定义
 *
 * 【这个文件被两边同时 include】
 *   1. 内核态  kernel/ecap_*.c   （__KERNEL__ 已定义）
 *   2. 用户态  user/ecapctl.c    （__KERNEL__ 未定义，Android NDK 编译）
 *
 * 因此这里只允许出现"双方都认识的东西"：固定宽度整数、结构体、宏。
 * 绝对不能 include <linux/xxx.h>，也绝对不能出现指针类型 —— 用户态与
 * 内核态的地址空间完全不同，结构体里放指针就是 ABI 灾难。
 *
 * 【改动的纪律】
 * 这里的任何一个字段顺序/宽度变化，都会导致内核与用户态的解释错位。
 * 改动必须两边同时改，并且重新编译 .ko 与 ecapctl。为此：
 *   - 所有结构体都显式占满字节，不留隐式填充空洞；
 *   - 留 reserved 字段给后续扩展；
 *   - 用 ECAP_ABI_VERSION 做运行期握手，版本不符直接拒绝。
 */
#ifndef _ECAP_UAPI_H_
#define _ECAP_UAPI_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
/*
 * 用户态也用 <linux/types.h> 提供 __u8/__u32/__u64。
 *
 * 【为什么不用 stdint.h 自己 typedef】
 * 试过自己写 typedef，结果是灾难：只要用户的 .c 里 include 了任何
 * 会间接引入 <linux/types.h> 的头（<sys/stat.h>、<elf.h> 都会），
 * 就会和 asm-generic/int-ll64.h 里的定义撞车，报
 *   "redefinition of __s64" / "conflicting types for __u64"。
 * 而 __u8/__u16/__u32/__u64 本来就是 Linux 的 UAPI 命名，
 * 用它的原始定义是最不容易出错的。Android NDK 与 glibc 都提供这个头。
 */
#include <linux/types.h>
#include <sys/ioctl.h>
#endif

/* ======================================================================
 * 一、基本常量
 * ====================================================================== */

/*
 * ABI 版本。任何结构体布局变化都必须 +1。
 * 用户态 open() 之后先发 ECAP_IOC_VERSION 握手，内核返回本值；
 * 不相等就说明 .ko 和 ecapctl 不是同一次编译出来的，直接退出。
 */
#define ECAP_ABI_VERSION 1u

/*
 * 事件槽大小（字节，必须是 2 的幂）。
 *
 * 【为什么定长】
 * 内核里的 kfifo 在这个 GKI 上没有导出 record 模式所需的 __kfifo_out_r，
 * 只有 __kfifo_in_r 被导出。用变长记录会导致出队时无法判断边界，
 * 因此这里固定每个事件占一个槽：写满 4096 字节、读一次拿 4096 字节。
 *
 * 好处是内核与用户态两侧都完全无状态：不需要长度前缀、不需要处理
 * "只读到半个事件"的情况，read() 要么返回 4096，要么返回 0 / -EAGAIN。
 *
 * 代价是每个小事件也要占 4KB 带宽，所以内核侧在入队前会做截断
 * （见 EcAP_EVENT_FLAG_TRUNC），把小包压在一个槽里。
 */
#define ECAP_SLOT_SIZE 4096u

/* 进程名长度，必须等于内核的 TASK_COMM_LEN */
#define ECAP_COMM_LEN 16u

/*
 * SSL_read 挂起表容量（M3）。
 *
 * 每个正在执行、尚未返回的 SSL_read 调用会占一条记录，用来把
 * "入口时拿到的 buf 指针"传给"返回时的 handler"。
 *
 * 256 条足够覆盖绝大多数场景：这是并发线程数，不是总调用数 ——
 * 记录在 ret_handler 里立刻被删除。只有"线程被 kill 在 SSL_read 中间"
 * 这种极端情况才会残留。
 */
#define ECAP_PENDING_MAX 256u

/* ======================================================================
 * 二、M4：TLS 密钥与网络包
 * ====================================================================== */

/*
 * TLS keylog 事件（路径 B 的一半）。
 *
 * BoringSSL 的 ssl_log_secret 会在密钥派生完成时被调用，参数是：
 *
 *     void ssl_log_secret(const SSL *ssl, const char *label,
 *                         Span<const uint8_t> secret)
 *
 *   x0 = ssl
 *   x1 = label    —— 以 NUL 结尾的字符串，例如 "CLIENT_TRAFFIC_SECRET_0"
 *   x2 = data     —— 密钥字节
 *   x3 = size     —— 密钥长度（TLS 1.3 是 32 字节，TLS 1.2 master key 是 48）
 *
 * 注意 Span 是按"两个独立寄存器"传的（data 在 x2、size 在 x3），
 * 不是传一个指向 Span 结构体的指针。这一点从调用点的反汇编可以直接确认。
 *
 * 【为什么要 client_random】
 * pcapng 的 DSB（Decryption Secrets Block）块需要把密钥和某条 TLS 连接
 * 关联起来，关联键就是 client_random（32 字节）。Wireshark 靠它把
 * SSLKEYLOG 格式的三元组 (label, client_random, secret) 与实际连接匹配。
 *
 * client_random 的获取有两级方案：
 *   一级：从 ssl 结构体的固定偏移读（快，但依赖 BoringSSL 内部布局）
 *   二级：hook SSL_get_client_random（稳，但多一个探测点）
 */

/* label 最大长度，含 NUL。"SERVER_TRAFFIC_SECRET_0" 是 23 字节 */
#define ECAP_KEYLOG_LABEL_MAX 32u
/* TLS 1.3 traffic secret 32 字节，TLS 1.2 master secret 48 字节，留余量 */
#define ECAP_KEYLOG_SECRET_MAX 64u
/* TLS client_random 固定 32 字节 */
#define ECAP_CLIENT_RANDOM_LEN 32u

/*
 * keylog 事件的 payload 布局（定长 128 字节）：
 *
 *   0   char  label[32]
 *   32  u8    client_random[32]
 *   64  u8    secret[64]
 *
 * 总计 128 字节，无填充。
 *
 * 【为什么把 label 直接放进 payload 而不复用 hdr.comm】
 * comm 是进程名（TASK_COMM_LEN=16），语义完全不同，混用会导致
 * 用户态无法区分"这条事件的进程名叫 SERVER_TRAFFIC_SECRET_0"这种荒谬情况。
 */
struct ecap_keylog_payload {
	char label[ECAP_KEYLOG_LABEL_MAX];
	__u8 client_random[ECAP_CLIENT_RANDOM_LEN];
	__u8 secret[ECAP_KEYLOG_SECRET_MAX];
};

#define ECAP_KEYLOG_PAYLOAD_LEN sizeof(struct ecap_keylog_payload)

/* keylog payload 的字段偏移，供用户态取用 */
#define ECAP_KL_OFF_LABEL  0u
#define ECAP_KL_OFF_CRANDOM 32u
#define ECAP_KL_OFF_SECRET 64u

/*
 * 一个抓到的网络包（路径 B 的另一半）。
 *
 * payload 布局（变长）：
 *
 *   0   struct ecap_pkt_meta
 *   N   u8 帧数据（从 L2 或 L3 开始，取决于内核侧的实现）
 *
 * 【为什么带五元组】
 * pcapng 的 EPB 只需要原始帧 + 时间戳，但要把包与进程/密钥关联起来，
 * 用户态需要五元组来还原连接。所以元数据里带上协议与端口。
 */
struct ecap_pkt_meta {
	__u8  ip_version;  /* 4 或 6 */
	__u8  proto;       /* IPPROTO_TCP / IPPROTO_UDP */
	__u8  direction;   /* ECAP_PKT_OUT / ECAP_PKT_IN */
	__u8  pad;         /* 对齐填充，实际值无意义 */
	__u16 sport;       /* 主机序 */
	__u16 dport;       /* 主机序 */
	__u32 saddr4;      /* 网络序，仅 ip_version==4 有效 */
	__u32 daddr4;
	__u8  saddr6[16];  /* 仅 ip_version==6 有效 */
	__u8  daddr6[16];
	__u32 caplen;      /* 实际抓到的字节数 */
	__u32 origlen;     /* 原始帧长（可能大于 caplen） */
};

/*
 * 布局（56 字节，无隐式填充空洞）：
 *   0  u8  ip_version
 *   1  u8  proto
 *   2  u8  direction
 *   3  u8  pad
 *   4  u16 sport
 *   6  u16 dport
 *   8  u32 saddr4
 *  12  u32 daddr4
 *  16  u8  saddr6[16]
 *  32  u8  daddr6[16]
 *  48  u32 caplen
 *  52  u32 origlen
 *  56  (end)
 */
#define ECAP_PKT_META_LEN sizeof(struct ecap_pkt_meta)

/* 包方向 */
#define ECAP_PKT_OUT 1u /* 本机发出（NF_INET_LOCAL_OUT） */
#define ECAP_PKT_IN  2u /* 发往本机（NF_INET_LOCAL_IN）  */

/* 一次最多抓多少字节的帧（剩下的只记 origlen）。2048 足以容纳标准 MTU 1500 的 QUIC/TCP 包 */
#define ECAP_PKT_SNAPLEN 2048u

/* ======================================================================
 * 三、事件定义
 * ====================================================================== */

/* 事件类型 */
enum ecap_event_type {
	ECAP_EV_NONE = 0,
	ECAP_EV_PING = 1,        /* M1 自测用：ioctl 塞进来的假事件 */
	ECAP_EV_SSL_DATA = 2,    /* 路径 A：SSL_read / SSL_write 的明文 */
	ECAP_EV_KEYLOG = 3,      /* 路径 B：ssl_log_secret 的密钥（M4） */
	ECAP_EV_PACKET = 4,      /* 路径 B：Netfilter 抓到的 sk_buff（M4） */
};

/*
 * 事件头标志位
 */
#define ECAP_EV_FLAG_TRUNC 0x01u /* payload 被截断，只保留了前 len 字节 */

/*
 * 事件方向。
 *
 * SSL_write 与 SSL_read 产生的事件类型都是 ECAP_EV_SSL_DATA，
 * 靠这个字段区分是"发出去的"还是"收回来的"。
 *
 * 为什么不在 type 里区分：用户态对两类明文的处理方式完全一样
 * （都是打印 / 写 pcap），只有展示时需要知道方向。用独立字段比
 * 复制一套事件类型更省事，也不会让 type 枚举继续膨胀。
 */
#define ECAP_DIR_UNKNOWN 0u
#define ECAP_DIR_WRITE   1u /* SSL_write：App 发出去的明文 */
#define ECAP_DIR_READ    2u /* SSL_read：App 收回来的明文 */

/*
 * 事件头，48 字节，无隐式填充：
 *   0  u32 type
 *   4  u32 len
 *   8  u64 ts_ns
 *  16  u32 tgid
 *  20  u32 tid
 *  24  u32 uid
 *  28  u8  flags
 *  29  u8  dir      ← M3 新增（原先这里是 reserved[0]）
 *  30  u8  reserved[2]
 *  32  char comm[16]
 *  48  (end)
 *
 * 【为什么能复用 reserved 的字节而不改 ABI 大小】
 * 结构体总大小仍是 48，布局没有位移，所以 ECAP_ABI_VERSION 不需要
 * 递增。老版本用户态读到 dir 的位置会当成 reserved[0]（值为 0），
 * 表现就是"方向未知"——这是可接受的降级，不会错位。
 */
struct ecap_hdr {
	__u32 type;     /* enum ecap_event_type */
	__u32 len;      /* payload[] 中的有效字节数 */
	__u64 ts_ns;    /* ktime_get_ns()，单调时钟，单位纳秒 */
	__u32 tgid;     /* 线程组 id（用户态看到的 pid） */
	__u32 tid;      /* 内核 pid（线程 id） */
	__u32 uid;
	__u8  flags;    /* ECAP_EV_FLAG_* */
	__u8  dir;      /* ECAP_DIR_*，仅 SSL_DATA 有意义 */
	__u8  reserved[2];
	char  comm[ECAP_COMM_LEN];
};

/* 一个完整的事件槽 */
struct ecap_event {
	struct ecap_hdr hdr;
	__u8 payload[ECAP_SLOT_SIZE - sizeof(struct ecap_hdr)];
};

/* payload 能达到的最大长度（由槽大小与事件头大小推导） */
#define ECAP_PAYLOAD_MAX (ECAP_SLOT_SIZE - 48u)

/* ======================================================================
 * 四、下发的探测请求
 * ====================================================================== */

/*
 * 探测点类型。
 *
 * 用户态负责把"库路径 + 符号名"翻译成"fd + 文件偏移"，
 * 内核只认 offset，不解析 ELF —— 这样内核侧完全不做 I/O，最稳。
 *
 * 【SSL_WRITE 与 SSL_READ 的机制差异 —— 这是 M3 的核心】
 *
 *   SSL_write(SSL *ssl, const void *buf, int num)
 *       x0=ssl, x1=buf, x2=num
 *       ▲ 入口时 buf 和 num 都已经确定，直接读即可。
 *         不需要返回值，也不需要保存任何状态。
 *
 *   SSL_read(SSL *ssl, void *buf, int num)
 *       x0=ssl, x1=buf, x2=num
 *       ▲ 入口时只知道"最多能读 num 字节"，
 *         **实际读到多少要看返回值 x0**。
 *         所以必须：
 *           1. entry  : 记住 (tid -> buf) 的映射
 *           2. ret     : 读 regs->regs[0] 得到实际字节数 n
 *           3. 若 n > 0，按记住的 buf 拷 n 字节
 *
 *   这就是为什么 SSL_read 只能用 ret_handler，而 SSL_write 用 entry。
 *   也因此 SSL_read 必须按 **tid**（线程 id）索引，不能用 tgid ——
 *   同一进程的多个线程会并发调 SSL_read，用 tgid 会互相覆盖。
 */
enum ecap_probe_kind {
	ECAP_PROBE_SSL_WRITE = 1, /* SSL_write(ssl, buf, num)，entry 直接读 buf */
	ECAP_PROBE_SSL_READ = 2,  /* SSL_read(ssl, buf, num)，ret_handler 读 buf */
	ECAP_PROBE_KEYLOG = 3,    /* ssl_log_secret(ssl, label, span) —— M4 */
};

/*
 * 一条探测请求，16 字节，无填充：
 *   0  u32 fd      —— 用户态 open() 目标 .so 得到的 fd
 *   4  u32 kind    —— enum ecap_probe_kind
 *   8  u64 offset  —— 目标函数在文件中的字节偏移
 *
 * 【为什么传 fd 而不是路径】
 * 内核里拿 inode 有两条路：
 *   a) kern_path()/filp_open() —— 在这个 GKI 上都没导出（CONFIG_TRIM_UNUSED_KSYMS），
 *      只能先 kallsyms 取地址再间接调用，增加 CFI 风险；
 *   b) 用户态 open() 好文件，把 fd 传进来，内核用 fget() + igrab(file_inode())。
 *      fget 与 igrab 都是 EXPORT_SYMBOL，直接调用，零 kallsyms。
 * 这里选 b。
 */
struct ecap_probe_req {
	__u32 fd;
	__u32 kind;
	__u64 offset;
};

/*
 * 删除探测点。内核侧按 (offset) 找已注册项；fd 仅用于定位 inode 做校验。
 */
struct ecap_probe_del {
	__u32 fd;
	__u32 kind;
	__u64 offset;
};

/*
 * 抓包过滤规则（M3 新增）。
 *
 * 通过 ECAP_IOC_SET_FILTER 下发。全部是"与"关系，任一条不满足就丢弃。
 * 值为 0 表示该条不过滤。
 *
 * 【为什么过滤要放在内核侧】
 * 如果只在用户态过滤，所有 SSL_write/SSL_read 的 payload 都要走一遍
 * copy_from_user + 入队 + copy_to_user，开销全在目标进程的关键路径上。
 * 在 handler 里先比对 pid/uid，不匹配就立刻返回，一个字节都不拷。
 *
 * 【为什么只支持 pid/uid 而不支持端口/域名】
 * handler 里拿不到 socket 信息（SSL 对象是黑盒），要拿就得额外 hook
 * tcp_sendmsg 做归因（那是 M4 的路径 B）。M3 先用最可靠的两个维度。
 */
struct ecap_filter {
	__u32 tgid;      /* 只抓这个进程（用户态看到的 pid）。0 = 不过滤 */
	__u32 uid;       /* 只抓这个 uid。0 = 不过滤 */
	__u32 include_all; /* 非 0 时忽略 tgid/uid，全抓（默认） */
	__u32 reserved;  /* 显式保留，保证后续扩展不改布局 */
};

/*
 * M3：同时挂 SSL_write 与 SSL_read 的便捷请求。
 *
 * 一次 ioctl 完成两件事，避免用户态分别下发两个探测点、还要处理
 * "只成功一个"的中间状态。
 *
 * offsets[i] 为 0 表示跳过该方向。
 */
struct ecap_probe_pair {
	__u32 fd;
	__u32 reserved;
	__u64 write_offset; /* SSL_write 的文件偏移，0 = 不挂 */
	__u64 read_offset;  /* SSL_read  的文件偏移，0 = 不挂 */
};

/* M1 自测：让内核往事件队列里塞一条 ECAP_EV_PING 假事件 */
struct ecap_ping {
	__u32 len;     /* 想回显的字节数，<= ECAP_PAYLOAD_MAX */
	__u32 pattern; /* 填充模式，用户态可以据此校验数据完整性 */
};

/* 运行期统计，ioctl 读取 */
struct ecap_stats {
	__u64 pushed;    /* 成功入队事件数 */
	__u64 dropped;   /* 队列满丢弃事件数 */
	__u64 reads;     /* 成功 read() 次数 */
	__u64 ioctls;    /* 成功 ioctl 次数 */
	__u64 uprobe_hits; /* uprobe handler 被触发次数 */
	__u64 copy_fail; /* copy_from_user 失败次数 */
	/* --- M3 新增 --- */
	__u64 filtered;    /* 因 pid/uid 不匹配被过滤掉的事件数 */
	__u64 read_hits;   /* SSL_read 返回值 <= 0（没读到数据）的次数 */
	__u64 pending_miss; /* ret_handler 没找到 entry 记录的 buf 的次数 */
	__u32 pending;     /* 当前挂起表（tid -> buf）中的条目数 */
	__u32 pending_max; /* 挂起表容量 */
	/* --- M4 新增 --- */
	__u64 keylog_hits;   /* ssl_log_secret 被触发次数 */
	__u64 keylog_bad;    /* label 读取失败 / secret 长度为 0 的次数 */
	__u64 pkt_seen;      /* Netfilter hook 看到的包总数 */
	__u64 pkt_skipped;   /* 因端口/协议/解析失败被跳过的包数 */
	__u64 pkt_pushed;    /* 成功入队的包数 */
	__u32 pkt_queue_len; /* 当前包队列深度（快照） */
	__u32 pkt_queue_max; /* 包队列容量 */
	__u32 queued;    /* 当前队列中的字节数（快照） */
	__u32 slots;     /* 队列总容量（字节数） */
};

/* ======================================================================
 * 五、ioctl 命令
 * ====================================================================== */

/*
 * 'E' 是本驱动的幻数。同一系统里所有驱动应使用不同的幻数，
 * 否则一个驱动的 ioctl 可能被另一个驱动误认。
 *
 * 内核侧必须完整比较 cmd（含方向与大小），不能只比 _IOC_NR —— 否则
 * 用户态传错结构体大小也能"通过"校验，导致 copy_from_user 越界。
 */
#define ECAP_IOC_MAGIC 'E'

#define ECAP_IOC_VERSION    _IOR(ECAP_IOC_MAGIC, 1, __u32)
#define ECAP_IOC_PING       _IOW(ECAP_IOC_MAGIC, 2, struct ecap_ping)
#define ECAP_IOC_GET_STATS  _IOR(ECAP_IOC_MAGIC, 3, struct ecap_stats)
#define ECAP_IOC_ADD_PROBE  _IOW(ECAP_IOC_MAGIC, 4, struct ecap_probe_req)
#define ECAP_IOC_DEL_PROBE  _IOW(ECAP_IOC_MAGIC, 5, struct ecap_probe_del)
#define ECAP_IOC_CLEAR      _IO(ECAP_IOC_MAGIC, 6)
/* --- M3 新增 --- */
#define ECAP_IOC_SET_FILTER   _IOW(ECAP_IOC_MAGIC, 7, struct ecap_filter)
#define ECAP_IOC_ADD_PAIR     _IOW(ECAP_IOC_MAGIC, 8, struct ecap_probe_pair)
#define ECAP_IOC_DEL_PAIR     _IOW(ECAP_IOC_MAGIC, 9, struct ecap_probe_pair)
/* --- M4 新增 --- */
/*
 * 配置包抓取。
 *
 * 参数不是结构体而是 __u32 端口号（0 = 不按端口过滤）。
 * 因为包抓取只需要这一个参数，用结构体反而绕。
 */
#define ECAP_IOC_ENABLE_NF    _IOW(ECAP_IOC_MAGIC, 10, __u32)
#define ECAP_IOC_DISABLE_NF   _IO(ECAP_IOC_MAGIC, 11)

#define ECAP_IOC_MAXNR 11

/* ======================================================================
 * 六、编译期布局断言
 * ====================================================================== */

/*
 * 这些断言必须能出现在文件作用域（不能是语句），因此不能用
 * BUILD_BUG_ON（它是一个 do{}while(0) 语句宏）。内核与用户态都提供了
 * 文件作用域的 _Static_assert：
 *   - 内核  : include/linux/build_bug.h 里的 static_assert()
 *   - 用户态: C11 关键字
 *
 * 作用是在编译期就抓出"结构体被改坏了"，而不是等到运行时数据错位。
 */
#ifdef __KERNEL__
#include <linux/build_bug.h>
#define ECAP_ABI_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define ECAP_ABI_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

ECAP_ABI_ASSERT(sizeof(struct ecap_hdr) == 48, "ecap_hdr must be 48 bytes");
ECAP_ABI_ASSERT(sizeof(struct ecap_event) == ECAP_SLOT_SIZE,
		"ecap_event must equal ECAP_SLOT_SIZE");
ECAP_ABI_ASSERT(sizeof(struct ecap_probe_req) == 16,
		"ecap_probe_req must be 16 bytes");
ECAP_ABI_ASSERT(sizeof(struct ecap_probe_del) == 16,
		"ecap_probe_del must be 16 bytes");
ECAP_ABI_ASSERT(sizeof(struct ecap_ping) == 8, "ecap_ping must be 8 bytes");
/* M3 新增 */
ECAP_ABI_ASSERT(sizeof(struct ecap_filter) == 16,
		"ecap_filter must be 16 bytes");
ECAP_ABI_ASSERT(sizeof(struct ecap_probe_pair) == 24,
		"ecap_probe_pair must be 24 bytes");
/* M4 新增 */
ECAP_ABI_ASSERT(sizeof(struct ecap_keylog_payload) == 128,
		"ecap_keylog_payload must be 128 bytes");
ECAP_ABI_ASSERT(sizeof(struct ecap_pkt_meta) == 56,
		"ecap_pkt_meta must be 56 bytes");

#endif /* _ECAP_UAPI_H_ */
