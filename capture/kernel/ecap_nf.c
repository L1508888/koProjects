// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_nf.c - Netfilter 抓包 + kprobe 进程归因（M4，路径 B）
 *
 * 【这个文件解决什么问题】
 * M2/M3 的 uprobe 路径只能拿到"应用层明文"。如果你想要一份可以丢进
 * Wireshark 分析、包含 TCP 重传 / 握手 / QUIC 的完整抓包，就必须在
 * 网络层收包 —— 也就是这一层。
 *
 *   uprobe(ssl_log_secret)  →  密钥（KEYLOG 事件）
 *   Netfilter LOCAL_IN/OUT  →  原始包（PACKET 事件）
 *   两者合起来 →  pcapng（EPB + DSB）→ Wireshark 直接解密
 *
 * 【与 ecap_nf_attr.c 的关系】
 * 那个文件是 M1 之前的验证原型：它把五元组和归因结果用 pr_info 打到
 * dmesg，只用于证明"归因表思路可行"。
 * 本文件复用它的两个核心机制：
 *   1. kprobe tcp_sendmsg/udp_sendmsg 建立 (五元组 → pid/comm) 映射
 *   2. Netfilter hook 在 LOCAL_IN/OUT 上抓包并反查归因
 * 区别在于输出：不再打 dmesg，而是组装成 PACKET 事件入 kfifo。
 *
 * 【为什么 LOCAL_IN 需要归因表】
 * 收包方向（LOCAL_IN）在软中断上下文执行，`current` 是 ksoftirqd 或
 * 任意被打断的进程 —— 拿不到"这个包属于哪个 App"。
 * 所以在发包时（tcp_sendmsg，进程上下文，current 就是发包线程）先
 * 记下五元组与 pid 的映射，收包时反查。
 *
 * 【上下文约束 —— 这是本文件最容易出错的地方】
 * Netfilter hook 运行在：
 *   - LOCAL_OUT : 通常是进程上下文（sendmsg 路径），但可能是软中断
 *   - LOCAL_IN  : 软中断上下文
 * 所以 hook 里**绝对不能睡眠**：
 *   - 只能用 GFP_ATOMIC
 *   - 只能用自旋锁，不能 mutex
 *   - 不能用 copy_from_user
 * kprobe handler 同理。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include "ecap_nf.h"
#include "ecap_dev.h"

#define NF_TAG "ecap_tls: "

/* 归因表容量。每个活跃连接的映射占一条。 */
#define NF_CONN_MAX 4096
#define NF_CONN_HASH_BITS 10 /* 2^10 = 1024 个桶 */

/* ---------------- 统计 ---------------- */

static atomic64_t ecap_nf_stat_seen = ATOMIC64_INIT(0);
static atomic64_t ecap_nf_stat_skipped = ATOMIC64_INIT(0);
static atomic64_t ecap_nf_stat_pushed = ATOMIC64_INIT(0);

__u64 ecap_nf_pkt_seen(void)
{
	return (__u64)atomic64_read(&ecap_nf_stat_seen);
}

__u64 ecap_nf_pkt_skipped(void)
{
	return (__u64)atomic64_read(&ecap_nf_stat_skipped);
}

__u64 ecap_nf_pkt_pushed(void)
{
	return (__u64)atomic64_read(&ecap_nf_stat_pushed);
}

/* 包队列深度用事件队列的统计即可（两者共用同一个 kfifo） */
u32 ecap_nf_queue_len(void)
{
	return ecap_queue_used_bytes();
}

u32 ecap_nf_queue_max(void)
{
	return ecap_queue_capacity_bytes();
}

/* ---------------- 运行状态 ---------------- */

static u32 ecap_nf_port __read_mostly;
static bool ecap_nf_active;

/* ---------------- 五元组与归因表 ---------------- */

/*
 * 归因表的键。
 *
 * 【为什么端口用主机序】
 * kprobe 侧从 struct sock 读出来的是 sk_num（主机序）和
 * sk_dport（网络序），Netfilter 侧从 skb 读出来的是网络序。
 * 如果不在写入/查询前统一成同一字节序，memcmp 永远不相等 ——
 * 这是这类代码最经典的 bug。这里统一成**主机序**。
 */
struct ecap_nf_key {
	u8 ip_ver;
	u8 proto;
	u16 sport; /* 主机序 */
	u16 dport; /* 主机序 */
	__be32 saddr4;
	__be32 daddr4;
	u8 saddr6[16];
	u8 daddr6[16];
};

struct ecap_nf_node {
	struct hlist_node hnode;
	struct ecap_nf_key key;
	u32 pid;
	char comm[TASK_COMM_LEN];
};

static DEFINE_HASHTABLE(ecap_nf_tbl, NF_CONN_HASH_BITS);
static DEFINE_SPINLOCK(ecap_nf_lock);
static atomic_t ecap_nf_cnt = ATOMIC_INIT(0);

/*
 * 哈希函数。
 *
 * 注意：hash_add()/hash_for_each_possible() 的最后一个参数是"原始 key"，
 * 宏内部会用 hash_min(key, HASH_BITS(name)) 自己算桶号。
 * 所以这里返回未压缩的 32 位哈希值，不要在外面再算一次桶号。
 */
static u32 ecap_nf_hash(const struct ecap_nf_key *k)
{
	u32 h = ((u32)k->proto << 16) ^ ((u32)k->sport << 8) ^ k->dport;

	if (k->ip_ver == 4)
		h ^= k->saddr4 ^ k->daddr4;
	else
		h ^= *(const u32 *)k->saddr6 ^ *(const u32 *)k->daddr6;

	return h;
}

/* 插入或更新一条归因记录。kprobe 上下文，不能睡眠。 */
static void ecap_nf_upsert(const struct ecap_nf_key *key, u32 pid,
			   const char *comm)
{
	struct ecap_nf_node *node;
	unsigned long flags;
	u32 h = ecap_nf_hash(key);

	spin_lock_irqsave(&ecap_nf_lock, flags);

	hash_for_each_possible(ecap_nf_tbl, node, hnode, h) {
		if (!memcmp(&node->key, key, sizeof(*key))) {
			/* 已存在：更新 pid/comm（端口复用后同一五元组可能换进程） */
			node->pid = pid;
			memcpy(node->comm, comm, TASK_COMM_LEN);
			spin_unlock_irqrestore(&ecap_nf_lock, flags);
			return;
		}
	}

	if (atomic_read(&ecap_nf_cnt) >= NF_CONN_MAX) {
		spin_unlock_irqrestore(&ecap_nf_lock, flags);
		return;
	}

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (node) {
		node->key = *key;
		node->pid = pid;
		memcpy(node->comm, comm, TASK_COMM_LEN);
		hash_add(ecap_nf_tbl, &node->hnode, h);
		atomic_inc(&ecap_nf_cnt);
	}

	spin_unlock_irqrestore(&ecap_nf_lock, flags);
}

/* 查表。可在软中断上下文调用。 */
static bool ecap_nf_lookup(const struct ecap_nf_key *key, u32 *pid, char *comm)
{
	struct ecap_nf_node *node;
	unsigned long flags;
	bool found = false;
	u32 h = ecap_nf_hash(key);

	spin_lock_irqsave(&ecap_nf_lock, flags);
	hash_for_each_possible(ecap_nf_tbl, node, hnode, h) {
		if (!memcmp(&node->key, key, sizeof(*key))) {
			*pid = node->pid;
			memcpy(comm, node->comm, TASK_COMM_LEN);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ecap_nf_lock, flags);
	return found;
}

static void ecap_nf_delete(const struct ecap_nf_key *key)
{
	struct ecap_nf_node *node;
	unsigned long flags;
	u32 h = ecap_nf_hash(key);

	spin_lock_irqsave(&ecap_nf_lock, flags);
	hash_for_each_possible(ecap_nf_tbl, node, hnode, h) {
		if (!memcmp(&node->key, key, sizeof(*key))) {
			hash_del(&node->hnode);
			atomic_dec(&ecap_nf_cnt);
			spin_unlock_irqrestore(&ecap_nf_lock, flags);
			/*
			 * kfree 放在锁外：虽然 kfree 本身不会睡眠，
			 * 但放锁外能缩短临界区，减少网络栈的等待。
			 */
			kfree(node);
			return;
		}
	}
	spin_unlock_irqrestore(&ecap_nf_lock, flags);
}

static void ecap_nf_clear(void)
{
	struct ecap_nf_node *node;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&ecap_nf_lock, flags);
	hash_for_each_safe(ecap_nf_tbl, bkt, tmp, node, hnode) {
		hash_del(&node->hnode);
		kfree(node);
	}
	atomic_set(&ecap_nf_cnt, 0);
	spin_unlock_irqrestore(&ecap_nf_lock, flags);
}

/* dst = src 的源/目的交换版本（收包方向反查用） */
static void ecap_nf_reverse(const struct ecap_nf_key *src,
			    struct ecap_nf_key *dst)
{
	*dst = *src;
	dst->sport = src->dport;
	dst->dport = src->sport;
	if (src->ip_ver == 4) {
		dst->saddr4 = src->daddr4;
		dst->daddr4 = src->saddr4;
	} else {
		memcpy(dst->saddr6, src->daddr6, 16);
		memcpy(dst->daddr6, src->saddr6, 16);
	}
}

/* ---------------- Kprobe：给连接打标签 ---------------- */

/*
 * 从 struct sock 填充归因键。
 *
 * 【字节序处理 —— 本文件最需要小心的地方】
 *   sk->sk_num   是主机序的 __u16（本地端口）
 *   sk->sk_dport 是网络序的 __be16（对端端口）
 * Netfilter 侧从 TCP 头读到的是网络序，统一 ntohs 后是主机序。
 * 所以这里也要统一成主机序，memcmp 才能逐字节相等。
 */
static int ecap_nf_trace_sendmsg(struct sock *sk, u8 proto)
{
	struct ecap_nf_key key = { 0 };
	char comm[TASK_COMM_LEN] = { 0 };

	if (!sk)
		return 0;

	key.proto = proto;
	if (sk->sk_family == AF_INET) {
		key.ip_ver = 4;
		key.saddr4 = sk->sk_rcv_saddr;
		key.daddr4 = sk->sk_daddr;
	} else if (sk->sk_family == AF_INET6) {
		key.ip_ver = 6;
		memcpy(key.saddr6, &sk->sk_v6_rcv_saddr, 16);
		memcpy(key.daddr6, &sk->sk_v6_daddr, 16);
	} else {
		return 0;
	}

	key.sport = sk->sk_num;
	key.dport = ntohs(sk->sk_dport);
	if (!key.sport || !key.dport)
		return 0;

	memcpy(comm, current->comm, TASK_COMM_LEN);
	ecap_nf_upsert(&key, (u32)task_tgid_nr(current), comm);
	return 0;
}

static int ecap_nf_kp_tcp_pre(struct kprobe *p, struct pt_regs *regs)
{
	return ecap_nf_trace_sendmsg((struct sock *)regs->regs[0], IPPROTO_TCP);
}

static int ecap_nf_kp_udp_pre(struct kprobe *p, struct pt_regs *regs)
{
	return ecap_nf_trace_sendmsg((struct sock *)regs->regs[0], IPPROTO_UDP);
}

static struct kprobe ecap_nf_kp_tcp = {
	.symbol_name = "tcp_sendmsg",
	.pre_handler = ecap_nf_kp_tcp_pre,
};

static struct kprobe ecap_nf_kp_udp = {
	.symbol_name = "udp_sendmsg",
	.pre_handler = ecap_nf_kp_udp_pre,
};

static bool ecap_nf_kprobes_registered;

/* ---------------- Netfilter：解析 + 查表 + 入队 ---------------- */

/*
 * 解析 L3 头，填充协议/地址，返回 L4 偏移。
 * false = 不关心这个包（非目标协议、分片、头非法）。
 */
static bool ecap_nf_parse_l3(struct sk_buff *skb, struct ecap_nf_key *k,
			     int *l4_off)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr _iph, *iph;

		iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
		if (!iph || iph->ihl < 5)
			return false;
		/* 分片包没有完整 L4 头，跳过 */
		if (iph->frag_off & htons(0x3fff))
			return false;
		if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
			return false;

		k->ip_ver = 4;
		k->proto = iph->protocol;
		k->saddr4 = iph->saddr;
		k->daddr4 = iph->daddr;
		*l4_off = iph->ihl * 4;
		return true;
	}

	if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr _ip6h, *ip6h;

		ip6h = skb_header_pointer(skb, 0, sizeof(_ip6h), &_ip6h);
		if (!ip6h)
			return false;
		/* 不追扩展头链：nexthdr 必须直接是 TCP/UDP */
		if (ip6h->nexthdr != IPPROTO_TCP &&
		    ip6h->nexthdr != IPPROTO_UDP)
			return false;

		k->ip_ver = 6;
		k->proto = ip6h->nexthdr;
		memcpy(k->saddr6, &ip6h->saddr, 16);
		memcpy(k->daddr6, &ip6h->daddr, 16);
		*l4_off = sizeof(struct ipv6hdr);
		return true;
	}

	return false;
}

/* TCP 与 UDP 头前 4 字节都是 sport/dport，共用 tcphdr 读取 */
static bool ecap_nf_parse_l4(struct sk_buff *skb, int l4_off,
			     struct ecap_nf_key *k)
{
	struct tcphdr _th, *th;

	th = skb_header_pointer(skb, l4_off, 4, &_th);
	if (!th)
		return false;

	k->sport = ntohs(th->source);
	k->dport = ntohs(th->dest);
	return true;
}

/* TCP flags 在第 13 字节，bit1 = SYN；tcphdr 里是位域，不能用 offsetof */
static bool ecap_nf_is_tcp_syn(struct sk_buff *skb, int l4_off)
{
	u8 flags = 0;

	if (skb_copy_bits(skb, l4_off + 13, &flags, 1))
		return false;
	return !!(flags & 0x02);
}

/*
 * 组装并提交一个 PACKET 事件。
 *
 * 【为什么要先拷到临时缓冲】
 * skb 的数据可能在非线性区（frags），不能直接取指针。
 * skb_copy_bits 会正确处理这种情况。而我们要么两次调用（先算长度再拷），
 * 要么一次拷到足够大的缓冲再截断。这里选后者，简单且只走一次 skb 遍历。
 *
 * 【为什么 payload = meta + 帧数据】
 * 用户态需要五元组来把包归属到连接，也需要原始帧来写 pcapng 的 EPB。
 * 放在一起省一次事件、也保证两者时间戳一致。
 */
static void ecap_nf_emit(struct sk_buff *skb, const struct ecap_nf_key *k,
			 const char *comm, u32 pid, u8 direction)
{
	struct ecap_pkt_meta *meta;
	struct ecap_blob b;
	u8 *buf;
	u32 cap, off;
	size_t total;
	int ret;

	/*
	 * 抓取长度按 ECAP_PKT_SNAPLEN 截断。
	 * 完整帧可能 64KB（巨型帧），但我们只需要前 1KB 就能看清
	 * L4 头 + TLS record 头 + 部分应用数据。pcapng 里会记 origlen，
	 * Wireshark 显示为 "captured 1024, on-wire 64000"。
	 */
	cap = min_t(u32, (u32)skb->len, ECAP_PKT_SNAPLEN);
	total = sizeof(struct ecap_pkt_meta) + cap;

	/* 必须 ≤ 槽容量。ECAP_PKT_META_LEN(48) + SNAPLEN(1024) = 1072，安全。 */
	if (total > ECAP_PAYLOAD_MAX) {
		cap = ECAP_PAYLOAD_MAX - sizeof(struct ecap_pkt_meta);
		total = sizeof(struct ecap_pkt_meta) + cap;
	}

	buf = kmalloc(total, GFP_ATOMIC);
	if (!buf) {
		atomic64_inc(&ecap_nf_stat_skipped);
		return;
	}

	meta = (struct ecap_pkt_meta *)buf;
	memset(meta, 0, sizeof(*meta));
	meta->ip_version = k->ip_ver;
	meta->proto = k->proto;
	meta->direction = direction;
	meta->sport = k->sport;
	meta->dport = k->dport;
	if (k->ip_ver == 4) {
		meta->saddr4 = k->saddr4;
		meta->daddr4 = k->daddr4;
	} else {
		memcpy(meta->saddr6, k->saddr6, 16);
		memcpy(meta->daddr6, k->daddr6, 16);
	}
	meta->caplen = cap;
	meta->origlen = skb->len;

	off = sizeof(struct ecap_pkt_meta);
	if (cap && skb_copy_bits(skb, 0, buf + off, cap)) {
		kfree(buf);
		atomic64_inc(&ecap_nf_stat_skipped);
		return;
	}

	memset(&b, 0, sizeof(b));
	b.type = ECAP_EV_PACKET;
	b.dir = direction;
	b.tgid = pid;
	b.tid = pid; /* 收包方向拿不到真实 tid，用 tgid 代替 */
	b.uid = 0;
	memcpy(b.comm, comm, ECAP_COMM_LEN);
	b.len = (u32)total;
	b.data = buf;

	ret = ecap_push(&b);
	kfree(buf);

	if (ret == 0)
		atomic64_inc(&ecap_nf_stat_pushed);
	else
		atomic64_inc(&ecap_nf_stat_skipped);
}

/*
 * Netfilter hook 主体。
 *
 * 运行上下文：LOCAL_OUT 通常是进程上下文，LOCAL_IN 是软中断。
 * 绝对不能睡眠。
 */
static unsigned int ecap_nf_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct ecap_nf_key key = { 0 }, rev = { 0 };
	char comm[TASK_COMM_LEN] = { 0 };
	u32 pid = 0;
	u8 direction;
	bool hit;
	int l4_off = 0;

	atomic64_inc(&ecap_nf_stat_seen);

	/* 1) 解析五元组 */
	if (!ecap_nf_parse_l3(skb, &key, &l4_off)) {
		atomic64_inc(&ecap_nf_stat_skipped);
		if (atomic64_read(&ecap_nf_stat_skipped) < 3)
			pr_info(NF_TAG "hook: L3 parse failed proto=0x%04x\n",
				skb->protocol);
		return NF_ACCEPT;
	}
	if (!ecap_nf_parse_l4(skb, l4_off, &key)) {
		atomic64_inc(&ecap_nf_stat_skipped);
		if (atomic64_read(&ecap_nf_stat_skipped) < 6)
			pr_info(NF_TAG "hook: L4 parse failed off=%d len=%u\n",
				l4_off, skb->len);
		return NF_ACCEPT;
	}

	/* 2) 端口过滤 */
	if (ecap_nf_port && key.sport != ecap_nf_port &&
	    key.dport != ecap_nf_port) {
		atomic64_inc(&ecap_nf_stat_skipped);
		return NF_ACCEPT;
	}

	if (l4_off >= skb->len) {
		atomic64_inc(&ecap_nf_stat_skipped);
		return NF_ACCEPT;
	}

	/* 3) TCP SYN = 新握手，清掉端口复用的旧记录 */
	if (key.proto == IPPROTO_TCP && ecap_nf_is_tcp_syn(skb, l4_off)) {
		ecap_nf_delete(&key);
		ecap_nf_reverse(&key, &rev);
		ecap_nf_delete(&rev);
	}

	/*
	 * 4) 查表归因。
	 *
	 * 正向命中 = 我们发出的包（LOCAL_OUT）
	 * 反向命中 = 发给我们的包（LOCAL_IN）
	 *
	 * 【为什么用 state->hook 而不是查表结果判断方向】
	 * LOCAL_OUT 的包在归因表里一定是正向；
	 * LOCAL_IN 的包一定是以"远端→本机"的形式出现，而表里存的是
	 * "本机→远端"，所以要反向查。
	 * 用 hook 点判断比猜更可靠。
	 */
	direction = (state->hook == NF_INET_LOCAL_OUT) ? ECAP_PKT_OUT
						      : ECAP_PKT_IN;

	if (direction == ECAP_PKT_OUT) {
		hit = ecap_nf_lookup(&key, &pid, comm);
	} else {
		ecap_nf_reverse(&key, &rev);
		hit = ecap_nf_lookup(&rev, &pid, comm);
	}

	/*
	 * 收包方向偶尔能在进程上下文（本地回环、loopback 的 IN 在
	 * 发送者上下文里）。这时 current 是有意义的，优先用它 ——
	 * 比归因表更准（表里可能因为 SYN 被清掉而过期）。
	 */
	if (!hit && direction == ECAP_PKT_OUT) {
		pid = (u32)task_tgid_nr(current);
		memcpy(comm, current->comm, TASK_COMM_LEN);
		hit = true;
	}

	if (!hit) {
		/* 归因不到进程（比如模块加载前就建立的长连接），照样抓包，
		 * 只是 pid=0。丢掉这些包会让抓包不完整。 */
		pid = 0;
		memcpy(comm, "?", 2);
	}

	/* 5) 提交事件 */
	{
		u64 before = ecap_nf_pkt_pushed();

		ecap_nf_emit(skb, &key, comm, pid, direction);
		if (ecap_nf_pkt_pushed() == before &&
		    atomic64_read(&ecap_nf_stat_skipped) < 10)
			pr_info(NF_TAG "hook: emit failed sp=%u dp=%u len=%u\n",
				key.sport, key.dport, skb->len);
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops ecap_nf_ops[] = {
	{ .hook = ecap_nf_hook, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_LOCAL_IN,  .priority = NF_IP_PRI_FIRST },
	{ .hook = ecap_nf_hook, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP_PRI_FIRST },
	{ .hook = ecap_nf_hook, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_LOCAL_IN,  .priority = NF_IP6_PRI_FIRST },
	{ .hook = ecap_nf_hook, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP6_PRI_FIRST },
};

/* ---------------- 启用 / 停用 ---------------- */

int ecap_nf_enable(u32 port)
{
	int ret;

	if (ecap_nf_active) {
		/* 已启用：允许改端口，先停再启 */
		ecap_nf_disable();
	}

	ecap_nf_port = port;

	/* 先注册 kprobe（归因表的数据来源），再挂 hook（消费者）。
	 * 注意：unregister_kprobe 不会清掉 kp.addr/flags，再次注册前必须重置，
	 * 否则 register_kprobe 会因为 symbol_name && addr 同时非空而返回 -EINVAL。 */
	ecap_nf_kp_tcp.addr = NULL;
	ecap_nf_kp_tcp.flags = 0;
	ret = register_kprobe(&ecap_nf_kp_tcp);
	if (ret) {
		pr_err(NF_TAG "register kprobe tcp_sendmsg failed: %d\n", ret);
		return ret;
	}
	ecap_nf_kp_udp.addr = NULL;
	ecap_nf_kp_udp.flags = 0;
	ret = register_kprobe(&ecap_nf_kp_udp);
	if (ret) {
		pr_err(NF_TAG "register kprobe udp_sendmsg failed: %d\n", ret);
		unregister_kprobe(&ecap_nf_kp_tcp);
		return ret;
	}
	ecap_nf_kprobes_registered = true;

	ret = nf_register_net_hooks(&init_net, ecap_nf_ops,
				    ARRAY_SIZE(ecap_nf_ops));
	if (ret) {
		pr_err(NF_TAG "nf_register_net_hooks failed: %d\n", ret);
		unregister_kprobe(&ecap_nf_kp_udp);
		unregister_kprobe(&ecap_nf_kp_tcp);
		ecap_nf_kprobes_registered = false;
		return ret;
	}

	ecap_nf_active = true;
	pr_info(NF_TAG "netfilter capture enabled: port=%u (0 = all)\n", port);
	return 0;
}

void ecap_nf_disable(void)
{
	if (!ecap_nf_active)
		return;

	/*
	 * 顺序与 enable 相反：先摘 hook（不再产生新事件），
	 * 再摘 kprobe（不再往表里写），最后清表。
	 */
	nf_unregister_net_hooks(&init_net, ecap_nf_ops,
				ARRAY_SIZE(ecap_nf_ops));

	if (ecap_nf_kprobes_registered) {
		unregister_kprobe(&ecap_nf_kp_udp);
		unregister_kprobe(&ecap_nf_kp_tcp);
		ecap_nf_kprobes_registered = false;
	}

	ecap_nf_clear();
	ecap_nf_active = false;

	pr_info(NF_TAG "netfilter capture disabled, released %d conn entries\n",
		atomic_read(&ecap_nf_cnt));
}

bool ecap_nf_is_enabled(void)
{
	return ecap_nf_active;
}
