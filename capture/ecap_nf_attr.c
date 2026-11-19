// SPDX-License-Identifier: Apache-2.0
/*
 * ecap_nf_attr.c - Netfilter 抓包 + Kprobe 进程归因（第二步）
 *
 * 相比第一步（ecap_nf_dump.c）只多了一件事：归因表。
 *
 *   进程上下文                      网络上下文
 *   ─────────                       ─────────
 *   kprobe tcp_sendmsg(sk)  ─┐
 *   kprobe udp_sendmsg(sk)  ─┴──> 哈希表: 五元组 -> {pid, comm}
 *                                        │
 *   Netfilter LOCAL_IN/OUT(skb) ──> 解析五元组 ──> 正向/反向查表 ──> pr_info
 *
 * 这样 LOCAL_IN（软中断上下文，current 是 ksoftirqd）也能报告真实业务进程。
 * 仍然没有字符设备 / kfifo / ioctl，所有输出走 pr_info + 私有限速。
 *
 * 编译与加载：
 *   make ... M=$PWD ecap_nf_attr.ko
 *   insmod ecap_nf_attr.ko target_port=443 verbose=1
 *   dmesg -w | grep ecap_nf
 *
 * 命名约定：本文件所有文件作用域标识符都带 nfattr_ 前缀，
 * 避免与内核已有符号冲突（例如 netfilter.h 里的 static inline nf_hook()、
 * hashtable.h 里的 HASH_BITS(name) 宏、list.h 里的 list_* 等）。
 *
 * 已知限制：
 *   - 只挂 init_net，不覆盖 VPN / 独立 netns。
 *   - 不追 IPv6 扩展头，跳过 IPv4 分片。
 *   - 归因表只在 sendmsg 时写入，"模块加载前已建立的长连接"抓不到 pid。
 *   - 表满（4096 条）后新连接不再入表；TCP 见 SYN 会清掉同五元组的旧记录。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
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
#include <net/sock.h>
#include <net/net_namespace.h>

#define NFATTR_TAG       "ecap_nf: "
#define NFATTR_SNAPLEN   256
#define NFATTR_CONN_MAX  4096
#define NFATTR_HASH_BITS 10    /* 2^10 = 1024 个桶 */

/* 包打印限速：每秒 10 条（printk 有全局锁，不限速会拖垮网络栈） */
static DEFINE_RATELIMIT_STATE(nfattr_pkt_rs, HZ, 10);

/* ---------------- 模块参数 ---------------- */

/* 0 表示不按端口过滤 */
static unsigned int nfattr_target_port __read_mostly = 443;
module_param_named(target_port, nfattr_target_port, uint, 0444);
MODULE_PARM_DESC(target_port, "Only dump packets matching this port (0 = no filter)");

/* 0=只打五元组 1=加 hexdump */
static unsigned int nfattr_verbose;
module_param_named(verbose, nfattr_verbose, uint, 0444);
MODULE_PARM_DESC(verbose, "1 = also hexdump L4 header and payload");

/* 0 表示不按进程过滤 */
static unsigned int nfattr_target_pid;
module_param_named(target_pid, nfattr_target_pid, uint, 0444);
MODULE_PARM_DESC(target_pid, "Only dump packets attributed to this TGID (0 = no filter)");

/* ---------------- 五元组与归因表 ---------------- */

struct nfattr_conn_key {
	u8   ip_ver;
	u8   proto;
	u16  sport;   /* 主机序 */
	u16  dport;   /* 主机序 */
	__be32 saddr4;
	__be32 daddr4;
	u8   saddr6[16];
	u8   daddr6[16];
};

struct nfattr_conn_node {
	struct hlist_node hnode;
	struct nfattr_conn_key key;
	u32  pid;
	char comm[TASK_COMM_LEN];
};

/*
 * DEFINE_HASHTABLE 会创建 hlist_head nfattr_conn_tbl[1 << NFATTR_HASH_BITS]。
 * 注意：hash_add() / hash_for_each_possible() 这类宏的最后一个参数是「原始 key」，
 * 宏内部会用 hash_min(key, HASH_BITS(name)) 自己算桶号。因此这里返回未压缩的
 * 32 位哈希值，不要在外面再算一次桶号（否则会把桶号当成 key 做二次哈希）。
 */
static DEFINE_HASHTABLE(nfattr_conn_tbl, NFATTR_HASH_BITS);
static DEFINE_SPINLOCK(nfattr_conn_lock);
static unsigned int nfattr_conn_cnt;

static u32 nfattr_conn_hash(const struct nfattr_conn_key *k)
{
	u32 h = ((u32)k->proto << 16) ^ ((u32)k->sport << 8) ^ k->dport;

	if (k->ip_ver == 4)
		h ^= k->saddr4 ^ k->daddr4;
	else
		h ^= *(const u32 *)k->saddr6 ^ *(const u32 *)k->daddr6;

	return h;
}

/* 插入或更新一条归因记录。kprobe 上下文，不能睡眠。 */
static void nfattr_conn_upsert(const struct nfattr_conn_key *key, u32 pid,
			       const char *comm)
{
	struct nfattr_conn_node *node;
	unsigned long flags;
	u32 h = nfattr_conn_hash(key);

	spin_lock_irqsave(&nfattr_conn_lock, flags);

	hash_for_each_possible(nfattr_conn_tbl, node, hnode, h) {
		if (!memcmp(&node->key, key, sizeof(*key))) {
			node->pid = pid;
			memcpy(node->comm, comm, TASK_COMM_LEN);
			spin_unlock_irqrestore(&nfattr_conn_lock, flags);
			return;
		}
	}

	if (nfattr_conn_cnt >= NFATTR_CONN_MAX) {
		spin_unlock_irqrestore(&nfattr_conn_lock, flags);
		return;
	}

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (node) {
		node->key = *key;
		node->pid = pid;
		memcpy(node->comm, comm, TASK_COMM_LEN);
		hash_add(nfattr_conn_tbl, &node->hnode, h);
		nfattr_conn_cnt++;
	}

	spin_unlock_irqrestore(&nfattr_conn_lock, flags);
}

/* 查表。命中返回 true 并回填 pid/comm。可在软中断上下文调用。 */
static bool nfattr_conn_lookup(const struct nfattr_conn_key *key, u32 *pid,
			       char *comm)
{
	struct nfattr_conn_node *node;
	unsigned long flags;
	bool found = false;
	u32 h = nfattr_conn_hash(key);

	spin_lock_irqsave(&nfattr_conn_lock, flags);
	hash_for_each_possible(nfattr_conn_tbl, node, hnode, h) {
		if (!memcmp(&node->key, key, sizeof(*key))) {
			*pid = node->pid;
			memcpy(comm, node->comm, TASK_COMM_LEN);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&nfattr_conn_lock, flags);
	return found;
}

static void nfattr_conn_delete(const struct nfattr_conn_key *key)
{
	struct nfattr_conn_node *node;
	unsigned long flags;
	u32 h = nfattr_conn_hash(key);

	spin_lock_irqsave(&nfattr_conn_lock, flags);
	hash_for_each_possible(nfattr_conn_tbl, node, hnode, h) {
		if (!memcmp(&node->key, key, sizeof(*key))) {
			hash_del(&node->hnode);
			kfree(node);
			nfattr_conn_cnt--;
			break;
		}
	}
	spin_unlock_irqrestore(&nfattr_conn_lock, flags);
}

static void nfattr_conn_clear(void)
{
	struct nfattr_conn_node *node;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&nfattr_conn_lock, flags);
	hash_for_each_safe(nfattr_conn_tbl, bkt, tmp, node, hnode) {
		hash_del(&node->hnode);
		kfree(node);
	}
	nfattr_conn_cnt = 0;
	spin_unlock_irqrestore(&nfattr_conn_lock, flags);
}

/* dst = src 的源/目的交换版本 */
static void nfattr_conn_reverse(const struct nfattr_conn_key *src,
				struct nfattr_conn_key *dst)
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

/* 取函数第一个参数（struct sock *sk） */
static inline struct sock *nfattr_first_arg(struct pt_regs *regs)
{
	return (struct sock *)regs->regs[0];
}

static int nfattr_trace_sendmsg(struct sock *sk, u8 proto)
{
	struct nfattr_conn_key key = {0};
	char comm[TASK_COMM_LEN] = {0};

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

	/*
	 * 字节序：sk_num 已是主机序（类型 __u16），sk_dport 是网络序（类型 __be16）。
	 * Netfilter 侧从 skb 读出的端口也都是网络序并统一 ntohs()，
	 * 因此这里必须统一成主机序，memcmp 才能逐字节相等。
	 */
	key.sport = sk->sk_num;
	key.dport = ntohs(sk->sk_dport);
	if (!key.sport || !key.dport)
		return 0;

	get_task_comm(comm, current);
	nfattr_conn_upsert(&key, (u32)task_tgid_nr(current), comm);
	return 0;
}

static int nfattr_kp_tcp_pre(struct kprobe *p, struct pt_regs *regs)
{
	return nfattr_trace_sendmsg(nfattr_first_arg(regs), IPPROTO_TCP);
}

static int nfattr_kp_udp_pre(struct kprobe *p, struct pt_regs *regs)
{
	return nfattr_trace_sendmsg(nfattr_first_arg(regs), IPPROTO_UDP);
}

static struct kprobe nfattr_kp_tcp_sendmsg = {
	.symbol_name = "tcp_sendmsg",
	.pre_handler = nfattr_kp_tcp_pre,
};

static struct kprobe nfattr_kp_udp_sendmsg = {
	.symbol_name = "udp_sendmsg",
	.pre_handler = nfattr_kp_udp_pre,
};

/* ---------------- Netfilter：解析 + 查表 + 打印 ---------------- */

/* 解析 L3 头，填充协议/地址，返回 L4 偏移。false = 不关心这个包。 */
static bool nfattr_parse_l3(struct sk_buff *skb, struct nfattr_conn_key *k,
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
		k->proto  = iph->protocol;
		k->saddr4 = iph->saddr;
		k->daddr4 = iph->daddr;
		*l4_off   = iph->ihl * 4;
		return true;
	}

	if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr _ip6h, *ip6h;

		ip6h = skb_header_pointer(skb, 0, sizeof(_ip6h), &_ip6h);
		if (!ip6h)
			return false;
		/* 不追扩展头链：nexthdr 必须直接是 TCP/UDP */
		if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
			return false;

		k->ip_ver = 6;
		k->proto  = ip6h->nexthdr;
		memcpy(k->saddr6, &ip6h->saddr, 16);
		memcpy(k->daddr6, &ip6h->daddr, 16);
		*l4_off   = sizeof(struct ipv6hdr);
		return true;
	}

	return false;
}

/* TCP 与 UDP 头前 4 字节都是 sport/dport，共用 tcphdr 读取 */
static bool nfattr_parse_l4(struct sk_buff *skb, int l4_off,
			    struct nfattr_conn_key *k)
{
	struct tcphdr _th, *th;

	th = skb_header_pointer(skb, l4_off, 4, &_th);
	if (!th)
		return false;

	k->sport = ntohs(th->source);
	k->dport = ntohs(th->dest);
	return true;
}

/* TCP flags 在第 13 字节，bit1=SYN；tcphdr 里是位域，不能用 offsetof */
static bool nfattr_is_tcp_syn(struct sk_buff *skb, int l4_off)
{
	u8 flags = 0;

	if (skb_copy_bits(skb, l4_off + 13, &flags, 1))
		return false;
	return !!(flags & 0x02);
}

static unsigned int nfattr_nf_hook(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	struct nfattr_conn_key key = {0}, rev = {0};
	char comm[TASK_COMM_LEN] = {0};
	u32 pid = 0;
	const char *dir, *who;
	int who_pid;
	int l4_off = 0;
	bool hit;

	/* 1) 解析五元组 */
	if (!nfattr_parse_l3(skb, &key, &l4_off))
		return NF_ACCEPT;
	if (!nfattr_parse_l4(skb, l4_off, &key))
		return NF_ACCEPT;

	/* 2) 端口过滤 */
	if (nfattr_target_port &&
	    key.sport != nfattr_target_port && key.dport != nfattr_target_port)
		return NF_ACCEPT;

	if (l4_off >= skb->len)
		return NF_ACCEPT;

	/* 3) TCP SYN = 新握手，清掉端口复用的旧记录 */
	if (key.proto == IPPROTO_TCP && nfattr_is_tcp_syn(skb, l4_off)) {
		nfattr_conn_delete(&key);
		nfattr_conn_reverse(&key, &rev);
		nfattr_conn_delete(&rev);
	}

	/* 4) 查表：正向 = 本机发出，反向 = 发给本机 */
	if (nfattr_conn_lookup(&key, &pid, comm)) {
		dir = "OUT";
		hit = true;
	} else {
		nfattr_conn_reverse(&key, &rev);
		hit = nfattr_conn_lookup(&rev, &pid, comm);
		dir = "IN ";
	}

	/* 5) 进程过滤 */
	if (nfattr_target_pid && (!hit || pid != nfattr_target_pid))
		return NF_ACCEPT;

	/* 6) 限速 */
	if (!__ratelimit(&nfattr_pkt_rs))
		return NF_ACCEPT;

	/* 7) 打印 */
	who     = hit ? comm : "?";
	who_pid = hit ? (int)pid : -1;

	if (key.ip_ver == 4)
		pr_info(NFATTR_TAG "%s pid=%d(%s) %pI4:%u -> %pI4:%u %s len=%u\n",
			dir, who_pid, who,
			(const __be32 *)&key.saddr4, key.sport,
			(const __be32 *)&key.daddr4, key.dport,
			key.proto == IPPROTO_TCP ? "TCP" : "UDP", skb->len);
	else
		pr_info(NFATTR_TAG "%s pid=%d(%s) [%pI6]:%u -> [%pI6]:%u %s len=%u\n",
			dir, who_pid, who,
			(const struct in6_addr *)key.saddr6, key.sport,
			(const struct in6_addr *)key.daddr6, key.dport,
			key.proto == IPPROTO_TCP ? "TCP" : "UDP", skb->len);

	/* 8) 可选 hexdump（从 L4 头开始） */
	if (nfattr_verbose) {
		u8 buf[NFATTR_SNAPLEN];
		unsigned int n = min_t(unsigned int, skb->len - l4_off,
				       NFATTR_SNAPLEN);

		if (!skb_copy_bits(skb, l4_off, buf, n))
			print_hex_dump(KERN_INFO, NFATTR_TAG "  ",
				       DUMP_PREFIX_OFFSET, 16, 1, buf, n, true);
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops nfattr_nf_ops[] = {
	{ .hook = nfattr_nf_hook, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_LOCAL_IN,  .priority = NF_IP_PRI_FIRST },
	{ .hook = nfattr_nf_hook, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP_PRI_FIRST },
	{ .hook = nfattr_nf_hook, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_LOCAL_IN,  .priority = NF_IP6_PRI_FIRST },
	{ .hook = nfattr_nf_hook, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP6_PRI_FIRST },
};

/* ---------------- 初始化与卸载 ---------------- */

static int __init nfattr_init(void)
{
	int ret;

	ret = register_kprobe(&nfattr_kp_tcp_sendmsg);
	if (ret) {
		pr_err(NFATTR_TAG "register kprobe tcp_sendmsg failed: %d\n", ret);
		return ret;
	}

	ret = register_kprobe(&nfattr_kp_udp_sendmsg);
	if (ret) {
		pr_err(NFATTR_TAG "register kprobe udp_sendmsg failed: %d\n", ret);
		goto err_udp;
	}

	ret = nf_register_net_hooks(&init_net, nfattr_nf_ops,
				    ARRAY_SIZE(nfattr_nf_ops));
	if (ret) {
		pr_err(NFATTR_TAG "nf_register_net_hooks failed: %d\n", ret);
		goto err_nf;
	}

	pr_info(NFATTR_TAG "loaded: port=%u pid=%u verbose=%u\n",
		nfattr_target_port, nfattr_target_pid, nfattr_verbose);
	return 0;

err_nf:
	unregister_kprobe(&nfattr_kp_udp_sendmsg);
err_udp:
	unregister_kprobe(&nfattr_kp_tcp_sendmsg);
	return ret;
}

static void __exit nfattr_exit(void)
{
	nf_unregister_net_hooks(&init_net, nfattr_nf_ops,
				ARRAY_SIZE(nfattr_nf_ops));
	unregister_kprobe(&nfattr_kp_udp_sendmsg);
	unregister_kprobe(&nfattr_kp_tcp_sendmsg);

	pr_info(NFATTR_TAG "unloaded, releasing %u conn entries\n",
		nfattr_conn_cnt);
	nfattr_conn_clear();
}

module_init(nfattr_init);
module_exit(nfattr_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eCapture LKM prototype");
MODULE_DESCRIPTION("Netfilter packet dump with kprobe process attribution");
MODULE_VERSION("0.2.0");
