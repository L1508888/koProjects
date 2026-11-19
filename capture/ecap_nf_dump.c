// SPDX-License-Identifier: Apache-2.0
/*
 * ecap_nf_dump.c - 最简 Netfilter 抓包示例
 *
 * 只做一件事：在 IPv4/IPv6 的 LOCAL_IN / LOCAL_OUT 上挂 Hook，
 * 按协议（TCP/UDP）与端口过滤，然后用 pr_info / print_hex_dump 把
 * 五元组和载荷直接打到 dmesg。没有字符设备、没有 kprobe、没有 ioctl。
 *
 * 编译：
 *   make KDIR=/path/to/android12-5.10-out ARCH=arm64 LLVM=1
 * CROSS_COMPILE=aarch64-linux-gnu-
 *
 * 加载与观察：
 *   insmod ecap_nf_dump.ko target_port=443 verbose=1
 *   dmesg -w | grep ecap_nf
 *
 * 说明：
 *   - 只挂 init_net，不覆盖 VPN / 独立 netns。
 *   - 只解析 IP 头紧接 TCP/UDP 的情形，IPv6 扩展头与分片包直接跳过。
 *   - LOCAL_OUT 的 current 就是发包进程；LOCAL_IN 处于软中断上下文，
 *     current 可能是 ksoftirqd，因此 ingress 方向不报告 pid。
 */

#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/net_namespace.h>

#define NFDUMP_TAG "ecap_nf: "
#define NFDUMP_SNAPLEN 256

#define nfdump_info(fmt, ...) pr_info(NFDUMP_TAG fmt, ##__VA_ARGS__)

/* 独立的限速状态：每 1 秒最多 10 条，避免 printk 拖垮网络栈 */
static DEFINE_RATELIMIT_STATE(nfdump_rs, HZ, 10);

/* target_port = 0 表示不按端口过滤 */
static unsigned int target_port = 443;
module_param(target_port, uint, 0444);
MODULE_PARM_DESC(
    target_port,
    "Only dump packets whose src or dst port matches (0 = no filter)");

/* verbose = 1 时额外 hexdump L4 头与载荷 */
static unsigned int verbose;
module_param(verbose, uint, 0444);
MODULE_PARM_DESC(verbose,
                 "1 = hexdump L4 header and payload via print_hex_dump");

/* 五元组（IPv4 用 saddr4/daddr4，IPv6 用 saddr6/daddr6） */
struct nfdump_key {
  u8 ip_ver;
  u8 proto;
  u16 sport;
  u16 dport;
  __be32 saddr4;
  __be32 daddr4;
  struct in6_addr saddr6;
  struct in6_addr daddr6;
  const char *indev;
  const char *outdev;
};

/*
 * 解析 L3 头，填充协议与地址，并返回 L4 头的偏移。
 * 返回 false 表示这个包不用管（非目标协议、分片、头非法）。
 */
static bool nfdump_parse_l3(struct sk_buff *skb, struct nfdump_key *k,
                            int *l4_off) {
  if (skb->protocol == htons(ETH_P_IP)) {
    struct iphdr _iph, *iph;

    iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
    if (!iph || iph->ihl < 5)
      return false;

    /* 分片包（MF 或 offset 非零）没有完整的 L4 头，直接跳过 */
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
    if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
      return false;

    k->ip_ver = 6;
    k->proto = ip6h->nexthdr;
    k->saddr6 = ip6h->saddr;
    k->daddr6 = ip6h->daddr;
    *l4_off = sizeof(struct ipv6hdr);
    return true;
  }

  return false;
}

/* TCP 与 UDP 头的前 4 字节都是 sport/dport，可以共用 tcphdr 读取 */
static bool nfdump_parse_l4(struct sk_buff *skb, int l4_off,
                            struct nfdump_key *k) {
  struct tcphdr _th, *th;

  th = skb_header_pointer(skb, l4_off, 4, &_th);
  if (!th)
    return false;

  k->sport = ntohs(th->source);
  k->dport = ntohs(th->dest);
  return true;
}

static unsigned int nfdump_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state) {
  u8 buf[NFDUMP_SNAPLEN];
  struct nfdump_key k = {0};
  int l4_off = 0;
  int pid;

  static const char nulldevname[16] __attribute__((aligned(sizeof(long))));


  //	这其实是网卡的名称，WiFi 使用的网卡名称为 wlan0
  k.indev = state->in ? state->in->name : nulldevname;
  k.outdev = state->out ? state->out->name : nulldevname;

  /* 1) 解析五元组 */
  if (!nfdump_parse_l3(skb, &k, &l4_off))
    return NF_ACCEPT;
  if (!nfdump_parse_l4(skb, l4_off, &k))
    return NF_ACCEPT;

  /* 2) 端口过滤 */
  if (target_port && k.sport != target_port && k.dport != target_port)
    return NF_ACCEPT;

  if (l4_off >= skb->len)
    return NF_ACCEPT;

  /* 3) 限速：超出配额就完全不打印，也不做 hexdump 拷贝 */
  if (!__ratelimit(&nfdump_rs))
    return NF_ACCEPT;

  /* 4) 打印五元组 */
  if (state->hook == NF_INET_LOCAL_OUT) {
    pid = (int)task_tgid_nr(current);
    if (k.ip_ver == 4)
      nfdump_info("OUT pid=%d(%s) %pI4:%u -> %pI4:%u %s len=%u indev=%s, outdev=%s\n", pid,
                  current->comm, (const __be32 *)&k.saddr4, k.sport,
                  (const __be32 *)&k.daddr4, k.dport,
                  k.proto == IPPROTO_TCP ? "TCP" : "UDP", skb->len, k.indev, k.outdev);
    else
      nfdump_info("OUT pid=%d(%s) [%pI6]:%u -> [%pI6]:%u %s len=%u indev=%s, outdev=%s\n", pid,
                  current->comm, &k.saddr6, k.sport, &k.daddr6, k.dport,
                  k.proto == IPPROTO_TCP ? "TCP" : "UDP", skb->len, k.indev, k.outdev);
  } else {
    /* LOCAL_IN 在软中断上下文，current 是 ksoftirqd，pid 无意义 */
    if (k.ip_ver == 4)
      nfdump_info("IN  pid=-(-) %pI4:%u -> %pI4:%u %s len=%u indev=%s, outdev=%s\n",
                  (const __be32 *)&k.saddr4, k.sport, (const __be32 *)&k.daddr4,
                  k.dport, k.proto == IPPROTO_TCP ? "TCP" : "UDP", skb->len, k.indev, k.outdev);
    else
      nfdump_info("IN  pid=-(-) [%pI6]:%u -> [%pI6]:%u %s len=%u indev=%s, outdev=%s\n", &k.saddr6,
                  k.sport, &k.daddr6, k.dport,
                  k.proto == IPPROTO_TCP ? "TCP" : "UDP", skb->len, k.indev, k.outdev);
  }

  /* 5) 可选：打印从 L4 头开始的内容 */
  if (verbose) {
    unsigned int copy_len =
        min_t(unsigned int, skb->len - l4_off, NFDUMP_SNAPLEN);

    if (skb_copy_bits(skb, l4_off, buf, copy_len) == 0)
      print_hex_dump(KERN_INFO, NFDUMP_TAG "  ", DUMP_PREFIX_OFFSET, 16, 1, buf,
                     copy_len, true);
  }

  return NF_ACCEPT;
}

static const struct nf_hook_ops nfdump_ops[] = {
    {
        .hook = nfdump_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = nfdump_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = nfdump_hook,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP6_PRI_FIRST,
    },
    {
        .hook = nfdump_hook,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP6_PRI_FIRST,
    },
};

static int __init nfdump_init(void) {
  int ret;

  ret = nf_register_net_hooks(&init_net, nfdump_ops, ARRAY_SIZE(nfdump_ops));
  if (ret) {
    pr_err(NFDUMP_TAG "nf_register_net_hooks failed: %d\n", ret);
    return ret;
  }

  nfdump_info("loaded: port=%u verbose=%u\n", target_port, verbose);
  return 0;
}

static void __exit nfdump_exit(void) {
  nf_unregister_net_hooks(&init_net, nfdump_ops, ARRAY_SIZE(nfdump_ops));
  nfdump_info("unloaded\n");
}

module_init(nfdump_init);
module_exit(nfdump_exit);

MODULE_LICENSE("Dual Apache/GPL");
MODULE_AUTHOR("eCapture LKM prototype");
MODULE_DESCRIPTION("Minimal netfilter packet dump via pr_info");
MODULE_VERSION("0.1.0");
