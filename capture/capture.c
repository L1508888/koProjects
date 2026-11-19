

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/printk.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Android 13 GKI 5.10 开了 CONFIG_CFI_CLANG=y 且 CONFIG_CFI_PERMISSIVE 没开。
 * 通过 kallsyms_lookup_name() 拿到的函数地址再用类型化函数指针去调用，
 * 编译器会在调用点插入 CFI hash 检查；模块自己算出的 type id 和 vmlinux
 * 里目标函数挂载的 type id 不一定一致，不一致就 __cfi_check_fail -> panic。
 * 解决：把任何"先 kallsyms 取地址再间接调用"的函数都标 __nocfi。 */
#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

MODULE_LICENSE("GPL");

/* ---- 通过 kallsyms 解析未导出符号 ---- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

// int nf_register_net_hooks(struct net *net, const struct nf_hook_ops *reg,
// unsigned int n);
typedef int (*nf_register_net_hooks_t)(struct net *, const struct nf_hook_ops,
                                       unsigned int);

// void nf_unregister_net_hooks(struct net *net, const struct nf_hook_ops *reg,
// unsigned int n);
typedef int (*nf_unregister_net_hooks_t)(struct net *, const struct nf_hook_ops,
                                         unsigned int);

nf_register_net_hooks_t p_nf_register_net_hooks;
nf_unregister_net_hooks_t p_nf_unregister_net_hooks;

static unsigned long lookup_via_kprobe(const char *name) {
  struct kprobe k;
  unsigned long addr = 0;

  memset(&k, 0, sizeof(k));
  k.symbol_name = name;
  if (register_kprobe(&k) == 0) {
    addr = (unsigned long)k.addr;
    unregister_kprobe(&k);
  }
  return addr;
}

static int __nocfi resolve_kernel_symbols(void) {
  kallsyms_lookup_name_t kln;
  unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");

  if (!addr) {
    pr_err("break: cannot resolve kallsyms_lookup_name\n");
    return -ENOENT;
  }
  kln = (kallsyms_lookup_name_t)addr;

  p_nf_register_net_hooks =
      (nf_register_net_hooks_t)kln("nf_register_net_hooks");
  p_nf_unregister_net_hooks =
      (nf_unregister_net_hooks_t)kln("nf_unregister_net_hooks");

  if (!p_nf_register_net_hooks || !p_nf_unregister_net_hooks) {
    pr_err("break: missing symbols p_nf_register_net_hooks=%px "
           "p_nf_unregister_net_hooks=%px \n",
           p_nf_register_net_hooks, p_nf_unregister_net_hooks);
    return -ENOENT;
  }
  return 0;
}

struct ecap_conn_key {
  __u8 ip_version; /* 4 or 6 */
  __u8 proto;      /* IPPROTO_TCP / IPPROTO_UDP */
  __u16 sport;
  __u16 dport;
  __u32 saddr4;
  __u32 daddr4;
  __u8 saddr6[16];
  __u8 daddr6[16];
  const char *indev;
  const char *outdev;
};

unsigned int capture_nat_hook(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
  int l4_off = 0;
  static const char nulldevname[16] __attribute__((aligned(sizeof(long))));
  struct ecap_conn_key key;
  key.indev = state->in ? state->in->name : nulldevname;
  key.outdev = state->out ? state->out->name : nulldevname;
  if (skb->protocol == htons(ETH_P_IP)) {
    struct iphdr _iph, *iph;
    iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
    if (!iph) {
      return NF_ACCEPT;
    }
    if (iph->protocol != IPPROTO_TCP || iph->protocol != IPPROTO_UDP) {
      return NF_ACCEPT;
    }

    key.ip_version = 4;
    key.proto = iph->protocol;
    key.saddr4 = iph->saddr;
    key.daddr4 = iph->daddr;
    l4_off = iph->ihl * 4;
  } else if (skb->protocol == htons(ETH_P_IPV6)) {
    struct ipv6hdr _ip6h, *ip6h;
    ip6h = skb_header_pointer(skb, 0, sizeof(_ip6h), &_ip6h);
    if (!ip6h)
      return NF_ACCEPT;
    if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
      return NF_ACCEPT;

    key.ip_version = 6;
    key.proto = ip6h->nexthdr;
    memcpy(key.saddr6, &ip6h->saddr, 16);
    memcpy(key.daddr6, &ip6h->daddr, 16);
    l4_off = sizeof(struct ipv6hdr);
  } else {
    return NF_ACCEPT;
  }

  return NF_ACCEPT;
}

const struct nf_hook_ops my_nat_ops[] = {
    {
        .hook = capture_nat_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = capture_nat_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = capture_nat_hook,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = capture_nat_hook,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int kp_tcp_sendmsg_pre(struct kprobe *p, struct pt_regs *kregs){
    struct sock *sk = (struct sock *)regs->regs[0];
}



static int kp_udp_sendmsg_pre(struct kprobe *p, struct pt_regs *kregs){
    struct sock *sk = (struct sock *)regs->regs[0];
}


static struct kprobe g_kp_tcp_sendmsg = {
	.symbol_name = "tcp_sendmsg",
	.pre_handler = kp_tcp_sendmsg_pre,
};

static struct kprobe g_kp_udp_sendmsg = {
	.symbol_name = "udp_sendmsg",
	.pre_handler = kp_udp_sendmsg_pre,
};



/* ---------- 模块初始化 / 退出 ---------- */
static int __init
init_mod(void) {
  int ret;

  ret = resolve_kernel_symbols();
  if (ret) {
    return ret;
  }
  //  建立设备文件
  ret = misc_register(&ecap_tls_miscdev);
  if (ret) {
    return ret;
  }

  pr_info("capture: module loaded \n");
  return 0;
}

static void __nocfi __exit exit_mod(void) {
  /* 先摘 kprobe，确保不再有新的 req 入队；
   * 再 flush 把队列里在途的 install/uninstall 跑完，避免 release_bp 之后
   * 还有 worker 引用已释放的资源；最后销毁队列。 */

  pr_info("capture: module exit \n");
}

module_init(init_mod);
module_exit(exit_mod);