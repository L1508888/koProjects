/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_nf.h - Netfilter 抓包（路径 B 的包采集）
 */
#ifndef _ECAP_NF_H_
#define _ECAP_NF_H_

#include <linux/types.h>
#include "../include/ecap_uapi.h"

/*
 * 启用包抓取。
 *
 * @port : 只抓源或目的端口等于此值的包。0 = 不过滤。
 *
 * 返回 0 成功。重复调用会先卸载旧的 hook 再装新的（端口可改）。
 */
int ecap_nf_enable(u32 port);

/* 停用包抓取并注销所有 hook */
void ecap_nf_disable(void);

/* 当前是否在抓包 */
bool ecap_nf_is_enabled(void);

/* 统计 getter */
__u64 ecap_nf_pkt_seen(void);
__u64 ecap_nf_pkt_skipped(void);
__u64 ecap_nf_pkt_pushed(void);
u32 ecap_nf_queue_len(void);
u32 ecap_nf_queue_max(void);

#endif /* _ECAP_NF_H_ */
