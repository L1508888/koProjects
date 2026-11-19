/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_uprobe.h - uprobe 探测点管理
 */
#ifndef _ECAP_UPROBE_H_
#define _ECAP_UPROBE_H_

#include <linux/types.h>
#include "../include/ecap_uapi.h"

/* ioctl 入口：下发 / 删除探测点。进程上下文，可睡眠。 */
long ecap_uprobe_add(void __user *uarg);
long ecap_uprobe_del(void __user *uarg);

/* M3：成对注册/注销（同时挂 SSL_write 与 SSL_read） */
long ecap_uprobe_add_pair(void __user *uarg);
long ecap_uprobe_del_pair(void __user *uarg);

/* M3：pid/uid 过滤规则 */
long ecap_uprobe_set_filter(void __user *uarg);

/* 统计快照（给 ecap_dev.c 的 GET_STATS 用） */
__u64 ecap_uprobe_hits(void);
__u64 ecap_uprobe_copy_fails(void);
/* M3 统计 */
__u64 ecap_uprobe_filtered(void);
__u64 ecap_uprobe_read_hits(void);
__u64 ecap_uprobe_pending_miss(void);
/* 当前挂起表条目数（tid -> buf） */
u32 ecap_uprobe_pending_count(void);
/* M4 统计 */
__u64 ecap_uprobe_keylog_hits(void);
__u64 ecap_uprobe_keylog_bad(void);

int ecap_uprobe_init(void);

/*
 * 注销全部探测点并等待所有在途 handler 结束。
 *
 * 【为什么必须单独一个函数，而不是在 exit 里顺手做】
 * rmmod 的顺序极其敏感：必须先摘 hook，再放设备。否则一个正在
 * uprobe handler 里跑着的线程会往已经释放的队列里写数据。
 */
void ecap_uprobe_exit(void);

#endif /* _ECAP_UPROBE_H_ */
