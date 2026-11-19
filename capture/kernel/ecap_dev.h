/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_dev.h - /dev/ecap_tls 字符设备与内核->用户态事件通道
 */
#ifndef _ECAP_DEV_H_
#define _ECAP_DEV_H_

#include <linux/types.h>
#include "../include/ecap_uapi.h"

/*
 * 一条待入队事件。
 *
 * 调用方（uprobe handler / Netfilter hook / ioctl）填好这个结构，
 * 剩下的交给我们：拼事件头、检查长度、入队、唤醒读者。
 *
 * 【为什么不用参数列表】
 * 事件字段有 7 个，用结构体传参可以避免调用点写错顺序 —— 这类 bug
 * 在 pid/uid/tgid 三个 u32 相邻的情况下特别难查。
 */
struct ecap_blob {
	__u8 type;                      /* enum ecap_event_type */
	__u8 flags;                     /* ECAP_EV_FLAG_* */
	__u8 dir;                       /* ECAP_DIR_*，SSL_DATA 用 */
	__u8 pad;                       /* 显式填充，避免 -Wpadded 隐患 */
	__u32 tgid;
	__u32 tid;
	__u32 uid;
	char comm[ECAP_COMM_LEN];
	__u32 len;                      /* data 中有效字节数 */
	const void *data;               /* payload 源地址，可为 NULL */
};

/*
 * 入队一条事件。
 *
 * 可在任意上下文调用（包含软中断）：内部用 spin_lock_irqsave + GFP_ATOMIC，
 * 绝不睡眠。队列满时直接丢弃并累加 dropped，不会阻塞调用方。
 *
 * 返回 0 表示入队成功，-ENOSPC 表示队列满被丢弃。
 */
int ecap_push(const struct ecap_blob *b);

/* 把 payload 长度裁到槽容量以内，并置 TRUNC 标志。返回裁剪后的长度。 */
u32 ecap_clamp_len(u32 len, __u8 *flags);

/*
 * 队列统计（字节数）。供 ecap_nf.c 上报包队列状态用。
 * 注意这两个数指的是同一个事件队列 —— 包事件和明文事件共用它。
 */
u32 ecap_queue_used_bytes(void);
u32 ecap_queue_capacity_bytes(void);

int ecap_dev_init(void);
void ecap_dev_exit(void);

#endif /* _ECAP_DEV_H_ */
