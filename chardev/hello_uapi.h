/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hello_uapi.h - 内核态与用户态共享的 ABI 定义（UAPI）
 *
 * 【为什么单独放一个头文件】
 * 这个文件会被两边的代码同时 include：
 *   1. 内核模块 hello_chardev.c（__KERNEL__ 已定义）
 *   2. 用户态测试程序 test_hello.c（没有 __KERNEL__）
 * 因此这里只能包含"双方都认识"的东西：固定宽度整数、结构体、宏。
 * 绝不能 include <linux/xxx.h>，也不能出现指针类型 —— 用户态和内核态
 * 指针宽度/地址空间完全不同，结构体里放指针就是 ABI 灾难。
 */
#ifndef _HELLO_UAPI_H_
#define _HELLO_UAPI_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint8_t  __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* 一条消息能携带的最大载荷字节数 */
#define HELLO_MSG_MAX 64

/*
 * 一条消息。字段顺序刻意这样排：
 *   u64(8) u32(4) u32(4) u32(4) u32(4) u8[64]
 * 合计 88 字节，且没有任何隐式填充空洞。
 * 一旦这里改了字段顺序或宽度，内核与用户态的解释就会错位 —— 这就是
 * "二进制 ABI" 的含义，改动必须两边同时改，并且加测试。
 */
struct hello_msg {
	__u64 ts_ns;              /* 写入时刻（ktime_get_ns，单调时钟，非墙上时间） */
	__u32 pid;                /* 写入进程的 TGID */
	__u32 len;                /* data[] 中有效字节数，<= HELLO_MSG_MAX */
	__u32 seq;                /* 全局自增序号，便于发现丢消息 */
	__u32 reserved;           /* 显式保留，保证后续扩展不改布局 */
	__u8  data[HELLO_MSG_MAX];
};

/* 运行期统计，通过 ioctl 读取 */
struct hello_stats {
	__u64 opens;      /* open() 次数 */
	__u64 releases;   /* release() 次数 */
	__u64 reads;      /* 成功 read() 次数 */
	__u64 writes;     /* 成功 write() 次数 */
	__u64 ioctls;     /* 成功 ioctl() 次数 */
	__u64 msgs_in;    /* 入队消息总数 */
	__u64 msgs_out;   /* 出队消息总数 */
	__u64 dropped;    /* 队列满导致丢弃的次数 */
	__u32 queued;     /* 当前队列深度（快照） */
	__u32 slots;      /* 环形队列容量（槽位数） */
};

/* -------------------- ioctl 命令定义 -------------------- */

/*
 * 'H' 是"幻数"，用于区分不同驱动。同一个系统里所有驱动的幻数应当不同，
 * 否则一个驱动的 ioctl 可能被另一个驱动误认。
 * _IO/_IOR/_IOW/_IOWR 会把 方向、大小、类型、序号 编码进一个 32 位 cmd：
 *
 *   31..30  方向（_IOC_READ=2, _IOC_WRITE=1）
 *   29..16  数据大小（由 sizeof(type) 自动算出）
 *   15..8   类型（幻数）
 *    7..0   序号（nr）
 *
 * 注意：内核里必须完整比较 cmd（包含方向与大小），不能只比 _IOC_NR，
 * 否则用户态传错大小也能"通过"校验，导致 copy_from_user 越界。
 */
#define HELLO_IOC_MAGIC  'H'

#define HELLO_IOC_GET_STATS  _IOR(HELLO_IOC_MAGIC, 1, struct hello_stats)
#define HELLO_IOC_RESET      _IO(HELLO_IOC_MAGIC, 2)
#define HELLO_IOC_SET_ECHO   _IOW(HELLO_IOC_MAGIC, 3, __u32)
#define HELLO_IOC_GET_ECHO   _IOR(HELLO_IOC_MAGIC, 4, __u32)

#define HELLO_IOC_MAXNR      4

#endif /* _HELLO_UAPI_H_ */
