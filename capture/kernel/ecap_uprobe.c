// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_uprobe.c - 用 uprobe 挂钩用户态 TLS 库，抓取明文
 *
 * 【本文件在 M2 阶段的职责】
 * 只实现路径 A 的第一半：hook SSL_write 的入口，把待发送的明文读出来。
 *
 *   SSL_write(SSL *ssl, const void *buf, int num)
 *      x0 = ssl, x1 = buf, x2 = num          (AAPCS64)
 *            ▲
 *            └── 入口就能拿到 buf，不需要等返回，也不需要按线程保存状态。
 *                这就是为什么先做 SSL_write：它是所有方向里最简单的一个。
 *
 * SSL_read 会复杂一些（要等返回才知道读到了多少字节），留给 M3。
 *
 * 【uprobe handler 的执行上下文 —— 这是本文件最关键的前提】
 * 很多人以为 uprobe handler 在"异常上下文"里跑，因此不能睡眠、不能用
 * copy_from_user。在本内核（arm64 5.10）上这个说法是错的：
 *
 *   BRK 异常  -> do_debug_exception -> brk_handler -> uprobe_pre_sstep_notifier
 *                （这里只是 set_thread_flag(TIF_UPROBE)，什么都不做）
 *   返回用户态前 -> el0_svc/ret_to_user -> uprobe_notify_resume
 *                -> handle_swbp -> handler_chain -> uc->handler()   ★
 *
 * 也就是说 handler 是在"即将返回用户态"的进程上下文里被调用的：
 * 可抢占、中断已打开、current 就是被探测的那个用户线程。
 * 因此 copy_from_user() 是安全的（内核自己 kernel/trace/trace_uprobe.c
 * 里的 probe_mem_read() 就是直接用 copy_from_user）。
 *
 * 但有一条限制必须记住：handler_chain() 全程持有 uprobe->register_rwsem
 * 的读锁。所以 handler 里不要做耗时操作，也不要在里面再注册/注销 uprobe
 * （那需要写锁，会自己把自己锁死）。
 *
 * 【指针标签（TBI/MTE）】
 * Android 11+ 用户态 ARM64 开启了 Top-Byte Ignore，传给 SSL_write 的 buf
 * 高 8 位可能带 tag。好消息是不用我们自己处理：arm64 的 raw_copy_from_user
 * 内部会调用 __uaccess_mask_ptr()，它先 untagged_addr() 再比较 addr_limit，
 * 所以带 tag 的指针能正常工作。
 * 但我们仍然显式去标签，原因有两个：
 *   1) 日志里打印出来的地址是人能看懂的（否则 0xb400... 会让人怀疑人生）；
 *   2) 后续要做 "buf 地址作为 key" 的比对时，带 tag 的地址无法直接比较。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/ptrace.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <linux/hash.h>

#include "ecap_uprobe.h"
#include "ecap_dev.h"
#include "ecap_ksym.h"

#define UP_TAG "ecap_tls: "

/*
 * SSL_write 原型：int SSL_write(SSL *ssl, const void *buf, int num)
 * BoringSSL / OpenSSL 一致。
 * AAPCS64 下前三个整型/指针参数依次在 x0/x1/x2。
 */
#define SSL_WRITE_ARG_SSL 0
#define SSL_WRITE_ARG_BUF 1
#define SSL_WRITE_ARG_NUM 2

static atomic64_t ecap_uprobe_stat_hits = ATOMIC64_INIT(0);
static atomic64_t ecap_uprobe_stat_copy_fail = ATOMIC64_INIT(0);
/* --- M3 新增 --- */
static atomic64_t ecap_uprobe_stat_filtered = ATOMIC64_INIT(0);
static atomic64_t ecap_uprobe_stat_read_hits = ATOMIC64_INIT(0);
static atomic64_t ecap_uprobe_stat_pending_miss = ATOMIC64_INIT(0);
/* --- M4 新增 --- */
static atomic64_t ecap_uprobe_stat_keylog_hits = ATOMIC64_INIT(0);
static atomic64_t ecap_uprobe_stat_keylog_bad = ATOMIC64_INIT(0);

__u64 ecap_uprobe_hits(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_hits);
}

__u64 ecap_uprobe_copy_fails(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_copy_fail);
}

/* M3 统计 getter，给 ecap_dev.c 的 GET_STATS 用 */
__u64 ecap_uprobe_filtered(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_filtered);
}

__u64 ecap_uprobe_read_hits(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_read_hits);
}

__u64 ecap_uprobe_pending_miss(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_pending_miss);
}

/* M4 统计 getter */
__u64 ecap_uprobe_keylog_hits(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_keylog_hits);
}

__u64 ecap_uprobe_keylog_bad(void)
{
	return (__u64)atomic64_read(&ecap_uprobe_stat_keylog_bad);
}

/* ------------------------------------------------------------------ */
/* 指针去标签                                                          */
/* ------------------------------------------------------------------ */

/*
 * 去掉 ARM64 用户态指针的高 8 位 tag。
 *
 * 和 eCapture 的 kern/openssl_untag.h 保持一致：掩掉 bit56..63。
 * 注意这里没有用内核的 untagged_addr() 宏，原因是我们拿到的是
 * pt_regs 里的裸 u64，不需要走 sign_extend64 那套 VA_BITS 相关逻辑，
 * 直接掩码更直观，也不会受 CONFIG_ARM64_VA_BITS 影响。
 */
#define ECAP_UNTAG_PTR(p) \
	((void __user *)((unsigned long)(p) & 0x00FFFFFFFFFFFFFFUL))

/* ------------------------------------------------------------------ */
/* 抓包过滤（M3）                                                       */
/* ------------------------------------------------------------------ */

/*
 * 过滤规则。
 *
 * 用 atomic 而不是加锁读：handler 在热路径上，每个 SSL_write/SSL_read
 * 都要判断一次。三个 u32 用 atomic_t 存，读取时不需要任何同步开销。
 *
 * 【为什么不做成"一个结构体 + RCU"】
 * 三个独立字段之间没有必须保持一致的关系（用户态也是逐条配置），
 * 极端情况下读到"新 tgid + 旧 uid"最多导致一次误过滤，
 * 不值得为此引入 RCU 或 seqlock 的复杂度。
 */
static atomic_t ecap_filter_tgid = ATOMIC_INIT(0);
static atomic_t ecap_filter_uid = ATOMIC_INIT(0);
static atomic_t ecap_filter_include_all = ATOMIC_INIT(1);

/*
 * 判断当前事件是否应该被采集。
 *
 * 在 handler 最开头调用，**在 copy_from_user 之前** —— 这是关键：
 * 不匹配就直接返回，一个字节都不拷，不给目标进程增加无谓开销。
 *
 * 返回 true 表示"要采集"。
 */
static bool ecap_filter_pass(void)
{
	int want_tgid = atomic_read(&ecap_filter_tgid);
	int want_uid = atomic_read(&ecap_filter_uid);

	if (atomic_read(&ecap_filter_include_all))
		return true;

	/*
	 * tgid 过滤：注意用 task_tgid_nr（不是 task_pid_nr）。
	 * 用户态说"我要抓 pid 1234"时，指的是进程 1234，
	 * 而这个进程的各个线程 tid 各不相同。
	 */
	if (want_tgid && want_tgid != (int)task_tgid_nr(current))
		return false;

	if (want_uid && want_uid != (int)__kuid_val(current_uid()))
		return false;

	return true;
}

/* ------------------------------------------------------------------ */
/* SSL_read 的挂起表（M3）                                              */
/* ------------------------------------------------------------------ */

/*
 * SSL_read 不能用"入口直接拷贝"的方式，必须等返回值。
 * 但 entry 和 ret_handler 之间需要一个地方传递 buf 指针 ——
 * 这就是这张表存在的原因。
 *
 * 【为什么按 tid 索引，而不是 tgid】
 * 同一个进程的多个线程会并发调用 SSL_read：
 *
 *   thread A: SSL_read(ssl, bufA, n)  → entry 记下 bufA
 *   thread B: SSL_read(ssl, bufB, n)  → entry 记下 bufB
 *   thread A: 返回 → 应该读 bufA
 *   thread B: 返回 → 应该读 bufB
 *
 * 如果用 tgid 索引，B 的 entry 会覆盖 A 的，A 的返回就会读到 bufB 的数据 ——
 * 典型的串包。用 tid（内核 pid）才能精确对应到线程。
 *
 * 【为什么不用 task_struct->utask 之类现成的字段】
 * 那是 uprobe 内核自己用的，我们不该碰。而且我们要存的是"应用层 buf"，
 * 语义上与 utask 无关。
 */

#define ECAP_PENDING_BITS 6          /* 2^6 = 64 个桶 */
/* ECAP_PENDING_MAX 定义在 ecap_uapi.h 里，因为它是 ABI 的一部分
 * （用户态通过 stats.pending_max 看到这个值） */

struct ecap_pending {
	struct hlist_node node;
	u32 tid;                 /* 索引键：线程 id */
	void __user *buf;        /* SSL_read 的输出缓冲 */
	u32 want;                /* 调用时的 num（上限提示） */
};

static DEFINE_HASHTABLE(ecap_pending_tbl, ECAP_PENDING_BITS);
static DEFINE_SPINLOCK(ecap_pending_lock);
static atomic_t ecap_pending_cnt = ATOMIC_INIT(0);

/*
 * 记录一条挂起项（entry 时调用）。
 *
 * 在 uprobe handler 里执行，**不能睡眠**，所以用 GFP_ATOMIC。
 *
 * 【同 tid 已有记录怎么办】
 * 正常情况下一个线程不会递归调 SSL_read（嵌套调用时 tid 相同），
 * 但为了不丢数据，这里选择"更新已有项"而不是"再插一条"：
 * 深层的调用会覆盖浅层的记录。极少数嵌套场景下可能读到错误 buf，
 * 但比内存泄漏或表膨胀好。
 */
static int ecap_pending_set(u32 tid, void __user *buf, u32 want)
{
	struct ecap_pending *p;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&ecap_pending_lock, flags);

	hash_for_each_possible(ecap_pending_tbl, p, node, tid) {
		if (p->tid == tid) {
			p->buf = buf;
			p->want = want;
			spin_unlock_irqrestore(&ecap_pending_lock, flags);
			return 0;
		}
	}

	if (atomic_read(&ecap_pending_cnt) >= ECAP_PENDING_MAX) {
		/* 表满：丢新的，不覆盖已有的。已有记录的 ret 还能正确配对。 */
		ret = -ENOSPC;
		spin_unlock_irqrestore(&ecap_pending_lock, flags);
		return ret;
	}

	/*
	 * GFP_ATOMIC 是因为本函数在 uprobe handler 里跑。
	 * 严格说 handler 在进程上下文可以睡眠，但为了不给目标线程的
	 * SSL 路径引入不可控的延迟，这里坚持用原子分配。
	 */
	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p) {
		spin_unlock_irqrestore(&ecap_pending_lock, flags);
		return -ENOMEM;
	}

	p->tid = tid;
	p->buf = buf;
	p->want = want;
	hash_add(ecap_pending_tbl, &p->node, tid);
	atomic_inc(&ecap_pending_cnt);

	spin_unlock_irqrestore(&ecap_pending_lock, flags);
	return 0;
}

/*
 * 取出并删除一条挂起项（ret_handler 时调用）。
 *
 * 返回 false 表示没找到 —— 这可能是：
 *   - entry 时表满没记上
 *   - 线程在 entry 和 ret 之间被换出后换了个 CPU，但 tid 不变，所以不会
 *   - entry handler 因为过滤被跳过了
 *
 * 无论哪种，都不是致命错误，只累加 pending_miss 计数。
 */
static bool ecap_pending_take(u32 tid, void __user **buf, u32 *want)
{
	struct ecap_pending *p;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&ecap_pending_lock, flags);
	hash_for_each_possible(ecap_pending_tbl, p, node, tid) {
		if (p->tid == tid) {
			*buf = p->buf;
			*want = p->want;
			hash_del(&p->node);
			atomic_dec(&ecap_pending_cnt);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ecap_pending_lock, flags);

	if (found)
		kfree(p);
	return found;
}

/* 清空整张表（模块卸载时） */
static void ecap_pending_clear(void)
{
	struct ecap_pending *p;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&ecap_pending_lock, flags);
	hash_for_each_safe(ecap_pending_tbl, bkt, tmp, p, node) {
		hash_del(&p->node);
		kfree(p);
	}
	atomic_set(&ecap_pending_cnt, 0);
	spin_unlock_irqrestore(&ecap_pending_lock, flags);
}

u32 ecap_uprobe_pending_count(void)
{
	return (u32)atomic_read(&ecap_pending_cnt);
}



/*
 * 一个已注册的探测点。
 *
 * 生命周期：
 *   add:  fget(fd) -> igrab(inode) -> uprobe_register -> 挂到链表
 *   del:  uprobe_unregister -> iput(inode) -> fput(file) -> 摘链 -> 释放
 *   exit: 遍历链表逐个走 del 的流程
 *
 * 【为什么要自己 igrab 再 iput】
 * uprobe_register 内部会给 inode 加引用（uprobe->inode = inode 之后靠
 * put_uprobe 释放），但那是在 uprobe 对象真正被回收时才放。为了让
 * "先注销 uprobe、再放 inode"这个顺序可控，我们自己额外持有一个引用，
 * 这样在 unregister 期间 inode 绝不会被回收。
 */
struct ecap_probe {
	struct list_head node;
	struct uprobe_consumer uc;
	struct inode *inode;
	struct file *file;     /* 只为持有 fput 的责任；register 后不再需要 */
	loff_t offset;
	u32 kind;
	u32 fd;
	bool registered;
};

/*
 * 全局探测点链表。
 *
 * 用 mutex 而不是 spinlock：add/del 只在 ioctl（进程上下文）里发生，
 * 而且 uprobe_register 内部自己会睡眠（down_write、分配内存）。
 *
 * 【handler 为什么不持这把锁】
 * handler 只读 uc 自身的内容（一个常量 kind），不遍历链表，
 * 所以它在 register_rwsem 保护下运行时不需要碰这里的 mutex。
 */
static LIST_HEAD(ecap_probes);
static DEFINE_MUTEX(ecap_probes_lock);
/* 保护 "还在跑的 handler 数量"，用于 exit 时等待在途 handler 退出 */
static atomic_t ecap_inflight = ATOMIC_INIT(0);
/* 在途计数归零时唤醒 unload 流程 */
static DECLARE_WAIT_QUEUE_HEAD(ecap_inflight_wq);

static void ecap_inflight_put(void)
{
	if (atomic_dec_and_test(&ecap_inflight))
		wake_up(&ecap_inflight_wq);
}

/* ------------------------------------------------------------------ */
/* uprobe handler                                                      */
/* ------------------------------------------------------------------ */

/*
 * 从用户态缓冲拷贝明文并入队。write / read 两条路径共用。
 *
 * @ubuf  : 已去标签的用户态缓冲
 * @want  : 想拷的字节数（调用方已截到 ECAP_PAYLOAD_MAX）
 * @limit : 调用方原始请求的长度，用于判断是否发生截断
 * @dir   : ECAP_DIR_WRITE / ECAP_DIR_READ
 *
 * 返回入队结果（0 成功，负值为错误码），失败已自行计数。
 *
 * 【为什么抽成函数】
 * SSL_write 和 SSL_read 的"拷贝 + 组装 blob + 入队"完全一样，
 * 只有"从哪里拿 buf"和"拷多少"不同。抽出来避免两份几乎相同的
 * 代码各自演化（那种重复最容易改了一边忘了另一边）。
 */
static int ecap_emit_plaintext(void __user *ubuf, size_t want, size_t limit,
			       u8 dir)
{
	struct ecap_blob b;
	unsigned long left;
	void *kbuf;
	size_t got;
	int ret;

	/*
	 * 内核栈只有 16KB，且这里可能要拷 4KB，所以缓冲必须从堆上拿。
	 * GFP_ATOMIC 是因为 handler 上下文虽然可睡眠，但为了不给
	 * 目标线程的 SSL 路径引入不可控的回收延迟，这里宁可用原子分配。
	 */
	kbuf = kmalloc(want, GFP_ATOMIC);
	if (unlikely(!kbuf)) {
		atomic64_inc(&ecap_uprobe_stat_copy_fail);
		return -ENOMEM;
	}

	/*
	 * copy_from_user 会返回"没能拷贝的字节数"。
	 *
	 * 这里刻意只调用一次：用户态 buffer 跨页且后一页未映射时，前一次
	 * 调用可能已经拷到一部分字节（raw_copy_from_user 允许短拷贝），
	 * 再调一次既浪费又会把两次结果混在一起。用返回值倒推已经拿到了多少。
	 */
	left = copy_from_user(kbuf, ubuf, want);
	if (left) {
		got = want - left;
		atomic64_inc(&ecap_uprobe_stat_copy_fail);
	} else {
		got = want;
	}

	if (got == 0) {
		kfree(kbuf);
		return -EFAULT;
	}

	memset(&b, 0, sizeof(b));
	b.type = ECAP_EV_SSL_DATA;
	b.dir = dir;
	b.tgid = (u32)task_tgid_nr(current);
	b.tid = (u32)task_pid_nr(current);
	b.uid = __kuid_val(current_uid());
	memcpy(b.comm, current->comm, ECAP_COMM_LEN);
	b.len = (u32)got;
	b.data = kbuf;
	if (want < limit)
		b.flags |= ECAP_EV_FLAG_TRUNC;

	ret = ecap_push(&b);
	kfree(kbuf);
	return ret;
}

/*
 * SSL_write 的入口 handler。
 *
 * 返回 0 表示"继续正常执行"，UPROBE_HANDLER_REMOVE 表示要摘掉这个点
 * （我们永远不返回它：抓包工具不应该因为一次拷贝失败就自我摘除）。
 */
static int ecap_ssl_write_entry(struct uprobe_consumer *uc,
				struct pt_regs *regs)
{
	unsigned long raw_buf, num;
	void __user *ubuf;
	size_t want;
	long n;

	atomic64_inc(&ecap_uprobe_stat_hits);
	atomic_inc(&ecap_inflight);

	/*
	 * 过滤放在最前面 —— 在 copy_from_user 之前。
	 * 不匹配就立刻返回，一个字节都不拷。
	 */
	if (!ecap_filter_pass()) {
		atomic64_inc(&ecap_uprobe_stat_filtered);
		goto out;
	}

	raw_buf = (unsigned long)regs->regs[SSL_WRITE_ARG_BUF];
	num = (unsigned long)regs->regs[SSL_WRITE_ARG_NUM];

	/*
	 * num 是 int 参数（第 3 个参数，x2）。
	 *
	 * 【必须按 32 位 int 解释，理由同 ecap_ssl_read_ret 里的详细说明】
	 * 正常情况 num > 0；若为 0 或负数（调用方传错了），直接跳过，
	 * 避免下面把它当成巨大无符号数去 memcpy。
	 *
	 * 写成 (long)num 是错的：num 已经是 unsigned long，如果调用方
	 * 传了 -1，寄存器里是 0x00000000FFFFFFFF，转 long 得到 4294967295
	 * 而不是 -1，会被当成"要写 4GB"。
	 */
	n = (long)(int)(u32)num;
	if (n <= 0)
		goto out;

	/*
	 * 先截到槽上限，避免为一次 2MB 的 write 分配 2MB 内核内存。
	 * 真正的截断标志由 ecap_clamp_len 在入队时再确认一次。
	 */
	want = (size_t)n;
	if (want > ECAP_PAYLOAD_MAX)
		want = ECAP_PAYLOAD_MAX;

	ubuf = ECAP_UNTAG_PTR(raw_buf);

	ecap_emit_plaintext(ubuf, want, (size_t)n, ECAP_DIR_WRITE);

out:
	ecap_inflight_put();
	return 0;
}

/*
 * SSL_read 的入口 handler。
 *
 * 这里**不拷贝任何数据**，只记下 (tid -> buf) 的映射，
 * 真正的读取留到 ret_handler。
 *
 * 【为什么必须这样】
 * SSL_read(ssl, buf, num) 的 num 是"缓冲区有多大"，
 * 不是"会读到多少"。入口时 buf 里还是旧数据，
 * 读了就是垃圾。必须等函数返回，看它实际写入了多少字节。
 */
static int ecap_ssl_read_entry(struct uprobe_consumer *uc,
			       struct pt_regs *regs)
{
	unsigned long raw_buf, num;
	long n;

	atomic64_inc(&ecap_uprobe_stat_hits);
	atomic_inc(&ecap_inflight);

	if (!ecap_filter_pass()) {
		atomic64_inc(&ecap_uprobe_stat_filtered);
		goto out;
	}

	raw_buf = (unsigned long)regs->regs[SSL_WRITE_ARG_BUF]; /* x1 同位置 */
	num = (unsigned long)regs->regs[SSL_WRITE_ARG_NUM];     /* x2 同位置 */

	/* 同 write 路径：必须按 32 位 int 解释，否则 -1 会变成 4GB */
	n = (long)(int)(u32)num;
	if (n <= 0)
		goto out;

	/*
	 * 只记录，不拷贝。want 存的是 num，作为 ret 阶段的"上限校验"：
	 * 如果 ret_handler 看到返回值 > want，说明要么 SSL 内部越界
	 * 写坏了内存，要么我们的记录错了 —— 两种情况都该丢弃而不是
	 * 按一个巨大长度去 copy_from_user。
	 *
	 * 表满/分配失败只影响这一次，不需要中断整个抓包。
	 */
	ecap_pending_set((u32)task_pid_nr(current),
			 ECAP_UNTAG_PTR(raw_buf), (u32)n);

out:
	ecap_inflight_put();
	return 0;
}

/*
 * SSL_read 的返回 handler。
 *
 * 此时函数已经执行完，regs->regs[0] 是返回值：
 *   > 0  —— 实际读到的字节数，可以按这个长度读 buf
 *   = 0  —— 对端关闭（或非阻塞下没数据），不上报
 *   < 0  —— 出错，不上报
 *
 * 【func 参数是什么】
 * 内核传进来的是被探测函数的地址（ri->func）。我们只有一个
 * read 探测点，所以直接忽略。
 *
 * 【这条路径的上下文】
 * 它在 handle_trampoline() 里被调用（返回地址被劫持到了 trampoline），
 * 同样是即将返回用户态的进程上下文，可以 copy_from_user。
 * 但注意它持着 uprobe->register_rwsem 的读锁。
 */
static int ecap_ssl_read_ret(struct uprobe_consumer *uc, unsigned long func,
			     struct pt_regs *regs)
{
	void __user *ubuf = NULL;
	u32 recorded_want = 0;
	size_t want;
	long n;

	atomic_inc(&ecap_inflight);

	/*
	 * 【关键：返回值必须按 32 位 int 解释，不能直接当 long 读】
	 *
	 * SSL_read 返回 int。arm64 上 "写 32 位寄存器"（W0）会**清零**
	 * 高 32 位 x0[63:32]，而不是符号扩展。
	 * 所以返回 -1 时：
	 *
	 *   真实用户态看到的  : (int)0xFFFFFFFF        = -1
	 *   直接 (long)regs->regs[0] : 0x00000000FFFFFFFF = 4294967295  ← 正数！
	 *
	 * 这是个实测踩到的坑：一开始写成 n = (long)regs->regs[0]，
	 * 结果 3 次返回 -1 的 SSL_read 全被当成"读了 4GB"，
	 * 走进了上限校验分支，copy_fail 计数莫名其妙变成 3。
	 *
	 * 正确做法是先截成 int，再赋给 long 让它自然符号扩展。
	 */
	n = (long)(int)(u32)regs->regs[0];

	/*
	 * 先把挂起记录取出来，无论后面是否上报 ——
	 * 不然 <= 0 的情况下记录会一直留在表里，慢慢把表填满。
	 */
	if (!ecap_pending_take((u32)task_pid_nr(current), &ubuf,
			       &recorded_want)) {
		atomic64_inc(&ecap_uprobe_stat_pending_miss);
		goto out;
	}

	if (n <= 0) {
		/* 没读到数据（EOF 或错误），这是常态，不是异常 */
		atomic64_inc(&ecap_uprobe_stat_read_hits);
		goto out;
	}

	/*
	 * 上限校验：n 不应该超过入口时的 num。
	 * 超过了说明记录错乱或库内部有异常，直接丢弃比按巨大长度
	 * copy_from_user 安全得多。
	 */
	if ((u64)n > (u64)recorded_want) {
		atomic64_inc(&ecap_uprobe_stat_copy_fail);
		goto out;
	}

	want = (size_t)n;
	if (want > ECAP_PAYLOAD_MAX)
		want = ECAP_PAYLOAD_MAX;

	ecap_emit_plaintext(ubuf, want, (size_t)n, ECAP_DIR_READ);

out:
	ecap_inflight_put();
	return 0;
}

/* ------------------------------------------------------------------ */
/* M4：TLS 密钥提取（路径 B）                                          */
/* ------------------------------------------------------------------ */

/*
 * BoringSSL 的结构体偏移。
 *
 * 【这些数字是怎么来的】
 * 不是猜的，也不是从某个版本的源码里抄的 —— 是从**目标库的反汇编**
 * 里读出来的。
 *
 * 以 SSL_get_client_random 为例（它是导出符号，可以直接反汇编）：
 *
 *     SSL_get_client_random(const SSL *ssl, uint8_t *out, size_t max_out)
 *         x0 = ssl, x1 = out, x2 = max_out
 *
 *     ldr  x8, [x0, #48]      ; x8 = ssl->s3       ← SSL 结构体 +0x30
 *     add  x8, x8, #48        ; x8 = &s3->client_random  ← s3 +0x30
 *     ...
 *     bl   memcpy
 *
 * 由此得到：
 *     ssl->s3         在 SSL   结构体的 +0x30
 *     s3->client_random 在 s3  结构体的 +0x30
 *
 * 【为什么不能写死而不校验】
 * 这两个偏移随 BoringSSL 版本变化。所以运行时必须做校验：
 * 从 ssl 指针读出来的 client_random 如果全零或全 0xff，说明偏移错了，
 * 该条 keylog 事件就只上报 label 和 secret，client_random 留空 ——
 * 用户态可以退化为"按时间顺序配对"，不至于整条丢掉。
 *
 * 实测环境（Pixel 6 / Android 13 / 2026-11 的 conscrypt）：
 *     ssl->s3 = *(void **)(ssl + 0x30)
 *     client_random = *(uint8_t *)(s3 + 0x30)，32 字节
 */
#define BSSL_SSL_S3_OFFSET       0x30
#define BSSL_S3_CLIENT_RANDOM    0x30

/* 读取 client_random，成功返回 true。
 *
 * 三重校验，任何一项不过就认为偏移不适用：
 *   1) s3 指针必须非空且看起来像个内核态可读的地址范围内的用户指针
 *   2) 读出来的 32 字节不能全 0（未初始化）
 *   3) 不能全 0xff（也是未初始化的常见模式）
 *
 * 注意用 copy_from_user 而不是直接解引用：这是用户态内存，
 * 直接读会 panic。
 */
static bool ecap_read_client_random(const void __user *ssl,
				    u8 *out /* ECAP_CLIENT_RANDOM_LEN */)
{
	void __user *s3;
	u8 tmp[ECAP_CLIENT_RANDOM_LEN];
	unsigned int i;
	bool all_zero = true, all_ff = true;

	if (!ssl)
		return false;

	/* 第一级：读 ssl->s3 */
	if (copy_from_user(&s3, (void __user *)ssl + BSSL_SSL_S3_OFFSET,
			   sizeof(s3)))
		return false;

	s3 = ECAP_UNTAG_PTR(s3);
	if (!s3)
		return false;

	/* 第二级：读 s3->client_random */
	if (copy_from_user(tmp, (void __user *)s3 + BSSL_S3_CLIENT_RANDOM,
			   sizeof(tmp)))
		return false;

	for (i = 0; i < sizeof(tmp); i++) {
		if (tmp[i] != 0x00)
			all_zero = false;
		if (tmp[i] != 0xff)
			all_ff = false;
		if (!all_zero && !all_ff)
			break;
	}

	if (all_zero || all_ff)
		return false;

	memcpy(out, tmp, sizeof(tmp));
	return true;
}

/*
 * bssl::ssl_log_secret 的 handler（M4 核心）。
 *
 * 签名（从 .gnu_debugdata 的符号表确认的 mangled name）：
 *     _ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE
 *     → bssl::ssl_log_secret(ssl_st const*, char const*,
 *                            bssl::Span<unsigned char const>)
 *
 * AAPCS64 参数传递（从调用点反汇编确认）：
 *     x0 = ssl
 *     x1 = label   （C 字符串指针）
 *     x2 = data    （Span 的 data_）
 *     x3 = size    （Span 的 size_）
 *
 * 【Span 是按"两个独立寄存器"传的】
 * Span 是 { T* data_; size_t size_; } 这个双字段结构体。按 AAPCS64，
 * 一个 16 字节的聚合体既可能放在两个寄存器里，也可能通过隐藏指针传递。
 * 这里通过看调用点确认了是**前者**：
 *
 *     2c9d0: 83 0e 80 b9   ldrsw  x3, [x20, #12]   ; x3 = size
 *     2c9cc: 82 42 00 91   add    x2, x20, #16     ; x2 = data
 *     2c9dc: bd 48 00 94   bl     0x3ecd0          ; ssl_log_secret
 *
 * 所以直接读 x2 / x3 就对了，不要去解引用 x2 当结构体。
 *
 * 【返回值】
 * 永远返回 0。密钥提取失败也不能摘掉探测点 ——
 * 那会让整个路径 B 静默失效。
 */
static int ecap_keylog_entry(struct uprobe_consumer *uc, struct pt_regs *regs)
{
	struct ecap_keylog_payload kl;
	const void __user *ssl;
	const void __user *label;
	const void __user *secret;
	unsigned long size;
	struct ecap_blob b;
	long n;

	atomic64_inc(&ecap_uprobe_stat_hits);
	atomic64_inc(&ecap_uprobe_stat_keylog_hits);
	atomic_inc(&ecap_inflight);

	if (!ecap_filter_pass()) {
		atomic64_inc(&ecap_uprobe_stat_filtered);
		goto out;
	}

	ssl = ECAP_UNTAG_PTR(regs->regs[0]);
	label = ECAP_UNTAG_PTR(regs->regs[1]);
	secret = ECAP_UNTAG_PTR(regs->regs[2]);
	size = (unsigned long)regs->regs[3];

	if (!label || !secret || !size)
		goto bad;

	/*
	 * 长度截断。TLS 1.3 的 traffic secret 是 32 字节，
	 * TLS 1.2 的 master secret 是 48 字节，都在 64 以内。
	 * 超出说明要么是别的用途（比如 early secret 的中间值），
	 * 要么参数错位 —— 截断即可，不影响 pcapng 使用。
	 */
	if (size > ECAP_KEYLOG_SECRET_MAX)
		size = ECAP_KEYLOG_SECRET_MAX;

	memset(&kl, 0, sizeof(kl));

	/*
	 * 读 label。
	 *
	 * 用 strncpy_from_user 而不是 copy_from_user：
	 * label 是 C 字符串，长度未知，我们必须靠 NUL 结束符判断边界。
	 * 最后一个字节显式置 0，保证一定以 NUL 结尾。
	 */
	n = strncpy_from_user(kl.label, label, sizeof(kl.label) - 1);
	if (n <= 0)
		goto bad;
	kl.label[sizeof(kl.label) - 1] = '\0';

	/* 读 secret。这是定长读，用 copy_from_user。 */
	if (copy_from_user(kl.secret, secret, size))
		goto bad;

	/*
	 * client_random 是"尽力而为"的：读失败只影响 pcapng 的关联，
	 * 不影响密钥本身的价值（用户态可以按时间顺序配对）。
	 */
	if (!ecap_read_client_random(ssl, kl.client_random)) {
		/* 全零即"未知"，用户态据此走降级路径 */
		memset(kl.client_random, 0, sizeof(kl.client_random));
	}

	memset(&b, 0, sizeof(b));
	b.type = ECAP_EV_KEYLOG;
	/*
	 * 借用 hdr.dir 传递精确的 secret 字节数（1..64）。
	 * ECAP_EV_KEYLOG 本身不用方向字段，这样在不改 ABI 结构体
	 * 大小的前提下，用户态不必靠"去尾部 0"猜测长度（避免末尾
	 * 恰好是 0x00 的密钥被截短）。
	 */
	b.dir = (u8)size;
	b.tgid = (u32)task_tgid_nr(current);
	b.tid = (u32)task_pid_nr(current);
	b.uid = __kuid_val(current_uid());
	memcpy(b.comm, current->comm, ECAP_COMM_LEN);
	b.len = (u32)ECAP_KEYLOG_PAYLOAD_LEN;
	b.data = &kl;

	ecap_push(&b);
	goto out;

bad:
	atomic64_inc(&ecap_uprobe_stat_keylog_bad);
	pr_debug_ratelimited(UP_TAG "keylog: bad label/secret args\n");

out:
	ecap_inflight_put();
	return 0;
}

static struct uprobe_consumer ecap_keylog_consumer = {
	.handler = ecap_keylog_entry,
	.ret_handler = NULL,
	.filter = NULL,
};

static struct uprobe_consumer ecap_ssl_write_consumer = {
	.handler = ecap_ssl_write_entry,
	.ret_handler = NULL,
	.filter = NULL,
};

static struct uprobe_consumer ecap_ssl_read_consumer = {
	.handler = ecap_ssl_read_entry,
	.ret_handler = ecap_ssl_read_ret,
	.filter = NULL,
};

/*
 * 按 kind 选对应的 consumer 模板。
 *
 * 【为什么每个探测点要拷一份 consumer，而不是共用一个全局的】
 * uprobe_consumer 内部有 `struct uprobe_consumer *next` 字段，
 * 注册时会被挂进 uprobe->consumers 链表。同一个 consumer 对象注册到
 * 第二个 (inode, offset) 会破坏那个链表的结构。
 * 所以每个 ecap_probe 必须持有自己的一份拷贝（结构体拷贝，
 * 函数指针指向同一份实现，这是安全的）。
 *
 * 返回 NULL 表示不支持的 kind。
 */
static struct uprobe_consumer *ecap_consumer_for(u32 kind)
{
	switch (kind) {
	case ECAP_PROBE_SSL_WRITE:
		return &ecap_ssl_write_consumer;
	case ECAP_PROBE_SSL_READ:
		return &ecap_ssl_read_consumer;
	case ECAP_PROBE_KEYLOG:
		return &ecap_keylog_consumer;
	default:
		return NULL;
	}
}

/* ------------------------------------------------------------------ */
/* 设备 inode 获取                                                     */
/* ------------------------------------------------------------------ */

/*
 * 从用户态传来的 fd 拿到 inode。
 *
 * 【为什么走 fd 而不是路径】
 * 见 ecap_uapi.h 中 struct ecap_probe_req 的说明：kern_path / filp_open
 * 在 GKI 5.10 上都没有导出。用 fd 则只需 fget（EXPORT_SYMBOL）。
 *
 * 【注意 fd 的进程归属】
 * ioctl 一定是由"打开了目标 .so 的那个进程"发出的，所以 fget(fd) 在
 * current 的文件表里查找是正确的。如果将来改成"由守护进程 ioctl、
 * 由目标进程 open"，就必须换成 fget_task(target, fd)。
 *
 * 返回值：成功时 *out_file / *out_inode 都带引用，调用方负责 fput/iput。
 */
static int ecap_get_inode_by_fd(u32 fd, struct file **out_file,
				struct inode **out_inode)
{
	struct file *f;
	struct inode *i;

	f = fget((unsigned int)fd);
	if (!f) {
		pr_err(UP_TAG "fget(%u) failed\n", fd);
		return -EBADF;
	}

	i = file_inode(f);
	if (!i || !S_ISREG(i->i_mode)) {
		pr_err(UP_TAG "fd %u is not a regular file\n", fd);
		fput(f);
		return -EINVAL;
	}

	/*
	 * igrab 会额外加一个引用，并在 inode 正在被销毁时返回 NULL。
	 * 我们自己持一份引用，保证 uprobe 注销期间 inode 不会被回收。
	 */
	i = igrab(i);
	if (!i) {
		pr_err(UP_TAG "igrab failed for fd %u\n", fd);
		fput(f);
		return -ENOENT;
	}

	*out_file = f;
	*out_inode = i;
	return 0;
}

/* ------------------------------------------------------------------ */
/* ioctl 入口                                                          */
/* ------------------------------------------------------------------ */

static const char *ecap_kind_name(u32 kind)
{
	switch (kind) {
	case ECAP_PROBE_SSL_WRITE:
		return "SSL_write";
	case ECAP_PROBE_SSL_READ:
		return "SSL_read";
	case ECAP_PROBE_KEYLOG:
		return "ssl_log_secret";
	default:
		return "?";
	}
}

/*
 * 找到已注册的探测点。
 *
 * 【为什么必须比较 inode，而不能只比 kind + offset】
 * uprobe 的定位键是 (inode, offset)，不是 (offset)。两个不同的
 * libssl.so（例如系统的 /apex/com.android.conscrypt/lib64/libssl.so 与
 * App 自带的 libssl.so）里 SSL_write 的偏移大概率不同，但"偶然相同"
 * 完全可能 —— 尤其是同一版本 BoringSSL 编译出来的两份副本，偏移必然
 * 一模一样。只比 offset 就会把"给第二个库挂同一个点"误判成重复，
 * 让用户态收到 -EEXIST 却毫无头绪。
 *
 * 必须在 ecap_probes_lock 内调用。
 */
static struct ecap_probe *ecap_find_probe(struct inode *inode, u32 kind,
					 loff_t offset)
{
	struct ecap_probe *p;

	list_for_each_entry(p, &ecap_probes, node) {
		if (p->inode == inode && p->kind == kind && p->offset == offset)
			return p;
	}
	return NULL;
}

/*
 * 按 (kind, offset) 查找，用于 del —— 用户态可能不传 fd，或者传了
 * 一个已经换过的 fd。这里退化为宽松匹配，但把 inode 也纳入比较
 * （如果能拿到）。
 */
static struct ecap_probe *ecap_find_probe_loose(struct inode *inode, u32 kind,
					       loff_t offset)
{
	struct ecap_probe *p;

	list_for_each_entry(p, &ecap_probes, node) {
		if (p->kind != kind || p->offset != offset)
			continue;
		if (inode && p->inode != inode)
			continue;
		return p;
	}
	return NULL;
}

static void ecap_probe_free(struct ecap_probe *p)
{
	/*
	 * 顺序很重要：
	 *   1) 先注销 uprobe —— 此后不会再有新 handler 进来
	 *   2) 再放 inode   —— 我们自己的 igrab 引用
	 *   3) 最后 fput     —— 归还 fget 的引用
	 * 反过来做会导致内核在已经释放的 inode 上操作（panic）。
	 */
	if (p->registered) {
		ecap_uprobe_unregister(p->inode, p->offset, &p->uc);
		p->registered = false;
	}
	if (p->inode) {
		iput(p->inode);
		p->inode = NULL;
	}
	if (p->file) {
		fput(p->file);
		p->file = NULL;
	}
	kfree(p);
}

/*
 * 在一个已经拿到的 inode 上注册一个探测点。
 *
 * 调用方必须持有 ecap_probes_lock，并且负责 f/inode 的引用释放。
 * 抽出来是为了让"单个添加"和"成对添加"共用同一套注册+去重逻辑。
 *
 * @i      : 已 igrab 的 inode
 * @f      : 已 fget 的 file（转交给 probe 持有）
 * @fd     : 原始 fd，仅记录
 * @kind   : 探测点类型
 * @offset : 文件偏移
 *
 * 成功时 probe 已挂进链表并接管 f/inode 的所有权；
 * 失败时 *out_probe 为 NULL，且不触碰 f/i（由调用方释放）。
 */
static long ecap_add_one(struct inode *i, struct file *f, u32 fd, u32 kind,
			 u64 offset, struct ecap_probe **out_probe)
{
	struct uprobe_consumer *tmpl;
	struct ecap_probe *p, *dup;
	long ret;

	*out_probe = NULL;

	tmpl = ecap_consumer_for(kind);
	if (!tmpl) {
		pr_warn(UP_TAG "probe kind %u (%s) not supported\n", kind,
			ecap_kind_name(kind));
		return -EOPNOTSUPP;
	}

	if (offset == 0) {
		pr_err(UP_TAG "offset 0 rejected for %s\n",
		       ecap_kind_name(kind));
		return -EINVAL;
	}

	mutex_lock(&ecap_probes_lock);

	dup = ecap_find_probe(i, kind, (loff_t)offset);
	if (dup) {
		mutex_unlock(&ecap_probes_lock);
		pr_warn(UP_TAG "duplicate probe %s @0x%llx (inode %lu)\n",
			ecap_kind_name(kind), (unsigned long long)offset,
			(unsigned long)i->i_ino);
		return -EEXIST;
	}

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		mutex_unlock(&ecap_probes_lock);
		return -ENOMEM;
	}

	p->inode = i;
	p->file = f;
	p->fd = fd;
	p->offset = (loff_t)offset;
	p->kind = kind;
	/*
	 * 结构体拷贝：函数指针指向同一份实现，但 next 字段是独立的一份。
	 * 这是必须的 —— 见 ecap_consumer_for 的说明。
	 */
	p->uc = *tmpl;

	/*
	 * uprobe_register 可能睡眠（内部 down_write + kzalloc），
	 * 所以不能持 spinlock。这里持有的是 mutex，没问题。
	 */
	ret = ecap_uprobe_register(i, (loff_t)offset, &p->uc);
	if (ret) {
		mutex_unlock(&ecap_probes_lock);
		pr_err(UP_TAG "uprobe_register(%s @0x%llx) failed: %d "
		       "(inode=%lu, arm64 上 INSN_REJECTED 也是 -EINVAL)\n",
		       ecap_kind_name(kind), (unsigned long long)offset, ret,
		       i->i_ino);
		kfree(p);
		return ret;
	}

	p->registered = true;
	list_add(&p->node, &ecap_probes);
	mutex_unlock(&ecap_probes_lock);

	pr_info(UP_TAG "probe added: %s @0x%llx inode=%lu\n",
		ecap_kind_name(kind), (unsigned long long)offset,
		(unsigned long)i->i_ino);

	*out_probe = p;
	return 0;
}

long ecap_uprobe_add(void __user *uarg)
{
	struct ecap_probe_req req;
	struct ecap_probe *p = NULL;
	struct file *f = NULL;
	struct inode *i = NULL;
	long ret;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;

	ret = ecap_get_inode_by_fd(req.fd, &f, &i);
	if (ret)
		return ret;

	ret = ecap_add_one(i, f, req.fd, req.kind, req.offset, &p);
	if (ret) {
		/*
		 * 注册失败：f/inode 的所有权还在我们手上，需要归还。
		 * ecap_add_one 只在成功时才把所有权转交给 probe，
		 * 失败路径一律不碰 f/i，所以这里统一释放。
		 */
		iput(i);
		fput(f);
	}

	return ret;
}

/*
 * 内核侧删除一个探测点（不接收用户指针）。
 *
 * 抽出来是因为 ADD_PAIR/DEL_PAIR 的回滚路径要在内核里直接调用，
 * 手上只有内核结构体，没有 __user 指针。
 */
static long ecap_del_one(u32 fd, u32 kind, u64 offset)
{
	struct ecap_probe *p;
	struct inode *want_inode = NULL;
	struct file *want_file = NULL;

	/*
	 * 尽力用 fd 定位到具体的 inode，让"同一个 offset、不同库"的
	 * 两个探测点能被精确区分。
	 *
	 * fd 拿不到不算错误：用户态可能在 close 之后才发 DEL，
	 * 或者干脆不传 fd。这时退化为按 (kind, offset) 匹配。
	 */
	if (fd) {
		struct file *f = fget((unsigned int)fd);

		if (f) {
			struct inode *i = file_inode(f);

			if (i && S_ISREG(i->i_mode)) {
				want_file = f;
				want_inode = i;
			} else {
				fput(f);
			}
		}
	}

	mutex_lock(&ecap_probes_lock);
	p = ecap_find_probe_loose(want_inode, kind, (loff_t)offset);
	if (!p) {
		mutex_unlock(&ecap_probes_lock);
		if (want_file)
			fput(want_file);
		return -ENOENT;
	}
	list_del(&p->node);
	mutex_unlock(&ecap_probes_lock);

	if (want_file)
		fput(want_file);

	/*
	 * 出锁之后再释放：ecap_probe_free 会调 uprobe_unregister，
	 * 而后者内部要拿 register_rwsem 的写锁，可能等待正在跑的 handler
	 * 退出。持着 probe 链表的 mutex 做这个会很长时间阻塞其他 ioctl。
	 */
	ecap_probe_free(p);
	pr_info(UP_TAG "probe removed: %s @0x%llx\n", ecap_kind_name(kind),
		(unsigned long long)offset);
	return 0;
}

long ecap_uprobe_del(void __user *uarg)
{
	struct ecap_probe_del req;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;

	return ecap_del_one(req.fd, req.kind, req.offset);
}

/* ------------------------------------------------------------------ */
/* M3：过滤器配置                                                       */
/* ------------------------------------------------------------------ */

long ecap_uprobe_set_filter(void __user *uarg)
{
	struct ecap_filter f;

	if (copy_from_user(&f, uarg, sizeof(f)))
		return -EFAULT;

	/*
	 * 注意写入顺序：先写 tgid/uid，最后写 include_all。
	 *
	 * handler 侧读的是"先看 include_all，再读 tgid/uid"，所以
	 * 这个顺序能保证不会出现"已经放开 include_all，但 tgid 还是旧值"
	 * 的中间状态被观察到。
	 *
	 * 反过来的风险是：如果先写 include_all=0、后写 tgid，中间瞬间
	 * 会出现"tgid 是旧值（比如 0）且 include_all 已是 0" ——
	 * 那会变成 tgid=0 意味着不过滤，反而全抓了。所以顺序很重要。
	 */
	atomic_set(&ecap_filter_tgid, (int)f.tgid);
	atomic_set(&ecap_filter_uid, (int)f.uid);
	atomic_set(&ecap_filter_include_all, f.include_all ? 1 : 0);

	pr_info(UP_TAG "filter set: include_all=%u tgid=%u uid=%u\n",
		f.include_all, f.tgid, f.uid);
	return 0;
}

/* ------------------------------------------------------------------ */
/* M3：成对注册 / 注销（同时挂 SSL_write 与 SSL_read）                  */
/* ------------------------------------------------------------------ */

/*
 * 一次挂两个方向。
 *
 * 【为什么需要"成对"这个接口，而不是让用户态调两次 ADD_PROBE】
 * 两次调用会引入"只有一个成功"的中间状态：用户态必须记得回滚，
 * 而回滚本身也可能失败（比如第二次失败时第一次已经挂上）。
 * 放在一个 ioctl 里，内核可以保证"要么两个都挂上，要么一个都不挂"。
 *
 * 【回滚怎么做】
 * 第二个失败时，把第一个已挂上的摘掉。因为此时还没返回用户态，
 * 用户态完全不知道这件事，必须由内核负责清理干净。
 */
long ecap_uprobe_add_pair(void __user *uarg)
{
	struct ecap_probe_pair req;
	struct ecap_probe *pw = NULL, *pr = NULL;
	struct file *f = NULL;
	struct inode *i = NULL;
	long ret;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;

	if (!req.write_offset && !req.read_offset) {
		pr_err(UP_TAG "add_pair: both offsets are 0\n");
		return -EINVAL;
	}

	ret = ecap_get_inode_by_fd(req.fd, &f, &i);
	if (ret)
		return ret;

	/* 第一个：SSL_write */
	if (req.write_offset) {
		ret = ecap_add_one(i, f, req.fd, ECAP_PROBE_SSL_WRITE,
				   req.write_offset, &pw);
		if (ret) {
			iput(i);
			fput(f);
			return ret;
		}
		/*
		 * 第一个成功后，f 与 i 的所有权已经转交给 pw 了。
		 * 如果还需要挂第二个探测点，必须重新拿一份引用 ——
		 * 不能让两个 probe 共享同一个 file/inode 引用，
		 * 否则某个先释放时另一个就悬空了。
		 */
		if (req.read_offset) {
			f = NULL;
			i = NULL;
			ret = ecap_get_inode_by_fd(req.fd, &f, &i);
			if (ret) {
				pr_err(UP_TAG "add_pair: re-acquire inode failed: %ld\n",
				       ret);
				goto err_undo_write;
			}
		}
	}

	/* 第二个：SSL_read */
	if (req.read_offset) {
		ret = ecap_add_one(i, f, req.fd, ECAP_PROBE_SSL_READ,
				   req.read_offset, &pr);
		if (ret) {
			iput(i);
			fput(f);
			goto err_undo_write;
		}
	}

	return 0;

err_undo_write:
	/*
	 * 回滚：把已经挂上的 write 探测点摘掉。
	 * 用户态完全不知道它曾经挂上过，必须由我们清干净。
	 */
	if (pw) {
		mutex_lock(&ecap_probes_lock);
		list_del(&pw->node);
		mutex_unlock(&ecap_probes_lock);
		ecap_probe_free(pw);
		pr_info(UP_TAG "add_pair: rolled back SSL_write probe\n");
	}
	return ret;
}

long ecap_uprobe_del_pair(void __user *uarg)
{
	struct ecap_probe_pair req;
	long ret_w = 0, ret_r = 0;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;

	/*
	 * 两个方向分别删。offset 为 0 的方向跳过。
	 * 删一个不存在的探测点返回 -ENOENT 不算错误 ——
	 * 用户态可能只挂了其中一个。
	 */
	if (req.write_offset) {
		ret_w = ecap_del_one(req.fd, ECAP_PROBE_SSL_WRITE,
				     req.write_offset);
		if (ret_w == -ENOENT)
			ret_w = 0;
	}
	if (req.read_offset) {
		ret_r = ecap_del_one(req.fd, ECAP_PROBE_SSL_READ,
				     req.read_offset);
		if (ret_r == -ENOENT)
			ret_r = 0;
	}

	if (ret_w)
		return ret_w;
	return ret_r;
}

/* ------------------------------------------------------------------ */
/* 初始化 / 退出                                                       */
/* ------------------------------------------------------------------ */

int ecap_uprobe_init(void)
{
	INIT_LIST_HEAD(&ecap_probes);
	return 0;
}

void ecap_uprobe_exit(void)
{
	struct ecap_probe *p, *tmp;

	mutex_lock(&ecap_probes_lock);
	list_for_each_entry_safe(p, tmp, &ecap_probes, node) {
		list_del(&p->node);
		ecap_probe_free(p);
	}
	mutex_unlock(&ecap_probes_lock);

	/*
	 * uprobe_unregister 会拿 register_rwsem 的写锁，而正在执行的
	 * handler 持着读锁 —— 所以 unregister 返回时，所有 handler 理论上
	 * 都已经退出。这里的 inflight 计数是一道额外保险：
	 * handler 可能在 unregister 之前的最后一刻刚被调用，我们要等它
	 * 真正跑完，才能让上层释放队列内存。
	 *
	 * 用 wait_event 睡眠等待，不要 busy-loop —— rmmod 是进程上下文，
	 * 可以睡；忙等会白白烧掉一个 CPU，还可能因为抢占延迟观察者。
	 */
	if (wait_event_timeout(ecap_inflight_wq, atomic_read(&ecap_inflight) == 0,
			       msecs_to_jiffies(500)) == 0)
		pr_warn(UP_TAG "%d handlers still in flight at unload\n",
			atomic_read(&ecap_inflight));

	/*
	 * 清空挂起表。
	 *
	 * 必须在等所有 handler 退出之后做：ret_handler 里会调
	 * ecap_pending_take，如果它还在跑而我们先把表清了，
	 * 那个 handler 就会 take 到空并计一次 pending_miss（无害），
	 * 但更糟的是它可能正在遍历哈希桶 —— 所以顺序不能反。
	 *
	 * 残留的条目是"entry 已经执行、但对应的 ret 还没来"的记录，
	 * 线程被 kill 或长跳转（longjmp）都会留下这种孤儿。
	 * 先看一眼数量，有残留就打日志（方便判断是否有 handler 配对问题），
	 * 然后再清。
	 */
	if (atomic_read(&ecap_pending_cnt))
		pr_warn(UP_TAG "%d orphan pending entries at unload "
			"(entry 执行了但 ret 没来，通常是线程被 kill)\n",
			atomic_read(&ecap_pending_cnt));
	ecap_pending_clear();
}
