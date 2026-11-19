// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_dev.c - /dev/ecap_tls：内核 -> 用户态的事件通道
 *
 * 【为什么要有这一层】
 * eBPF 用 BPF_MAP_TYPE_PERF_EVENT_ARRAY 把事件推给用户态，LKM 没有这个东西。
 * 这里手工实现等价物，只需要三个部件：
 *
 *   kfifo（环形队列） + spinlock（保护） + waitqueue（唤醒读者）
 *
 * 数据流向：
 *
 *   uprobe handler / Netfilter hook  (任意上下文，不能睡眠)
 *        │  ecap_push()
 *        ▼
 *   kfifo（定长槽，每槽 4096 字节）
 *        │  __wake_up()
 *        ▼
 *   用户态 ecapctl: poll() 有数据 -> read() 读出一个完整槽
 *
 * 【三个刻意的设计决定】
 *
 * 1) 定长槽，不用变长记录。
 *    本内核没导出 __kfifo_out_r（record 模式的出队函数），变长记录会导致
 *    出队时无法判断边界。定长槽让 read() 的语义变得极简：
 *    要么返回 4096，要么返回 0。用户态不需要拼包。
 *
 * 2) 队列满就丢，绝不阻塞。
 *    这是抓包工具的第一原则：宁可丢事件，也不能把目标 App 的 SSL 线程
 *    或者网络软中断卡住。丢一条就把 dropped 计数 +1，用户态可以查 stats。
 *
 * 3) kfifo 的元素类型就是"一个槽"，而不是 unsigned char。
 *    这样 kfifo_in(fifo, &slot, 1) 天然是"整槽原子入队"，不需要自己算
 *    剩余空间够不够放满一个槽 —— 空间不够时 __kfifo_in 直接不放。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kfifo.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/cred.h>

#include "ecap_dev.h"
#include "ecap_uprobe.h"
#include "ecap_nf.h"

#define DEV_TAG "ecap_tls: "

/* 队列槽数，必须是 2 的幂。256 槽 × 4KB = 1MB 缓冲。 */
static unsigned int ecap_queue_slots __read_mostly = 256;
module_param_named(queue_slots, ecap_queue_slots, uint, 0444);
MODULE_PARM_DESC(queue_slots, "Event ring buffer size in 4KB slots (power of 2)");

/*
 * 环形队列。元素类型 = struct ecap_event（4096 字节），
 * 所以 kfifo 的 in/out 计数单位是"槽"，不是字节。
 */
static DECLARE_KFIFO_PTR(ecap_queue, struct ecap_event);

/* 队列底层的连续内存。用 vzalloc 而不是 kmalloc：
 * 1MB 以上的连续物理内存 kmalloc 经常失败（MAX_ORDER 限制），
 * 而 kfifo 只要求虚拟地址连续。 */
static void *ecap_queue_buf;

static DEFINE_SPINLOCK(ecap_queue_lock);
static DECLARE_WAIT_QUEUE_HEAD(ecap_waitq);

/* 统计计数。用 atomic64 而不是 spinlock 保护，避免在热路径上抢锁。 */
static atomic64_t ecap_stat_pushed = ATOMIC64_INIT(0);
static atomic64_t ecap_stat_dropped = ATOMIC64_INIT(0);
static atomic64_t ecap_stat_reads = ATOMIC64_INIT(0);
static atomic64_t ecap_stat_ioctls = ATOMIC64_INIT(0);

/*
 * 设备是否处于可用状态。
 *
 * 【为什么需要这个标志，而不能只看 ecap_queue_buf 是否为空】
 * 读者循环是：
 *     反复 { kfifo_out() ; 若空则睡在 waitqueue }
 * 卸载路径是：
 *     { vfree(队列) ; wake_up_all() }
 *
 * 如果只把 ecap_queue_buf 置空再唤醒，读者醒来后会重新进入循环、
 * 再次调用 kfifo_out() —— 而此时队列内存已经 vfree 了，直接 UAF。
 *
 * 正确做法是"先立旗子（alive = false），再唤醒，最后才释放内存"：
 * 读者每轮循环都先检查 alive，看到 false 就立刻返回 -ENODEV，
 * 绝不会再去碰 kfifo。
 *
 * 注意：正常情况下 rmmod 会因为模块引用计数（fops.owner = THIS_MODULE）
 * 在仍有 fd 打开时失败，所以这条路径实际上很难触发。但依赖引用计数
 * 来保证内存安全是脆弱的（有人可能改成不占引用计数的写法），
 * 显式立旗子才是可靠的。
 */
static bool ecap_dev_alive;

/*
 * 每个 CPU 一块暂存槽。
 *
 * 【为什么需要它】
 * 入队时要把调用方的散装字段（type/len/pid/...）拼成一个 4096 字节的
 * 完整槽。这个槽不能放在内核栈上（栈只有 16KB），直觉做法是
 * kmalloc(4096, GFP_ATOMIC) —— 但这样每条事件都要分配一次 4KB，
 * 在 SSL_write 的热路径上既慢又可能因为内存碎片而失败。
 *
 * 改成 per-CPU 常驻缓冲：
 *   - 无锁（同一时刻一个 CPU 只有一个执行流在用它）；
 *   - 不分配；
 *   - 天然避免了"多个线程同时拼槽"的竞争。
 *
 * 【为什么不会被并发写坏】
 * 取暂存槽、填槽、入队这一段全程关中断（local_irq_save），
 * 保证本 CPU 只有当前这一个执行流在动这块缓冲：
 *   - 另一个 CPU 用的是它自己的槽，互不影响；
 *   - 本 CPU 上的软中断（Netfilter 路径）无法插进来踩同一块内存。
 *
 * 需要注意的代价：关中断期间做了一次最大 4KB 的 memcpy，
 * 在本 CPU 上会推迟中断响应一小段时间。这个量级（微秒级）远小于
 * 一次 SSL 记录的处理时间，可以接受；但如果将来 payload 变成几十 KB，
 * 就必须改成"关中断只做指针交换，拷贝放到中断外"的写法。
 */
static struct ecap_event *ecap_stage[NR_CPUS];

/* ------------------------------------------------------------------ */
/* 入队                                                                */
/* ------------------------------------------------------------------ */

u32 ecap_clamp_len(u32 len, __u8 *flags)
{
	if (len > ECAP_PAYLOAD_MAX) {
		len = ECAP_PAYLOAD_MAX;
		*flags |= ECAP_EV_FLAG_TRUNC;
	}
	return len;
}

int ecap_push(const struct ecap_blob *b)
{
	struct ecap_event *ev;
	unsigned long irqflags;
	u8 evflags = b->flags;
	unsigned int cpu;
	u32 len;
	bool ok;

	if (unlikely(!ecap_dev_alive || !ecap_queue_buf))
		return -ENODEV;

	/*
	 * 关掉本 CPU 的中断，然后拿本 CPU 的暂存槽。
	 *
	 * 【为什么关中断而不是只关抢占】
	 * uprobe handler 在进程上下文跑，本身是允许被中断打断的。而
	 * Netfilter 的软中断路径也可能调 ecap_push。如果只禁抢占，
	 * 一个软中断插进来就会把同一个 CPU 的暂存槽写花。
	 * local_irq_save 提供的是"本 CPU 不可被打断"，这才是 per-CPU
	 * 缓冲能免锁使用的真正前提。
	 *
	 * 注意这里没有拿 ecap_queue_lock —— 填槽不需要跨 CPU 互斥，
	 * 只要保证"每个 CPU 只有自己动自己的槽"。少持一次全局锁，
	 * 也就不会让 4KB memcpy 阻塞别的 CPU。
	 */
	local_irq_save(irqflags);
	cpu = smp_processor_id();
	ev = ecap_stage[cpu];
	if (unlikely(!ev)) {
		local_irq_restore(irqflags);
		atomic64_inc(&ecap_stat_dropped);
		return -ENOMEM;
	}

	/*
	 * 在本地副本上做截断，不回写调用方传入的 b（它是 const）。
	 */
	len = ecap_clamp_len(b->len, &evflags);

	memset(ev, 0, sizeof(*ev));
	ev->hdr.type = b->type;
	ev->hdr.len = len;
	ev->hdr.ts_ns = ktime_get_mono_fast_ns();
	ev->hdr.tgid = b->tgid;
	ev->hdr.tid = b->tid;
	ev->hdr.uid = b->uid;
	ev->hdr.flags = evflags;
	ev->hdr.dir = b->dir;
	memcpy(ev->hdr.comm, b->comm, ECAP_COMM_LEN);
	if (len && b->data)
		memcpy(ev->payload, b->data, len);

	/*
	 * 整槽入队。kfifo_in 的第 3 个参数是"元素个数"，
	 * 元素是 struct ecap_event，所以传 1 就是放一个完整槽。
	 * 空间不足时它返回 0，不会写半个槽 —— 这正是我们要的原子性。
	 */
	spin_lock(&ecap_queue_lock);
	ok = (kfifo_in(&ecap_queue, ev, 1) == 1);
	spin_unlock(&ecap_queue_lock);

	local_irq_restore(irqflags);

	if (ok) {
		atomic64_inc(&ecap_stat_pushed);
		/*
		 * 唤醒动作放在所有锁之外，避免把读者线程拉进持锁路径。
		 * 每成功入队一次就唤醒一次：读者被唤醒后会把队列排空，
		 * 所以这里不需要判断"队列是否刚变非空"。
		 */
		__wake_up(&ecap_waitq, TASK_INTERRUPTIBLE, 1, NULL);
		return 0;
	}

	atomic64_inc(&ecap_stat_dropped);
	return -ENOSPC;
}

/* ------------------------------------------------------------------ */
/* 文件操作                                                            */
/* ------------------------------------------------------------------ */

/*
 * 每个 open 一份读出缓冲。
 *
 * 为什么不放在全局：多个读者并发 read() 时，若共用一块缓冲，
 * 从 kfifo 取出到 copy_to_user 之间会互相覆盖。
 */
struct ecap_reader {
	struct ecap_event *slot;
};

static int ecap_dev_open(struct inode *inode, struct file *file)
{
	struct ecap_reader *r;

	/* 卸载流程刚开始时拒绝新的打开请求 */
	if (unlikely(!ecap_dev_alive))
		return -ENODEV;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	r->slot = kmalloc(sizeof(struct ecap_event), GFP_KERNEL);
	if (!r->slot) {
		kfree(r);
		return -ENOMEM;
	}

	file->private_data = r;
	return 0;
}

static int ecap_dev_release(struct inode *inode, struct file *file)
{
	struct ecap_reader *r = file->private_data;

	if (r) {
		kfree(r->slot);
		kfree(r);
		file->private_data = NULL;
	}
	return 0;
}

static ssize_t ecap_dev_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct ecap_reader *r = file->private_data;
	unsigned long flags;
	unsigned int got;
	int ret;

	if (!r)
		return -EINVAL;

	/*
	 * 只接受"一次读一个完整槽"。
	 * 传小 buffer 直接拒绝，而不是返回半条事件 —— 半条事件会让用户态
	 * 陷入拼包状态机，那正是我们在内核侧极力避免的复杂度。
	 */
	if (count < ECAP_SLOT_SIZE)
		return -EINVAL;

	if (unlikely(!ecap_dev_alive || !ecap_queue_buf))
		return -ENODEV;

	for (;;) {
		if (unlikely(!ecap_dev_alive))
			return -ENODEV;

		/*
		 * 取出 + 消费必须原子：否则两个读者可能拿到同一个槽。
		 * 取出到私有缓冲后立刻放锁，copy_to_user 在锁外做（可能缺页睡眠）。
		 */
		spin_lock_irqsave(&ecap_queue_lock, flags);
		got = kfifo_out(&ecap_queue, r->slot, 1);
		spin_unlock_irqrestore(&ecap_queue_lock, flags);

		if (got == 1)
			break;

		/* 非阻塞模式：队列空就是 -EAGAIN，这是 poll/read 的常规约定 */
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		/*
		 * 阻塞模式：真等一个事件，而不是返回 0。
		 *
		 * 【这里为什么不能返回 0】
		 * 用户态惯例把 read() 返回 0 当作 EOF，于是会跳出事件循环。
		 * 抓包工具里"队列暂时空"是最常见的状态（每个 SSL_write 之间
		 * 都可能空），返回 0 会让 capture 刚开始就以为设备关闭了。
		 *
		 * 用 wait_event_interruptible 而不是自己写 add_wait_queue：
		 * 它正确处理"条件检查与睡眠之间的竞态"，也能在收到信号时
		 * 返回 -ERESTARTSYS，让 Ctrl-C 能立刻退出。
		 */
		ret = wait_event_interruptible(
			ecap_waitq,
			!ecap_dev_alive || !kfifo_is_empty(&ecap_queue));
		if (ret)
			return ret; /* -ERESTARTSYS */
	}

	if (copy_to_user(buf, r->slot, ECAP_SLOT_SIZE))
		return -EFAULT;

	atomic64_inc(&ecap_stat_reads);
	return ECAP_SLOT_SIZE;
}

static __poll_t ecap_dev_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &ecap_waitq, wait);

	if (unlikely(!ecap_dev_alive))
		return EPOLLERR | EPOLLHUP;

	/* 无需加锁读 in/out：
	 * 读者只关心"是否非空"，这里允许短暂的不精确（可能多醒一次，
	 * 下一次 read 返回 0 而已）。加锁反而会在热路径上与写者争抢。 */
	if (!kfifo_is_empty(&ecap_queue))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

/* ------------------------------------------------------------------ */
/* ioctl                                                               */
/* ------------------------------------------------------------------ */

static long ecap_dev_ioctl_ping(void __user *arg)
{
	struct ecap_ping req;
	struct ecap_blob b;
	u8 *tmp;
	u32 i;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	if (req.len > ECAP_PAYLOAD_MAX)
		return -EINVAL;

	tmp = kmalloc(req.len ? req.len : 1, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	/* 用 pattern 填充，用户态据此校验数据在链路上没有被破坏 */
	for (i = 0; i < req.len; i++)
		tmp[i] = (u8)(req.pattern + i);

	memset(&b, 0, sizeof(b));
	b.type = ECAP_EV_PING;
	b.tgid = (u32)task_tgid_nr(current);
	b.tid = (u32)task_pid_nr(current);
	b.uid = __kuid_val(current_uid());
	memcpy(b.comm, current->comm, ECAP_COMM_LEN);
	b.len = req.len;
	b.data = tmp;

	i = (u32)ecap_push(&b);
	kfree(tmp);

	return (long)i;
}

/* 队列统计接口，供 ecap_nf.c 上报包队列状态 */
u32 ecap_queue_used_bytes(void)
{
	unsigned long flags;
	unsigned int used;

	if (unlikely(!ecap_queue_buf))
		return 0;

	spin_lock_irqsave(&ecap_queue_lock, flags);
	used = kfifo_len(&ecap_queue);
	spin_unlock_irqrestore(&ecap_queue_lock, flags);

	return used * ECAP_SLOT_SIZE;
}

u32 ecap_queue_capacity_bytes(void)
{
	return (u32)ecap_queue_slots * ECAP_SLOT_SIZE;
}

static long ecap_dev_ioctl_get_stats(void __user *arg)
{
	struct ecap_stats st;
	unsigned long flags;
	unsigned int used;

	memset(&st, 0, sizeof(st));

	spin_lock_irqsave(&ecap_queue_lock, flags);
	used = kfifo_len(&ecap_queue);
	spin_unlock_irqrestore(&ecap_queue_lock, flags);

	st.pushed = (__u64)atomic64_read(&ecap_stat_pushed);
	st.dropped = (__u64)atomic64_read(&ecap_stat_dropped);
	st.reads = (__u64)atomic64_read(&ecap_stat_reads);
	st.ioctls = (__u64)atomic64_read(&ecap_stat_ioctls);
	st.uprobe_hits = ecap_uprobe_hits();
	st.copy_fail = ecap_uprobe_copy_fails();
	/* M3 */
	st.filtered = ecap_uprobe_filtered();
	st.read_hits = ecap_uprobe_read_hits();
	st.pending_miss = ecap_uprobe_pending_miss();
	st.pending = ecap_uprobe_pending_count();
	st.pending_max = ECAP_PENDING_MAX;
	/* M4 */
	st.keylog_hits = ecap_uprobe_keylog_hits();
	st.keylog_bad = ecap_uprobe_keylog_bad();
	st.pkt_seen = ecap_nf_pkt_seen();
	st.pkt_skipped = ecap_nf_pkt_skipped();
	st.pkt_pushed = ecap_nf_pkt_pushed();
	st.pkt_queue_len = ecap_nf_queue_len();
	st.pkt_queue_max = ecap_nf_queue_max();
	st.queued = used * ECAP_SLOT_SIZE;
	st.slots = (__u32)ecap_queue_slots * ECAP_SLOT_SIZE;

	if (copy_to_user(arg, &st, sizeof(st)))
		return -EFAULT;
	return 0;
}

static long ecap_dev_unlocked_ioctl(struct file *file, unsigned int cmd,
				    unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	long ret;

	/*
	 * 完整比较 cmd（包含方向与大小位），不只看 _IOC_NR。
	 * 否则用户态传错结构体大小也能通过校验，进而在
	 * copy_from_user 里写出内核缓冲边界。
	 */
	switch (cmd) {
	case ECAP_IOC_VERSION: {
		__u32 ver = ECAP_ABI_VERSION;
		if (copy_to_user(uarg, &ver, sizeof(ver)))
			return -EFAULT;
		ret = 0;
		break;
	}
	case ECAP_IOC_PING:
		ret = ecap_dev_ioctl_ping(uarg);
		break;
	case ECAP_IOC_GET_STATS:
		ret = ecap_dev_ioctl_get_stats(uarg);
		break;
	case ECAP_IOC_ADD_PROBE:
		ret = ecap_uprobe_add(uarg);
		break;
	case ECAP_IOC_DEL_PROBE:
		ret = ecap_uprobe_del(uarg);
		break;
	/* --- M3 --- */
	case ECAP_IOC_SET_FILTER:
		ret = ecap_uprobe_set_filter(uarg);
		break;
	case ECAP_IOC_ADD_PAIR:
		ret = ecap_uprobe_add_pair(uarg);
		break;
	case ECAP_IOC_DEL_PAIR:
		ret = ecap_uprobe_del_pair(uarg);
		break;
	/* --- M4 --- */
	case ECAP_IOC_ENABLE_NF: {
		__u32 port = 0;
		if (copy_from_user(&port, uarg, sizeof(port)))
			return -EFAULT;
		ret = ecap_nf_enable(port);
		break;
	}
	case ECAP_IOC_DISABLE_NF:
		ecap_nf_disable();
		ret = 0;
		break;
	case ECAP_IOC_CLEAR: {
		unsigned long flags;
		spin_lock_irqsave(&ecap_queue_lock, flags);
		kfifo_reset(&ecap_queue);
		spin_unlock_irqrestore(&ecap_queue_lock, flags);
		ret = 0;
		break;
	}
	default:
		return -ENOTTY;
	}

	if (ret == 0)
		atomic64_inc(&ecap_stat_ioctls);
	return ret;
}

static const struct file_operations ecap_dev_fops = {
	.owner = THIS_MODULE,
	.open = ecap_dev_open,
	.release = ecap_dev_release,
	.read = ecap_dev_read,
	.poll = ecap_dev_poll,
	.unlocked_ioctl = ecap_dev_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ecap_dev_unlocked_ioctl,
#endif
	.llseek = no_llseek,
};

static struct miscdevice ecap_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ecap_tls",
	.fops = &ecap_dev_fops,
	.mode = 0600,
};

/* ------------------------------------------------------------------ */
/* 初始化 / 销毁                                                       */
/* ------------------------------------------------------------------ */

int ecap_dev_init(void)
{
	unsigned int slots = roundup_pow_of_two(ecap_queue_slots);
	unsigned int cpu;
	size_t bytes;
	int ret;

	if (slots < 2) {
		pr_err(DEV_TAG "queue_slots must be >= 2\n");
		return -EINVAL;
	}

	bytes = (size_t)slots * sizeof(struct ecap_event);

	/*
	 * 先分配 per-CPU 暂存槽。
	 *
	 * 顺序刻意放在队列之前：ecap_push 里只要发现暂存槽为空就会返回
	 * -ENOMEM，所以在队列可用之前就必须把暂存槽准备好。
	 * 反过来（先队列后暂存槽）会出现一个窗口：队列已可写、暂存槽还没
	 * 分配好，此时进来的事件会白白丢掉。
	 */
	for_each_possible_cpu(cpu) {
		ecap_stage[cpu] = kzalloc(sizeof(struct ecap_event), GFP_KERNEL);
		if (!ecap_stage[cpu]) {
			pr_err(DEV_TAG "stage alloc failed on cpu %u\n", cpu);
			ret = -ENOMEM;
			goto err_stage;
		}
	}

	/*
	 * vzalloc：虚拟地址连续、物理页可以分散，1MB 以上不会像 kmalloc 那样
	 * 因为找不到连续物理页而失败。
	 */
	ecap_queue_buf = vzalloc(bytes);
	if (!ecap_queue_buf) {
		pr_err(DEV_TAG "vzalloc(%zu) failed\n", bytes);
		ret = -ENOMEM;
		goto err_stage;
	}

	/*
	 * kfifo_init 的 size 参数是"字节数"，内部会除以 esize 得到元素个数，
	 * 并向 2 的幂向下取整。传入 slots * 4096 正好得到 slots 个槽。
	 */
	ret = kfifo_init(&ecap_queue, ecap_queue_buf, (unsigned int)bytes);
	if (ret) {
		pr_err(DEV_TAG "kfifo_init failed: %d\n", ret);
		/* 同上：buffer 是 vzalloc 的，只能 vfree，不能 kfifo_free */
		vfree(ecap_queue_buf);
		ecap_queue_buf = NULL;
		goto err_stage;
	}

	ecap_queue_slots = kfifo_size(&ecap_queue);

	ret = misc_register(&ecap_miscdev);
	if (ret) {
		pr_err(DEV_TAG "misc_register failed: %d\n", ret);
		vfree(ecap_queue_buf);
		ecap_queue_buf = NULL;
		goto err_stage;
	}

	pr_info(DEV_TAG "/dev/ecap_tls ready: %u slots x %zu bytes = %zu KB\n",
		ecap_queue_slots, sizeof(struct ecap_event), bytes / 1024);

	/*
	 * 最后才把 alive 置 true。
	 * 顺序：内存就绪 -> kfifo 就绪 -> 设备节点就绪 -> 允许使用。
	 * 前面任何一步失败都不会让读者看到一个"半成品"设备。
	 */
	ecap_dev_alive = true;
	return 0;

err_stage:
	for_each_possible_cpu(cpu) {
		kfree(ecap_stage[cpu]);
		ecap_stage[cpu] = NULL;
	}
	return ret;
}

void ecap_dev_exit(void)
{
	unsigned int cpu;

	/*
	 * 先摘设备节点，此后不会有新的 open()/ioctl() 进来。
	 * 已经在 read() 里阻塞的读者会因 misc_deregister 后的行为自行返回；
	 * 真正的保证来自 ecap_main.c 的顺序：先 ecap_uprobe_exit()，
	 * 再 ecap_dev_exit()，所以此时不再有新的写入者。
	 */
	misc_deregister(&ecap_miscdev);

	/*
	 * 【卸载顺序：立旗 -> 唤醒 -> 释放】
	 *
	 * 1) 先把 alive 置 false。此后 read() 的每一轮循环都会立刻返回
	 *    -ENODEV，不会再去碰队列内存。
	 * 2) 唤醒所有睡在 read() 里的读者，让它们看到这个旗子。
	 * 3) 最后才 vfree。此时已经没有任何执行流会访问队列。
	 *
	 * 如果反过来（先 vfree 再唤醒），读者从 wait_event 出来后就会在
	 * 已释放的 kfifo 上调用 kfifo_out —— use-after-free。
	 */
	ecap_dev_alive = false;
	wake_up_all(&ecap_waitq);

	/*
	 * 给在途的读者一点时间跑完 read() 的尾段。
	 *
	 * 严格说，模块引用计数（fops.owner = THIS_MODULE）已经保证
	 * "还有 fd 打开时 rmmod 不会成功"，所以这里理论上等不到东西。
	 * 但 ecap_dev_exit 也可能在初始化失败的回滚路径上被调用，
	 * 那时引用计数的语义不适用，多等一步是免费的保险。
	 */
	if (ecap_queue_buf) {
		/*
		 * 【不要调用 kfifo_free】
		 * kfifo_free 会对 fifo->data 调 kfree，而我们的 buffer 是
		 * vzalloc 分配的 —— 用 kfree 释放 vmalloc 内存会直接 panic。
		 * kfifo_init 用的是"外部传入 buffer"模式，所有权仍在我们手上，
		 * 所以正确做法是：只把 kfifo 的 in/out 归零，然后自己 vfree。
		 */
		kfifo_reset(&ecap_queue);
		vfree(ecap_queue_buf);
		ecap_queue_buf = NULL;
	}

	/*
	 * 释放 per-CPU 暂存槽。
	 *
	 * 必须在队列之后再释放：ecap_push 会先检查 ecap_queue_buf，
	 * 队列已置空的情况下它直接返回 -ENODEV，不会再碰暂存槽。
	 * 反过来的话，一个刚进来的 push 可能拿到已释放的暂存槽。
	 */
	for_each_possible_cpu(cpu) {
		kfree(ecap_stage[cpu]);
		ecap_stage[cpu] = NULL;
	}
}
