// SPDX-License-Identifier: GPL-2.0
/*
 * hello_chardev.c - 一个"教科书式"的字符设备驱动，用于教学
 *
 * 这个模块刻意做得小而完整，覆盖写驱动必须掌握的每一个环节：
 *
 *   1. module_init / module_exit 的配对与错误回滚阶梯
 *   2. alloc_chrdev_region / cdev_init / cdev_add / device_create 的装配顺序
 *   3. struct file_operations 里每个回调的职责、返回值约定、并发模型
 *   4. copy_to_user / copy_from_user 与 __user 标注
 *   5. ioctl 的 cmd 编码、方向校验、兼容性处理
 *   6. 自旋锁 / 互斥锁的分工，以及"内核态不能信任用户指针"
 *   7. 阻塞 I/O（poll/read）与 O_NONBLOCK
 *   8. mmap / llseek / compat_ioctl 这几个"可选但常见"的回调怎么留位置
 *
 * 编译：见同目录 Makefile。加载后会出现 /dev/hello。
 * 测试：见同目录 test_hello.c 与 README-chardev.md。
 *
 * 【与 ecap_tls_main.c 的关系】
 * 后者用 miscdevice（只要一个字符设备、不需要动态次设备号、不需要 sysfs 节点时
 * 最省事的注册方式）。本文件用"完整版"字符设备注册流程，把 miscdevice 帮你
 * 隐藏的那些步骤全部摊开。理解了这里的每一步，再看 misc_register() 就一眼明白
 * 它内部做了什么。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>

#include "hello_uapi.h"

#define DEV_NAME   "hello"
#define CLASS_NAME "hello_class"
#define RING_SLOTS 16          /* 环形队列容量（必须是 2 的幂，便于掩码取模） */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eCapture teaching example");
MODULE_DESCRIPTION("A minimal but complete char device driver for learning file_operations");
MODULE_VERSION("1.0.0");

/* =========================================================================
 * 一、设备状态：一个"每设备一份"的结构体
 * =========================================================================
 *
 * 关键设计原则：**不要用全局变量装设备状态**。
 * 一个驱动可能管理多个设备实例（多个次设备号），状态必须能从
 * file->private_data 顺着找到。这里只有一个实例，但仍然把它分配出来，
 * 目的就是让"状态归属"这件事在代码结构上成立。
 */
struct hello_dev {
	struct cdev cdev;                 /* 必须内嵌，cdev_add 时传它的地址 */
	struct device *dev;               /* sysfs /dev 节点 */

	/*
	 * 环形队列：写端 push、读端 pop。
	 * 用 spinlock 而不是 mutex，因为 push 可能在原子上下文被调用
	 * （未来若挂 timer/irq 就已是原子上下文）。这里虽然都在进程上下文，
	 * 但保持"生产者锁必须能在原子上下文用"这条纪律，避免将来踩坑。
	 */
	struct hello_msg *ring;           /* RING_SLOTS 个槽位，vmalloc 分配 */
	u32 head;                         /* 生产者位置（只被持有 ring_lock 者修改） */
	u32 tail;                         /* 消费者位置 */
	spinlock_t ring_lock;

	wait_queue_head_t readq;          /* 读者在这里等"队列非空" */
	wait_queue_head_t writeq;         /* （可选）写者在这里等"队列不满" */

	/* 标量配置：用 mutex 保护，因为可能包含需要睡眠的操作 */
	struct mutex cfg_lock;
	u32 echo_value;                   /* HELLO_IOC_SET_ECHO / GET_ECHO 的载体 */

	/* 统计：纯计数用 atomic64，读快照时逐个读即可 */
	atomic64_t stat_opens;
	atomic64_t stat_releases;
	atomic64_t stat_reads;
	atomic64_t stat_writes;
	atomic64_t stat_ioctls;
	atomic64_t stat_msgs_in;
	atomic64_t stat_msgs_out;
	atomic64_t stat_dropped;
	atomic_t   stat_openers;          /* 当前打开者数量 */
	atomic_t   seq;                   /* 消息序号 */
};

static dev_t g_devno;                 /* 主+次设备号 */
static struct class *g_class;
static struct hello_dev *g_hdev;

/*
 * 全局实例的保护锁：g_hdev 在模块加载时创建、卸载时销毁，
 * 生命周期与模块相同，因此访问它不需要额外同步。
 */

/* =========================================================================
 * 二、内部辅助函数
 * ========================================================================= */

/* 队列是否为空 */
static bool ring_is_empty(struct hello_dev *d)
{
	bool empty;

	spin_lock(&d->ring_lock);
	empty = (d->head == d->tail);
	spin_unlock(&d->ring_lock);
	return empty;
}

/* 队列是否已满：环形队列留一个空位来区分"满"和"空" */
static bool ring_is_full(struct hello_dev *d)
{
	bool full;

	spin_lock(&d->ring_lock);
	full = ((d->head + 1) & (RING_SLOTS - 1)) == d->tail;
	spin_unlock(&d->ring_lock);
	return full;
}

/*
 * 入队一条消息。
 * 返回 0 成功；-ENOSPC 队列满。
 *
 * 注意：入队后必须 wake_up，否则已经在 read() 里睡眠的读者永远不会醒来。
 * wake_up_interruptible 可以在持锁时调用，但更推荐在释放锁之后调用，
 * 以减少"被唤醒者立刻抢同一把锁"的自旋。
 */
static int ring_push(struct hello_dev *d, const struct hello_msg *msg)
{
	u32 next;
	int ret = 0;

	spin_lock(&d->ring_lock);
	next = (d->head + 1) & (RING_SLOTS - 1);
	if (next == d->tail) {
		/* 满了：丢弃并计数。绝不在这里睡眠等待。 */
		ret = -ENOSPC;
	} else {
		d->ring[d->head] = *msg;
		d->head = next;
		atomic64_inc(&d->stat_msgs_in);
	}
	spin_unlock(&d->ring_lock);

	if (ret == 0)
		wake_up_interruptible(&d->readq);
	return ret;
}

/*
 * 出队一条消息。调用者需保证队列非空（或接受 -EAGAIN）。
 * 返回 0 成功；-EAGAIN 队列空。
 */
static int ring_pop(struct hello_dev *d, struct hello_msg *out)
{
	int ret = 0;

	spin_lock(&d->ring_lock);
	if (d->head == d->tail) {
		ret = -EAGAIN;
	} else {
		*out = d->ring[d->tail];
		d->tail = (d->tail + 1) & (RING_SLOTS - 1);
		atomic64_inc(&d->stat_msgs_out);
	}
	spin_unlock(&d->ring_lock);

	/* pop 之后队列腾出空位，若有人在等"可写"则唤醒 */
	if (ret == 0)
		wake_up_interruptible(&d->writeq);
	return ret;
}

/*
 * 等待并取出一条消息。
 *
 * 为什么需要这个循环而不是"检查 + 取出"两步？
 *   多个 reader 并发时，A 检查到非空、B 抢先 pop 走了，
 *   A 随后 pop 会失败。阻塞语义下不能把 -EAGAIN 返回给用户
 *   （用户没开 O_NONBLOCK，期望的是"一直等到有数据"）。
 *   所以必须重试，而不是直接把竞态失败暴露给用户态。
 */
static int ring_pop_wait(struct hello_dev *d, struct hello_msg *out, bool nonblock)
{
	for (;;) {
		int ret = ring_pop(d, out);

		if (ret == 0)
			return 0;
		if (nonblock)
			return -EAGAIN;

		/*
		 * wait_event_interruptible 在"条件已满足"时立即返回 0，
		 * 因此这个循环不会无谓地睡下去；被信号打断时返回 -ERESTARTSYS。
		 */
		ret = wait_event_interruptible(d->readq, !ring_is_empty(d));
		if (ret)
			return -ERESTARTSYS;
	}
}

/*
 * 等待并压入一条消息。与 ring_pop_wait 镜像。
 */
static int ring_push_wait(struct hello_dev *d, const struct hello_msg *msg,
			  bool nonblock)
{
	for (;;) {
		int ret = ring_push(d, msg);

		if (ret == 0)
			return 0;
		if (nonblock) {
			atomic64_inc(&d->stat_dropped);
			return -ENOSPC;
		}

		ret = wait_event_interruptible(d->writeq, !ring_is_full(d));
		if (ret) {
			atomic64_inc(&d->stat_dropped);
			return -ERESTARTSYS;
		}
	}
}

/* =========================================================================
 * 三、struct file_operations 的各个回调
 * =========================================================================
 *
 * 先建立一个心智模型：
 *
 *   用户态动作            内核 VFS 调用               本驱动实现
 *   ------------------------------------------------------------------
 *   open("/dev/hello")    f_op->open()                hello_open
 *   read(fd, buf, n)      f_op->read()  (或 read_iter) hello_read
 *   write(fd, buf, n)     f_op->write() (或 write_iter) hello_write
 *   ioctl(fd, cmd, arg)   f_op->unlocked_ioctl()      hello_ioctl
 *   lseek(fd, off, wh)    f_op->llseek()               hello_llseek
 *   poll(fd, POLLIN)      f_op->poll()                 hello_poll
 *   mmap(...)             f_op->mmap()                 hello_mmap
 *   close(fd)             f_op->release()              hello_release
 *
 * 每一个回调都是"内核在进程上下文里、以该进程的身份"调用的，
 * 因此：
 *   - 默认可以睡眠（除非你自己关抢占/持自旋锁/在中断里）
 *   - user 指针必须用 copy_*_user 而非直接解引用
 *   - 返回值用负数 errno，成功用非负值（read/write 返回字节数）
 *   - 多个进程可能同时进入同一个回调 → 必须自己加锁
 */

/* -------------------------------------------------------------------------
 * 1) open()
 *
 * 原型：int (*open)(struct inode *inode, struct file *file)
 *
 * 职责：
 *   - 做"一次性"校验（比如设备是否就绪）
 *   - 把本设备的状态挂到 file->private_data，后续所有回调从这里取
 *   - 递增使用者计数
 *
 * 返回值：0 成功，负数失败（VFS 会把它作为 open() 的 errno 返回给用户）。
 *
 * 常见错误：在这里做耗时的初始化。open 会被频繁调用，应尽量轻量；
 * 真正的重活放在 module_init 或第一次使用时（lazy init）。
 * ------------------------------------------------------------------------- */
static int hello_open(struct inode *inode, struct file *file)
{
	struct hello_dev *d;

	/*
	 * container_of 是驱动里最常用的宏：已知 cdev 的地址，
	 * 反推包含它的 hello_dev 地址。
	 *   inode->i_cdev 指向我们在 cdev_add 时注册的 cdev。
	 */
	d = container_of(inode->i_cdev, struct hello_dev, cdev);
	if (!d)
		return -ENODEV;

	/*
	 * 把设备指针塞进 file->private_data。
	 * 之后 read/write/ioctl/release 全部通过 file->private_data 取回，
	 * 不需要再走 inode（inode 在某些路径上可能不易拿到）。
	 */
	file->private_data = d;

	atomic64_inc(&d->stat_opens);
	atomic_inc(&d->stat_openers);

	pr_info("hello: open by pid=%d comm=%s (openers=%d)\n",
		task_tgid_nr(current), current->comm,
		atomic_read(&d->stat_openers));
	return 0;
}

/* -------------------------------------------------------------------------
 * 2) release()
 *
 * 原型：int (*release)(struct inode *inode, struct file *file)
 *
 * 注意它叫 release 不叫 close：**只有最后一个引用被关闭时才会调用一次**。
 * open / dup / fork 都会让同一个 struct file 的引用计数增加，
 * 每一次 close() 只减少引用计数，计数归 0 时才触发 release。
 * 所以"释放设备资源"放在这里是正确的，但不要以为它等价于"用户每次 close 都通知你"。
 *
 * 返回值：0 成功。release 的返回值用户态看不到（close 返回 void），
 * 但仍应返回正确值以便内核日志/调试追踪。
 *
 * 常见错误：以为 release 一定会被调用。进程如果被 SIGKILL 且没有正常
 * 关闭 fd，内核仍会在进程退出时调用 release —— 这点是可靠的。但如果
 * 模块先被 rmmod（引用计数非 0 时 rmmod 会失败），则顺序不保证。
 * ------------------------------------------------------------------------- */
static int hello_release(struct inode *inode, struct file *file)
{
	struct hello_dev *d = file->private_data;

	if (!d)
		return 0;

	atomic64_inc(&d->stat_releases);
	pr_info("hello: release by pid=%d (openers=%d)\n",
		task_tgid_nr(current), atomic_dec_return(&d->stat_openers));
	return 0;
}

/* -------------------------------------------------------------------------
 * 3) read()
 *
 * 原型：ssize_t (*read)(struct file *file, char __user *buf,
 *                      size_t count, loff_t *ppos)
 *
 * 职责：从设备取数据，写到用户缓冲区 buf（最多 count 字节）。
 *
 * 返回值约定（非常重要）：
 *    > 0 : 实际拷贝的字节数（可以小于 count，用户态负责循环）
 *    = 0 : EOF，用户态 read() 会返回 0
 *    < 0 : -errno
 *      -EAGAIN  : 非阻塞模式下暂时无数据
 *      -EFAULT  : 用户缓冲区非法
 *      -EINTR   : 被信号打断
 *
 * 四个必须遵守的纪律：
 *   a) buf 是 __user 指针，**绝不能直接解引用**（*buf / memcpy 都不行），
 *      只能用 copy_to_user()。__user 是 sparse 的标注，帮助静态检查。
 *   b) 睡眠前必须检查 O_NONBLOCK，否则 poll() 报告"可读"之前就阻塞了。
 *   c) 被唤醒后要**重新检查条件**（wait_event 宏会自动做，手写循环千万别忘），
 *      否则可能因为虚假唤醒(spurious wakeup)而读到空数据。
 *   d) 返回值是字节数，不是"消息条数"。
 *
 * 本实现采用"一条 read 返回一条消息"的语义，因此要求 count >= sizeof(msg)，
 * 否则返回 -EINVAL 而不是截断 —— 截断会让用户态解析出错误结构。
 * ------------------------------------------------------------------------- */
static ssize_t hello_read(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct hello_dev *d = file->private_data;
	struct hello_msg msg;
	int ret;

	if (count < sizeof(msg))
		return -EINVAL;

	/*
	 * 第一步：从环形队列取一条消息。
	 * ring_pop_wait 内部完成"等待 + 重试"，并处理 O_NONBLOCK：
	 *   - 队列空且 O_NONBLOCK → 返回 -EAGAIN
	 *   - 队列空且阻塞       → 睡在 readq 上直到有数据
	 *   - 被信号打断         → 返回 -ERESTARTSYS
	 *
	 * 自己手写等价代码时最容易漏掉的是"被唤醒后重新检查条件"
	 * （虚假唤醒 + 多 reader 竞争都会让第一次 pop 失败）。
	 */
	ret = ring_pop_wait(d, &msg, file->f_flags & O_NONBLOCK);
	if (ret)
		return ret;

	/*
	 * 第二步：拷到用户缓冲区。
	 * copy_to_user 返回"未能拷贝的字节数"，0 表示全部成功。
	 * 千万不要写成 if (copy_to_user(...)) 然后当成成功 —— 那是反的。
	 */
	if (copy_to_user(buf, &msg, sizeof(msg)))
		return -EFAULT;

	atomic64_inc(&d->stat_reads);
	return sizeof(msg);
}

/* -------------------------------------------------------------------------
 * 4) write()
 *
 * 原型：ssize_t (*write)(struct file *file, const char __user *buf,
 *                       size_t count, loff_t *ppos)
 *
 * 与 read 镜像：从用户缓冲区读数据进设备。
 *
 * 同样四个纪律，另外加一条：
 *   e) 不能假设用户一次 write 的数据正好是一条完整消息。真实驱动要么
 *      攒够一条再处理（需要中间缓冲），要么明确文档化"必须整条写入"。
 *      本实现选后者：count != sizeof(msg) 直接 -EINVAL，语义清晰。
 *
 * 返回值：成功写入的字节数；失败 -errno。
 *   -ENOSPC 队列满（非阻塞模式）
 * ------------------------------------------------------------------------- */
static ssize_t hello_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	struct hello_dev *d = file->private_data;
	struct hello_msg msg;
	int ret;

	if (count != sizeof(msg))
		return -EINVAL;

	/*
	 * 先拷到内核栈上的临时变量，再做业务处理。
	 * 不要在持锁状态下 copy_from_user —— copy_from_user 可能缺页并睡眠，
	 * 而持自旋锁不允许睡眠。
	 */
	if (copy_from_user(&msg, buf, sizeof(msg)))
		return -EFAULT;

	/* 校验用户给的 len 字段，防止越界读 data[] */
	if (msg.len > HELLO_MSG_MAX)
		return -EINVAL;

	/*
	 * 清掉 len 之后的残留字节。
	 * 即便 copy_from_user 已完整覆盖整个结构体，仍建议这样做 ——
	 * 用户可能在 data[len..] 里塞垃圾，而下游若按"整个 data[] 都是有效
	 * 内容"处理就会泄露或误解析。
	 */
	memset(msg.data + msg.len, 0, HELLO_MSG_MAX - msg.len);

	/* 内核补全元数据，不信任用户填的 */
	msg.ts_ns = ktime_get_ns();
	msg.pid = task_tgid_nr(current);
	msg.seq = (u32)atomic_inc_return(&d->seq);
	msg.reserved = 0;

	ret = ring_push_wait(d, &msg, file->f_flags & O_NONBLOCK);
	if (ret)
		return ret;

	atomic64_inc(&d->stat_writes);
	return sizeof(msg);
}

/* -------------------------------------------------------------------------
 * 5) unlocked_ioctl()
 *
 * 原型：long (*unlocked_ioctl)(struct file *file, unsigned int cmd,
 *                              unsigned long arg)
 *
 * 名字里的 "unlocked" 是历史遗留：老接口 ioctl() 会持有 BKL（大内核锁），
 * 新接口不再持有，因此叫 unlocked。**它运行在进程上下文，可以睡眠**，
 * 所以可以放心用 mutex_lock / copy_from_user。
 *
 * 三个必须做的事：
 *   a) 校验 cmd 的类型（幻数）与序号，不认识的返回 -ENOTTY
 *     （注意是 ENOTTY "Not a typewriter" 这个历史名字，不是 EINVAL）
 *   b) 方向校验：_IOC_DIR(cmd) 决定是 copy_from_user 还是 copy_to_user，
 *      写反了就是安全漏洞
 *   c) arg 是 unsigned long，用户态可能传任意值 —— 必须视为不可信
 *
 * 为什么不能只比较 _IOC_NR：
 *   如果只比序号，用户态传一个大小不对的 cmd 也能进来，
 *   随后 copy_from_user(&kstruct, arg, sizeof(kstruct)) 可能读到越界内存。
 *   比较完整 cmd 常量（含大小）才能挡住。
 * ------------------------------------------------------------------------- */
static long hello_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct hello_dev *d = file->private_data;
	void __user *uarg = (void __user *)arg;
	long ret = 0;

	/* 第一步：幻数校验。类型不对直接拒绝。 */
	if (_IOC_TYPE(cmd) != HELLO_IOC_MAGIC)
		return -ENOTTY;
	if (_IOC_NR(cmd) > HELLO_IOC_MAXNR)
		return -ENOTTY;

	switch (cmd) {
	case HELLO_IOC_GET_STATS: {
		struct hello_stats st;

		memset(&st, 0, sizeof(st));
		st.opens    = atomic64_read(&d->stat_opens);
		st.releases = atomic64_read(&d->stat_releases);
		st.reads    = atomic64_read(&d->stat_reads);
		st.writes   = atomic64_read(&d->stat_writes);
		st.ioctls   = atomic64_read(&d->stat_ioctls);
		st.msgs_in  = atomic64_read(&d->stat_msgs_in);
		st.msgs_out = atomic64_read(&d->stat_msgs_out);
		st.dropped  = atomic64_read(&d->stat_dropped);
		st.slots    = RING_SLOTS;

		spin_lock(&d->ring_lock);
		st.queued = (d->head - d->tail) & (RING_SLOTS - 1);
		spin_unlock(&d->ring_lock);

		/* _IOR：内核 -> 用户，用 copy_to_user */
		if (copy_to_user(uarg, &st, sizeof(st)))
			return -EFAULT;
		break;
	}

	case HELLO_IOC_RESET:
		/* _IO：无数据，只做动作 */
		atomic64_set(&d->stat_opens, 0);
		atomic64_set(&d->stat_releases, 0);
		atomic64_set(&d->stat_reads, 0);
		atomic64_set(&d->stat_writes, 0);
		atomic64_set(&d->stat_ioctls, 0);
		atomic64_set(&d->stat_msgs_in, 0);
		atomic64_set(&d->stat_msgs_out, 0);
		atomic64_set(&d->stat_dropped, 0);
		break;

	case HELLO_IOC_SET_ECHO: {
		u32 v;

		/* _IOW：用户 -> 内核，用 copy_from_user */
		if (copy_from_user(&v, uarg, sizeof(v)))
			return -EFAULT;
		mutex_lock(&d->cfg_lock);
		d->echo_value = v;
		mutex_unlock(&d->cfg_lock);
		break;
	}

	case HELLO_IOC_GET_ECHO: {
		u32 v;

		mutex_lock(&d->cfg_lock);
		v = d->echo_value;
		mutex_unlock(&d->cfg_lock);
		/* _IOR：内核 -> 用户 */
		if (copy_to_user(uarg, &v, sizeof(v)))
			return -EFAULT;
		break;
	}

	default:
		ret = -ENOTTY;
		break;
	}

	if (ret == 0)
		atomic64_inc(&d->stat_ioctls);
	return ret;
}

/* -------------------------------------------------------------------------
 * 6) compat_ioctl()：32 位用户态程序调用 64 位内核时使用
 *
 * 为什么需要它：指针在 32 位下是 4 字节，64 位下是 8 字节。
 * 如果结构体里含指针或 long，两边的布局不同，就不能直接复用。
 * 本驱动的结构体全部用固定宽度整数，因此可以直接转发。
 *
 * 若驱动不提供 compat_ioctl，32 位程序调用 ioctl 会得到 -ENOTTY
 * （VFS 找不到兼容处理路径）。Android 上这很常见：64 位系统跑 32 位 App。
 * ------------------------------------------------------------------------- */
static long hello_compat_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	/*
	 * 本驱动的所有 ioctl 结构体都不含指针/long，因此直接复用。
	 * 若含指针，需要在这里定义一套 *_compat 结构体并做转换。
	 */
	return hello_ioctl(file, cmd, arg);
}

/* -------------------------------------------------------------------------
 * 7) llseek()
 *
 * 原型：loff_t (*llseek)(struct file *file, loff_t offset, int whence)
 *
 * 字符设备的读写默认是"流"，没有文件偏移的概念。用户态若调用 lseek()
 * 而驱动没实现 llseek，会得到 -ESPIPE（Illegal seek）。
 *
 * 两种常见策略：
 *   1) 实现 no_llseek（返回 -ESPIPE，显式不支持）—— 流式设备推荐
 *   2) 实现 noop_llseek（返回当前 *ppos 不变）—— 兼容某些工具的行为
 *
 * 若设备是"块状"的（比如 EEPROM、寄存器窗口），应该实现真正的 seek：
 *   - 更新 *ppos
 *   - 校验越界
 *   - 返回新位置
 * ------------------------------------------------------------------------- */
static loff_t hello_llseek(struct file *file, loff_t offset, int whence)
{
	struct hello_dev *d = file->private_data;
	loff_t newpos;

	switch (whence) {
	case SEEK_SET:
		newpos = offset;
		break;
	case SEEK_CUR:
		newpos = file->f_pos + offset;
		break;
	case SEEK_END:
		/* 环形队列没有"末尾"，用已入队条数当作长度 */
		newpos = (loff_t)atomic_read(&d->seq) + offset;
		break;
	default:
		return -EINVAL;
	}

	if (newpos < 0)
		return -EINVAL;

	file->f_pos = newpos;
	return newpos;
}

/* -------------------------------------------------------------------------
 * 8) poll()
 *
 * 原型：__poll_t (*poll)(struct file *file, struct poll_table_struct *wait)
 *
 * 职责：告诉 VFS "这个 fd 现在能不能读/写"，并注册等待队列。
 *
 * 标准三步：
 *   1. poll_wait(file, &queue, wait)   —— 注册（可能调用多次，注册多个队列）
 *   2. 检查条件
 *   3. 返回就绪掩码（EPOLLIN / EPOLLOUT / EPOLLERR ...）
 *
 * poll() 本身**不睡眠**，它只是注册 + 报告。真正的睡眠发生在
 * VFS/poll 系统调用层。这是 poll 与 read 的关键区别。
 *
 * 返回值用 __poll_t（4 字节），不是老式的 unsigned int。
 * ------------------------------------------------------------------------- */
static __poll_t hello_poll(struct file *file, poll_table *wait)
{
	struct hello_dev *d = file->private_data;
	__poll_t mask = 0;

	/* 注册两个队列：可读队列 + 可写队列 */
	poll_wait(file, &d->readq, wait);
	poll_wait(file, &d->writeq, wait);

	if (!ring_is_empty(d))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (!ring_is_full(d))
		mask |= EPOLLOUT | EPOLLWRNORM;

	/* 若设备处于错误状态，应置 EPOLLERR / EPOLLHUP */
	return mask;
}

/* -------------------------------------------------------------------------
 * 9) mmap()
 *
 * 原型：int (*mmap)(struct file *file, struct vm_area_struct *vma)
 *
 * 把内核（或物理）内存映射到用户空间。这是"零拷贝"的基础。
 *
 * 两条主流路线：
 *   a) remap_vmalloc_range：把 vzalloc/vmalloc 分配的（物理上可能不连续的）
 *      缓冲区映射到用户空间。内部会遍历 vmalloc 区域逐页建映射。
 *   b) remap_pfn_range：把一段物理连续的页映射过去（__get_free_pages、
 *      DMA coherent buffer）。**不能**用于 vmalloc 缓冲区 —— 那只会映射
 *      第一页，是经典 bug 来源。
 *
 * 本例的 ring 用 vzalloc 分配，因此若要启用必须走 (a)。下面保留了一行
 * 注释掉的正确实现，同时默认返回 -ENODEV，避免给出一个"看起来能编译、
 * 实际有 bug"的示例。
 * ------------------------------------------------------------------------- */
static int hello_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct hello_dev *d = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long want = (unsigned long)RING_SLOTS * sizeof(struct hello_msg);

	if (size > want)
		return -EINVAL;

	/* 只支持 MAP_SHARED：MAP_PRIVATE 的写时复制语义对共享队列没意义 */
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	/*
	 * 启用 mmap 时改为：
	 *     return remap_vmalloc_range(vma, d->ring, vma->vm_pgoff);
	 * 注意 vma->vm_pgoff 是"页偏移"，用户态 mmap 时传入的 offset
	 * 必须是页大小的整数倍。
	 */
	(void)d;
	return -ENODEV;
}

/* =========================================================================
 * 四、file_operations 表本身
 * =========================================================================
 *
 * 注意几个要点：
 *
 * 1) 只填你实现的回调。未填的字段为 NULL，VFS 对该操作返回 -EINVAL
 *    或 -ENOTTY（视操作而定）。全填 NULL 是错的，会让用户态
 *    得到莫名其妙的行为而不是明确错误。
 *
 * 2) .owner = THIS_MODULE 是**必须的**。VFS 在进入回调前后会做
 *    try_module_get/module_put，保证回调执行期间模块不能被卸载。
 *    漏掉它 = 卸载时 use-after-free（经典崩溃）。
 *
 * 3) 用 designated initializer（.field = fn）而不是位置初始化，
 *    这样内核版本升级时字段顺序变化不会静默改变你的绑定。
 *
 * 4) 读/写有 iter 版本（read_iter/write_iter），面向 iov_iter。
 *    新驱动建议实现 iter 版本以获得更好的性能与兼容性；简单驱动
 *    实现 read/write 也完全可用（VFS 会自动包装）。
 */
static const struct file_operations hello_fops = {
	.owner          = THIS_MODULE,
	.open           = hello_open,
	.release        = hello_release,
	.read           = hello_read,
	.write          = hello_write,
	.unlocked_ioctl = hello_ioctl,
	.compat_ioctl   = hello_compat_ioctl,
	.llseek         = hello_llseek,
	.poll           = hello_poll,
	.mmap           = hello_mmap,
};

/* =========================================================================
 * 五、注册与注销：字符设备的标准装配流程
 * =========================================================================
 *
 * 完整步骤（顺序不能乱）：
 *
 *   alloc_chrdev_region()  动态申请 (主设备号, 次设备号基数, 数量)
 *        ↓
 *   cdev_alloc / 内嵌 cdev + cdev_init()  把 cdev 与 fops 绑定
 *        ↓
 *   cdev_add()             把 cdev 注册进内核，从此 open 才可能到达你
 *        ↓
 *   class_create()         创建 /sys/class/hello_class/
 *        ↓
 *   device_create()        创建 /sys/class/hello_class/hello 与 /dev/hello 节点
 *
 * 注销必须**严格逆序**，并且在任何一步失败时**只回滚已完成的部分**。
 * 这就是下面 init 里 goto 阶梯的来源 —— 内核代码最常见的错误处理风格。
 */

static int __init hello_init(void)
{
	int ret;

	/*
	 * 分配设备状态。
	 * 用 kzalloc 而非 kmalloc：清零是必须的（head/tail/锁都需要初始 0）。
	 */
	g_hdev = kzalloc(sizeof(*g_hdev), GFP_KERNEL);
	if (!g_hdev)
		return -ENOMEM;

	/* 环形队列：用 vzalloc，避免大块连续物理内存需求 */
	g_hdev->ring = vzalloc(RING_SLOTS * sizeof(struct hello_msg));
	if (!g_hdev->ring) {
		ret = -ENOMEM;
		goto err_free_dev;
	}

	spin_lock_init(&g_hdev->ring_lock);
	mutex_init(&g_hdev->cfg_lock);
	init_waitqueue_head(&g_hdev->readq);
	init_waitqueue_head(&g_hdev->writeq);
	atomic_set(&g_hdev->seq, 0);
	atomic_set(&g_hdev->stat_openers, 0);

	/*
	 * 第 1 步：申请设备号。
	 * 第一个参数 NULL 表示"让我用 0 表示动态分配主设备号"。
	 * 也可以传 &g_devno 并预先设为 0，效果一样。
	 */
	ret = alloc_chrdev_region(&g_devno, 0, 1, DEV_NAME);
	if (ret) {
		pr_err("hello: alloc_chrdev_region failed: %d\n", ret);
		goto err_free_ring;
	}
	pr_info("hello: major=%d minor=%d\n", MAJOR(g_devno), MINOR(g_devno));

	/*
	 * 第 2 步：初始化 cdev 并绑定 fops。
	 * cdev_init 会把 cdev->ops 设为 hello_fops，并初始化 kobject。
	 */
	cdev_init(&g_hdev->cdev, &hello_fops);
	g_hdev->cdev.owner = THIS_MODULE;

	/*
	 * 第 3 步：把 cdev 加入内核。
	 * 从这一刻起，/dev 下若有对应节点，open() 就会进入 hello_open。
	 */
	ret = cdev_add(&g_hdev->cdev, g_devno, 1);
	if (ret) {
		pr_err("hello: cdev_add failed: %d\n", ret);
		goto err_unregister_region;
	}

	/*
	 * 第 4 步：创建 class。
	 * 有了 class，udev/mdev 才能自动创建 /dev 节点。
	 * 第二个参数是父设备，NULL 表示挂在 /sys/class 下。
	 *
	 * 注意 API 变化：Linux 6.4 起 class_create() 去掉了 owner 参数。
	 * Android 5.10 (GKI 2.0) 仍是两个参数的版本，用版本宏做兼容。
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	g_class = class_create(CLASS_NAME);
#else
	g_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
	if (IS_ERR(g_class)) {
		ret = PTR_ERR(g_class);
		pr_err("hello: class_create failed: %d\n", ret);
		goto err_cdev_del;
	}

	/*
	 * 第 5 步：创建设备节点。
	 * 这里的 DEV_NAME 就是 /dev 下的名字。
	 */
	g_hdev->dev = device_create(g_class, NULL, g_devno, NULL, DEV_NAME);
	if (IS_ERR(g_hdev->dev)) {
		ret = PTR_ERR(g_hdev->dev);
		pr_err("hello: device_create failed: %d\n", ret);
		goto err_class_destroy;
	}

	pr_info("hello: loaded, /dev/%s ready\n", DEV_NAME);
	return 0;

	/*
	 * 错误回滚阶梯：每一步的标签只回滚"该步之前已成功"的资源。
	 * 这种写法比在每个失败点重复写 cleanup 更不容易漏。
	 */
err_class_destroy:
	class_destroy(g_class);
err_cdev_del:
	cdev_del(&g_hdev->cdev);
err_unregister_region:
	unregister_chrdev_region(g_devno, 1);
err_free_ring:
	vfree(g_hdev->ring);
err_free_dev:
	kfree(g_hdev);
	g_hdev = NULL;
	return ret;
}

static void __exit hello_exit(void)
{
	/* 严格逆序注销 */
	device_destroy(g_class, g_devno);
	class_destroy(g_class);
	cdev_del(&g_hdev->cdev);
	unregister_chrdev_region(g_devno, 1);

	/*
	 * 此时已不会有新的 open 进来，但可能仍有进程阻塞在 read/write 里
	 * 等待队列。必须先唤醒它们（返回 0 数据 / -ENODEV），否则 rmmod 会
	 * 卡在"模块引用计数非 0"上。
	 *
	 * 生产中更严谨的做法是在 file_operations 里加一个 "device_down" 标志，
	 * 唤醒后让 read/write 检查该标志并返回 -ENODEV。
	 */
	wake_up_interruptible_all(&g_hdev->readq);
	wake_up_interruptible_all(&g_hdev->writeq);

	vfree(g_hdev->ring);
	kfree(g_hdev);
	g_hdev = NULL;

	pr_info("hello: unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);
