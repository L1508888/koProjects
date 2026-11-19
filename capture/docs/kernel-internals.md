# 内核态源码详解

本文逐个函数解释 `kernel/` 下的四个 C 文件。
`ecap_ksym.c` 不在此文范围内（它只有 kallsyms 两级跳这一件事，
相关说明见 `README.md` 第四节第 2、3 条）。

- [一、ecap_main.c](#一ecap_mainc)
- [二、ecap_dev.c](#二ecap_devc)
- [三、ecap_uprobe.c](#三ecap_uprobec)
- [四、ecap_nf.c](#四ecap_nfc)

---

## 一、ecap_main.c

### 这个文件做什么

**只有一件事：按严格顺序装配和拆卸三个子系统。**

它不含任何业务逻辑 —— 没有 uprobe handler、没有队列操作、没有 ioctl 分发。
所有实质工作都在 `ecap_dev.c` 和 `ecap_uprobe.c` 里。

之所以单独拆一个文件，是因为**装配顺序本身就是正确性的一部分**。
把顺序集中在一处、用注释写清每一步为什么不能调换，比散在各个模块的
init/exit 里安全得多。

### 依赖关系

```
ecap_main.c
    ├── ecap_ksym_init()     解析 uprobe_register / uprobe_unregister 地址
    ├── ecap_dev_init()      建 /dev/ecap_tls、环形队列、per-CPU 暂存槽
    └── ecap_uprobe_init()   初始化探测点链表（此时还没有任何探测点）
```

### 函数详解

#### `static int __init ecap_init(void)`

模块加载入口，由 `module_init(ecap_init)` 注册。

**执行顺序（三步，缺一不可的前后依赖）：**

| 步骤 | 调用 | 为什么必须在这个位置 |
| :-- | :-- | :-- |
| 1 | `ecap_ksym_init()` | 后面注册 uprobe 要用它解析出来的函数地址。没有符号表什么都做不了 |
| 2 | `ecap_dev_init()` | uprobe handler 需要队列才有地方写事件。队列必须先于探测点存在 |
| 3 | `ecap_uprobe_init()` | 只初始化链表头，很轻。放在最后是因为它逻辑上"依赖前两者就绪" |

**错误回滚：** 采用经典的 goto 阶梯。第 2 步失败回到 `err_ksym` 只清符号表；
第 3 步失败回到 `err_dev`，先销毁设备再清符号表。顺序与初始化相反，
保证每一层只释放自己已成功申请的资源。

**注意：** 任何一步失败都直接返回非 0，让 `insmod` 报错。
不做"加载了但功能残缺"这种降级 —— 那种状态最难排查。

```c
static int __init ecap_init(void)
{
    ret = ecap_ksym_init();       /* 1. 符号 */
    if (ret) return ret;

    ret = ecap_dev_init();        /* 2. 设备 */
    if (ret) goto err_ksym;

    ret = ecap_uprobe_init();     /* 3. 探测点管理 */
    if (ret) goto err_dev;
    ...
err_dev:
    ecap_dev_exit();
err_ksym:
    ecap_ksym_exit();
    return ret;
}
```

#### `static void __nocfi __exit ecap_exit(void)`

模块卸载入口，由 `module_exit(ecap_exit)` 注册。

**执行顺序是 `ecap_init` 的镜像，而且这里一步都不能错：**

| 步骤 | 调用 | 如果顺序错了会怎样 |
| :-- | :-- | :-- |
| 1 | `ecap_uprobe_exit()` | 先摘探测点。handler 里会 `ecap_push()` 往队列写数据 |
| 2 | `ecap_dev_exit()` | 再释放队列。若反过来，正在执行的 handler 会写到已 `vfree` 的内存 → use-after-free → panic |
| 3 | `ecap_ksym_exit()` | 最后清符号表。`ecap_uprobe_exit` 内部要用 `uprobe_unregister` 的函数指针，不能提前置空 |

**`__nocfi` 为什么在这里：**

卸载链路上有"间接调用未导出函数"（`ecap_probe_free` → `ecap_uprobe_unregister`
→ 通过 kallsyms 拿到的 `uprobe_unregister` 指针）。在
`CONFIG_CFI_CLANG=y` 且 `CONFIG_CFI_PERMISSIVE` 未开的内核上，
CFI 违规会直接 `__cfi_check_fail` → panic。给入口标 `__nocfi` 是兜底，
实际起作用的是 `ecap_ksym.c` 里那些转发函数自己的 `__nocfi`。

**`__exit` 的意义：** 告诉编译器这个函数只在模块卸载时用。
如果内核是 built-in（`=y`）而非模块（`=m`），这个函数会被丢弃。

---

## 二、ecap_dev.c

### 这个文件做什么

实现 `/dev/ecap_tls` 字符设备，以及内核 → 用户态的**事件通道**。

用 eBPF 时这部分由 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 提供；LKM 没有这个东西，
必须自己造。只需要三个部件：

```
kfifo（定长环形队列） + spinlock（跨 CPU 互斥） + waitqueue（唤醒读者）
```

### 数据流

```
uprobe handler / ioctl            （任意上下文，不能睡眠）
      │  ecap_push(&blob)
      ▼
struct ecap_blob（散装字段）
      │  拼成 4096 字节的 struct ecap_event
      ▼
per-CPU 暂存槽（免锁，靠关中断保护）
      │  kfifo_in(&ecap_queue, ev, 1)
      ▼
kfifo（256 槽 × 4096 字节 = 1MB）
      │  __wake_up()
      ▼
用户态 ecapctl: poll() → read() 读出一个完整槽
```

### 全局状态

| 变量 | 作用 |
| :-- | :-- |
| `ecap_queue` | `DECLARE_KFIFO_PTR`，元素类型是 `struct ecap_event`。**注意 `in`/`out` 计数单位是"槽"不是"字节"** |
| `ecap_queue_buf` | 队列底层内存，`vzalloc` 分配（见 `ecap_dev_init`） |
| `ecap_queue_lock` | 保护 kfifo 的跨 CPU 互斥 |
| `ecap_waitq` | 读者等待队列 |
| `ecap_stage[NR_CPUS]` | per-CPU 拼装缓冲，见 `ecap_push` |
| `ecap_dev_alive` | 设备生命周期标志，卸载时防止 UAF |
| `ecap_stat_*` | 五个 `atomic64_t` 统计计数 |

### 函数详解

#### `u32 ecap_clamp_len(u32 len, __u8 *flags)`

把 payload 长度裁到槽容量以内，空间不够时置 `ECAP_EV_FLAG_TRUNC`。

**为什么需要它：** 一次 `SSL_write` 可能要写 2MB（比如上传文件），
但一个槽只有 4096 字节。直接 `memcpy` 会溢出。

```c
#define ECAP_PAYLOAD_MAX (ECAP_SLOT_SIZE - 48u)   /* 4096 - 48 = 4048 */
```

`flags` 用指针传，因为调用方需要知道"发生了截断"。
这个函数本身不分配、不加锁，纯计算，可在任意上下文调用。

#### `int ecap_push(const struct ecap_blob *b)`

**整个模块的热路径。** 把一条散装事件拼成完整槽并入队。

**返回值：** `0` 成功，`-ENOSPC` 队列满被丢弃，`-ENOMEM` 暂存槽未就绪，
`-ENODEV` 设备已卸载。

**关键设计一：为什么不用 `kmalloc(4096, GFP_ATOMIC)`**

`struct ecap_event` 有 4096 字节，放栈上会爆（内核栈 16KB）。
最初写法是每条事件 `kmalloc` 一次 4KB —— 在 `SSL_write` 热路径上
既慢又可能因内存碎片失败。改成 per-CPU 常驻缓冲后：无锁、不分配。

**关键设计二：为什么必须关中断，而不是只关抢占**

uprobe handler 在进程上下文跑，本身允许被中断打断。而 Netfilter 的软中断
路径将来也会调 `ecap_push`。如果只禁抢占，一个软中断插进来就会把同一个 CPU
的暂存槽写花。`local_irq_save()` 提供的"本 CPU 不可被打断"才是 per-CPU 缓冲
能免锁使用的真正前提。

**关键设计三：为什么拿 `ecap_queue_lock` 时不带 `irqsave`**

因为外面已经被 `local_irq_save()` 包住了，中断已经关闭，再 `irqsave` 是冗余的。
两个函数如果都用 `irqsave` 也不会错，但这里是刻意区分开的。

**已知代价：** 关中断期间做了一次最大 4KB 的 `memcpy`，会推迟本 CPU 的中断响应
微秒级时间。如果将来 payload 涨到几十 KB，必须改成"关中断只做指针交换，
拷贝放到中断外"。

```c
local_irq_save(irqflags);
cpu = smp_processor_id();
ev  = ecap_stage[cpu];
...
memset(ev, 0, sizeof(*ev));        /* 填头 */
ev->hdr.dir = b->dir;              /* ← M3：写方向 */
memcpy(ev->payload, b->data, len); /* 填 payload */
spin_lock(&ecap_queue_lock);
ok = (kfifo_in(&ecap_queue, ev, 1) == 1);  /* 整槽原子入队 */
spin_unlock(&ecap_queue_lock);
local_irq_restore(irqflags);

if (ok) __wake_up(&ecap_waitq, TASK_INTERRUPTIBLE, 1, NULL);
```

唤醒放在所有锁之外，避免把读者线程拉进持锁路径。

**M3 的 `dir` 字段：** `ecap_blob` 加了一个 `dir`（`ECAP_DIR_WRITE` /
`ECAP_DIR_READ`），直接写进 `hdr.dir`。它占用了原先 `reserved[0]` 的位置，
所以结构体总大小仍是 48 字节，`ECAP_ABI_VERSION` 不需要递增。

#### `static int ecap_dev_open(struct inode *inode, struct file *file)`

`open("/dev/ecap_tls")` 的处理。

为每个 fd 分配一份**独立的读出缓冲** `struct ecap_reader`。
不能共用全局缓冲：多个读者并发 `read()` 时，从 kfifo 取出到
`copy_to_user` 之间会互相覆盖。

开头检查 `ecap_dev_alive`，卸载流程刚开始时拒绝新的打开请求。

#### `static int ecap_dev_release(struct inode *inode, struct file *file)`

`close()` 处理，释放 `ecap_reader` 及其缓冲。

#### `static ssize_t ecap_dev_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)`

**读出事件。**

**约束一：只接受一次读一个完整槽。**

```c
if (count < ECAP_SLOT_SIZE)
    return -EINVAL;
```

传小 buffer 直接拒绝，而不是返回半条事件。半条事件会让用户态陷入拼包
状态机 —— 那正是定长槽设计极力避免的复杂度。

**约束二：阻塞模式不返回 0。**

用户态惯例把 `read() == 0` 当 EOF。但抓包里"队列暂时空"是最常见状态
（两次 `SSL_write` 之间都可能空），返回 0 会让 capture 刚开始就跳出循环。

所以阻塞模式下用 `wait_event_interruptible` 真等：

```c
ret = wait_event_interruptible(ecap_waitq,
                               !ecap_dev_alive || !kfifo_is_empty(&ecap_queue));
```

非阻塞模式（`O_NONBLOCK`）返回 `-EAGAIN`，这是 poll/read 的常规约定。

**注意：** 等待条件里是 `!ecap_dev_alive`（而不是 `!ecap_queue_buf`）。
`ecap_dev_exit` 会先把 alive 置 false 再唤醒，读者醒来看到它就直接
返回 `-ENODEV`，绝不会去碰已释放的 kfifo。

**锁的粒度：** `kfifo_out` 在锁内（必须原子，否则两个读者可能拿到同一个槽），
`copy_to_user` 在锁外（可能缺页睡眠，不能持自旋锁）。

#### `static __poll_t ecap_dev_poll(struct file *file, poll_table *wait)`

`poll()`/`epoll()` 支持。

```c
poll_wait(file, &ecap_waitq, wait);
if (unlikely(!ecap_dev_alive))
    return EPOLLERR | EPOLLHUP;
if (!kfifo_is_empty(&ecap_queue))
    mask |= EPOLLIN | EPOLLRDNORM;
```

**为什么 `kfifo_is_empty` 不加锁：** 读者只关心"是否非空"，允许短暂的不精确
（最多多醒一次，下一次 read 返回 0）。加锁反而会在热路径上与写者争抢。
64 位内核上读 `in`/`out` 两个 `unsigned int` 不会撕裂。

#### `static long ecap_dev_ioctl_ping(void __user *arg)`

M1 自测用：往队列里塞一条 `ECAP_EV_PING` 假事件。

payload 用 `pattern + i` 填充，用户态据此逐字节校验 —— 能抓出
"内核侧串包 / 缓冲被覆盖"这类 bug。

#### `static long ecap_dev_ioctl_get_stats(void __user *arg)`

填充 `struct ecap_stats` 并拷回用户态。

统计计数用 `atomic64_read`（无锁），只有队列深度需要临时拿一下锁快照。

`uprobe_hits` / `copy_fail` 从 `ecap_uprobe.c` 取，保持"谁产生谁拥有"的归属。

**M3 新增的五个字段：**

| 字段 | 来源 | 含义 |
| :-- | :-- | :-- |
| `filtered` | `ecap_uprobe_filtered()` | 被 pid/uid 过滤掉的次数 |
| `read_hits` | `ecap_uprobe_read_hits()` | `SSL_read` 返回 `<= 0` 的次数 |
| `pending_miss` | `ecap_uprobe_pending_miss()` | ret 找不到 entry 记录的次数 |
| `pending` | `ecap_uprobe_pending_count()` | 当前挂起表条目数 |
| `pending_max` | `ECAP_PENDING_MAX` | 挂起表容量 |

**为什么要把 `pending` 暴露给用户态：** 它是判断"handler 配对是否健康"的
唯一指标。正常空闲时必须是 0；持续增长说明有 entry 执行了但 ret 没来
（线程被 kill、longjmp 等）。

#### `static long ecap_dev_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)`

ioctl 分发器，`switch (cmd)` 分派到九个命令。

**关键点：必须完整比较 `cmd`，不能只比 `_IOC_NR`。**

```c
switch (cmd) {
case ECAP_IOC_VERSION:    ...
case ECAP_IOC_PING:       ...
case ECAP_IOC_GET_STATS:  ...
case ECAP_IOC_ADD_PROBE:  ...
case ECAP_IOC_DEL_PROBE:  ...
case ECAP_IOC_CLEAR:      ...
/* --- M3 --- */
case ECAP_IOC_SET_FILTER: ...
case ECAP_IOC_ADD_PAIR:   ...
case ECAP_IOC_DEL_PAIR:   ...
default: return -ENOTTY;
}
```

`_IOW`/`_IOR` 宏会把**方向**和**结构体大小**编进 cmd 的高 16 位。
如果只比 `_IOC_NR`，用户态传错结构体大小也能"通过"校验，
进而让 `copy_from_user` 写出内核缓冲边界。

**M3 的三个新命令都是薄封装**，实际逻辑在 `ecap_uprobe.c`：

| 命令 | 转发到 |
| :-- | :-- |
| `SET_FILTER` | `ecap_uprobe_set_filter` |
| `ADD_PAIR` | `ecap_uprobe_add_pair` |
| `DEL_PAIR` | `ecap_uprobe_del_pair` |

这样设备层完全不知道"探测点"是什么，只负责把 ioctl 转给对应的子系统。

#### `static const struct file_operations ecap_dev_fops`

回调表。`owner = THIS_MODULE` 提供了引用计数保护：
**有 fd 打开时 `rmmod` 会被拒绝**（实测返回 `Try again`）。
`.llseek = no_llseek` 因为字符流设备不支持定位。

#### `static struct miscdevice ecap_miscdev`

`misc_register` 比 `alloc_chrdev_region` + `cdev_add` + `device_create`
那套省事得多：只要一个字符设备、不需要动态次设备号、不需要 sysfs 节点时，
这是最省事的注册方式。

`.mode = 0600`：只有 root 能读写，避免普通 App 读到别人的明文。

#### `int ecap_dev_init(void)`

**执行顺序（顺序本身有讲究）：**

1. **先分配 per-CPU 暂存槽**
   ```c
   for_each_possible_cpu(cpu)
       ecap_stage[cpu] = kzalloc(sizeof(struct ecap_event), GFP_KERNEL);
   ```
   放在队列之前：`ecap_push` 里只要发现暂存槽为空就返回 `-ENOMEM`。
   反过来（先队列后暂存槽）会出现一个窗口 —— 队列已可写、暂存槽还没分配好，
   此时进来的事件会白白丢掉。

2. **`vzalloc` 分配队列内存**
   ```c
   ecap_queue_buf = vzalloc(bytes);   /* 1MB */
   ```
   为什么不用 `kmalloc`：1MB 以上的连续**物理**内存经常失败（MAX_ORDER 限制），
   而 kfifo 只要求虚拟地址连续。

3. **`kfifo_init` 而不是 `kfifo_alloc`**
   ```c
   kfifo_init(&ecap_queue, ecap_queue_buf, (unsigned int)bytes);
   ```
   `kfifo_init` 是"外部传入 buffer"模式，所有权仍在调用方手上。
   这样卸载时才能用 `vfree` 而不是 `kfree`（见 `ecap_dev_exit`）。

   `kfifo_init` 的 size 参数是**字节数**，内部除以 `esize` 得到元素个数
   并向 2 的幂向下取整。传 `slots * 4096` 正好得到 `slots` 个槽。

4. **`misc_register`**

5. **最后才置 `ecap_dev_alive = true`**
   前面任何一步失败都不会让读者看到"半成品"设备。

**错误处理：** 所有失败路径都走 `err_stage`，统一释放已分配的暂存槽。

#### `void ecap_dev_exit(void)`

**卸载顺序：立旗 → 唤醒 → 释放。这个顺序不能换。**

```c
misc_deregister(&ecap_miscdev);   /* 1. 不再有新 open/ioctl */

ecap_dev_alive = false;           /* 2. 立旗 */
wake_up_all(&ecap_waitq);         /* 3. 唤醒正在 read() 里睡的读者 */

kfifo_reset(&ecap_queue);         /* 4. 才释放队列 */
vfree(ecap_queue_buf);
ecap_queue_buf = NULL;

for_each_possible_cpu(cpu) {      /* 5. 最后释放暂存槽 */
    kfree(ecap_stage[cpu]);
    ecap_stage[cpu] = NULL;
}
```

**为什么必须严格按这个顺序：**

如果先 `vfree` 再唤醒，读者从 `wait_event` 出来后会在已释放的 kfifo 上
调用 `kfifo_out` → use-after-free。

**为什么不能调用 `kfifo_free`：**

`kfifo_free` 内部会对 `fifo->data` 调 `kfree`，而我们的 buffer 是 `vzalloc`
分配的 —— 用 `kfree` 释放 vmalloc 内存会直接 panic。只能 `kfifo_reset` + `vfree`。

**暂存槽为什么最后释放：** `ecap_push` 会先检查 `ecap_queue_buf`，
队列已置空的情况下它直接返回 `-ENODEV`，不会再碰暂存槽。反过来则可能
让一个刚进来的 push 拿到已释放的暂存槽。

---

## 三、ecap_uprobe.c

### 这个文件做什么

管理 uprobe 探测点的生命周期，并实现三组 handler：

| handler | 触发时机 | 干什么 |
| :-- | :-- | :-- |
| `ecap_ssl_write_entry` | `SSL_write` 入口 | 直接读 buf 得明文 |
| `ecap_ssl_read_entry` | `SSL_read` 入口 | 只记 tid→buf |
| `ecap_ssl_read_ret` | `SSL_read` 返回 | 看返回值决定读多少 |
| `ecap_keylog_entry` | `ssl_log_secret` 入口 | 读 label + secret（M4） |

M2 只做了 `SSL_write`；M3 补上了 `SSL_read`、pid/uid 过滤、成对注册；
M4 补上了 keylog handler。

### SSL_write 与 SSL_read 的机制差异

这是理解本文件的关键。两条路径的 handler 结构完全不同：

```
SSL_write(SSL *ssl, const void *buf, int num)
   x0 = ssl, x1 = buf, x2 = num          (AAPCS64)
         ▲
         └── 入口就能拿到 buf 和 num，直接 copy_from_user 即可。
             不需要返回值，也不需要保存任何状态。
             → 只用一个 handler

SSL_read(SSL *ssl, void *buf, int num)
   x0 = ssl, x1 = buf, x2 = num
         ▲
         └── 入口只知道"缓冲区有多大"（num），
             不知道"会读到多少"。buf 里此刻还是旧数据。
             必须等函数返回，看 x0 的实际字节数。
             → 需要 entry + ret 两个 handler，
               中间靠一张 (tid → buf) 挂起表传递状态
```

**为什么先做 SSL_write**：它只需要一个 handler，是最小可用版本。
`SSL_read` 要引入挂起表、要处理返回值语义，复杂度高一个量级。

### 五个 handler 与一张表

```
                    entry                          ret
SSL_write      ecap_ssl_write_entry                   —
                      │ 直接读 buf
                      ▼
                ecap_emit_plaintext ──────────┐
                                              │
SSL_read       ecap_ssl_read_entry            │     ecap_ssl_read_ret
                      │ 记 tid→buf            │              │
                      ▼                       │              │ 读 x0 得 n
                ecap_pending_set              │              │ n>0 才拷
                [挂起表 256 条]                │              ▼
                                              └──▶ ecap_emit_plaintext
                                                             │
ssl_log_secret ecap_keylog_entry                             │
                      │ 读 label + secret                     │
                      │ 读 ssl->s3->client_random             │
                      ▼                                      ▼
                ecap_push（KEYLOG 事件）              ecap_push（SSL_DATA）
```


### handler 的执行上下文（本文件最关键的前提）

很多人以为 uprobe handler 在"异常上下文"里跑，因此不能睡眠、不能用
`copy_from_user`。在 arm64 5.10 上这个说法**是错的**：

```
BRK 异常 → do_debug_exception → brk_handler → uprobe_pre_sstep_notifier
          （这里只 set_thread_flag(TIF_UPROBE)，什么都不做）

返回用户态前 → ret_to_user → uprobe_notify_resume
          → handle_swbp → handler_chain → uc->handler()      ★
```

handler 是在**即将返回用户态的进程上下文**里被调的：可抢占、中断打开、
`current` 就是被探测的那个用户线程。所以 `copy_from_user` 安全
（内核自己的 `kernel/trace/trace_uprobe.c` 里 `probe_mem_read()` 就这么做）。

**但有一条限制：** `handler_chain()` 全程持有 `uprobe->register_rwsem` 的读锁。
所以 handler 里不能注册/注销 uprobe（需要写锁，会自己锁死自己），
也不能做耗时操作。

### 全局状态

| 变量 | 作用 |
| :-- | :-- |
| `ecap_probes` | 已注册探测点链表 |
| `ecap_probes_lock` | 保护链表的 mutex（`add`/`del` 可能睡眠，不能用自旋锁） |
| `ecap_inflight` | 正在执行的 handler 计数，卸载时等待用 |
| `ecap_inflight_wq` | 计数归零时的唤醒队列 |
| `ecap_ssl_write_consumer` | `SSL_write` 的 `uprobe_consumer` 模板 |
| `ecap_ssl_read_consumer` | `SSL_read` 的 `uprobe_consumer` 模板（M3） |
| `ecap_uprobe_stat_*` | `hits` / `copy_fail` / `filtered` / `read_hits` / `pending_miss` 统计 |
| `ecap_filter_tgid` / `_uid` / `_include_all` | pid/uid 过滤规则（M3，atomic） |
| `ecap_pending_tbl` | `(tid → buf)` 挂起表（M3） |
| `ecap_pending_lock` | 保护挂起表的自旋锁 |
| `ecap_pending_cnt` | 当前挂起表条目数 |

### `struct ecap_probe`

```c
struct ecap_probe {
    struct list_head node;
    struct uprobe_consumer uc;
    struct inode *inode;
    struct file  *file;
    loff_t offset;
    u32 kind;
    u32 fd;
    bool registered;
};
```

**为什么要自己 `igrab` 再 `iput`：** `uprobe_register` 内部会给 inode 加引用，
但那是在 uprobe 对象真正被回收时才放。我们自己额外持一份引用，
保证"先注销 uprobe、再放 inode"这个顺序可控，注销期间 inode 绝不会被回收。

### 函数详解

#### `__u64 ecap_uprobe_hits(void)` / `__u64 ecap_uprobe_copy_fails(void)`

两个统计读取接口，给 `ecap_dev.c` 的 `GET_STATS` 用。

保持"谁产生谁拥有"：计数器定义在产生它的文件里，通过 getter 暴露，
而不是把 `atomic64_t` 变成全局变量。

**M3 新增的三个 getter**（同样用途）：

| 函数 | 对应的计数器 | 含义 |
| :-- | :-- | :-- |
| `ecap_uprobe_filtered()` | `stat_filtered` | 因 pid/uid 不匹配被过滤的次数 |
| `ecap_uprobe_read_hits()` | `stat_read_hits` | `SSL_read` 返回 `<= 0` 的次数 |
| `ecap_uprobe_pending_miss()` | `stat_pending_miss` | ret_handler 找不到 entry 记录的次数 |

**为什么 `hits` 和 `filtered` 要分开计：**

如果只看 `pushed == 0`，无法区分两种情况：

- 探测点根本没挂上（`hits == 0`）
- 挂上了但都被过滤掉了（`hits > 0 && filtered == hits`）

这两个计数让排查变得直接。实测验证过：用 `--tgid 999999` 过滤时
`hits` 涨到 14 而 `filtered` 涨到 8、`pushed` 不变。

#### `static void ecap_inflight_put(void)`

handler 退出时递减在途计数，**归零时唤醒卸载流程**。

```c
if (atomic_dec_and_test(&ecap_inflight))
    wake_up(&ecap_inflight_wq);
```

用 `atomic_dec_and_test` 而不是 `atomic_dec` + 判断，避免"判断时已经不是 0、
但唤醒前又变成 0"这类竞态。

#### `static bool ecap_filter_pass(void)`  ← M3

判断当前事件是否应该被采集。在 handler 最开头调用。

```c
if (atomic_read(&ecap_filter_include_all))
    return true;

if (want_tgid && want_tgid != (int)task_tgid_nr(current))
    return false;
if (want_uid && want_uid != (int)__kuid_val(current_uid()))
    return false;
return true;
```

**三个设计要点：**

**1. 必须放在 `copy_from_user` 之前**

这是性能上的关键。如果先拷贝再过滤，所有 SSL 流量都要走一遍
`copy_from_user` + 入队 + `copy_to_user`，开销全压在目标进程的关键路径上。
不匹配就立刻返回，一个字节都不拷。

**2. 用 `task_tgid_nr` 而不是 `task_pid_nr`**

用户态说"我要抓 pid 1234"时，指的是**进程** 1234，而这个进程的
各个线程 tid 各不相同。用 tid 比对会一个都匹配不上。

**3. 用原子变量而不是 RCU/seqlock**

三个字段之间没有必须保持一致的关系（用户态也是逐条配置）。
极端情况下读到"新 tgid + 旧 uid"最多导致一次误过滤，
不值得为此引入 RCU 或 seqlock 的复杂度。

不过配置时的**写入顺序**是有讲究的，见 `ecap_uprobe_set_filter`。

#### `static int ecap_pending_set(u32 tid, void __user *buf, u32 want)`  ← M3

记录一条挂起项，在 `SSL_read` 的 **entry** handler 里调用。

**为什么需要这张表：** entry 和 ret 是两个独立的 handler 调用，
中间函数体已经执行完毕，栈和寄存器都变了。entry 拿到的 `buf` 指针
必须找个地方存起来，ret 才能用。

**为什么按 tid 索引，而不是 tgid —— 这是整个 M3 最关键的设计：**

```
thread A: SSL_read(ssl, bufA, n) → entry 记下 bufA
thread B: SSL_read(ssl, bufB, n) → entry 记下 bufB
thread A: 返回 → 必须读 bufA
thread B: 返回 → 必须读 bufB
```

用 tgid 索引的话，B 的记录会覆盖 A 的，A 返回时就读到 bufB 的数据 ——
典型串包。用 tid（内核 pid）才能精确对应到线程。

实测验证：`tls_read_test` 的两个线程（tid 26351 / 26352）事件严格归属，
无交叉。

**同 tid 已有记录时选择"更新"而不是"再插一条"：**

```c
hash_for_each_possible(ecap_pending_tbl, p, node, tid) {
    if (p->tid == tid) {
        p->buf = buf;      /* 覆盖 */
        p->want = want;
        return 0;
    }
}
```

正常情况一个线程不会递归调 `SSL_read`，但真正嵌套时深层调用会覆盖浅层记录。
极少数场景下可能读到错误 buf，但比内存泄漏或表膨胀好。

**表满时不覆盖已有记录：**

```c
if (atomic_read(&ecap_pending_cnt) >= ECAP_PENDING_MAX)
    return -ENOSPC;
```

丢新的而不是覆盖旧的 —— 已有记录的 ret 还能正确配对。

**用 `GFP_ATOMIC`：** 虽然在进程上下文（可以睡眠），但为了不给目标线程的
SSL 路径引入不可控的回收延迟，坚持用原子分配。

#### `static bool ecap_pending_take(u32 tid, void __user **buf, u32 *want)`  ← M3

取出并删除一条挂起项，在 `SSL_read` 的 **ret** handler 里调用。

**"取出即删除"是刻意的：** 无论这次 `SSL_read` 是否上报数据，
记录都必须清掉。否则返回 `<= 0` 的那些调用会留下孤儿记录，
慢慢把表填满。

实测验证：`read_empty=3`（3 次返回 -1）和 `pending=0/256` 同时成立，
证明清理正确。

返回 `false` 表示没找到。可能是：

- entry 时表满没记上
- entry handler 因为过滤被跳过了

两种都不是致命错误，只累加 `pending_miss` 计数。

#### `static void ecap_pending_clear(void)`  ← M3

清空整张表，只在模块卸载时调用。

**为什么必须等 handler 都退出之后再清：** `ret_handler` 里会调
`ecap_pending_take`，如果它还在跑而我们先把表清了，
那个 handler 可能正在遍历哈希桶 —— 会踩到已释放的 `hlist_node`。

所以 `ecap_uprobe_exit` 的顺序是：摘探测点 → 等 inflight 归零 → 清表。

#### `u32 ecap_uprobe_pending_count(void)`  ← M3

返回当前挂起表条目数，给 `GET_STATS` 的 `stats.pending` 用。

这个值在正常空闲时应该是 0。如果不是 0，说明有 handler 配对问题
（entry 执行了但 ret 没来，通常是被探测的线程在 `SSL_read` 中间被 kill）。


#### `static int ecap_emit_plaintext(void __user *ubuf, size_t want, size_t limit, u8 dir)`  ← M3

从用户态缓冲拷贝明文并入队。**`SSL_write` 和 `SSL_read` 两条路径共用。**

**为什么抽成函数：** 两条路径的"拷贝 + 组装 blob + 入队"完全一样，
只有"从哪里拿 buf"和"拷多少"不同。抽出来避免两份几乎相同的代码
各自演化（那种重复最容易改了一边忘了另一边）。

**参数：**

| 参数 | 含义 |
| :-- | :-- |
| `ubuf` | 已去标签的用户态缓冲 |
| `want` | 想拷的字节数（调用方已截到 `ECAP_PAYLOAD_MAX`） |
| `limit` | 调用方原始请求的长度，`want < limit` 时置 `TRUNC` 标志 |
| `dir` | `ECAP_DIR_WRITE` / `ECAP_DIR_READ` |

**流程（六步）：**

1. **堆上分配拷贝缓冲**
   ```c
   kbuf = kmalloc(want, GFP_ATOMIC);
   ```
   内核栈只有 16KB，这里可能要拷 4KB。用 `GFP_ATOMIC` 是因为 handler
   虽然在进程上下文（可以睡眠），但为了不给目标线程的 SSL 路径引入
   不可控的回收延迟，宁可用原子分配。

2. **只调一次 `copy_from_user`**
   ```c
   left = copy_from_user(kbuf, ubuf, want);
   got  = left ? (want - left) : want;
   ```
   **为什么只调一次：** 用户态 buffer 跨页且后一页未映射时，
   前一次调用可能已经拷到一部分字节（`raw_copy_from_user` 允许短拷贝），
   再调一次既浪费又会把两次结果混在一起。

3. **`got == 0` 直接放弃** —— 一个字节都没拿到，没必要上报空事件。

4. **组装 blob**
   ```c
   b.type = ECAP_EV_SSL_DATA;
   b.dir  = dir;                          /* ← M3：标注方向 */
   b.tgid = task_tgid_nr(current);
   b.tid  = task_pid_nr(current);
   b.uid  = __kuid_val(current_uid());
   ```

   `tgid` 是用户态看到的 pid，`tid` 是内核 pid。两个都记，
   因为多线程进程里仅靠 tgid 无法区分是哪个线程。

5. **置截断标志**
   ```c
   if (want < limit)
       b.flags |= ECAP_EV_FLAG_TRUNC;
   ```

6. **入队并释放缓冲**

#### `static int ecap_ssl_write_entry(struct uprobe_consumer *uc, struct pt_regs *regs)`

**`SSL_write` 入口 handler。**

**参数从哪里来：** AAPCS64 下前三个参数在 `x0`/`x1`/`x2`，
即 `regs->regs[0..2]`：

```
x0 = ssl   (不用)
x1 = buf   → SSL_WRITE_ARG_BUF
x2 = num   → SSL_WRITE_ARG_NUM
```

**流程：**

1. **统计 + 在途计数**

2. **过滤（M3，必须在拷贝之前）**
   ```c
   if (!ecap_filter_pass()) {
       atomic64_inc(&ecap_uprobe_stat_filtered);
       goto out;
   }
   ```

3. **取参数并按 32 位 int 解释 `num`**
   ```c
   n = (long)(int)(u32)regs->regs[SSL_WRITE_ARG_NUM];
   if (n <= 0) goto out;
   ```
   **这一行有个坑，见下方专门说明。**

4. **截断到槽上限**
   ```c
   want = min((size_t)n, ECAP_PAYLOAD_MAX);
   ```

5. **去指针标签**
   ```c
   ubuf = ECAP_UNTAG_PTR(raw_buf);   /* 掩掉 bit56..63 */
   ```
   实测中 `SSL_new()` 返回的指针是 `0xb40000757758e0d8`，高 8 位 `0xb4`
   就是 MTE/TBI tag。虽然 arm64 的 `copy_from_user` 内部也会 untag，
   但显式处理让日志可读，也让将来把 buf 地址作 key 比对时能正确相等。

6. **交给 `ecap_emit_plaintext`**

**永远返回 0**，不返回 `UPROBE_HANDLER_REMOVE`。抓包工具不应该
因为一次拷贝失败就自我摘除。

#### ⚠️ 32 位返回值不能直接当 64 位读（M3 实测踩到的坑）

这是 M3 开发中最值得记录的一个 bug，`SSL_write` 和 `SSL_read` 都受影响。

`SSL_write` 的 `num` 和 `SSL_read` 的返回值都是 `int`。arm64 上
"写 32 位寄存器"（W0）会**清零**高 32 位，而不是符号扩展。所以
一个返回 -1 的函数，寄存器里的真实内容是：

```
x0 = 0x00000000FFFFFFFF
```

于是：

```c
n = (long)regs->regs[0];     // ← 错误！得到 4294967295，是个正数
```

后果是 `n <= 0` 判断失效，然后 `4294967295 > 511`（`num`）命中
"返回值超过 num"的上限校验分支，`copy_fail` 计数莫名其妙变成 3
（正好等于测试里 read 的次数）。

正确写法是先截成 `int`，再赋给 `long` 让它自然符号扩展：

```c
n = (long)(int)(u32)regs->regs[0];   // ← 正确：得到 -1
```

**这个 bug 只有在设备上跑真实调用才会暴露** —— 主机上的单元测试
无法覆盖，因为测试里拿不到真实的 `pt_regs`。

#### `static int ecap_ssl_read_entry(struct uprobe_consumer *uc, struct pt_regs *regs)`  ← M3

**`SSL_read` 的入口 handler。这里不拷贝任何数据。**

```c
x0 = ssl   (不用)
x1 = buf   → 记下来
x2 = num   → 记下来，作为 ret 阶段的"上限校验"基准
```

**为什么这里不拷贝：**

`SSL_read(ssl, buf, num)` 的 `num` 是"**缓冲区有多大**"，
不是"会读到多少"。入口时 `buf` 里还是上一次的旧数据，
读了就是垃圾。必须等函数返回，看它实际写入了多少字节。

**流程：**

1. 统计 + 过滤（同 write）
2. `n = (long)(int)(u32)regs->regs[2]`，`n <= 0` 就退出
3. `ecap_pending_set(task_pid_nr(current), UNTAG(buf), n)`

**记录 `want` 的用途：** ret 阶段要校验 `返回值 <= want`。
如果返回一个比 `num` 还大的数，说明要么库内部越界写坏了内存，
要么我们的记录错了 —— 两种情况都该丢弃，而不是按一个巨大长度去
`copy_from_user`。

**表满/分配失败只影响这一次**，不需要中断整个抓包。

#### `static int ecap_ssl_read_ret(struct uprobe_consumer *uc, unsigned long func, struct pt_regs *regs)`  ← M3

**`SSL_read` 的返回 handler。**

此时函数已经执行完，`regs->regs[0]` 是返回值：

| 返回值 | 含义 | 处理 |
| :-- | :-- | :-- |
| `> 0` | 实际读到的字节数 | 按这个长度读 `buf` 并上报 |
| `= 0` | 对端关闭，或非阻塞下没数据 | 不上报，计 `read_hits` |
| `< 0` | 出错 | 不上报，计 `read_hits` |

**流程：**

1. `n = (long)(int)(u32)regs->regs[0]`（**必须按 int 解释**）

2. **先取挂起记录，无论后面是否上报**
   ```c
   if (!ecap_pending_take(tid, &ubuf, &recorded_want)) {
       atomic64_inc(&ecap_uprobe_stat_pending_miss);
       goto out;
   }
   ```
   这个顺序很重要：如果先判断 `n <= 0` 再取记录，那些返回 `<= 0`
   的调用就会把记录永久留在表里，慢慢把表填满。

3. `n <= 0` → 计 `read_hits`，退出

4. **上限校验**
   ```c
   if ((u64)n > (u64)recorded_want) {
       atomic64_inc(&ecap_uprobe_stat_copy_fail);
       goto out;
   }
   ```

5. `ecap_emit_plaintext(ubuf, min(n, PAYLOAD_MAX), n, ECAP_DIR_READ)`

**`func` 参数是什么：** 内核传进来的是被探测函数的地址（`ri->func`）。
我们每个探测点只对应一个函数，所以直接忽略。

**这条路径的上下文：** 它在 `handle_trampoline()` 里被调用 ——
`SSL_read` 的返回地址被劫持到了 trampoline。同样是即将返回用户态的
进程上下文，可以 `copy_from_user`。但注意它持着
`uprobe->register_rwsem` 的读锁。

#### `static bool ecap_read_client_random(const void __user *ssl, u8 *out)`  ← M4

从 `SSL` 结构体里读出 32 字节的 `client_random`。

**这些偏移是怎么来的 —— 不是猜的**

从目标库的反汇编里读出来的。`SSL_get_client_random` 是导出符号，
可以直接反汇编（`llvm-objdump -d`）：

```
SSL_get_client_random(const SSL *ssl, uint8_t *out, size_t max_out)
   433dc:  cbz  x2, ...          ; max_out == 0 时返回 0
   433e0:  ldr  x8, [x0, #48]    ; x8 = ssl->s3       ← SSL 结构体 +0x30
   433e4:  cmp  x2, #32
   433f4:  add  x8, x8, #48      ; x8 = &s3->client_random ← s3 +0x30
   433fc:  mov  x1, x8
   43400:  bl   memcpy@plt
```

于是得到：

```c
#define BSSL_SSL_S3_OFFSET    0x30   /* ssl->s3 */
#define BSSL_S3_CLIENT_RANDOM 0x30   /* s3->client_random */
```

**必须做三重校验**（偏移随 BoringSSL 版本变）：

1. `ssl->s3` 指针非空
2. 读出的 32 字节不全 0（未初始化）
3. 不全 0xff（也是未初始化的常见模式）

任一不满足就返回 false，调用方把 `client_random` 留空。
用户态看到全零就知道"偏移不适用"，可以退化为"按时间顺序配对"，
不至于整条 keylog 事件作废。

**必须用 `copy_from_user` 而不是直接解引用** —— 这是用户态内存，
直接读会 panic。

#### `static int ecap_keylog_entry(struct uprobe_consumer *uc, struct pt_regs *regs)`  ← M4

**`bssl::ssl_log_secret` 的 handler。** 这是路径 B 拿到密钥的唯一途径。

**签名（从 `.gnu_debugdata` 的符号表确认）：**

```
_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE
→ bssl::ssl_log_secret(ssl_st const*, char const*,
                       bssl::Span<unsigned char const>)
```

**参数传递（从调用点反汇编确认）：**

```
x0 = ssl
x1 = label   （C 字符串指针）
x2 = data    （Span 的 data_）
x3 = size    （Span 的 size_）
```

**关键：`Span` 是按"两个独立寄存器"传的。**

`Span` 是 `{ T* data_; size_t size_; }` 这个双字段结构体。
按 AAPCS64，16 字节的聚合体既可能放两个寄存器，也可能走隐藏指针。
看调用点才能确认是前者：

```
2c9cc:  add   x2, x20, #16    ; x2 = data
2c9d0:  ldrsw x3, [x20, #12]  ; x3 = size
2c9dc:  bl    0x3ecd0         ; ssl_log_secret
```

所以直接读 `x2` / `x3`，**不要**把 `x2` 当结构体指针解引用。

**流程：**

1. 统计 + 过滤（同前两个 handler）
2. 取 4 个参数，去指针标签
3. `strncpy_from_user` 读 label（C 字符串，长度未知，靠 NUL 判断边界，
   最后一个字节显式置 0 保证以 NUL 结尾）
4. `copy_from_user` 读 secret（定长，`min(size, 64)`）
5. `ecap_read_client_random` 尽力读 client_random
6. 组装 `struct ecap_keylog_payload`（128 字节定长）并入队

**为什么 payload 里放 label 而不复用 `hdr.comm`：**
`comm` 是进程名（16 字节），语义完全不同。混用会导致用户态无法区分
"这条事件的进程名叫 `SERVER_TRAFFIC_SECRET_0`"这种荒谬情况。

**永远返回 0** —— 密钥提取失败也不能摘掉探测点，
那会让整个路径 B 静默失效。

#### `static struct uprobe_consumer *ecap_consumer_for(u32 kind)`  ← M3

按 `kind` 返回对应的 consumer 模板，不支持的类型返回 NULL。

**为什么每个探测点要拷一份 consumer，而不是共用一个全局的：**

`uprobe_consumer` 内部有 `struct uprobe_consumer *next` 字段，
注册时会被挂进 `uprobe->consumers` 链表。**同一个 consumer 对象
注册到第二个 `(inode, offset)` 会破坏那个链表的结构。**

所以每个 `ecap_probe` 必须持有自己的一份结构体拷贝：

```c
p->uc = *tmpl;   /* 结构体拷贝，函数指针共享，next 独立 */
```

函数指针指向同一份实现是安全的，`next` 字段独立才是关键。


#### `static int ecap_get_inode_by_fd(u32 fd, struct file **out_file, struct inode **out_inode)`

从用户态传来的 fd 拿到 `(file, inode)`，**两者都带引用**。

**为什么走 fd 而不是路径：** `kern_path` / `path_put` / `filp_open` 在本 GKI 上
全部未导出（`CONFIG_TRIM_UNUSED_KSYMS=y`）。用 fd 则只需 `fget`
（`EXPORT_SYMBOL`）+ `igrab`，整条路径零 kallsyms。

**fd 的进程归属：** ioctl 一定由"打开了目标 .so 的那个进程"发出，
所以 `fget(fd)` 在 `current` 的文件表里查是正确的。将来若改成
"守护进程 ioctl、目标进程 open"，必须换成 `fget_task(target, fd)`。

**校验：** 只接受普通文件（`S_ISREG`），避免用户态传个目录或设备 fd 进来。

**失败路径：** `igrab` 返回 NULL 说明 inode 正在被销毁，此时要 `fput` 归还
`fget` 的引用。

#### `static const char *ecap_kind_name(u32 kind)`

`enum ecap_probe_kind` → 人类可读名字，只用于日志。
把这种映射集中一处，日志里就不会出现"种类 1"这种看不懂的输出。

#### `static struct ecap_probe *ecap_find_probe(struct inode *inode, u32 kind, loff_t offset)`

**添加时的去重查找**，比较 `inode + kind + offset` 三者。

**为什么必须比 inode：** uprobe 的定位键是 `(inode, offset)` 而不是
`(offset)`。两个不同的 `libssl.so` 里 `SSL_write` 的偏移可能相同
（同一版本 BoringSSL 编译出的两份副本，偏移必然一模一样）。
只比 offset 会把"给第二个库挂同一个点"误判成重复。

**必须在 `ecap_probes_lock` 内调用。**

#### `static struct ecap_probe *ecap_find_probe_loose(struct inode *inode, u32 kind, loff_t offset)`

**删除时的查找**，比上面宽松：`inode` 为 NULL 时退化为只比 `kind + offset`。

因为用户态发 DEL 时可能不传 fd，或者传了个已经关掉/换过的 fd。
此时只能按 `(kind, offset)` 匹配。

#### `static void ecap_probe_free(struct ecap_probe *p)`

释放一个探测点。**顺序极其重要：**

```c
if (p->registered)  ecap_uprobe_unregister(p->inode, p->offset, &p->uc);
if (p->inode)       iput(p->inode);
if (p->file)        fput(p->file);
kfree(p);
```

1. **先注销 uprobe** —— 此后不会再有新 handler 进来
2. **再放 inode** —— 归还我们自己的 `igrab` 引用
3. **最后 fput** —— 归还 `fget` 的引用

反过来做会让内核在已经释放的 inode 上操作 → panic。

#### `static long ecap_add_one(struct inode *i, struct file *f, u32 fd, u32 kind, u64 offset, struct ecap_probe **out_probe)`  ← M3

在一个已经拿到的 inode 上注册一个探测点。**M2 的 `ecap_uprobe_add`
逻辑被抽到这里**，为的是让"单个添加"和"成对添加"共用同一套
注册 + 去重逻辑。

**调用约定（重要）：**

- 调用方必须**已持有** `f` 和 `i` 的引用
- 调用方**不持** `ecap_probes_lock`（本函数内部自己加）
- **成功**时 probe 接管 `f`/`i` 的所有权，调用方不要再动它们
- **失败**时一律不碰 `f`/`i`，调用方负责释放

**流程：**

1. `ecap_consumer_for(kind)` —— 不支持的 kind 直接 `-EOPNOTSUPP`
2. 拒绝 `offset == 0`
3. 加锁 → `ecap_find_probe` 去重 → `kzalloc` → 填字段 → `p->uc = *tmpl`
4. `ecap_uprobe_register`（可能睡眠，所以持的是 mutex 而非自旋锁）
5. `list_add` → 解锁

**`uprobe_register` 失败时的 `-EINVAL`：** 这通常意味着目标指令不能被探测
（`arch_uprobe_analyze_insn` 返回 `INSN_REJECTED`）。日志里特意注明了
这一点，避免排查时误以为是符号找错。

#### `long ecap_uprobe_add(void __user *uarg)`

`ECAP_IOC_ADD_PROBE` 的处理，用户态下发**单个**探测点。

```c
copy_from_user(&req, ...);
ecap_get_inode_by_fd(req.fd, &f, &i);          /* 拿引用 */
ret = ecap_add_one(i, f, req.fd, req.kind, req.offset, &p);
if (ret) {
    iput(i);    /* 失败：自己释放 */
    fput(f);
}
```

**M3 的变化：** 不再硬编码只接受 `SSL_WRITE`。`kind` 的合法性由
`ecap_consumer_for` 判断，加新的探测点类型只需在那里加一个 case。

用户态通常直接用 `ADD_PAIR`（一次挂两个方向），单点接口保留给
"只想挂一个方向"或将来更复杂的场景。

#### `static long ecap_del_one(u32 fd, u32 kind, u64 offset)`  ← M3

内核侧删除一个探测点。**不接收用户指针**。

**为什么抽出来：** `DEL_PAIR` 要在内核里对两个方向分别删除，
手上只有内核结构体，没有 `__user` 指针。

**流程：**

1. **尽力用 fd 定位 inode**（拿不到不算错误）
   ```c
   if (fd) {
       f = fget(fd);
       if (f && S_ISREG(file_inode(f)->i_mode)) want_inode = file_inode(f);
   }
   ```
   这样"同一个 offset、不同库"的两个探测点能被精确区分。
2. 加锁 → `ecap_find_probe_loose` → 摘链 → 解锁
3. **出锁后才 `ecap_probe_free`**

**为什么出锁才释放：** `ecap_probe_free` 会调 `uprobe_unregister`，
后者要拿 `register_rwsem` 的**写锁**，可能等待正在跑的 handler 退出。
持着链表的 mutex 做这个会长时间阻塞其他 ioctl。

#### `long ecap_uprobe_del(void __user *uarg)`

`ECAP_IOC_DEL_PROBE` 的处理，只是一个薄封装：

```c
copy_from_user(&req, uarg, sizeof(req));
return ecap_del_one(req.fd, req.kind, req.offset);
```

#### `long ecap_uprobe_set_filter(void __user *uarg)`  ← M3

`ECAP_IOC_SET_FILTER` 的处理，配置 pid/uid 过滤规则。

**写入顺序有讲究（这是本函数唯一需要注意的地方）：**

```c
atomic_set(&ecap_filter_tgid, (int)f.tgid);
atomic_set(&ecap_filter_uid,  (int)f.uid);
atomic_set(&ecap_filter_include_all, f.include_all ? 1 : 0);   /* 最后 */
```

handler 侧是"先看 `include_all`，再读 `tgid`/`uid`"。这个顺序保证
不会出现"已经放开 `include_all`，但 `tgid` 还是旧值"的中间态被观察到。

**反过来的风险：** 如果先写 `include_all = 0`、后写 `tgid`，中间瞬间
会出现"`tgid` 是旧值（比如 0）且 `include_all` 已是 0"。而 `tgid == 0`
在本实现里意味着"不过滤" —— 反而变成全抓了。所以顺序必须如此。

#### `long ecap_uprobe_add_pair(void __user *uarg)`  ← M3

`ECAP_IOC_ADD_PAIR` 的处理，**一次挂两个方向**。

**为什么需要"成对"接口，而不是让用户态调两次 `ADD_PROBE`：**

两次调用会引入"只有一个成功"的中间状态。用户态必须记得回滚，
而回滚本身也可能失败（第二次失败时第一次已经挂上了）。

放在一个 ioctl 里，内核可以保证**要么两个都挂上，要么一个都不挂**。

**流程（含一个容易写错的细节）：**

```c
i = ecap_get_inode_by_fd(...);          /* 第一次取引用 */

if (req.write_offset) {
    ret = ecap_add_one(i, f, ..., &pw);  /* 成功后 f/i 所有权转给 pw */
    if (ret) { iput(i); fput(f); return ret; }

    /*
     * ★ 必须重新取一份引用给第二个探测点用。
     *   不能让两个 probe 共享同一个引用 ——
     *   某个先释放时另一个就悬空了。
     */
    f = NULL; i = NULL;
    i = ecap_get_inode_by_fd(req.fd, &f, &i);
}

if (req.read_offset) {
    ret = ecap_add_one(i, f, ..., &pr);
    if (ret) { iput(i); fput(f); goto err_undo_write; }
}
```

**回滚：**

```c
err_undo_write:
    if (pw) {
        mutex_lock(&ecap_probes_lock);
        list_del(&pw->node);
        mutex_unlock(&ecap_probes_lock);
        ecap_probe_free(pw);
    }
```

用户态完全不知道它曾经挂上过，必须由内核清干净。

#### `long ecap_uprobe_del_pair(void __user *uarg)`  ← M3

`ECAP_IOC_DEL_PAIR` 的处理。对两个方向分别调 `ecap_del_one`。

**`-ENOENT` 不算错误：** 用户态可能只挂了其中一个方向
（用了 `--no-read` 或 `--no-write`）。删不到就跳过，不返回错误。

#### `int ecap_uprobe_init(void)`

只做一件事：`INIT_LIST_HEAD(&ecap_probes)`。

初始化时**不注册任何探测点** —— 探测点完全由用户态按需下发。
这样模块加载本身没有副作用，加载后系统行为与加载前完全一致。


#### `void ecap_uprobe_exit(void)`

卸载时摘掉所有探测点、等待在途 handler 退出、清空挂起表。

```c
/* 1) 摘掉所有探测点 */
mutex_lock(&ecap_probes_lock);
list_for_each_entry_safe(p, tmp, &ecap_probes, node) {
    list_del(&p->node);
    ecap_probe_free(p);
}
mutex_unlock(&ecap_probes_lock);

/* 2) 等在途 handler 跑完 */
if (wait_event_timeout(ecap_inflight_wq, atomic_read(&ecap_inflight) == 0,
                       msecs_to_jiffies(500)) == 0)
    pr_warn(...);

/* 3) 清挂起表（M3） */
if (atomic_read(&ecap_pending_cnt))
    pr_warn("%d orphan pending entries at unload\n", ...);
ecap_pending_clear();
```

**为什么还要额外等 inflight：** `uprobe_unregister` 拿写锁时会等正在跑的
handler（它们持读锁），所以理论上返回时 handler 都已退出。但 handler
可能在 unregister 之前的最后一刻刚被调用，inflight 计数是一道额外保险 ——
必须等它真正跑完，才能让上层释放队列内存。

**为什么清表必须在等 handler 之后：** `ret_handler` 里会调
`ecap_pending_take`。如果它还在跑而我们先把表清了，那个 handler 可能
正在遍历哈希桶 —— 会踩到已释放的 `hlist_node`。

**orphan 警告的意义：** 如果卸载时表里还有残留，说明存在
"entry 执行了但 ret 没来"的情况（通常是被探测的线程在 `SSL_read`
中间被 kill 或 longjmp）。这个警告能暴露潜在的 handler 配对问题。

**为什么用 `wait_event_timeout` 而不是忙等：** `rmmod` 是进程上下文，
可以睡眠。忙等会白白烧掉一个 CPU。用 timeout 版本是为了避免万一
某个 handler 卡住导致 `rmmod` 永久挂死。

---

## 四、ecap_nf.c

### 这个文件做什么

在 Netfilter 上抓原始网络包，并用 kprobe 做进程归因。这是 M4 的路径 B。

**与路径 A（uprobe）的分工：**

```
路径 A（ecap_uprobe.c）  应用层明文   →  终端 / 事件流
路径 B（ecap_nf.c）      原始网络帧   →  pcapng → Wireshark
```

两者是互补的：路径 A 能直接看到 HTTP 内容但看不到握手/重传/QUIC，
路径 B 能看到全部报文但需要密钥才能解密。

**与 ecap_nf_attr.c（原型）的关系：**

`ecap_nf_attr.c` 是 M1 之前的验证原型，用 `pr_info` 把五元组打到 dmesg，
只证明了"归因表思路可行"。本文件复用了它的两个核心机制，但输出改成入队：

1. kprobe `tcp_sendmsg` / `udp_sendmsg` 建立 `(五元组 → pid/comm)` 映射
2. Netfilter hook 在 `LOCAL_IN` / `LOCAL_OUT` 上抓包并反查归因

### 数据流

```
进程上下文                          软中断上下文
─────────                          ─────────────
tcp_sendmsg(sk)  ──┐
udp_sendmsg(sk)  ──┴─→ 归因表（1024 桶哈希）
                        五元组 → {pid, comm}
                              ▲
                              │ 反查
LOCAL_OUT(skb) ───────────────┤
LOCAL_IN(skb)  ───────────────┘
        │
        │ skb_copy_bits
        ▼
   ecap_pkt_meta + 帧数据
        │
        ▼
   ecap_push(PACKET 事件)
```

### 为什么收包方向需要归因表

`LOCAL_IN` 在**软中断上下文**执行，`current` 是 `ksoftirqd` 或任意
被打断的进程 —— 拿不到"这个包属于哪个 App"。

所以在**发包时**（`tcp_sendmsg`，进程上下文，`current` 就是发包线程）
先记下五元组与 pid 的映射；收包时反查。

### 全局状态

| 变量 | 作用 |
| :-- | :-- |
| `ecap_nf_tbl` | 归因表，`DEFINE_HASHTABLE(…, 10)` = 1024 桶 |
| `ecap_nf_lock` | 保护归因表的自旋锁 |
| `ecap_nf_cnt` | 当前条目数（上限 4096） |
| `ecap_nf_port` | 端口过滤，0 = 不过滤 |
| `ecap_nf_active` | 是否已启用 |
| `ecap_nf_stat_*` | `seen` / `skipped` / `pushed` 统计 |

### 函数详解

#### `static u32 ecap_nf_hash(const struct ecap_nf_key *k)`

把五元组压成一个 32 位哈希值。

**注意返回的是"原始 key"，不是桶号。**

`hash_add()` / `hash_for_each_possible()` 这类宏的最后一个参数是原始 key，
宏内部会用 `hash_min(key, HASH_BITS(name))` 自己算桶号。
如果在外面再算一次桶号传进去，会变成"对桶号做二次哈希"，
结果就是查不到自己刚插入的条目。

#### `static void ecap_nf_upsert(const struct ecap_nf_key *key, u32 pid, const char *comm)`

插入或更新一条归因记录。在 kprobe 上下文执行，**不能睡眠**。

**两种情况：**

- 五元组已存在 → 更新 `pid`/`comm`
  （端口复用后同一个五元组可能换进程）
- 不存在且表未满 → `kzalloc(GFP_ATOMIC)` 后插入

表满（4096 条）时直接放弃，不淘汰旧条目 —— 淘汰需要 LRU 逻辑，
而且抓包场景下"漏掉新连接的归因"比"误删活跃连接的归因"影响小。

#### `static bool ecap_nf_lookup(const struct ecap_nf_key *key, u32 *pid, char *comm)`

查表。可在软中断上下文调用（只用自旋锁）。

#### `static void ecap_nf_delete(const struct ecap_nf_key *key)`

删除一条记录。TCP SYN 时调用，清掉端口复用的旧记录。

**`kfree` 放在锁外** —— 虽然 kfree 本身不会睡眠，但放锁外能缩短临界区，
减少网络栈的等待。

#### `static void ecap_nf_clear(void)`

清空整张表，在 `ecap_nf_disable()` 里调用。

#### `static void ecap_nf_reverse(const struct ecap_nf_key *src, struct ecap_nf_key *dst)`

生成"源/目的交换"版本，用于收包方向反查。

#### `static int ecap_nf_trace_sendmsg(struct sock *sk, u8 proto)`

从 `struct sock` 填充归因键。**这里是字节序最容易出错的地方。**

```c
sk->sk_num   是主机序的 __u16（本地端口）
sk->sk_dport 是网络序的 __be16（对端端口）
```

Netfilter 侧从 TCP 头读到的是网络序，统一 `ntohs` 后是主机序。
所以这里也要统一成主机序，`memcmp` 才能逐字节相等。

```c
key.sport = sk->sk_num;
key.dport = ntohs(sk->sk_dport);
```

不统一字节序的后果：表永远查不中，归因率 0%，但代码看起来完全正常。

#### `static int ecap_nf_kp_tcp_pre` / `ecap_nf_kp_udp_pre`

两个 kprobe pre_handler，各自从 `regs->regs[0]` 取 `struct sock *`。

`tcp_sendmsg` 与 `udp_sendmsg` 的第一个参数都是 `struct sock *sk`，
所以可以共用 `ecap_nf_trace_sendmsg`。

#### `static bool ecap_nf_parse_l3(struct sk_buff *skb, struct ecap_nf_key *k, int *l4_off)`

解析 IP 头，填充协议/地址，返回 L4 偏移。

**跳过两类包：**

- 分片包（`iph->frag_off & htons(0x3fff)`）—— 没有完整 L4 头
- IPv6 扩展头链 —— 只接受 `nexthdr` 直接是 TCP/UDP 的

返回 false 表示"不关心这个包"。

#### `static bool ecap_nf_parse_l4(struct sk_buff *skb, int l4_off, struct ecap_nf_key *k)`

读 L4 端口。TCP 与 UDP 头前 4 字节都是 sport/dport，
所以共用 `tcphdr` 读取（只读 4 字节，不关心后面的字段）。

#### `static bool ecap_nf_is_tcp_syn(struct sk_buff *skb, int l4_off)`

判断是不是 TCP SYN。

**为什么用 `skb_copy_bits(skb, l4_off + 13, &flags, 1)` 而不是结构体字段：**

`tcphdr` 里的 `syn` 是位域，`offsetof` 拿不到它的偏移。
第 13 字节的 bit1 是 SYN 标志，直接按字节读最可靠。

#### `static void ecap_nf_emit(struct sk_buff *skb, const struct ecap_nf_key *k, const char *comm, u32 pid, u8 direction)`

组装并提交一个 PACKET 事件。

**为什么先拷到临时缓冲：**

skb 的数据可能在非线性区（frags），不能直接取指针。
`skb_copy_bits` 会正确处理这种情况。这里一次拷到足够大的缓冲再截断，
只走一次 skb 遍历。

**payload 布局：**

```
0                    struct ecap_pkt_meta (56 字节)
56                   u8 帧数据（从 L3 开始，最多 ECAP_PKT_SNAPLEN=1024）
```

用户态需要五元组来把包归属到连接，也需要原始帧来写 pcapng 的 EPB。
放在一起省一次事件、也保证两者时间戳一致。

**抓取长度按 `ECAP_PKT_SNAPLEN` 截断：**

完整帧可能有 64KB，但我们只需要前 1KB 就能看清 L4 头 + TLS record 头。
pcapng 里会记 `origlen`，Wireshark 显示为
"captured 1024, on-wire 64000"。

#### `static unsigned int ecap_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)`

**Netfilter hook 主体。**

**运行上下文：** `LOCAL_OUT` 通常是进程上下文，`LOCAL_IN` 是软中断。
**绝对不能睡眠。**

**流程：**

1. 解析五元组（失败计入 `skipped`）
2. 端口过滤
3. TCP SYN → 清掉旧记录
4. 查表归因
5. `ecap_nf_emit`

**方向判断用 `state->hook` 而不是查表结果：**

```c
direction = (state->hook == NF_INET_LOCAL_OUT) ? ECAP_PKT_OUT
                                               : ECAP_PKT_IN;
```

- `LOCAL_OUT` 的包在归因表里一定是正向
- `LOCAL_IN` 的包一定是以"远端→本机"形式出现，而表里存的是"本机→远端"，
  所以要反向查

用 hook 点判断比猜更可靠。

**`LOCAL_OUT` 归因失败时的兜底：**

```c
if (!hit && direction == ECAP_PKT_OUT) {
    pid = task_tgid_nr(current);
    memcpy(comm, current->comm, TASK_COMM_LEN);
    hit = true;
}
```

发包方向 `current` 就是发包线程，比过期的归因表更准。

**归因失败的包照样抓：**

```c
if (!hit) {
    pid = 0;
    memcpy(comm, "?", 2);
}
```

模块加载前就建立的长连接查不到 pid，但**丢掉这些包会让抓包不完整**。
pid=0 是明确的"未知"，用户可以自己判断。

#### `static const struct nf_hook_ops ecap_nf_ops[]`

四个 hook：IPv4/IPv6 × LOCAL_IN/LOCAL_OUT。

优先级用 `NF_IP_PRI_FIRST`，尽量早看到包（此时 skb 还比较完整）。

#### `int ecap_nf_enable(u32 port)`

启用包抓取。

**注册顺序（有讲究）：**

1. 先注册 kprobe（归因表的数据来源）
2. 再挂 hook（归因表的消费者）

反过来的话，hook 已经能看到包但归因表还是空的，
前几个包会全部 pid=0。

**已启用时允许改端口：** 先 `ecap_nf_disable()` 再重新走一遍。

#### `void ecap_nf_disable(void)`

停用并清理。**顺序与 enable 相反：**

1. 先摘 hook（不再产生新事件）
2. 再摘 kprobe（不再往表里写）
3. 最后清表

`nf_unregister_net_hooks()` 内部会做同步，保证返回后不会再有 hook
在运行 —— 这是"先摘 hook"能生效的前提。

#### `bool ecap_nf_is_enabled(void)`

状态查询。

#### 统计 getter

`ecap_nf_pkt_seen()` / `_skipped()` / `_pushed()` / `_queue_len()` / `_queue_max()`

队列深度直接复用 `ecap_dev.c` 的 `ecap_queue_used_bytes()` ——
包事件和明文事件共用同一个 kfifo。

**共用队列的一个副作用：** 大量包事件可能挤掉明文事件。
如果将来发现这个问题，应该拆成两个队列。

## 附：四个文件的职责边界

| | ecap_main.c | ecap_dev.c | ecap_uprobe.c | ecap_nf.c |
| :-- | :-- | :-- | :-- | :-- |
| **职责** | 装配顺序 | 事件通道 | 抓应用层明文/密钥 | 抓网络包 |
| **上下文** | init/exit | 任意（含软中断） | 进程上下文 | 软中断 / 进程 |
| **能睡眠？** | 能 | `push` 不能 | handler 能，但刻意不用 | **完全不能** |
| **锁** | 无 | spinlock + local_irq_save | mutex + 挂起表 spinlock | 两个 spinlock |
| **对外接口** | — | `/dev/ecap_tls` | ioctl ADD/DEL/SET_FILTER/PAIR | ioctl ENABLE_NF/DISABLE_NF |

**依赖方向：**

```
ecap_main → ecap_dev, ecap_uprobe, ecap_nf
ecap_uprobe → ecap_dev (ecap_push)
ecap_nf     → ecap_dev (ecap_push)
ecap_dev    → ecap_uprobe, ecap_nf (getter 取统计)
```

三个业务文件都只通过 `ecap_push()` 往队列写、通过几个统计 getter 上报，
彼此之间没有直接调用。这是刻意控制的 ——
如果再加入更多交叉调用，就应该抽一个中间层了。

**为什么 ecap_nf.c 的上下文约束最严：**

Netfilter hook 在 `LOCAL_IN` 时运行于**软中断上下文**。那里：
- 不能睡眠（`GFP_ATOMIC` 是唯一选择）
- 不能用 mutex（只能用 spinlock）
- 不能用 `copy_from_user`（那是用户态操作）
- `current` 不可靠（可能是 ksoftirqd）

而 `ecap_uprobe.c` 的 handler 虽然在进程上下文、理论上可以睡眠，
但为了不拖慢目标线程的 SSL 路径，也刻意用了 `GFP_ATOMIC` 和短临界区。

### M3 新增内容一览

| 文件 | 新增项 |
| :-- | :-- |
| `ecap_uprobe.c` | `ecap_filter_pass`、`ecap_pending_set/take/clear/count`、`ecap_emit_plaintext`、`ecap_ssl_read_entry`、`ecap_ssl_read_ret`、`ecap_consumer_for`、`ecap_add_one`、`ecap_del_one`、`ecap_uprobe_set_filter`、`ecap_uprobe_add_pair`、`ecap_uprobe_del_pair` |
| `ecap_dev.c` | ioctl 分发加三个新命令；`GET_STATS` 多填 5 个 M3 字段 |
| `ecap_uapi.h` | `ecap_filter`、`ecap_probe_pair`、`ECAP_DIR_*`、`ECAP_PENDING_MAX`、hdr 的 `dir` 字段、3 个新 ioctl |

### M4 新增内容一览

| 文件 | 新增项 |
| :-- | :-- |
| `ecap_nf.c`（新文件） | Netfilter 抓包全部实现：归因表、kprobe、hook、emit |
| `ecap_uprobe.c` | `ecap_read_client_random`、`ecap_keylog_entry`、`ecap_keylog_consumer`、3 个 M4 统计 getter |
| `ecap_dev.c` | `ecap_queue_used_bytes` / `ecap_queue_capacity_bytes`（供 nf 用）；ioctl 加 ENABLE_NF / DISABLE_NF；`GET_STATS` 多填 7 个 M4 字段 |
| `ecap_main.c` | 卸载顺序最前面加 `ecap_nf_disable()` |
| `ecap_uapi.h` | `ecap_keylog_payload`、`ecap_pkt_meta`、`ECAP_PKT_*`、`ECAP_KEYLOG_SYMBOL` 相关的常量与两个新 ioctl |

### M4 修的 bug（都只有跑真实数据才会暴露）

| bug | 症状 | 根因 |
| :-- | :-- | :-- |
| pcapng 文件始终 0 字节 | `pkt_pushed=30` 但文件空 | 只在 close 时 flush，进程被 kill 就全丢 |
| 探测点泄漏，第二次启动报 `File exists` | `killall` 后无法重新抓包 | SIGTERM 默认动作直接终止，跳过 cleanup |
| LZMA `len_coder` 数组越界 | 解压前 39 字节正确、之后崩 | 按"符号数 272"声明，实际需要 513 项 |
