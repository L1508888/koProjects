# ecap_tls —— Android GKI 5.10 LKM 版 TLS 明文抓包

M1 + M2 阶段的实现说明。

---

## 一、当前进度

| 里程碑 | 内容 | 状态 |
| :-- | :-- | :-- |
| **M1** | 未导出符号解析（kallsyms 两级跳）+ `/dev/ecap_tls` 事件通道 | 已完成 |
| **M2** | `SSL_write` uprobe → 明文事件 → 用户态打印 | 已完成 |
| **M3** | `SSL_read`（ret_handler + 按 tid 挂起表）+ pid/uid 过滤 + 双向抓包 | 已完成 |
| **M4** | Netfilter 抓包 + kprobe 进程归因 + pcapng 输出 | 已完成 |
| **M4b** | `ssl_log_secret` 密钥提取（`.gnu_debugdata` + XZ） | 部分完成 ※ |
| M5 | pcapng DSB 密钥块 + 实时解密 | 待 M4b |

※ **M4b 的现状**：符号解析链路已打通（能从 `.gnu_debugdata` 里
解出 `bssl::ssl_log_secret` 的偏移 `0x3ecd0`），自实现的 XZ 解码器对
**单 block 流完全正确**（7/7 用例，含 200KB 数据），但真实的
`.gnu_debugdata` 是**双 block**，第二个 block 的距离解码还差一处。
因此设备上 `--keylog` 暂不可用。详见
[docs/kernel-internals.md](docs/kernel-internals.md) 与
[user/ecap_lzma.c](user/ecap_lzma.c) 文件头的"正确性状态"。

已产出四个可部署的产物：

```
ecap_tls.ko            1.4 MB   arm64 内核模块（vermagic 与 GKI 5.10 匹配）
user/ecapctl            39 KB   aarch64 Android 用户态控制端（API 29）
user/tls_probe_test      9 KB   设备侧测试：无连接的 SSL_write/SSL_read
user/tls_read_test      13 KB   设备侧测试：本地回环真实 TLS 双向读写
```

---

## 二、目录结构

```
capture/
├── include/
│   └── ecap_uapi.h          内核与用户态共享的 ABI（事件、ioctl、探测请求）
├── kernel/
│   ├── ecap_main.c          模块入口：按严格顺序装配/拆卸
│   ├── ecap_ksym.c/.h       未导出符号解析（唯一使用 kallsyms 的地方）
│   ├── ecap_dev.c/.h        /dev/ecap_tls：kfifo + poll/read/ioctl
│   ├── ecap_uprobe.c/.h     探测点管理 + SSL_write/SSL_read/keylog handler
│   └── ecap_nf.c/.h         Netfilter 抓包 + kprobe 进程归因（M4）
├── user/
│   ├── ecapctl.c            主程序：设备交互 + 事件循环 + 输出
│   ├── ecap_elf.c/.h        ELF 符号查找（.dynsym + .gnu_debugdata）
│   ├── ecap_xz.c/.h         XZ 解压入口（liblzma 优先，自实现兜底）
│   ├── ecap_lzma.c/.h       自包含的 XZ/LZMA2 解压器（M4）
│   └── ecap_pcapng.c/.h     pcapng 输出（SHB/IDB/EPB/DSB）
├── docs/
│   ├── kernel-internals.md  内核态源码详解（逐函数）
│   └── userland-ecapctl.md  用户态源码详解（逐函数）
├── tests/
│   ├── test_insn.c          指令可探测性判断的单元测试（30 条用例）
│   ├── test_lzma.c          LZMA 解压器测试驱动
│   ├── run_lzma_tests.py    LZMA 回归测试（用 python lzma 当参照）
│   ├── tls_probe_test.c     设备侧触发器：无连接的 SSL_write/SSL_read
│   └── tls_read_test.c      设备侧触发器：本地回环真实 TLS 双向读写
├── tools/
│   └── ecap_smoke.sh        设备冒烟测试脚本（7 步 + M4 扩展）
├── Makefile
│
├── ecap_nf_dump.c/.ko       【保留】Netfilter 抓包基线原型
├── ecap_nf_attr.c/.ko       【保留】抓包 + 归因原型（ecap_nf.c 的前身）
├── capture.c                【废弃】M1 之前的半成品，未被 Makefile 引用
├── capture_tls.c            【废弃】同上
└── android-5.10-lkm-tls-capture-guide.md   原始方案文档
```

### 源码详解文档

想了解每个函数具体做什么，看这两份：

- **[docs/kernel-internals.md](docs/kernel-internals.md)** —
  内核态逐函数说明，含每条设计决策的"为什么"和"顺序错了会怎样"。
  `ecap_ksym.c` 只有 kallsyms 两级跳这一件事，见本文第四节第 2、3 条。
- **[docs/userland-ecapctl.md](docs/userland-ecapctl.md)** —
  用户态逐函数说明，含 ELF 偏移换算、arm64 指令可探测性判断、
  pcapng 块格式、LZMA 解码器的结构与已知问题。

`capture.c` / `capture_tls.c` 保留在原地作为历史记录，但**不参与编译**。
它们存在三个硬伤（`regs` 与 `kregs` 混用、恒真条件、未定义的 ioctl 回调），
不建议作为参考。

---

## 三、架构

```
       ┌──────────────────────────────────────────────────────────────┐
       │  用户态 ecapctl                                              │
       │                                                              │
       │  【路径 A：应用层明文】                                      │
       │   1. 解析 libssl.so → SSL_write/SSL_read 偏移（.dynsym）     │
       │   2. 校验两处目标指令都可被 uprobe 探测                      │
       │   3. open(libssl.so) → fd 交给内核                           │
       │   4. SET_FILTER 下发 pid/uid 过滤规则                        │
       │   5. ADD_PAIR 一次性挂上两个方向的探测点                     │
       │   6. poll()/read() 消费 4KB 定长事件，按 W/R 标注方向        │
       │                                                              │
       │  【路径 B：pcapng + 密钥】                                   │
       │   7. 解析 .gnu_debugdata → ssl_log_secret 偏移（M4b，未完）  │
       │   8. ENABLE_NF 开启 Netfilter 抓包                           │
       │   9. PACKET 事件 → pcapng EPB 块                             │
       │      KEYLOG 事件 → pcapng DSB 块（SSLKEYLOG 格式）           │
       └────────────┬─────────────────────────────────────────────────┘
          ioctl     │      read / poll
   ┌────────────────▼─────────────────────────────────────────────┐
   │  内核态 ecap_tls.ko                                          │
   │                                                              │
   │  ecap_ksym   kprobe→kallsyms_lookup_name→uprobe_*            │
   │                                                              │
   │  ecap_uprobe                                                 │
   │    ├─ SSL_write  entry ──── 直接读 buf ─────┐                │
   │    ├─ SSL_read   entry ── 记 tid→buf ──┐    │                │
   │    │             ret   ── 看返回值 ────┴────┤                │
   │    └─ ssl_log_secret entry ── label+secret ─┤                │
   │                            [挂起表 256 条]  │                │
   │                                             ▼                │
   │  ecap_nf  ┌─ kprobe tcp_sendmsg/udp_sendmsg                 │
   │           │    └→ 归因表：五元组 → pid/comm                 │
   │           └─ Netfilter LOCAL_IN/OUT                         │
   │                └→ 查归因表 + skb_copy_bits ──┐               │
   │                                              ▼               │
   │  ecap_dev    per-CPU 暂存槽 → kfifo(256×4KB) → waitqueue     │
   │              → /dev/ecap_tls                                 │
   └──────────────────────────────────────────────────────────────┘
```

两条路径产出的东西不一样，各有用途：

| | 路径 A（uprobe 明文） | 路径 B（Netfilter + 密钥） |
| :-- | :-- | :-- |
| 拿到什么 | 应用层解密后的明文 | 原始 TCP/UDP 帧 + TLS 密钥 |
| 能看什么 | HTTP 请求/响应内容 | 握手、重传、QUIC、任意协议 |
| 需要什么 | 只需库符号偏移 | 库符号 + `.gnu_debugdata` 解析 |
| 产物 | 终端输出 | pcapng（Wireshark 可直接解密） |
| 状态 | ✅ 完整可用 | 包抓取 ✅ / 密钥 ⚠️ |

### SSL_write 与 SSL_read 的机制差异（M3 的核心）

这是整个 M3 最需要理解的一点：

```
SSL_write(SSL *ssl, const void *buf, int num)
    x0=ssl, x1=buf, x2=num
    ▲ 入口时 buf 和 num 都已确定 → 直接 copy_from_user 即可
      不需要返回值，也不需要保存任何状态

SSL_read(SSL *ssl, void *buf, int num)
    x0=ssl, x1=buf, x2=num
    ▲ 入口时只知道"缓冲区有多大"，不知道"会读到多少"
      必须等函数返回，看 x0 的实际字节数

    所以：
      entry : 记下 (tid → buf)，不拷贝
      ret   : 读 x0 得 n，若 n > 0 才按 n 拷贝
```

**为什么按 tid 而不是 tgid 索引：**

```
thread A: SSL_read(ssl, bufA, n) → entry 记下 bufA
thread B: SSL_read(ssl, bufB, n) → entry 记下 bufB
thread A: 返回 → 必须读 bufA
thread B: 返回 → 必须读 bufB
```

用 tgid 索引的话，B 的记录会覆盖 A 的，A 返回时就读到 bufB 的数据 —— 典型串包。
实测中 `tls_read_test` 的两个线程（tid 26351/26352）就是这样被正确区分的。


---

## 四、关键技术决策（以及为什么这样选）

这些结论都是对着内核源码和 `Module.symvers` 逐条核实过的，不是推测。

### 1. 用 fd 传 inode，而不是传路径

`kern_path` / `path_put` / `filp_open` 在本 GKI 上**全部未导出**
（`CONFIG_TRIM_UNUSED_KSYMS=y`）。若用路径，就得再走一次 kallsyms 间接调用，
增加 CFI 风险。

改成：用户态 `open()` 好目标 `.so`，把 `fd` 传进来；内核用
`fget()`（`EXPORT_SYMBOL`）+ `igrab(file_inode(f))`。
**整条路径零 kallsyms。**

### 2. `uprobe_register` 只能走 kallsyms 两级跳

`Module.symvers` 里查不到这两个符号，但 `System.map` 里是 `T uprobe_register`。
所以：`register_kprobe("kallsyms_lookup_name")` 拿地址 → 再用它查
`uprobe_register` / `uprobe_unregister`。

### 3. CFI 必须在间接调用点关掉

`CONFIG_CFI_CLANG=y` 且 `CONFIG_CFI_PERMISSIVE` 未开 → CFI 违规直接 panic。

因此所有"取地址后间接调用"的函数都标 `__nocfi`：
`ecap_ksym_init()`、`ecap_uprobe_register()`、`ecap_uprobe_unregister()`、
`ecap_exit()`。这是整个模块唯一"脏"的地方，其余代码全走导出符号。

### 4. uprobe handler 里可以用 `copy_from_user`

这一点和很多资料的说法相反，值得澄清。在 arm64 5.10 上：

```
BRK 异常 → do_debug_exception → brk_handler → uprobe_pre_sstep_notifier
           （这里只 set_thread_flag(TIF_UPROBE)，什么都不做）
返回用户态前 → ret_to_user → uprobe_notify_resume
           → handle_swbp → handler_chain → uc->handler()   ★
```

handler 是在**即将返回用户态的进程上下文**里被调的：可抢占、中断打开、
`current` 就是被探测的线程。所以 `copy_from_user` 安全
（内核自己的 `kernel/trace/trace_uprobe.c` 里 `probe_mem_read()` 就是这么做的）。

**但**：`handler_chain()` 全程持有 `uprobe->register_rwsem` 的读锁，
所以 handler 里不能注册/注销 uprobe（需要写锁），也不能做耗时操作。

### 5. 指针标签（TBI/MTE）由内核自动处理

arm64 的 `raw_copy_from_user()` 内部会调 `__uaccess_mask_ptr()`，
它先 `untagged_addr()` 再比 `addr_limit`，所以带 tag 的指针能正常工作。

我们仍然显式去标签（`ECAP_UNTAG_PTR`），目的只有两个：
日志里的地址可读、以及将来要把 buf 地址作为 key 比对时能正确相等。

### 6. 事件用定长槽，不用变长记录

`__kfifo_out_r`（record 模式的出队）**未导出**，只有 `__kfifo_in_r` 导出了。
用变长记录会导致出队时无法判断边界。

改成 4KB 定长槽后，`read()` 语义变得极简：要么返回 4096，要么返回 0 / `-EAGAIN`。
用户态不需要任何拼包状态机。

### 7. 用 per-CPU 暂存槽，而不是每事件 `kmalloc(4KB)`

`struct ecap_event` 有 4096 字节，放栈上会爆（内核栈 16KB）。

最初的写法是 `kmalloc(4096, GFP_ATOMIC)`，缺点是在 `SSL_write` 热路径上
每条事件都分配一次 4KB，既慢又可能因碎片失败。

改成 per-CPU 常驻缓冲 + 关中断临界区：
无锁、不分配、也不会被本 CPU 上的软中断踩坏。

### 8. 队列满就丢，绝不阻塞

抓包工具的第一原则：宁可丢事件，也不能卡住目标 App 的 SSL 线程或网络软中断。
丢一条就把 `dropped` 加一，用户态可用 `ecapctl stats` 查看。

### 9. 阻塞 `read()` 不返回 0

用户态惯例把 `read() == 0` 当 EOF。但抓包里"队列暂时空"是最常见状态
（两次 `SSL_write` 之间都可能空），返回 0 会让 capture 刚开始就跳出循环。
所以阻塞模式下用 `wait_event_interruptible` 真等，非阻塞模式返回 `-EAGAIN`。

### 10. 卸载顺序：先摘 uprobe，再释放队列

```
ecap_uprobe_exit()  →  ecap_dev_exit()  →  ecap_ksym_exit()
```

反过来的话，一个正在 `SSL_write` handler 里执行的线程会往已 `vfree`
的队列写数据 —— 典型 use-after-free，直接 panic。

`ecap_dev_exit()` 内部还有更细的顺序：**先置 `ecap_dev_alive = false`，
再 `wake_up_all()`，最后才 `vfree`**。否则读者从 `wait_event` 出来后
会在已释放的 kfifo 上调用 `kfifo_out`。

### 11. 32 位返回值不能直接当 64 位读（M3 实测踩到的坑）

这是 M3 开发中最值得记录的一个 bug。

`SSL_read` 返回 `int`。arm64 上 "写 32 位寄存器"（W0）会**清零**高 32 位，
而不是符号扩展。所以函数返回 -1 时，寄存器里的真实内容是：

```
x0 = 0x00000000FFFFFFFF
```

于是：

```c
n = (long)regs->regs[0];     // ← 错误！得到 4294967295，是个正数
```

后果是 `n <= 0` 的判断失效，然后 `4294967295 > 511` 命中"返回值超过 num"
的上限校验分支，`copy_fail` 计数莫名其妙变成 3（等于测试里 read 的次数）。

正确的写法是先截成 `int`，再赋给 `long` 让它自然符号扩展：

```c
n = (long)(int)(u32)regs->regs[0];   // ← 正确：得到 -1
```

同样的坑也存在于 `SSL_write` 的 `num` 参数（虽然正常调用不会传负数）。
两处都已修正。

**这个 bug 只有在设备上跑真实调用才会暴露** —— 主机上的单元测试无法覆盖，
因为测试里拿不到真实的 `pt_regs`。

### 12. 过滤必须在 copy_from_user 之前（M3）

```c
atomic64_inc(&ecap_uprobe_stat_hits);   /* 先计数：说明"handler 确实进来了" */
if (!ecap_filter_pass()) {
    atomic64_inc(&ecap_uprobe_stat_filtered);
    goto out;                            /* 不匹配 → 立刻返回，一个字节都不拷 */
}
```

如果把过滤放在拷贝之后，所有 SSL 流量都要走一遍
`copy_from_user` + 入队 + `copy_to_user`，开销全压在目标进程的关键路径上。

实测验证：用 `--tgid 999999` 过滤后，`uprobe_hits` 从 10 涨到 14（4 次调用
确实进了 handler），但 `filtered=4` 而 `pushed` 不变 —— 说明过滤点位置正确。

`hits` 与 `filtered` 两个计数分开的意义：如果只看 `pushed`=0，分不清是
"没挂上"还是"挂了但被过滤了"。有了 `hits` 就能区分。

### 13. 成对注册：要么两个都挂上，要么一个都不挂（M3）

用户态调两次 `ADD_PROBE` 会引入"只有一个成功"的中间状态，回滚本身也可能失败。

`ADD_PAIR` 把两件事放进一个 ioctl：第二个失败时，内核把第一个摘掉再返回错误。
用户态完全不知道中间状态存在过。

实现上有个细节：第一个探测点成功后，`file`/`inode` 的所有权已经转交给它了，
必须**重新 `fget` + `igrab`** 一份给第二个用。让两个 probe 共享同一个引用
会导致某个先释放时另一个悬空。

### 14. `ssl_log_secret` 只在 `.gnu_debugdata` 里（M4）

`SSL_write` / `SSL_read` 是**导出符号**，在 `.dynsym` 里，直接能查到。

但 `bssl::ssl_log_secret` 是 **C++ 内部函数**，不导出。它只存在于
`.gnu_debugdata` —— Android 的 BoringSSL 把一份"只有符号表的最小 ELF"
用 XZ 压缩后塞进这个节。

实测 Pixel 6 的 `/apex/com.android.conscrypt/lib64/libssl.so`：

```
.gnu_debugdata  节 0x2638 字节
  解压后        47832 字节的 ELF（no program header, not stripped）
  里面          _ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE @ 0x3ecd0
```

**换算偏移时要特别注意：** mini debug info 没有 program header，
不能用它自己的 `PT_LOAD` 做 `vaddr → offset` 换算。
它的 `st_value` 与主库共用同一套虚拟地址编号，所以必须用**主库**的
`PT_LOAD` 表来换算。

### 15. XZ 解压为什么是自己实现的（M4）

试过三条路，前两条都不通：

| 方案 | 结果 |
| :-- | :-- |
| `dlopen("liblzma.so")` + `lzma_stream_decoder` | ❌ 设备上的 liblzma 是 AOSP 版本，没有上游 API |
| 静态链接 NDK 的 liblzma | ❌ NDK 里根本没有 |
| `dlopen` + AOSP 的 `XzUnpacker_*` | ⚠️ 可用，但 `CLzma2Dec` 结构体布局随版本变，脆弱 |
| **自实现**（当前方案） | ✅ 无依赖、主机设备行为一致 |

设备上的 liblzma 导出的是 LZMA SDK 的内部名字：

```
$ nm -D /system/lib64/liblzma.so | grep -c lzma_code
0
$ nm -D /system/lib64/liblzma.so | grep -c -E "LzmaDec_|XzUnpacker_"
20+
```

所以"liblzma.so 存在"完全不代表能用。运行时必须验证符号能否 `dlsym`
到，而不是只看 `dlopen` 成不成功。

**当前进展与残留问题**见 [user/ecap_lzma.c](user/ecap_lzma.c) 文件头。
简要说：单 block 流已完全正确（7/7 用例），多 block 流的第二个 block
还差一处距离解码细节。

### 16. pcapng 必须每包 flush（M4）

第一版只在关闭文件时 `fflush`。结果实测：统计显示 `pkt_pushed=30`，
但 pcapng 文件是 **0 字节**。

原因：抓包进程通常是被 `kill` / 断电结束的，走不到 `ecap_pcapng_close`，
1MB 的用户态缓冲全部丢失。

改成每写一个 EPB 就 `fflush`。代价是每包一次 `write` 系统调用 ——
相对于 `copy_from_user` + 入队的成本可以忽略。

另外 `open` 之后也立刻 flush 一次，保证即使进程马上被杀，
文件也是一个**合法的空 pcapng**（104 字节的 SHB+IDB），
而不是 0 字节的垃圾 —— Wireshark 打开后者会直接报错。

### 17. SIGTERM 必须自己处理，否则探测点泄漏（M4）

`Ctrl-C` 会让 `poll()` 返回 `EINTR`，循环能正常跳出并清理。
但 `kill` / `killall`（SIGTERM）的默认动作是**直接终止进程**，
不会执行任何 cleanup。

后果：`DEL_PAIR` / `DEL_PROBE` 都不执行，探测点永久留在内核模块里，
下次启动 capture 就遇到

```
ECAP_IOC_ADD_PAIR failed: File exists
```

而且用户完全不知道为什么 —— 这个坑我在实测中踩到了。

所以 `cmd_capture` 一进来就 `install_signal_handlers()`，捕获
SIGINT / SIGTERM / SIGHUP，把"终止"变成"置标记 + 跳出循环"。
信号处理函数里只做 `g_stop = 1` 这种异步安全操作，
真正的清理在主循环退出后做。


---

## 五、构建

```bash
make            # 只编内核模块
make user       # 只编用户态 ecapctl（aarch64）
make devtests   # 编设备侧测试程序（tls_probe_test / tls_read_test）
make all        # 三者都编
make test       # 单元测试：指令判断 30 条 + LZMA 解压 7 条（本机）
make test-lzma  # 只跑 LZMA 解压测试
make host       # 编本机 x86_64 版 ecapctl（仅用于验证 ELF 解析逻辑）
make clean
```

依赖（已在 Makefile 顶部写死，按需改）：

```
KER := /home/liuxin/pixelKernel/common
MOR := /home/liuxin/pixelKernel/out/android13-5.10/common
NDK := /home/liuxin/Android/Sdk/ndk/25.1.8937393
```

---

## 六、设备实测结果

测试环境：Pixel 6 (oriole) / Android 13 / 内核 `5.10.252-android13-4-00010-g6c98ac824750-dirty` /
KernelSU root / SELinux enforcing。

### 通过项

| 验证项 | 结果 |
| :-- | :-- |
| 模块加载、vermagic 匹配 | ✅ 与 `uname -r` 完全一致，无需重编 |
| kallsyms 两级跳 | ✅ 解析出 `uprobe_register` = `ffffffffd50dbeb2e4`，与 System.map 尾数一致 |
| `/dev/ecap_tls` + ABI 握手 | ✅ `kernel ABI version : 1` / `OK` |
| 事件通道（ping） | ✅ 32 条零丢零损；500 条压力下按设计丢弃 244 条、`corrupt 0` |
| 真实 libssl.so 符号解析 | ✅ `SSL_write` @ `0x408fc`、`SSL_read` @ `0x40514`，与 `objdump` 一致 |
| 指令预检 | ✅ `0xd10143ff` (`sub sp,sp,#0x50`)、`0xa9bd7bfd` 均判定可探测 |
| uprobe 成对注册 | ✅ 一次 `ADD_PAIR` 挂上 `SSL_write` + `SSL_read` 两个点 |
| **明文捕获（W 方向）** | ✅ 完整抓到 HTTP 请求行、Host 头 |
| **明文捕获（R 方向）** | ✅ 抓到 HTTP 响应，含状态行与所有响应头 |
| 真实系统流量 | ✅ 抓到 `networkstack` / `vending` 的 `/generate_204` 连通性检测 |
| 真实回环 TLS 双向 | ✅ `SSL_connect -> 1`，两端 write/read 全部抓到 |
| 按 tid 精确归属 | ✅ tid 26351/26352 双线程严格区分，无串包 |
| read 返回负值不上报 | ✅ 3 次 `-1` → `read_empty=3`、`pushed` 不增 |
| pid 过滤生效 | ✅ `--tgid 999999` → `filtered=4`、`pushed` 不增 |
| 挂起表无泄漏 | ✅ `pending=0/256`，卸载时零 orphan 警告 |
| 并发隔离 | ✅ 4 进程 × 5 轮，各进程事件严格归属，无串包 |
| 高频压力 | ✅ 8 进程 × 50 轮 = 400 次调用，`dropped=0`、`copy_fail=0` |
| 超长 payload 截断 | ✅ 20000 字节 → `len=4048 TRUNC`（4048 = 4096 − 48） |
| 内核稳定性 | ✅ 全程零 oops / panic / warning |
| 卸载安全性 | ✅ 有 fd 打开时 `rmmod` 被拒绝（引用计数保护）；关闭后干净卸载 |
| 加载/卸载循环 | ✅ 5 次循环无泄漏 |
| **M4：Netfilter 抓包** | ✅ `pkt_seen=30` / `pkt_pushed=30` / `pkt_skipped=0` |
| **M4：pcapng 输出** | ✅ 30 个 EPB，尾部长度全部校验通过，`file` 识别为 pcapng v1.0 |
| **M4：IP 头解析** | ✅ `ipver=4 proto=6(TCP) 127.0.0.1 → 127.0.0.1` |
| **M4：XZ 符号解析** | ✅ `.gnu_debugdata` 解出 `ssl_log_secret @ 0x3ecd0`（主机侧） |
| **M4：自实现 LZMA** | ⚠️ 单 block 7/7 通过，多 block 的第二个 block 未完成 |

### M3 双向抓包实测样本

用 `tls_read_test`（本地回环 + 自签名证书）产生一次真实的 TLS 双向通信，
客户端与服务端在**同一进程的两个线程**里。

```
[389367.562s] W pid=26351 tid=26351 uid=0 len=56
  text: ECAPTEST-W-CLIENT-0-GET / HTTP/1.1..Host: ecap.local....
[389367.604s] R pid=26351 tid=26352 uid=0 len=56
  text: ECAPTEST-W-CLIENT-0-GET / HTTP/1.1..Host: ecap.local....
[389367.604s] W pid=26351 tid=26352 uid=0 len=140
  text: HTTP/1.1 200 OK..Content-Type: text/plain..X-Ecap-Dir: server-to-client
        ..Content-Length: 46....ECAPTEST-R-FROM-SERVER-0123456789ABCDEFGHIJ..
[389367.604s] R pid=26351 tid=26351 uid=0 len=140
  text: HTTP/1.1 200 OK..Content-Type: text/plain..X-Ecap-Dir: server-to-client
        ..Content-Length: 46....ECAPTEST-R-FROM-SERVER-0123456789ABCDEFGHIJ..
```

四行输出正好是这次通信的完整视图：

| 事件 | tid | 含义 |
| :-- | :-- | :-- |
| `W` | 26351 | 主线程（客户端）发出请求 |
| `R` | 26352 | 服务端线程读到同一份请求 |
| `W` | 26352 | 服务端线程发出响应 |
| `R` | 26351 | 主线程（客户端）读到同一份响应 |

同一份 payload 在 `W` 与 `R` 两侧成对出现，证明两条链路都在正确工作；
tid 严格区分，证明按 tid 索引挂起表的设计有效。

对应的统计：

```
uprobe_hits  : 10     ← 6 次 write + 4 次 read
pushed       : 6      ← 实际入队的事件数
read_empty   : 4      ← read 返回 <= 0 被跳过的次数（含无连接的测试）
pending      : 0/256  ← 挂起表全清，无泄漏
copy_fail    : 0
```


### 实测抓到的真实流量样本

系统连通性检测（`networkstack` / `vending`）：

```
[388609.484s] W pid=28671 tid=23627 uid=1073 len=212
  text: GET /generate_204 HTTP/1.1..Connection: close..User-Agent: Mozilla/5.0 ...
        ..Host: www.google.com..Accept-Encoding: gzip....
[388609.485s] W pid=14027 tid=23647 uid=10145 len=232
  text: GET /generate_204 HTTP/1.1..User-Agent: Mozilla/5.0 ...
        ..Host: connectivitycheck.gstatic.com..Connection: Keep-Alive....
```

Play 商店的真实业务请求（`com.android.vending:quick_launch`）：

```
[388565.100s] W pid=22727 tid=22781 uid=10145 len=190
  text: GET /play/log/timestamp HTTP/1.1..User-Agent: Dalvik/2.1.0 ...
        ..Host: play.googleapis.com..Connection: Keep-Alive....

[388565.561s] W pid=22727 tid=22781 uid=10145 len=2057
  text: POST /play/log?format=raw&proto_v2=true HTTP/1.1
        ..Content-Encoding: gzip..Content-Type: application/x-gzip
        ..User-Agent: Android-Finsky/54.2.12-31 ...
        ..Authorization: Bearer ya29.m.CrwCAZEM...  ← 完整 OAuth2 token
        ..Host: play.googleapis.com..Content-Length: 1190
```

**这验证了本工具的核心价值，同时也说明了它的危险性。**

### ⚠️ 安全提示

上面的输出里包含一份**可直接重放的 OAuth2 Bearer token**。
TLS 在这条链路上被完全绕过——不需要证书、不需要中间人。

因此 `ecapctl capture` 输出的是**完整原始明文**，其中可能包含
`Authorization` / `Cookie` / `Set-Cookie` 等凭据。`cap.log` 这类
事件日志必须当作敏感数据对待：

- 不要提交到仓库、不要贴进聊天记录、不要留在共享机器上
- 只在授权范围内、对自己拥有或已获书面许可的设备上使用
- 需要长期保存时，建议自己用 `sed` / `grep -v` 过滤后再落盘

### 一个重要发现：TBI 指针标签确实存在

测试程序里 `SSL_new()` 返回的指针是 `0xb40000757758e0d8`，高 8 位 `0xb4` 就是 MTE/TBI tag。
`ECAP_UNTAG_PTR` 的掩码处理是必需的 —— 虽然 arm64 的 `copy_from_user` 内部
也会 untag，但显式处理让日志可读、也让将来的地址比对能正确相等。

### 已知限制（实测确认）

**Chrome 抓不到**。虽然 `com.android.chrome` 的 maps 里有
`/apex/com.android.conscrypt/lib64/libssl.so`，但用 Chrome 打开网页时没有产生
任何事件。原因有两层：

1. Chrome 的实际网络 I/O 在各渲染进程（`sandboxed_process0`）里，
   这些进程可能在 `uprobe_register` 之后才 fork；
2. Chrome 主体用 Cronet 封装，未必走到 `SSL_write` 这条路径。

这正是 M3「多目标库 + 覆盖 App 自带 BoringSSL」要解决的问题。
目前可靠的工作方式是**抓系统进程**（networkstack、vending、gms 等）。

---

```bash
# 1. 确认设备内核版本与 .ko 的 vermagic 一致
adb shell uname -r
#   5.10.252-android13-4-00010-g6c98ac824750-dirty
uname -r  # 在 .ko 所在机器上：modinfo ecap_tls.ko | grep vermagic

# 2. 推送并加载
adb push ecap_tls.ko user/ecapctl /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/ecap_tls.ko'
adb shell su -c 'dmesg | grep ecap_tls'

# 期望看到：
#   ecap_tls: kallsyms_lookup_name = 0x...
#   ecap_tls: uprobe_register = 0x..., uprobe_unregister = 0x...
#   ecap_tls: /dev/ecap_tls ready: 256 slots x 4096 bytes = 1024 KB
#   ecap_tls: loaded, waiting for probes on /dev/ecap_tls

# 3. M1 验证：事件通道
adb shell su -c '/data/local/tmp/ecapctl version'
adb shell su -c '/data/local/tmp/ecapctl ping -n 32 -l 64'
#   期望：ping: sent 32, received 32, corrupt 0

# 4. M3 验证：双向抓明文
adb shell su -c '/data/local/tmp/ecapctl capture \
    --lib /apex/com.android.conscrypt/lib64/libssl.so --hex'

#    然后让某个 App 发一个 HTTPS 请求，终端上会实时打印明文。
#    输出里每行开头的 W / R 表示方向：
#      W = SSL_write，App 发出去的明文
#      R = SSL_read， App 收回来的明文

# 5. 只抓某个进程（M3 新增）
adb shell su -c '/data/local/tmp/ecapctl capture \
    --lib /apex/com.android.conscrypt/lib64/libssl.so --tgid 14027'
#    --uid 也可以过滤

# 6. 只抓一个方向（M3 新增）
adb shell su -c '... capture --lib ... --no-read'    # 只抓 write
adb shell su -c '... capture --lib ... --no-write'   # 只抓 read

# 7. 看完整统计
adb shell su -c '/data/local/tmp/ecapctl stats'
```

`capture` 的完整参数：

| 参数 | 说明 |
| :-- | :-- |
| `-l, --lib PATH` | 目标 TLS 库（必填） |
| `-h, --hex` | 额外输出前 64 字节的十六进制 |
| `-v, --stats` | 结束时打印统计（默认开启） |
| `-W, --no-read` | 只抓 SSL_write |
| `-R, --no-write` | 只抓 SSL_read |
| `-p, --tgid PID` | 只抓这个进程（0 = 不过滤） |
| `-u, --uid UID` | 只抓这个 uid（0 = 不过滤） |
| `-w, --pcap PATH` | 同时写 pcapng 文件（M4） |
| `-P, --packet` | 同时抓网络包（Netfilter，M4） |
| `-o, --port PORT` | 包端口过滤（默认 443，0 = 不过滤） |
| `-k, --keylog` | 提取 TLS 密钥写进 pcapng（M4b，见第七节） |

### M4：完整抓包（pcapng + 网络包）

```bash
adb shell su -c '/data/local/tmp/ecapctl capture \
    --lib /apex/com.android.conscrypt/lib64/libssl.so \
    --pcap /sdcard/ecap.pcapng \
    --packet --port 443'
```

抓完之后把 `ecap.pcapng` 拉到开发机，用 Wireshark 打开即可看到
原始 TCP 帧。注意此时**还不能自动解密**——密钥需要 `--keylog`
（当前未完成，见第七节）。

抓到的 pcapng 结构（实测 30 个包）：

```
SHB  1 个   文件头（版本 1.0）
IDB  1 个   接口描述（linktype=101 RAW，snaplen=1024，时间戳精度=纳秒）
EPB  30 个  每个包一块（含纳秒时间戳 + 完整 IP 帧）
```

### 用本地回环做确定性验证

不依赖外网、不依赖 App，用自签名证书在设备上建一个回环 TLS 连接：

```bash
# 生成自签名证书（在开发机上）
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout ecap_key.pem -out ecap_cert.pem -subj /CN=ecap.local

adb push ecap_cert.pem ecap_key.pem user/tls_read_test /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/tls_read_test'

# 一边跑 capture，一边跑测试
adb shell su -c '/data/local/tmp/tls_read_test'
```

期望在 capture 输出里看到 4 条事件（W/R 各两条），对应客户端与服务端
两个线程的完整往返。

**注意**：`ecapctl` 必须与目标进程有相同的「能否访问该库」的权限。
最省事的做法是全程 `su`，但要注意此时抓到的 `uid` 字段仍然是 App 自己的。


---

## 七、已知限制（M4 阶段）

| 限制 | 原因 | 后续 |
| :-- | :-- | :-- |
| **`--keylog` 在设备上不可用** | 多 block XZ 解压未完成，拿不到 `ssl_log_secret` 偏移 | 见第八节 |
| 只支持系统 BoringSSL | App 自带的 `libssl.so` / `libflutter.so` 路径不同，需逐个下发 | M5（多目标库） |
| 只挂 `init_net` | 不覆盖 VPN / 独立 netns | M5 |
| 过滤维度只有 pid/uid | handler 里拿不到 socket 信息（SSL 对象是黑盒） | 已加 Netfilter 归因，可扩展 |
| `SSL_write` 不校验返回值 | 入口拿到的是"想写多少"，实际写出去多少要看返回值 | 见下方说明 |
| 挂起表容量 256 | 并发 SSL_read 线程数上限；满了会丢该次记录 | 可调 `ECAP_PENDING_MAX` |
| 包抓取只支持单 filter | 只支持 LZMA2，不支持 BCJ/DELTA 预处理 | 实际 `.gnu_debugdata` 不需要 |
| 包队列与明文队列共用 | 同一个 kfifo，包多时可能挤掉明文事件 | 可拆成两个队列 |

### 关于 `SSL_write` 不校验返回值

严格来说 `SSL_write` 也可能短写（返回值 < num），但：

1. 入口 hook 时函数还没执行，拿不到返回值；
2. 要拿返回值就得也挂 `ret_handler`，而 `SSL_write` 的 ret 路径会额外
   劫持返回地址（uretprobe），给目标进程增加开销；
3. 短写在 BoringSSL 里很少见（它会内部重试直到写完或出错）。

所以按 num 上报。如果将来发现需要精确值，可以给 write 也加
`ret_handler`，用同一套挂起表机制。

### 关于 `--keylog` 的当前状态

`.gnu_debugdata` 的 XZ 解码器（`user/ecap_lzma.c`）是自实现的，
不依赖设备上的 liblzma（后者是 AOSP 版本，没有上游 API）。

**已完成**：单 block 流全部正确 —— 7 条回归用例（1/2/3 字节、
100 个相同字节、重复序列、序列数据、200KB 混合数据）全部与
python 的 `lzma.decompress()` 逐字节一致。

**未完成**：真实的 `.gnu_debugdata` 是**两个 block** 的流
（第一个 32768 字节、第二个 15064 字节）。第一个 block 解码完全正确，
第二个 block 从第 13 字节起解出越界距离（`rep0=242111`）。

由于符号表在第二个 block 里（节表偏移 47448 > 32768），
必须解完整个流才能定位 `ssl_log_secret`，所以 `--keylog` 暂时不可用。

**不影响**：路径 A 的明文抓包（M2/M3）与路径 B 的包抓取 + pcapng（M4）
都完整可用 —— 它们不需要 XZ 解压。

## 八、下一步

### 8.1 补完多 block XZ 解压（最高优先，解锁 `--keylog`）

两条路选一条：

**方案 A：继续修自实现解码器**

当前状态：单 block 全对，第二个 block 从第 13 字节起偏。
排查线索已记在 `user/ecap_lzma.c` 文件头：

- 前 3 个 literal 正确，第 4 个进入短重复（`state=9`）后状态开始偏
- 约 13 字节处出现 `rep0=242111`（远超本 block 已输出量 13）
- 可疑点：`lzma_decode_distance` 里 `pos_decoders` 的基址
  （`base - slot - 1`），或 `reset dict` 后字典窗口的语义

**本机有一份可信的参照实现可以对照：**

```
/home/liuxin/aosp13/external/lzma/C/
  ├── LzmaDec.c    LZMA 核心（literal/match/rep/EOSB 全部细节）
  ├── Lzma2Dec.c   LZMA2 chunk 状态机
  └── XzDec.c      XZ 容器（block 边界 / check / padding）
```

靠它已经确认三件事（其中两件修掉了 bug）：

| 结论 | 状态 |
| :-- | :-- |
| `checkSize = (t==0) ? 0 : 4 << ((t-1)/3)` | 本实现一致 ✅ |
| block padding 必须全为零字节 | 已加校验 ✅ |
| `distance == 0xFFFFFFFF` 是 EOSB 结束标记 | 已补上处理 ✅ |

下一步应重点比对 `LzmaDec.c` 的 `kBadRepCode` / 首个符号特殊处理，
以及 `Lzma2Dec.c` 里 `control >= 0xE0 → NEW_BLOCK` 时 `dicPos` 归零的时机。

建议做法：用 python 写一个逐 bit 的参考实现（只覆盖第二 block 的前 20 个符号），
与 C 的 trace 逐行 diff。我已经用这个方法修掉了 3 个 bug
（`len_coder` 数组越界、漏了 `choice2` 位、读错 check 类型字节）。

**方案 B：改调设备上的 `XzUnpacker_*`**

`/system/lib64/liblzma.so` 已确认导出 `XzUnpacker_Construct` /
`XzUnpacker_Code` / `XzUnpacker_Free` 等。风险是 `CLzma2Dec`
结构体布局随 AOSP 版本变化，需要运行时探测大小或做大缓冲占位。

### 8.2 多目标库支持

内核侧 `ecap_probes` 链表已支持多库（去重键是 `inode + kind + offset`），
用户态只需支持多个 `--lib`，并按包名自动找 App 自带的库路径。

### 8.3 pcapng 的 DSB 密钥块

`ecap_pcapng_write_dsb()` 已经实现并验证（块结构正确、
`secrets_type` 在文件里是 `TLSK`）。等 8.1 完成后，
KEYLOG 事件就能直接写进 DSB，Wireshark 打开 pcapng 即可自动解密。

还需要补的一环：`client_random` 的获取。内核侧已实现
"从 `ssl->s3->client_random` 读"（偏移 `0x30/0x30`，从
`SSL_get_client_random` 的反汇编确认），但需要在设备上实测验证这个偏移
对当前 BoringSSL 版本是否有效 —— 无效时会退化为"只上报 label+secret"。

### 8.4 QUIC / HTTP3

QUIC 不走 `SSL_write`，但 TLS 1.3 的密钥仍然经过 `ssl_log_secret`。
所以 8.1 + 8.3 完成后，QUIC 的密钥就能抓到；
再配合路径 B 的 UDP 包抓取（已支持），可以还原 QUIC 会话。

