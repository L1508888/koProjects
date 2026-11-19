# Android 5.10 内核基于 LKM（内核模块）实现类 eCapture TLS 抓包的可行性与可执行方案

## 一、 结论：完全可行

在 **Android 5.10（GKI 2.0，ARM64）** 环境中，**完全可以**通过编写 **Linux 内核模块（LKM, `.ko`）** 来实现与 eCapture `tls` 模块等价的无证书 TLS 抓包功能（支持明文 Hook 捕获与“密钥提取 + 网络抓包”两种路径）。

根本原因在于：eBPF 能够实现 `uprobe`、`kprobe` 与网卡数据包拦截，底层依赖的正是内核原生子系统（`uprobes`、`kprobes`、`Netfilter`/`dev_add_pack`）。LKM 运行在内核特权态，不仅可以直接调用这些原生子系统，还**不受 eBPF 校验器（512 字节栈、循环次数、指令数、辅助函数白名单）的限制**，并且可直接利用 `copy_from_user()` 读取用户态大块内存。

但同时，Android 5.10（GKI 2.0）引入了严格的符号裁剪、模块签名与安全加固，工程落地时必须解决以下关键约束。

---

## 二、 Android 5.10（GKI 2.0）的核心技术约束与解法

| 约束点 | 原因说明 | 工程解法 |
| :--- | :--- | :--- |
| **1. `kallsyms_lookup_name` 未导出** | Linux 5.7+ 移除了 `kallsyms_lookup_name` 的 `EXPORT_SYMBOL`，且 GKI 开启了 `CONFIG_TRIM_UNUSED_KSYMS`，导致 `uprobe_register` 等函数可能无法直接链接。 | **使用 `register_kprobe` 探测符号地址**：`register_kprobe` 在 GKI 5.10 中是导出的。向 `"kallsyms_lookup_name"` 注册一个临时 `kprobe`，读取 `kp.addr` 后立即注销，即可拿回 `kallsyms_lookup_name` 函数指针，进而解析 `uprobe_register`、`uprobe_unregister` 等任意未导出内核符号。 |
| **2. ARM64 指针标签（TBI / MTE）** | Android 11+ ARM64 用户态开启了 Top-Byte Ignore (TBI) / MTE，传给 `SSL_read/write` 或 `ssl_log_secret` 的指针高 8 位可能带有非零 Tag，直接解引用会导致 `copy_from_user` 失败（`-EFAULT`）。 | 与 eCapture `kern/openssl_untag.h` 一致，读取任何用户态指针前执行去标签掩码：<br>`#define UNTAG_PTR(p) ((void *)((unsigned long)(p) & 0x00FFFFFFFFFFFFFFUL))` |
| **3. BoringSSL 符号定位** | Android 系统 TLS 库主要是 `/apex/com.android.conscrypt/lib64/libssl.so`（以及 App 自带的 `libssl.so` / `libflutter.so`）。内部函数 `bssl::ssl_log_secret` 通常不在动态符号表 `.dynsym` 中，而是位于 XZ 压缩的 `.gnu_debugdata` 节中。 | 在 **用户态控制程序** 中使用 ELF + XZ 解析库读取目标 `libssl.so` 的 `.dynsym` 与 `.gnu_debugdata`，算出目标函数在文件中的物理偏移（`vaddr - PT_LOAD.vaddr + PT_LOAD.offset`），连同文件路径或 `inode` 通过 `ioctl` 传给 LKM。 |
| **4. 网卡抓包替代 TC** | LKM 中直接编程构造 TC `cls_act` 较繁琐。 | 使用 **`nf_register_net_hook`（Netfilter）** 或 **`dev_add_pack`（`ETH_P_ALL`）**。Netfilter 在 `NF_INET_LOCAL_OUT` 钩子中仍处于发包进程上下文或可直接访问 `skb->sk`，比 TC 更易做进程归因。 |
| **5. 内核态 -> 用户态高速传输** | LKM 没有 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`。 | 注册一个字符设备（`misc_register` `/dev/ecap_tls`），内部维护无锁或自旋锁保护的环形缓冲区（`kfifo` / Per-CPU RingBuffer），用户态通过 `poll()` + `read()`（或 `mmap`）消费事件。 |
| **6. GKI 模块加载限制** | 内核开启了 `CONFIG_MODVERSIONS`、`CONFIG_MODULE_SIG` 及 SELinux。 | 1. 编译 `.ko` 时必须使用与目标设备 `uname -r` 完全一致的 Android 5.10 GKI `Module.symvers` 和 Clang 工具链；<br>2. 设备需已解锁并具备 root 权限（Magisk / KernelSU / `su`），加载前处理好 SELinux 策略或临时宽容模式。 |

---

## 三、 整体方案架构

推荐采用 **“用户态控制端（Go/C++） + 内核态模块（LKM `.ko`）”** 分离架构，与 eCapture 保持相同的两条核心抓包路径：

```text
+-------------------------------------------------------------------+
| 用户态控制端 (ecap_ctl)                                           |
|  1. 解析目标 libssl.so ELF (.dynsym / .gnu_debugdata) 获取偏移    |
|  2. 通过 ioctl(/dev/ecap_tls) 下发目标路径、偏移、PID/UID 过滤规则|
|  3. 从 /dev/ecap_tls 读取事件：                                   |
|     - 路径A (Hook): 直接打印/转发 SSL_read/SSL_write 明文         |
|     - 路径B (Keylog+Net): 组装 pcapng (Packet + DSB 密钥块)       |
|       -> 写入 .pcapng 文件 或 送入 ecapture_decryptor 解密还原    |
+-------------------------------------------------------------------+
                   ^  ioctl (下发配置)        |  read / poll (事件流)
===================|==========================v======================
| 内核态 LKM (ecap_tls.ko)                                          |
|  [Uprobe 子系统]                                                  |
|   - 挂载点 1: SSL_write / SSL_read (entry & ret_handler) -> 明文  |
|   - 挂载点 2: bssl::ssl_log_secret (或 SSL_do_handshake) -> 密钥  |
|  [Kprobe / Netfilter 子系统 (路径B)]                              |
|   - kprobe: tcp_sendmsg / udp_sendmsg -> 记录五元组->PID/comm 映射|
|   - Netfilter: NF_INET_LOCAL_OUT / NF_INET_LOCAL_IN -> 抓 sk_buff |
|  [环形缓冲区] Per-CPU / kfifo -> 唤醒 /dev/ecap_tls 等待队列      |
+-------------------------------------------------------------------+
```

---

## 四、 分步可执行实现说明

### 第一步：准备 Android 5.10 GKI 编译环境

1. **确认设备内核信息**：
   ```bash
   adb shell uname -a
   # 示例: Linux localhost 5.10.107-android12-9-00001-... #1 SMP PREEMPT aarch64
   adb shell zcat /proc/config.gz | grep -E "CONFIG_UPROBES|CONFIG_KPROBES|CONFIG_NETFILTER|CONFIG_MODVERSIONS|CONFIG_MODULE_SIG"
   ```
   确保 `CONFIG_UPROBES=y`、`CONFIG_KPROBES=y`、`CONFIG_NETFILTER=y`（Android 5.10 GKI 默认均开启）。

2. **获取对应的 GKI 内核构建产物/头文件**：
   - 从 AOSP 官方 `kernel/manifest`（对应分支如 `common-android12-5.10`）拉取源码与预编译 Clang（`prebuilts/clang/host/linux-x86`），或直接使用对应版本的内核编译产物目录（需包含 `include/`、`arch/arm64/include/` 以及 **`Module.symvers`**）。
   - 如果目标是通用 GKI 测试，需保证编译出来的 `.ko` 的 `vermagic` 字符串与设备 `uname -r` 一致（可在内核构建配置中设置 `LOCALVERSION`）。

---

### 第二步：实现核心 LKM 模块（`ecap_tls.ko`）

#### 1. 解决未导出符号（`kallsyms_lookup_name` 与 `uprobe_register`）

```c
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uprobes.h>

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t fn_kallsyms_lookup_name = NULL;

typedef int (*uprobe_register_t)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc);
typedef void (*uprobe_unregister_t)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc);
static uprobe_register_t fn_uprobe_register = NULL;
static uprobe_unregister_t fn_uprobe_unregister = NULL;

static int resolve_kernel_symbols(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0)
        return -ENOENT;
    fn_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!fn_kallsyms_lookup_name)
        return -EINVAL;

    fn_uprobe_register = (uprobe_register_t)fn_kallsyms_lookup_name("uprobe_register");
    fn_uprobe_unregister = (uprobe_unregister_t)fn_kallsyms_lookup_name("uprobe_unregister");
    if (!fn_uprobe_register || !fn_uprobe_unregister)
        return -ENOENT;

    return 0;
}
```

#### 2. 实现 Uprobe 挂载与用户态数据读取

`uprobe_consumer` 的 `handler` 和 `ret_handler` 运行在**被探测进程的上下文（可睡眠）**，因此可以安全地调用 `copy_from_user()`（必须先去标签）。

**路径 A：Hook `SSL_write` / `SSL_read` 捕获明文**
- `SSL_write(SSL *ssl, const void *buf, int num)`：
  - ARM64 调用约定中：`x0` = `ssl`，`x1` = `buf`，`x2` = `num`（即 `regs->regs[0..2]`）。
  - `handler` 中直接用 `copy_from_user` 读取 `UNTAG_PTR(regs->regs[1])`，长度为 `min(num, MAX_BUF_SIZE)`，或在 `ret_handler` 中读取实际返回值 `regs->regs[0]`（若在入口记录了 `buf` 指针，可通过与 `current->pid` 绑定的哈希表/Per-Task 缓存传递给 `ret_handler`）。
- `SSL_read(SSL *ssl, void *buf, int num)`：
  - 入口 `handler` 记录 `(current->pid, UNTAG_PTR(regs->regs[1]))`。
  - 返回 `ret_handler` 读取 `int ret = (int)regs->regs[0]`，若 `ret > 0`，从缓存取出 `buf` 调用 `copy_from_user()` 读出解密后的明文并推入环形缓冲区。

**路径 B：Hook `bssl::ssl_log_secret` 提取 TLS 密钥**
- 函数签名：`void ssl_log_secret(const SSL *ssl, const char *label, Span<const uint8_t> secret)`。
- 在 ARM64 AAPCS64 下：
  - `regs->regs[0]` (`x0`)：`const SSL *ssl`
  - `regs->regs[1]` (`x1`)：`const char *label`（C 字符串，如 `"CLIENT_TRAFFIC_SECRET_0"`）
  - `regs->regs[2]` (`x2`)：`Span.data_` 指针（`const uint8_t *`）
  - `regs->regs[3]` (`x3`)：`Span.size_` 长度（`size_t`）
- 密钥提取流程：
  1. `strncpy_from_user(evt.label, UNTAG_PTR(regs->regs[1]), sizeof(evt.label))` 读取标签；
  2. `copy_from_user(evt.secret, UNTAG_PTR(regs->regs[2]), min(regs->regs[3], 64))` 读取密钥；
  3. 从 `ssl` 指针读取 `client_random`（参考 `kern/boringssl_masterkey.h` 中的 `ssl->s3->client_random` 偏移，通过 `copy_from_user` 读取），校验非全零后推入环形缓冲区。

#### 3. 获取目标库 `inode` 并注册 Uprobe

```c
#include <linux/namei.h>

// 根据用户态传入的路径（如 "/apex/com.android.conscrypt/lib64/libssl.so"）获取 inode
struct path target_path;
int err = kern_path(lib_path, LOOKUP_FOLLOW, &target_path);
if (!err) {
    struct inode *target_inode = igrab(d_inode(target_path.dentry));
    path_put(&target_path);
    // 注册 uprobe: offset 为 ELF 文件偏移
    fn_uprobe_register(target_inode, file_offset, &my_uprobe_consumer);
}
```
> **注意**：模块卸载（`rmmod`）时，必须先对所有已注册点调用 `fn_uprobe_unregister(target_inode, offset, &uc)`，再 `iput(target_inode)`，否则会引发内核 Panic。

#### 4. 网络数据包抓取与进程归因（路径 B 配套）

若走“密钥 + 抓包”路径，可在 LKM 中注册 Netfilter Hook：
- 注册 `NF_INET_LOCAL_OUT`（出向）和 `NF_INET_LOCAL_IN`（入向）两个 `struct nf_hook_ops`（优先级 `NF_IP_PRI_FIRST`）。
- **进程归因**：
  - 在 `NF_INET_LOCAL_OUT` 中，通常 `skb->sk` 非空，可通过 `kprobe` Hook `tcp_sendmsg`/`udp_sendmsg`（与 `kern/tc.h` 完全一致的五元组 LRU 哈希表逻辑），记录 `(proto, saddr, daddr, sport, dport) -> (pid, uid, comm)`。
  - Netfilter 回调运行在软中断或进程上下文（**禁止睡眠**），使用 `skb_copy_bits(skb, 0, buf, skb->len)`（或处理非线性 `skb_linearize` 的只读拷贝）将数据包连同查表得到的 `pid`/`comm` 写入自旋锁保护的 `kfifo`/RingBuffer。

#### 5. 内核态与用户态通信通道（`/dev/ecap_tls`）

- 使用 `misc_register()` 创建字符设备 `/dev/ecap_tls`。
- 实现 `unlocked_ioctl`：接收用户态下发的配置（目标 `.so` 路径、函数文件偏移、目标 `pid`/`uid` 过滤、启停命令）。
- 实现 `poll` 与 `read`：用户态通过 `epoll`/`poll` 等待 `wait_queue_head_t` 唤醒，批量 `read` 出二进制事件结构体（`uprobe` 明文事件、密钥事件、`sk_buff` 数据包事件）。

---

### 第三步：用户态控制端实现（可复用 eCapture 现有组件）

用户态程序可以非常轻量地用 Go 或 C++ 编写，如果复用 eCapture 源码，只需极少改动：
1. **符号与偏移解析**：直接复用 `internal/probe/openssl/boringssl_symbol.go` 的 `findBoringSSLKeylogAddress()` 解析 `.gnu_debugdata`，以及 `debug/elf` 解析 `SSL_read` / `SSL_write` 的文件偏移。
2. **数据输出与解密**：
   - 若接收 LKM 上报的明文事件：直接格式化输出；
   - 若接收 LKM 上报的 `PacketEvent` + `KeylogEvent`：直接喂给 `internal/output/pcapng/session.go`（生成带 DSB 的 `.pcapng` 文件）或 `internal/output/decrypt/sink.go`（实时解密 HTTP/1.x、HTTP/2、QUIC）。

---

## 五、 两种抓包路径在 Android 5.10 上的选择建议

1. **优先选择“路径 A（Uprobe 纯 Hook `SSL_read` / `SSL_write`）”的场景**：
   - 只需捕获应用层明文（如分析 App API 请求、HTTPS 报文），不需要底层 TCP 重传/握手/QUIC 原始包；
   - 无需处理 Netfilter `sk_buff` 拷贝与五元组进程归因，LKM 代码量最小（约 400~600 行 C 代码即可跑通），稳定性最高。
2. **选择“路径 B（Uprobe `ssl_log_secret` + Netfilter 抓包）”的场景**：
   - 需要导出完整的 `.pcapng` 在 Wireshark 中分析，或目标应用使用 QUIC/HTTP3、自定义传输层（仅 Hook `SSL_read/write` 难以覆盖所有 I/O）；
   - 需要对不同 App 捆绑的静态/动态 `libssl.so` 提取密钥并用统一的离线/在线解密器重组。

---

## 六、 关键安全与稳定性检查清单

1. **上下文睡眠检查**：`kprobe` 和 Netfilter 回调运行在原子/软中断上下文，**严禁**调用可能睡眠的函数（必须用 `GFP_ATOMIC`、`spin_lock_irqsave`，禁止 `mutex_lock` 和 `copy_from_user`）。`uprobe_consumer` 回调运行在进程上下文，可安全使用 `copy_from_user()`。
2. **资源上限与防丢包**：为 RingBuffer 设置固定上限（如 4MB~16MB），队列满时直接丢弃新事件并累加 `dropped_count`，绝不阻塞目标 App 线程或内核网络栈。
3. **干净卸载（`rmmod`）**：必须在 `module_exit` 中严格按顺序注销：Netfilter Hooks -> Kprobes -> Uprobes（遍历释放所有 `iput(inode)`）-> `misc_deregister` -> 释放缓冲区内存。
4. **App 自带 BoringSSL 适配**：除系统 `/apex/com.android.conscrypt/lib64/libssl.so` 外，Chrome/WebView/Flutter/Cronet 等通常内置独立的 `libssl.so` / `libflutter.so` / `libcronet.so`；用户态控制器只需支持传入多个目标库路径与偏移即可同时覆盖。
