# 用户态源码详解

本文逐个函数解释 `user/` 下的五个 C 文件。内核侧的说明见
[`kernel-internals.md`](kernel-internals.md)。

- [一、概览](#一概览)
- [二、ecapctl.c](#二ecapctlc)
- [三、ecap_elf.c](#三ecap_elfc)
- [四、ecap_xz.c](#四ecap_xzc)
- [五、ecap_lzma.c](#五ecap_lzmac)
- [六、ecap_pcapng.c](#六ecap_pcapngc)

---

## 一、概览

| 文件 | 职责 | 大致行数 |
| :-- | :-- | :-- |
| `ecapctl.c` | 主程序：设备交互、事件循环、输出 | 1300 |
| `ecap_elf.c` | ELF 符号查找（`.dynsym` + `.gnu_debugdata`） | 520 |
| `ecap_xz.c` | XZ 解压入口（liblzma 优先，自实现兜底） | 210 |
| `ecap_lzma.c` | 自包含的 XZ/LZMA2 解码器 | 1100 |
| `ecap_pcapng.c` | pcapng 输出（SHB/IDB/EPB/DSB） | 380 |

**依赖关系（单向）：**

```
ecapctl.c
   ├→ ecap_elf.c ──→ ecap_xz.c ──→ ecap_lzma.c
   └→ ecap_pcapng.c
```

`ecapctl.c` 是唯一知道"设备交互"这件事的文件；其余四个都是
纯粹的算法/格式模块，不碰 `/dev/ecap_tls`。

---

## 二、ecapctl.c

### 2.1 这个程序做什么

`ecap_tls.ko` 的控制端。M4 阶段提供四个子命令：

| 子命令 | 作用 |
| :-- | :-- |
| `version` | ABI 握手，确认 `.ko` 与 `ecapctl` 是同一次编译产物 |
| `ping` | 验证 `/dev/ecap_tls` 的 poll/read/事件编解码链路 |
| `stats` | 读取内核统计计数 |
| `capture` | 解析目标 `.so` → 下发过滤规则与探测点 → 消费事件 |

`capture` 的参数：

| 参数 | 说明 |
| :-- | :-- |
| `-l, --lib PATH` | 目标 TLS 库（必填） |
| `-h, --hex` | 额外输出前 64 字节的十六进制 |
| `-v, --stats` | 结束时打印统计（默认开启） |
| `-W, --no-read` | 只抓 SSL_write |
| `-R, --no-write` | 只抓 SSL_read |
| `-p, --tgid PID` | 只抓这个进程（0 = 不过滤） |
| `-u, --uid UID` | 只抓这个 uid（0 = 不过滤） |
| `-w, --pcap PATH` | 同时写 pcapng 文件 |
| `-P, --packet` | 同时抓网络包（Netfilter） |
| `-o, --port PORT` | 包端口过滤（默认 443，0 = 不过滤） |
| `-k, --keylog` | 提取 TLS 密钥（依赖多 block XZ，当前未完成） |

### 2.2 信号处理（M4 新增，很重要）

```c
static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void install_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);   /* 不设 SA_RESTART */

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
}
```

**为什么必须显式捕获 SIGTERM —— 这是实测踩到的坑：**

`Ctrl-C`（SIGINT）会让 `poll()` 返回 `EINTR`，主循环能正常跳到 cleanup。
但 `kill` / `killall`（SIGTERM）的**默认动作是直接终止进程**，
不执行任何代码。

后果：`DEL_PAIR` / `DEL_PROBE` 都不执行，探测点永久留在内核模块里。
下次再启动 capture 就遇到

```
ECAP_IOC_ADD_PAIR failed: File exists
```

而且完全看不出原因。

**三个设计点：**

1. **不设 `SA_RESTART`** —— 让 `poll()` 被打断时返回 `EINTR`，
   主循环才能尽快检查 `g_stop`
2. **`sig_atomic_t`** —— 信号处理函数的硬性要求，只有这个类型能保证
   在信号上下文里读写不撕裂
3. **信号处理函数只置标记** —— 不能在信号处理函数里调用 `ioctl`/`free`
   这类非异步安全函数；真正的清理在主循环退出后做

### 2.3 基础工具函数

#### `static void die(const char *msg)` / `static void die_msg(const char *msg)`

`die` 打印 `msg: <errno 描述>` 后退出；`die_msg` 只打印纯文本。

**为什么 `die` 的调用点都要先保存 `errno`：**

```c
if (ioctl(fd, ECAP_IOC_VERSION, &ver) < 0) {
    int e = errno;
    close(fd);
    errno = e;        /* 恢复 errno，否则 close 可能改它 */
    die("ECAP_IOC_VERSION failed");
}
```

#### `static int open_dev(void)`

打开 `/dev/ecap_tls`，用 `O_RDWR | O_CLOEXEC`。

**刻意不加 `O_NONBLOCK`：** 阻塞模式下 `read()` 会真正等到事件才返回，
比"轮询 + 返回 0"省 CPU。

#### `static const char *ev_type_name(uint32_t t)`

事件类型 → 字符串。M3 起只用于**未知类型的诊断**：

```c
default:
    fprintf(stderr, "[skip] unknown event type %u (%s)\n",
            ev->hdr.type, ev_type_name(ev->hdr.type));
```

这样将来加新事件类型时，如果内核发了但用户态还没处理，日志会明确显示
"事件到了但被跳过了"，而不是静默丢弃。

#### `static const char *dir_name(uint8_t dir)`

`ECAP_DIR_WRITE` / `ECAP_DIR_READ` → `"W"` / `"R"`。

类型和方向是两个正交的维度：`SSL_write` 和 `SSL_read` 产生的事件
**类型相同**（都是 `ECAP_EV_SSL_DATA`），只有方向不同。
混进 type 枚举会让枚举不断膨胀。

#### `static void dump_payload(const uint8_t *p, uint32_t len, bool hex)`

打印 payload，两种视图：文本（不可打印字节显示 `.`）+ 可选十六进制前 64 字节。

**注意：** 输出的是**原始明文**，可能包含 `Authorization`、`Cookie`
等凭据。事件日志应视为敏感数据。

#### `static void fmt_ns(uint64_t ts_ns, char *buf, size_t n)`

内核 `ktime_get_mono_fast_ns()` 的纳秒数 → `秒.毫秒s`。

**这是单调时钟，不是墙上时间。** 它是相对系统启动的偏移，
不能和 `date` 对比。用单调时钟是因为它不受 NTP 校时影响，
事件之间的**相对间隔**始终可靠。

### 2.4 子命令

#### `static int cmd_version(void)`

ABI 握手：`ioctl(ECAP_IOC_VERSION)` 拿内核版本号，与编译期的
`ECAP_ABI_VERSION` 比对。

结构体布局一旦改变，内核与用户态的解释就会错位 ——
版本号让这种错配在第一时间暴露。

#### `static int cmd_ping(unsigned int count, unsigned int len, uint32_t pattern)`

M1 的自测命令，验证整条事件通道。

**发送阶段对 `-ENOSPC` 的处理：**

```c
if (errno == ENOSPC) {
    fprintf(stderr, "queue full, dropping (expected under load)\n");
    continue;   /* 不算失败 */
}
```

队列满丢弃是**设计行为**，不是错误。

**接收阶段逐字节校验 payload：**

```c
for (i = 0; i < len; i++) {
    if (ev.payload[i] != (uint8_t)(pattern + i)) { ... }
}
```

逐字节校验能抓出"内核侧串包 / 缓冲被覆盖"这类 bug。
只校验长度的话，一条被别的线程覆盖了一半的事件也能"通过"。

#### `static int cmd_stats(void)`

打印内核统计。M4 后共 14 个字段，各自回答一个具体问题：

| 字段 | 回答什么问题 |
| :-- | :-- |
| `uprobe_hits` | 探测点到底有没有被触发？（0 = 没挂上或目标没调这个函数） |
| `filtered` | 触发了但被 pid/uid 过滤掉多少？（`hits - filtered` = 实际处理的） |
| `read_empty` | 有多少次 `SSL_read` 返回 `<= 0`？（正常现象） |
| `pending_miss` | 有多少次 ret 找不到 entry 记录？（应为 0） |
| `pending` | 现在表里还有多少条？（空闲时必须为 0） |
| `keylog_hits` | `ssl_log_secret` 被触发多少次？（0 = 探测点没挂上） |
| `keylog_bad` | 有多少次密钥读取失败？ |
| `pkt_seen` | Netfilter hook 看到多少包？ |
| `pkt_pushed` | 成功入队多少？（= `seen - skipped`） |
| `pkt_skipped` | 因端口/协议/解析失败跳过多少？ |

**典型排查路径：**

```
pushed=0 且 hits=0                → 探测点没挂上
pushed=0 且 hits>0 且 filtered==hits → 过滤规则太严
pkt_seen>0 但 pkt_pushed=0        → 端口过滤挡掉了
pending 持续增长                   → SSL_read 的 entry/ret 配对失败
```

### 2.5 主功能：capture

#### `static int resolve_symbol(const char *lib, const char *sym, uint64_t *out_off, const char *what)`

解析一个符号并预检指令可探测性。

**M4 变化：** 改用 `ecap_elf_find_symbol()`，它会先查 `.dynsym`，
再查 `.gnu_debugdata`。打印时会带上符号来源：

```
found SSL_write  (write) at file offset 0x408fc  [via dynsym]
found _ZN4bssl14 (keylog) at file offset 0x3ecd0  [via debugdata]
```

`[via ...]` 对排查很有用 —— 一眼就能看出符号是从哪个节找到的。

#### `static bool keylog_to_line(const struct ecap_keylog_payload *kl, char *out, size_t out_cap)`

把 keylog 事件转成 SSLKEYLOG 文本行：

```
<LABEL> <client_random_hex> <secret_hex>
```

**为什么用文本而不是二进制：** 这是 NSS/Wireshark 的标准格式
（`SSLKEYLOGFILE` 就是这个格式），人类可读、方便和实际 keylog 文件对照。

**`client_random` 全零时直接返回 false（不上报）：**

全零说明内核侧的 BoringSSL 结构体偏移不适用（版本变了）。
这种行写进 pcapng 也匹配不到连接，等于垃圾数据。
跳过并计数，用户看到 `keylog written=0 skipped=N` 就知道该更新偏移了。

**secret 长度怎么确定：** 事件是定长的（64 字节），实际长度靠
"去掉尾部零字节"反推。TLS 1.3 的 traffic secret 是 32 字节、
TLS 1.2 master key 是 48 字节，两者非零结尾的概率都极高，
所以这个方法实际可靠。

#### `static int cmd_capture(const struct capture_opts *o)`

十步流程：

| 步骤 | 做什么 |
| :-- | :-- |
| 1 | 安装信号处理器（必须在挂探测点之前） |
| 2 | 解析符号偏移（write / read / keylog） |
| 3 | 打开 pcapng（如果要求） |
| 4 | 打开目标库，拿 fd |
| 5 | ABI 校验 |
| 6 | 下发过滤规则 |
| 7 | `ADD_PAIR` 成对下发明文探测点 |
| 8 | 单独下发 keylog 探测点 |
| 9 | `ENABLE_NF` 开启包抓取 |
| 10 | 事件循环；退出后按逆序清理 |

**第 10 步的清理顺序（严格逆序）：**

```c
if (nf_enabled)     ioctl(devfd, ECAP_IOC_DISABLE_NF);
if (keylog_added)   ioctl(devfd, ECAP_IOC_DEL_PROBE, &kdel);
                    ioctl(devfd, ECAP_IOC_DEL_PAIR, &pair);
```

先停包抓取（它在软中断上下文，最活跃），再摘 uprobe。

**事件循环按类型分派（M4 从两个分支扩到三个）：**

```c
switch (ev->hdr.type) {
case ECAP_EV_SSL_DATA:  打印 W/R + 明文
case ECAP_EV_KEYLOG:    转成 SSLKEYLOG 行 → 写 DSB（不打印到终端）
case ECAP_EV_PACKET:    写 EPB（--hex 时才打印摘要）
}
```

**keylog 事件为什么不打印到终端：**

密钥出现在终端回滚缓冲 / shell 历史里是实打实的凭据泄露风险。
只写进 pcapng，用户自己决定那个文件放哪。

---

## 三、ecap_elf.c

### 3.1 为什么需要两级查找

**一级：`.dynsym`（动态符号表）**

`SSL_write` / `SSL_read` 都是**导出符号**，App 要动态链接它们，
所以一定在 `.dynsym` 里。这一级不需要任何外部依赖。

**二级：`.gnu_debugdata`（XZ 压缩的 mini debug info）**

`bssl::ssl_log_secret` 是 **C++ 内部函数**，不导出。
Android 的 BoringSSL 把一份"只有符号表的最小 ELF"用 XZ 压缩后
塞在 `.gnu_debugdata` 节里。

实测 Pixel 6 的 conscrypt `libssl.so`：

```
.gnu_debugdata  节 0x2638 字节
  解压后        47832 字节的 ELF（no program header, not stripped）
  里面有        _ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE
                st_value = 0x3ecd0
```

### 3.2 偏移换算的关键细节

```c
static bool elf_vaddr_to_offset(const struct elf_blob *lib,
                                const Elf64_Ehdr *libr_eh,
                                uint64_t vaddr, uint64_t *out)
```

**必须用主库的 `PT_LOAD` 表，不能用 mini debug info 自己的。**

原因：mini debug info 的 ELF **没有 program header**
（`e_phoff == 0`），而且它的 `st_value` 与主库共用同一套虚拟地址编号。
所以换算时要用主库的段表：

```
文件偏移 = st_value - p_vaddr + p_offset
```

**还要排除 `.bss`：**

```c
if (vaddr - ph[i].p_vaddr >= ph[i].p_filesz)
    return false;
```

`p_memsz > p_filesz` 的尾部是 `.bss`，那里没有文件实体。

### 3.3 函数说明

#### `static int elf_load_file(const char *path, struct elf_blob *out)`

一次性把整个文件读进内存。`.so` 通常几百 KB 到几 MB，
一次性读比反复 `pread` 简单。

#### `static int elf_check_header(const struct elf_blob *b, const char *what, const Elf64_Ehdr **out_eh)`

校验 ELF 头：magic、`ELFCLASS64`、`ELFDATA2LSB`、
节头表在文件范围内。

#### `static const char *elf_sh_name(...)`

取节名字符串表中的第 N 项。

#### `static uint64_t elf_scan_symtab(const struct elf_blob *b, const Elf64_Shdr *sh, unsigned int sym_idx, const char *symname, char *out_found, size_t found_len)`

在一张符号表里线性扫描。

**线性扫描而不是二分：** 符号表通常几百到几千条，
一次性解析的开销可以忽略，代码简单得多。

**名字匹配（这里有个坑）：**

```c
if (strcmp(name, symname) != 0) {
    want = strlen(symname);
    if (strncmp(name, symname, want) != 0 ||
        (name[want] != '@' && name[want] != '\0'))
        continue;
}
```

`libssl.so` 里同时有 `SSL_write`、`SSL_write_ex`、`SSL_write_early_data`。
纯前缀匹配会误命中后两个。所以要求匹配后紧跟 `@` 或字符串结束。

C++ mangled 名字本身唯一，精确 `strcmp` 就够。

#### `static int elf_extract_debugdata(const struct elf_blob *lib, const Elf64_Ehdr *eh, struct elf_blob *out)`

找到 `.gnu_debugdata` 节，XZ 解压成一个新的 ELF blob。

解压后的大小上限设 4MB（实测 libssl 是 47KB，留足余量）。

#### `static int elf_find_in_debugdata(...)`

在解压出的 mini ELF 里扫符号表。

**注意它扫 `SHT_SYMTAB` 而不是 `SHT_DYNSYM`** ——
mini debug info 不是给动态链接用的，符号表类型是前者。
两种都扫一遍更稳。

#### `int ecap_elf_find_symbol(const char *path, const char *symname, uint64_t *out_offset, char *out_found, size_t found_len, const char **out_from)`

对外接口，串起两级查找。

`out_from` 回填 `"dynsym"` 或 `"debugdata"`，方便日志里显示符号来源。

---

## 四、ecap_xz.c

### 4.1 两条解压路径

| 路径 | 实现 | 何时使用 |
| :-- | :-- | :-- |
| A | `dlopen` 上游 liblzma + `lzma_stream_decoder` | 宿主 / 部分设备 |
| B | 自实现 `ecap_xz_unpack`（见下一节） | **Android 设备上必须走这条** |

**为什么设备上必须走 B：**

Android 的 `/system/lib64/liblzma.so` 是 AOSP 版本，导出的是
LZMA SDK 的内部名字（`LzmaDec_*`、`XzUnpacker_*`、`AesCbc_Decode` ...），
**没有**上游 liblzma 的 `lzma_code` / `lzma_stream_decoder`：

```
$ nm -D /system/lib64/liblzma.so | grep -c lzma_code
0
```

所以"liblzma.so 存在"完全不代表能用。运行时必须验证符号能否
`dlsym` 到，而不是只看 `dlopen` 成不成功。

### 4.2 函数说明

#### `int ecap_xz_init(void)`

依次尝试 `liblzma.so` 和 `/system/lib64/liblzma.so`，
然后 `dlsym` 两个必需符号。任一失败就关掉句柄返回 -1
（不影响后续，自实现会兜底）。

#### `bool ecap_xz_available(void)`

**永远返回 true** —— 因为自实现不依赖任何外部库。
这个语义与 M2 时代的"liblzma 可用吗"不同，注释里说明了，
免得将来看到这个函数困惑。

#### `static int xz_via_liblzma(...)`

用上游 liblzma 解压。

**`lzma_stream` 的处理：** 它约 136 字节，但我们只需要把地址传进去。
用一个 256 字节的对齐数组占位，并按公开 ABI 的前缀结构体访问
`next_in` / `avail_in` / `next_out` / `avail_out` ——
这些字段是 liblzma 公开 API 的一部分，应用代码就是要直接读写它们的。

#### `int ecap_xz_decompress(...)`

先试 liblzma，失败再试自实现。两个都失败才算失败。

---

## 五、ecap_lzma.c

### 5.1 这是什么

一个自包含的 XZ 容器 + LZMA2 + LZMA 解码器，约 1100 行。
不依赖任何外部库，主机和设备行为一致。

### 5.2 三层结构

```
XZ 容器        Stream Header / Block Header / Block / Index / Footer
   ↓ 只支持单个 filter id = 0x21 (LZMA2)
LZMA2          chunk 流：0x00 结束 / 0x01,0x02 未压缩 / 0x80+ LZMA
   ↓
LZMA 核心      range coder + 概率模型（literal / match / rep）
```

**为什么不直接把 XZ 解成 LZMA2 后交给别的东西：** 没有别的东西可用
（见上一节）。

### 5.3 关键数据结构

#### `struct range_dec`

范围解码器。维护 `[range, code)` 这个区间，每读一位就把区间二分。

```c
uint32_t range;
uint32_t code;
size_t   in_pos;
```

#### `struct lzma_dec`

LZMA 解码器的全部状态：

| 字段组 | 内容 |
| :-- | :-- |
| 概率表 | `literal[0x300<<(4+4)]`、`is_match[12][16]`、`is_rep[12]`、`pos_slot[4][64]`、`len_coder[514]` ... |
| 参数 | `lc` / `lp` / `pb` |
| 运行状态 | `state`、`rep0..3`、`len` |
| 输出 | `out` / `out_pos` / `out_len` / `dict_start` |

### 5.4 函数说明

#### `static uint8_t rd_byte(struct range_dec *rd)`

读一个字节。**输入耗尽时返回 0，不报错。**

LZMA 的 range coder 允许在流末尾"隐式读 0"：所有数据解码完后，
解码器还会继续归一化几次。我最初在这里置 err 并让归一化提前退出，
结果是解压全 'A' 的 100 字节数据时前 16 字节正确、之后全是垃圾。

#### `static void rd_normalize(struct range_dec *rd)`

**必须是 `while` 而不是 `if`。**

规范里写的是单次移位（正常情况一次就够），但在"解码长距离 +
概率接近边界"的组合下 range 可能连续两次低于 2^24。
用 `if` 会让 range 衰减得比编码端慢（实测约 2 倍），
后面所有概率计算全部偏移。

#### `static unsigned int rd_bit(struct range_dec *rd, uint16_t *prob)`

解一位，并更新自适应概率：

```
命中 0：prob += (2048 - prob) >> 5
命中 1：prob -= prob >> 5
```

这就是"自适应"——频繁出现的位概率趋近 1。

#### `static uint32_t rd_direct(struct range_dec *rd, unsigned int nbits)`

解 n 位直接编码的整数（不经过概率模型）。

**归一化的位置极关键** —— 必须是"减半 → 比较 → 归一化"三步每次循环都做：

```c
while (nbits--) {
    rd->range >>= 1;
    if (rd->code >= rd->range) { rd->code -= rd->range; result = (result<<1)|1; }
    else                       { result <<= 1; }
    if (rd->range < (1u << 24)) { rd->range <<= 8; rd->code = (rd->code<<8)|rd_byte(rd); }
}
```

我最初把归一化写在循环开头，看起来等价，实际多/少了一次移位 ——
直接导致距离解码出来的数字完全不对。

#### `static uint32_t rd_tree(...)` / `static uint32_t rd_tree_rev(...)`

解标准位树（MSB 优先）与反向位树（LSB 优先）。
后者用于位置槽和 align 位。

#### `static uint32_t lzma_decode_len(struct lzma_dec *d, uint16_t *probs, unsigned int pos_state)`

**这里有个我踩过的坑：长度编码有 `两个` 独立的 choice 位。**

```
if (choice1 == 0)  return BitTree(low, 3)          // 0..7
if (choice2 == 0)  return 8 + BitTree(mid, 3)      // 8..15
return 16 + BitTree(high, 8)                       // 16..271
```

我最初只写了 `choice1`，然后用"mid 树解出的值 == 7"判断是否进入
high 分支 —— 那是错的。正确做法是读第二个 choice 位。

**后果极其隐蔽：** 整个位流从长度解码开始错位，后面所有 bit 的解读
全部偏移。症状是 literal 全对（它不经过长度解码），
一到第一个 match 就崩，解出的距离槽是个天文数字。

因为多了一个 choice，概率表大小也从 513 变成 514：

```c
#define LEN_CODER_SIZE \
    (2u + POS_STATES_MAX * LEN_LOW_SYMBOLS + \
         POS_STATES_MAX * LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS)
```

#### `static uint32_t lzma_decode_distance(struct lzma_dec *d, uint32_t len)`

解距离。按 `posSlot` 分三种情况：

```
slot < 4          → dist = slot
slot < 14         → dist = ((2|(slot&1)) << limit) + reverse_tree(...)
slot >= 14        → dist = base + (direct(limit-4) << 4) + reverse_tree(align)
```

#### `static int lzma_decode_symbol(struct lzma_dec *d)`

**整个解码器的心脏。** 每调用一次产出一个符号：

```
读 is_match[state][pos_state]
├─ 0 → literal（逐位解，state >= 7 时参考 match_byte）
└─ 1 → 读 is_rep[state]
        ├─ 0 → 新匹配：解 len + dist，更新 rep0..3
        └─ 1 → 重复匹配：
                ├─ is_rep0[state] == 0
                │   └─ is_rep0_long == 0 → 短重复（len=1）
                └─ 用 rep1/rep2/rep3 中的一个
        然后执行复制
```

**`pos_state` 用 block 内的相对位置：**

```c
uint32_t rel_pos = (uint32_t)(d->out_pos - d->dict_start);
uint32_t pos_state = rel_pos & ((1u << d->pb) - 1);
```

单 block 时 `dict_start = 0`，与全局位置等价；多 block 时必须用相对位置，
否则第二个 block 会带着第一个 block 的偏移去选概率表。

**复制时逐字节而不是 memcpy：** 源和目标是同一块缓冲，可能重叠。
`dist=1` 时就是"重复填充前一个字节"，`memcpy` 会得到未定义结果。

#### `static int lzma2_decode(struct lzma_dec *d, const uint8_t *in, size_t in_len, size_t *consumed)`

LZMA2 chunk 循环。**控制字节的语义是本文件最容易搞错的地方：**

| 控制字节 | 含义 |
| :-- | :-- |
| `0x00` | 结束 |
| `0x01` | 未压缩 chunk |
| `0x02` | 未压缩 chunk + reset dict |
| `0x03..0x7F` | 保留（遇到就是数据损坏） |
| `0x80..0xFF` | LZMA chunk，高 5 位是解压长度的高位 |

我最初把 `0x00` 同时当"结束"和"重置字典"，又漏掉了 `0x01`，
结果是：所有走未压缩 chunk 的流全部解析失败 —— 连解压 1 个字节都做不到。

**LZMA chunk 的 reset 模式（控制字节的 bit 6..5）：**

| 值 | 含义 |
| :-- | :-- |
| 0 | 不 reset |
| 1 | reset state |
| 2 | reset state + 新属性（lc/lp/pb） |
| 3 | reset dict + state + 新属性 |

#### `static size_t xz_decode_block(...)`

解一个 Block：解析块头（支持可选的 compressed/uncompressed size）、
校验 filter id 是 `0x21`、解 LZMA2 流、跳过 padding 与 check 字段。

**每个 Block 开始时重置 LZMA 状态与概率表**（规范：block 之间不共享状态）。

**整张 literal 表都要重置，不只重置"当前 lc/lp 用到的那部分"** ——
多 block 流中，如果后一个 block 的 lc/lp 比前一个大，
它就会用到前一个 block 遗留的脏概率。

#### `int ecap_xz_unpack(...)`

对外接口。解析 Stream Header → 循环处理 Block → 累加输出。

**Stream Header 的 check 类型在 `p[7]` 的低 4 位，不是 `p[6]`。**

我一度读成 `p[6]`，得到 check_type=0（None）、check_sz=0，
于是跳过 block 边界时没跳过 check 字段 ——
第二个 block 的头正好落在 check 数据上，
解析出 "unsupported filter id 0x174"。

### 5.5 当前状态

**已正确：** 单 block 的 XZ 流。7 条回归用例（1/2/3 字节、
100 个相同字节、200 字节重复、1024 字节序列、200KB 混合数据）
全部与 python `lzma.decompress()` 逐字节一致。

**未完成：** 多 block 流中第二个及之后的 block。
实测量的 `.gnu_debugdata` 正好是两个 block，第一个 32768 字节完全正确，
第二个 15064 字节从第 13 字节起解出越界距离（`rep0=242111`）。

排查线索与修复方向见 `user/ecap_lzma.c` 文件头的"正确性状态"。

---

## 六、ecap_pcapng.c

### 6.1 pcapng 是什么

pcap 的下一代格式。相比经典 pcap，它支持多接口、纳秒时间戳、
以及任意元数据块。

我们只用到四种块：

| 块 | 作用 |
| :-- | :-- |
| **SHB** Section Header | 文件头，必须有且只有开头一个 |
| **IDB** Interface Description | 描述抓包接口（链路类型、快照长度、时间戳精度） |
| **EPB** Enhanced Packet | 一个包 |
| **DSB** Decryption Secrets | TLS 密钥，让 Wireshark 自动解密 |

### 6.2 所有块的结构都一样

```
+----------------+  4 字节：块类型
+----------------+  4 字节：块总长度
|  块体（Body）  |
+----------------+  4 字节：块总长度（重复）
```

所有多字节字段都是**小端序**，块体按 4 字节对齐。

**总长度写两遍的原因：** pcapng 设计时考虑双向遍历 ——
从文件头往后读用第一份，从文件尾往前读用最后一份。
最后一份必须等于第一份，否则 Wireshark 报 "corrupted file"。

### 6.3 函数说明

#### `static void put_u16 / put_u32 / put_u64(uint8_t *p, ...)`

小端序写入。

#### `static uint32_t pad4(uint32_t n)`

4 字节对齐。

#### `static int write_block(struct ecap_pcapng *p, uint32_t bt, const void *body, uint32_t blen)`

写一个完整块：补齐 + 两份总长度。

**为什么先拼到内存再一次性写：** 块的总长度写在开头，
而它取决于块体内容。逐字段写就得先算长度再 `fseek` 回头改。
先拼内存再一次写出，逻辑简单且不会有文件位置错乱。

#### `static uint32_t put_option(uint8_t *buf, uint16_t code, uint16_t len, const void *val)`

写一个选项（`code(u16) len(u16) value padding`）。

**长度必须用 `strlen`/`sizeof-1`，不能手数：**

我最初给 SHB 的注释字符串手写了长度 30（实际 25 字节），
`put_option` 里的 `memcpy` 会越界读 5 字节 ——
编译器的 `-Wstringop-overflow` 抓到了。

#### `static int write_shb(struct ecap_pcapng *p)`

写 Section Header Block。

```
0  u32 byte-order magic (0x1A2B3C4D)
4  u16 major version (1)
6  u16 minor version (0)
8  i64 section length (-1 = 未知)
16 options（我们只放一个注释）
```

#### `static int write_idb(struct ecap_pcapng *p)`

写 Interface Description Block。

```
0  u16 linktype
2  u16 reserved
4  u32 snaplen
8  options
```

**两个关键选项：**

- `if_name = "ecap_tls"` —— 纯为了在 Wireshark 里好看
- **`if_tsresol = 9`** —— 时间戳单位是 10^-9 秒（纳秒）。
  默认是 6（微秒），必须显式改成纳秒，否则内核给的纳秒值会被当成微秒，
  时间戳差 1000 倍。

#### `struct ecap_pcapng *ecap_pcapng_open(const char *path, uint32_t linktype, uint32_t snaplen)`

创建文件，立即写 SHB + IDB，并 **`fflush` 一次**。

**为什么要立刻 flush：** 保证即使进程马上被杀，文件也是一个
**合法的空 pcapng**（104 字节），而不是 0 字节的垃圾 ——
Wireshark 打开后者会直接报错。

#### `int ecap_pcapng_write_epb(struct ecap_pcapng *p, uint64_t ts_ns, uint32_t if_id, const void *data, uint32_t len)`

写一个包。

```
0   u32 interface id
4   u32 timestamp high
8   u32 timestamp low
12  u32 captured length
16  u32 original length
20  帧数据（补齐到 4 字节）
```

**每写一个包就 `fflush` —— 这是实测踩到的坑：**

第一版只在 `close` 时 flush。结果统计显示 `pkt_pushed=30`，
但 pcapng 文件是 **0 字节**。

原因：抓包进程通常是被 `kill` 结束的，走不到 `ecap_pcapng_close`，
1MB 的用户态缓冲全部丢失。

代价是每包一次 `write` 系统调用，相对于 `copy_from_user` + 入队
的成本可以忽略。

#### `int ecap_pcapng_write_dsb(struct ecap_pcapng *p, uint32_t secrets_type, const void *data, uint32_t len)`

写解密密钥块。

```
0  u32 secrets type
4  u32 secrets length
8  secrets data
```

**`secrets_type` 的字节序有个容易搞反的地方：**

`ECAP_DSB_TLS_KEY_LOG` 的值是 `0x4B534C54`，不是 `0x544C534B`。

pcapng 里多字节字段是小端序，而规范给这类"类型"用的是 **ASCII 4 字符**，
写进文件时按小端存放 —— 文件里的字节顺序应该正好是
`'T','L','S','K'`（`54 4C 53 4B`）。
要让 `put_u32` 写出这 4 个字节，那个 u32 的值必须是 `0x4B534C54`。

我最初写成 `0x544C534B`，文件里变成 `4B 53 4C 54` = `"KSLT"` —— 反了。
Wireshark 对 secrets type 是**按数值比较**的，写反了不会报错，
只会表现为"DSB 块存在但密钥没被用上"，极难排查。

---

## 七、M4 变更一览

### 新增文件

| 文件 | 作用 |
| :-- | :-- |
| `user/ecap_elf.c/.h` | ELF 符号查找（从 ecapctl.c 拆出并扩展） |
| `user/ecap_xz.c/.h` | XZ 解压入口 |
| `user/ecap_lzma.c/.h` | 自包含 XZ/LZMA2 解码器 |
| `user/ecap_pcapng.c/.h` | pcapng 输出 |
| `tests/test_lzma.c` | LZMA 测试驱动 |
| `tests/run_lzma_tests.py` | LZMA 回归测试（用 python lzma 当参照） |

### 从 ecapctl.c 移出

| 原代码 | 新位置 |
| :-- | :-- |
| `struct elf_ctx`、`elf_is_aarch64`、`vaddr_to_file_offset`、`find_symbol_offset` | `ecap_elf.c` |

**为什么拆出去：** M2 时它只有 `.dynsym` 一条查找路径，混在
`ecapctl.c` 里还能接受。M4 加了 `.gnu_debugdata`（XZ 解压 +
二级 ELF 解析）后代码量翻倍，而且和"抓包主流程"完全无关。

### 修改的函数

| 函数 | 变化 |
| :-- | :-- |
| `cmd_capture` | 六步 → 十步：加信号处理、keylog、pcapng、Netfilter |
| `cmd_stats` | 输出加 7 行 M4 字段 |
| `resolve_symbol` | 改用 `ecap_elf_find_symbol`，日志带符号来源 |
| `main` | 选项加 `-w/-k/-P/-o`；启动时尝试 `ecap_xz_init` |
| `usage` | 补全 M4 选项与完整抓包示例 |

### 新增的辅助函数

| 函数 | 作用 |
| :-- | :-- |
| `install_signal_handlers` / `on_signal` | 捕获 SIGINT/SIGTERM/SIGHUP |
| `keylog_to_line` | keylog 事件 → SSLKEYLOGFILE 文本行 |
