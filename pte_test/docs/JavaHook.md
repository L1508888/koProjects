# Java 层 Hook 实现说明

本文档说明本项目在原 **native 层 PTE hook** 之上新增的**Java 层（ART 方法级）hook** —— 完整设计、实现、使用与限制。

- 实现文件：`javahook.c` / `javahook.h`（策略与槽位管理）、`jh_tramp.c` / `jh_tramp.h`（trampoline 生成器）
- 控制通道：`/proc/pte_java`（见 `main.c` 的 `java_cmd_dispatch`）
- 用户态工具：`tools/pte_java.c`
- 测试程序：`test/java/JavaHookTest.java`
- 验证脚本：`tools/compare.sh`（用真实汇编器逐字节核对 trampoline）、`tools/simtest.c`（规则语义自测）

**能力概览**

| 能力 | 怎么做 |
| --- | --- |
| 输出函数参数 | `arg<N>=print` |
| 修改函数参数 | `arg<N>=set/add/or/and:<v>` |
| 输出函数返回值 | `retop=print` |
| 修改函数返回值 | `retop=set/add/or/and:<v>` |
| 完全接管（不调原方法） | `skip ret=<v>` |
| 跳到自己的函数 | `replace=<addr>` |

---

## 0. 真机验证结果

已在 **Pixel 6 / Android 13 / 内核 5.10.252-android13-4-00010** 上完整验证通过：

| 项 | 结果 |
| --- | --- |
| 模块加载 / 卸载 | 通过（`insmod` / `rmmod` 均返回 0，9 步退出流程全部走完） |
| `probe` ArtMethod 布局 | 通过（实测 `entry_off = 0x18`，见 5.1） |
| 输出函数参数 | 通过（`x1/x2` 正确显示为 receiver 与实参） |
| 修改函数参数 | 通过（`arg2=set:0x64` 使 `hot(6,7)` 从 42 变 700） |
| 输出函数返回值 | 通过（`retop=print` 捕获到 `x0=0x2a` = 42） |
| 修改函数返回值 | 通过（`retop=set:0x3e7` 使返回值变 999） |
| 组合规则 | 通过（`arg2=add:0x1 retop=print` → `(6+1)*7 = 49`） |
| 卸载还原 | 通过（行为恢复 42，`entry_point_` 还原为原入口） |
| **按包名定位（不给 pid）** | 通过（`hook - <am> pkg=<name>` → 自动解析到正确 pid） |
| **按 uid 定位** | 通过（`uid=0` 这类 root 进程也能作为目标） |

验证过程中发现并修复了五个**真机才会暴露**的问题，都写进了第 9 节：

1. **CFI 导致 panic**（9.11）—— 最严重，最初空载 `rmmod` 也会让设备重启；
   后来又发现 `access_process_vm` 与内部 helper 的间接调用同样会被 CFI 拦，
   现在整个模块里 `__cfi_slowpath` 调用数为 **0**；
2. **`ArtMethod.entry_point_` 偏移是 0x18 而非 0x20**（4.5）；
3. **被内联的方法 hook 不到**（9.10）+ **ART 会重写 entry_point_**（9.2.1）；
4. **RCU 临界区内不能睡眠**（9.12）—— 按包名扫进程时踩到，会直接 panic；
5. **不能"第一个名字命中就采用"**（9.13）—— 父 shell 的 cmdline 也含包名，
   且它没有 mm，选中它 hook 装不上。

## 0.1 怎么用（最常用的两种写法）

```bash
# 知道 pid（拿到 ArtMethod 时通常已经知道）
pte_java hook <pid> <art_method> arg1=print

# 只知道包名（pid 填 "-"，由内核按包名找进程）
pte_java hook - <art_method> arg1=print pkg=com.example.app

# 只知道 uid
pte_java hook - <art_method> arg1=print uid=10123

# 两者都给：要求同时满足，更精确（推荐，避免同名进程误匹配）
pte_java hook - <art_method> arg1=print pkg=com.example.app uid=10123
```

安装结果里会回显**实际解析到的 pid**，后续 `unhook` / `read` 用它就行：

```
[OK] ret=0 pid=6536 method=0x7a1b2c3d40
  entry_off  = 0x18
  ...
  target     = pkg=com.example.app uid=0 -> pid 6536
```

> **ArtMethod 地址仍需你提供**。它是**目标进程内**的用户态地址，
> 无法凭类名/方法名在内核侧可靠算出（ART 内部结构逐版本变化，
> `GetMethodsPtr` 之类还是 inline、无导出符号）。
> 用 `tools/pte_java_resolve`，或在目标进程内用 JNI 取（`test/java/ArtMethodHelper.java`，
> 原理：ART 里 `jmethodID` **就是** `ArtMethod*`，`FromReflectedMethod` 可直接拿到）。
> 这是刻意设计的分工：内核只做"找进程 + 装 hook"，不做 ART 结构解析。

## 1. 背景：为什么 Java 层 hook 可以用 PTE 做

Android 的 Java 方法最终都编译成 **ARM64 机器码**，其入口地址记录在两处之一：

| 位置 | 说明 |
| --- | --- |
| `ArtMethod.entry_point_`（8 字节字段） | ART 数据结构里记录的方法入口 |
| 编译代码本身的首地址 | `.oat` / `.so` / JIT 生成的可执行页 |

也就是说，**Java 层 hook 的本质和 native 层没有区别**：都是"把执行流从 A 点引到 B 点"。
差别只在于**怎么找到 A 点**（要懂 ART 的 `ArtMethod` 布局）和**怎么改**（数据字段写 vs. PTE 控制）。

### 为什么不需要 root、不需要注入框架

模块只做三件事：

1. `access_process_vm()` 读写目标进程的用户内存（内核态调用，不需要目标进程配合）；
2. `__get_free_pages()` 申请物理页，手工把 PTE 塞进目标进程页表（**不建 VMA**，所以 `/proc/<pid>/maps` 里看不到）；
3. `follow_pte()` 改目标页 PTE 的 UXN 位，配合已有的 `do_mem_abort` kprobe 做取指重定向。

最终产物就只有 **一个 `.ko` 文件**，加载后即可用。

---

## 2. 整体链路

```
                     ┌────────────────────────────────────────┐
   用户态            │ tools/pte_java ──write──▶ /proc/pte_java │
                     └────────────────────────────────────────┘
                                     │  进程上下文（可睡眠）
                                     ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ main.c : java_cmd_dispatch                                  │
   │   "hook <pid> <art_method> arg1=print retop=add:0x1 ..."    │
   └─────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ javahook.c : java_hook_method()                             │
   │   1. 定位 ArtMethod.entry_point_ 偏移（探测或显式指定）       │
   │   2. 读原入口，判断是否可执行                                 │
   │   3. jh_tramp.c 生成 trampoline（按规则决定形态）             │
   │   4. 申请 ghost 页 → 写入代码 → 同步 i-cache                 │
   │   5. 切换入口（写字段 / 装 UXN）                              │
   └─────────────────────────────────────────────────────────────┘
             │                                     │
             │ 策略 A（字段）                       │ 策略 B（UXN）
             ▼                                     ▼
   ArtMethod.entry_point_ = tramp         hook_install_sync(entry, tramp)
             │                                     │
             └──────────────┬──────────────────────┘
                            ▼
              trampoline (ghost 页, 无 VMA)
              ┌──────────────────────────────┐
              │ brk #0xBF00   入口观察点      │ ← 看/改参数
              │ stp x29,x30,[sp,#-16]!       │ （仅需返回值时才保存）
              │ movz/movk x17, target        │
              │ blr  x17                     │ ← 调用原方法
              │ brk  #0xBF01  出口观察点      │ ← 看/改返回值
              │ ldp  x29,x30,[sp],#16        │
              │ ret                          │
              └──────────────────────────────┘
                            │
                            ▼
                        原方法代码
```

---

## 3. 两种策略

### 策略 A：改写 `ArtMethod.entry_point_`（默认）

```
ArtMethod.entry_point_  ──▶  trampoline ──▶  目标（replace 或原入口）
```

- **改动**：只写 8 字节字段，代码页一个字节都不动，PTE 也不动。
- **优点**：最简单、最稳；不需要 `do_mem_abort` 钩子参与；对 JIT 代码、AOT 代码、解释器桩都一致有效。
- **缺点**：修改对 ART **可见**（ART 自己能读到这个字段被改了）；如果 ART 在别处缓存了入口（少见），可能不生效。

| 用法 | trampoline 目标 | `backup` |
| --- | --- | --- |
| `hook ... arg1=print` | 原入口 | `orig_entry` |
| `hook ... replace=0x..` | `replace` | ghost 里的 backup trampoline（跳到原入口） |
| `hook ... skip ret=0x..` | ——（直接 `ret`） | `orig_entry` |

### 策略 B：PTE/UXN 取指劫持（`uxn`）

```
入口页 PTE 置 UXN（EL0 禁止执行）
    │
    └─ 取指异常 (do_mem_abort, EC=0x20/IFSC=0b0011xx)
          ├─ far == 目标入口      → pc = trampoline
          └─ far == 同页其它地址  → pc = DBI 重编译副本（语义等价）
```

- **改动**：只改 PTE 的一个属性位，`ArtMethod` 和代码字节都保持原样。
- **优点**：ART 数据结构与代码段完全干净，面向 ART 侧的完整性校验无从发现。
- **缺点**：依赖 `do_mem_abort` kprobe（本内核实测可注册）；每次调用多一次异常往返；
  同页的所有代码都会被搬到 ghost 页执行（PTE 以页为单位的固有代价）。

**backup 地址的关键差异**（重要）：

| 策略 | `backup`（"调用原方法"用） |
| --- | --- |
| A | `orig_entry`（原入口没被改，直接跳） |
| B | ghost 里该入口的重编译副本（跳 `orig_entry` 会再次 UXN fault → 死循环） |

---

## 4. trampoline：两种形态

生成器在 `jh_tramp.c`，是**纯函数**（输入规则 → 输出指令数组），
所以可以拿到用户态用真实汇编器逐字节核对（`tools/compare.sh`）。

### 4.1 尾跳形态（只需要在"入口"做事）

```
    brk  #0xBF00        ; 入口观察点（需要看/改参数时才有）
    movz x17, #imm16    ; 目标绝对地址
    movk x17, #imm16, lsl #16
    movk x17, #imm16, lsl #32
    movk x17, #imm16, lsl #48
    br   x17            ; 尾跳：原方法直接把返回值返回给调用者
```

适用：只看/改参数。**最快**，不改变栈布局。

### 4.2 调用形态（需要在"返回后"做事）

```
    brk  #0xBF00        ; 入口观察点（可选）
    stp  x29, x30, [sp, #-16]!
    movz/movk x17, target
    blr  x17            ; 调用原方法，返回值落在 x0/x1
    brk  #0xBF01        ; 出口观察点：此刻 x0/x1 就是返回值
    ldp  x29, x30, [sp], #16
    ret                 ; 把（可能被改过的）返回值交回调用者
```

适用：要看/改返回值。

**为什么必须保存 x29/x30**：`blr` 会把返回地址写进 `x30`，覆盖掉调用者的 LR。
不保存的话，原方法返回后我们回不到调用者。用 `stp/ldp` 成对保存，
顺带让栈回溯链完整（`x29` 帧指针）。

**为什么不额外保存 x0..x7**：两种形态都不改参数寄存器，原方法自己会
保存它要用的参数。只有在调用形态下 `x0/x1` 被返回值占用——那正是
我们要观察的东西。`x19..x28`（被调用者保存）由原方法自己保护。

### 4.3 为什么用 x17

AAPCS64 规定 `x16`(IP0) / `x17`(IP1) 是"调用者可被跳板破坏的临时寄存器"，
ART 自己的跳板代码也这么用。用 `x17` 不会破坏任何调用约定。

### 4.4 skip 形态

`skip`（不调用原方法）时不需要 `blr`：

```
    [brk #0xBF00]
    movz/movk x0, #ret_val
    movz x1, #0              ; long/double 的第二个八字节清零
    [brk #0xBF01]            ; 出口观察点仍可看/改这个值
    ret
```

`x1` 的清零不能省：漏了它 32 位 int 返回值的高位会是垃圾，
ART 侧按 64 位读就会算错。

---

## 4.5 ArtMethod 布局：怎么找到 entry_point_

内核侧不去读 dex、不依赖 `libart.so` 私有符号，而是用**候选偏移表**逐个试，
判据是"该 8 字节是否指向一张 EL0 可取指的页"（PTE present 且未置 UXN）：

```c
static const unsigned int jh_entry_candidates[] = { 0x18, 0x20, 0x10, 0x28 };
```

这个判据可靠的原因：`ArtMethod` 里其它 8 字节字段（`declaring_class_`、
`data_` 等）要么指向不可执行的堆/数据段，要么是压缩引用；
**只有 `entry_point_` 必然指向代码**。

### 实测布局（Pixel 6 / Android 13 / ART 13）

用 `ArtMethodHelper.dumpArtMethod` 打印的真实内存：

```
ArtMethod* = 0x73cc6ae088          ← add() 这个实例方法
  +0x00: 0x1828000112c065d0        declaring_class_ + access_flags_ + 索引等打包
  +0x08: 0xffff000b00000012        dex_code_item_offset_ / dex_method_index_ 等
  +0x10: 0x00000073d938f3f8        data_（指向堆，PTE uxn=1，不可执行）
  +0x18: 0x0000007119400090        entry_point_（libart.so r-x 段，可执行）← 实测
```

相邻方法的间隔正好 **0x20 字节**：

```
greet 0x73cc6ae028 → add 0x73cc6ae088 → hot 0x73cc6ae0a8 → tick 0x73cc6ae0c8
```

所以 `ArtMethod` 本身是 0x20 字节，**0x20 已经是下一个方法的起始**——
在 Android 13 上它不是 `entry_point_`（这是我最初按 Android 8~11 的经验
写成 0x20 而踩的坑）。

| 平台 | `entry_point_` 偏移 |
| --- | --- |
| Android 13 / ART 13（实测 Pixel 6） | **0x18** |
| Android 8 ~ 11（常见） | 0x20 |

探测器会打印实际命中的偏移；都不匹配时用 `entry=` 显式指定。

### 未编译的方法共用入口

实测同一个进程里：

```
add        +0x18: 0x7119400090   ← 与 greet 完全相同
greet      +0x18: 0x7119400090   ← 共享跳板
hot(JIT 后) +0x18: 0x98ed1530   ← 独有地址
```

`0x7119400090` 落在 `libart.so` 的 `r-xp` 段，是所有未编译方法共用的
跳板。**先把方法调"热"再 hook**，才能拿到方法独享的入口（见 9.1）。

---

## 5. 参数与返回值的读写

### 5.1 参数（入口观察点）

此刻 `x0..x7` 就是调用者传进来、**还没被原方法碰到**的原始值。
直接改 `uregs->regs[n]`，原方法看到的就是改过的参数。

**实测的寄存器布局**（`hot(6, 7)` 这个实例方法，`arg1=print arg2=print` 捕获）：

```
x0=73cc6ae0a8   ← ArtMethod* 本身
x1=12c343a0     ← receiver (this)
x2=6            ← 第一个形参 a
x3=7            ← 第二个形参 b
```

也就是说 **`x0` 是 `ArtMethod*`，`x1` 才是 receiver，形参从 `x2` 起**。
这与"x0=receiver"的常见说法不同，所以**一定要先 `arg0=print` 看清
自己的目标方法实际怎么摆**，不要凭经验猜。

参考语义：

```
x0      ArtMethod*
x1      receiver（实例方法）/ 第一个形参（静态方法，实测 greet 也是从 x1 起）
x2..x7  后续形参（long/double 各占一个；float/int 也只占一个）
x8      间接结果寄存器（返回大对象时用）
```

> **实用建议**：想改第一个形参，实测是 `arg2=...`（因为 x0=ArtMethod*、
> x1=receiver）。但不同调用路径可能不同，**先 `arg0=print` 看一次最稳**。

### 5.2 返回值（出口观察点）

此刻刚从原方法 `blr` 回来：

```
x0  = 返回值（int/long/boolean/引用都是它）
x1  = long/double 的第二个八字节（128 位宽的值）；不关心可忽略
```

`bits32` 时只改 `w0`（低 32 位），高位保持不变——ART 侧按 32 位读，
但有些路径会顺手当 64 位用，保持高位原状更安全。

### 5.3 操作

| op | 含义 | 例 |
| --- | --- | --- |
| `print` | 只记录，不修改 | `arg1=print` |
| `set` | `value = v` | `retop=set:0x64` |
| `add` | `value += v` | `arg2=add:0x10` |
| `or` | `value \|= v` | `arg1=or:0x1` |
| `and` | `value &= v` | `arg1=and:0xff` |

同一下标可以给多条规则，按给出的顺序依次叠加：

```
arg3=or:0x0f arg3=and:0xfc     # (v|0x0f)&0xfc
```

---

## 6. 输出通道：捕获环

**为什么不直接 printk**：观察点跑在 BRK 异常上下文（EL1、关中断、不可睡眠）。
在那里 `printk` 会拖慢每一次方法调用（高频方法直接拖死系统），
并把 dmesg 环形缓冲冲爆。

所以 `print` 只把寄存器快照写进一块**预分配的定长环**（512 条），
用户态用 `dump` 批量取走：

```
# 1234 ARG slot=0 pid=1234 method=0x7a1b2c3d40 x0=7a1b2c3d40 x1=3 x2=4 x3=0 x4=0 ...
# 1235 RET slot=0 pid=1234 method=0x7a1b2c3d40 x0=7 x1=0 x2=0 ...
```

**写入是无锁的**：

- 每条记录有个 `seq`（原子递增）；
- 写入者先填内容，再用 `smp_wmb` + `atomic64_set` 发布 `seq`；
- 读取者用 `smp_rmb` 检查 `seq`，只接受已发布的记录。

多 CPU 同时命中不会撕裂；读取者最多跳过一条正在写的记录。
环满了就覆盖最旧的（`seq - 1) % 512`），不会丢新数据。

**注意**：`print` 记录的是**修改前**的值。这样你看到的是"原方法真正收到
/真正返回了什么"，而不是被我们改过的值——排查问题时几乎总是想看前者。

`JH_FLAG_BRK`（`brk` 选项）额外把一份打到 dmesg，适合临时看一眼。
**高频方法不要用 `brk`**，用 `dump`。

---

## 7. 使用方式

### 7.1 准备

```bash
make modules                      # 产物：pte_main.ko
tools/build.sh                    # 产物：tools/pte_java（arm64 静态）

adb push pte_main.ko tools/pte_java /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/pte_main.ko'
adb shell su -c 'dmesg | tail -20'
```

预期：

```
pte_hook: access_process_vm=...
pte_hook: get symbol success
pte_hook: user break hook success
pte_hook: /proc/pte_java ready
pte_hook: module load success
```

### 7.2 命令

```bash
pte_java list                          # 当前所有 Java hook（含规则摘要）
pte_java probe  <pid> <art_method>     # 探测入口字段偏移
pte_java read   <pid> <art_method> [off]
pte_java write  <pid> <art_method> <off> <val>
pte_java hook   <pid> <art_method> [选项...]
pte_java unhook <pid> <art_method>
pte_java dump   [max]                  # 取走捕获环记录
pte_java cap    on|off|clear           # 捕获开关
pte_java watch  <pid|-> <art_method> [选项...]   # 安装并循环 dump
```

> 第一个参数是 pid。**不知道 pid 就填 `-`**，用 `pkg=` / `uid=` 定位
> （见 0.1 节和 9.13）。

### 7.3 四个核心场景

**① 输出参数**

```bash
pte_java hook 1234 0x7a1b2c3d40 arg1=print arg2=print
pte_java dump
# #1 ARG slot=0 pid=1234 method=0x7a1b2c3d40 x0=... x1=3 x2=4 ...
```

**② 修改参数**

```bash
# 把第 2 个参数（x1）固定成 100
pte_java hook 1234 0x7a1b2c3d40 arg1=set:0x64
```

**③ 输出返回值**

```bash
pte_java hook 1234 0x7a1b2c3d40 retop=print
pte_java dump
# #1 RET slot=0 pid=1234 method=0x7a1b2c3d40 x0=7 x1=0 ...
```

**④ 修改返回值**

```bash
# 返回值 +1（32 位 int）
pte_java hook 1234 0x7a1b2c3d40 retop=add:0x1 bits32
# 固定返回 100
pte_java hook 1234 0x7a1b2c3d40 retop=set:0x64 bits32
# 原方法照跑，但返回值总是 1
pte_java hook 1234 0x7a1b2c3d40 skip ret=0x1
```

**组合：看参数 + 改参数 + 看返回值**

```bash
pte_java watch 1234 0x7a1b2c3d40 arg1=print arg2=add:0x10 retop=print
# watch = 装 hook 然后每 300ms dump 一次，Ctrl-C 停止
```

### 7.4 验证用的测试 App

`test/java/JavaHookTest.java` 打印三个方法的 `ArtMethod` 地址并循环调用：

```bash
javac -source 8 -target 8 \
      -bootclasspath $ANDROID_HOME/platforms/android-33/android.jar \
      test/java/JavaHookTest.java -d /tmp/jout
d8 --lib $ANDROID_HOME/platforms/android-33/android.jar \
   /tmp/jout/pte/javatest/*.class --output /tmp/jout
adb push /tmp/jout/classes.dex /data/local/tmp/javatest.dex
adb shell 'CLASSPATH=/data/local/tmp/javatest.dex app_process / pte.javatest.JavaHookTest'
```

它循环调用 `obj.add(3, 4)` 并打印结果，正好用来验证
"参数改成 100 → 返回 100"、"返回值 +1 → 8" 这类效果。

---

## 8. `/proc/pte_java` 文本协议

```
hook <pid|-> <art_method> [选项...]
unhook <pid> <art_method>
probe <pid|-> <art_method>
read  <pid> <art_method> <off>
write <pid> <art_method> <off> <val>
list
dump  [max]
cap   on|off|clear
```

`hook` 的选项：

| 选项 | 含义 |
| --- | --- |
| `pkg=<包名>` | 按包名找进程（pid 填 `-` 时生效） |
| `uid=<userId>` | 按 App 的 userId 找进程（`uid=0` 这类 root 进程也支持） |
| `arg<N>=print` | 输出第 N 个参数（N = 0..7 → x0..x7） |
| `arg<N>=set/add/or/and:<v>` | 修改第 N 个参数 |
| `retop=print` | 输出返回值 |
| `retop=set/add/or/and:<v>` | 修改返回值 |
| `bits32` / `bits64` | 返回值按 32/64 位处理（默认 64） |
| `entry=0x20` | 显式指定入口字段偏移（默认自动探测） |
| `replace=0x..` | 替换函数地址 |
| `ret=0x..` | `skip` 时的返回值 |
| `uxn` | 策略 B（PTE/UXN，不动 ArtMethod） |
| `brk` | 额外用 dmesg 打印入口参数（调试用，别配高频方法） |
| `skip` | 不调用原方法 |
| `raw` | 不做 trampoline，入口直接指向 `replace` |

**pkg 的匹配规则**（`jh_match_rank`，取最高分）：

| rank | 条件 |
| --- | --- |
| 3 | `comm` 等于包名（zygote fork 的 App 主进程） |
| 2 | cmdline 的 `argv[0]`（basename）等于包名 |
| 1 | `argv[0]` 是 `app_process` 且后面某参数等于包名 |
| 0 | 不匹配 |

`com.foo` 能匹配 `com.foo` 与 `com.foo:remote` 这类私有进程，
但主进程优先。同时给 `pkg` 和 `uid` 时要求两者都满足。

结果只保留最近一次，写完立刻读回：

```
[OK] ret=0 pid=1234 method=0x7a1b2c3d40
  entry_off  = 0x20
  orig_entry = 0x7f2a3b4c50
  trampoline = 0x7a5b6c7000
  backup     = 0x7a1b2c3d40
  enter_brk  = 0x7a5b6c7000
  exit_brk   = 0x7a5b6c7010
  rules      = x1:print x2:add=0x10 ret:print
```

`enter_brk` / `exit_brk` 为 0 表示该形态没有对应的观察点。

权限 `0600`。

---

## 9. 已知限制与注意事项

### 9.1 ART 共享跳板问题（最重要）

ART 在**方法还没被编译**时，`entry_point_` 会指向 `libart.so` 里的共享跳板，
**所有方法共用同一个地址**。此时：

- 安装时会打印 `r-x 文件映射 → AOT 代码或 ART 共享跳板，需确认`；
- 直接 hook 这个地址 = hook 了所有走到该跳板的方法，
  参数规则也会作用到所有经过它的方法上；
- 本模块**不做猜测**，只照实反映入口值。

**应对办法**：

1. **先让方法被编译**：在 App 里把目标方法调用到"热"（ART 会 JIT），
   此时 `entry_point_` 变成 JIT 代码地址（匿名可执行页），hook 就精确了。
2. 或用 `brk` 观察点读 `x0` 里的 `ArtMethod*` 做二次过滤
   （`x0` 在实例方法里是 receiver，在静态方法里是 `ArtMethod*`，
   需按 `access_flags_` 的 `ACC_STATIC` 位区分）。

### 9.2 修改参数/返回值的可见性

改的是**寄存器**，只影响本次调用。原方法自己的逻辑、ART 的缓存、
被内联的调用点都不受影响——这也意味着：

- 如果方法被 **AOT/JIT 内联**进了调用者，改 `entry_point_` 不会生效
  （调用点根本没有跳转，内联后的代码直接执行）。**这一条已在真机上实测确认**：
  直接写 `obj.hot(6,7)` 时 hook 完全不命中；改成
  `hotM.invoke(obj, 6, 7)`（反射调用，不可能被内联）后立刻生效。
  验证/绕开办法见 9.10。
- 返回值规则只对**本次 `blr` 返回**有效；如果原方法自己做了尾调用优化，
  返回值仍然经过我们的出口观察点，所以是安全的。

### 9.2.1 ART 会重写 `entry_point_`（策略 A 的真实风险）

热方法在运行期间可能被 ART **反复重新 JIT / OSR**，每次都会把
`ArtMethod.entry_point_` 写成新的编译代码地址，**覆盖掉我们的 trampoline**。

真机上观察到的现象：装好 hook 并确认字段已被写成 trampoline 地址
（`read` 命令读回 `0x99f67000`），但方法行为没变；再 `probe` 一次发现
入口又变回了另一个 JIT 地址。

对策：
1. 用 `uxn` 策略 —— 它劫持的是**代码页**，ART 改字段不影响它；
2. 或定期 `read` 检查入口是否还是 trampoline，被覆盖就重装；
3. 或在方法已经"稳定"（不再被重新 JIT）之后才装 hook。

### 9.3 卸载时正在执行 trampoline 的线程

`jh_teardown()` 的顺序是：

1. 先 `used = 0` + `smp_wmb()`（BRK 路径据此停止匹配）；
2. 再还原入口（字段写回 / 解除 UXN）；
3. 最后释放 ghost 页。

第 3 步与"正在 trampoline 里执行的线程"之间仍**没有强同步**：
`ghost_free()` 的 `ic ialluis` + IPI 排空是**尽力而为**的。
若某线程正好在 `movz/movk → br` 之间被抢占，且物理页已回收，
恢复执行时会取到错误指令。这与 `hookManager` 的已知限制一致。
**实际影响很小**：trampoline 只有 2–10 条指令，窗口是纳秒级。

### 9.4 策略 A 的语义可见性

改写 `ArtMethod.entry_point_` 后，ART 自己读这个字段会拿到 trampoline 地址。
如果目标 App 有完整性校验（读自己方法的入口做比对），策略 A 会被发现。
需要隐蔽性时用策略 B（`uxn`）。

### 9.5 策略 B 的页粒度开销

UXN 以 4KB 页为单位。目标入口所在页的**所有**代码都会被搬进 ghost 执行。
另外**策略 B 下 `retop` 规则仍然有效**（trampoline 里同样有出口观察点），
但每次进入该页都会多一次异常往返。

### 9.6 捕获环的可见性开销

`print` 每次调用写一条记录（约 100 字节 + 两次原子操作）。
高频方法（每秒几十万次）建议：
- 不要用 `brk`（会 printk）；
- 观察够了就 `cap off` 或直接 `unhook`。

### 9.7 槽位上限

- `JH_MAX_SLOTS = 24`（Java hook 条数）
- `MAX_RECORD = 16`（`hookManager` 的页槽位数）
- `JH_CAP_SLOTS = 512`（捕获环条数）

### 9.8 进程退出 / exec

- 目标进程退出后，槽位在下次安装时被 `javahook_reap()` 回收，物理页归还；
- 目标进程 `exec` 后 `mm` 变了，`ghost_free()` 会拒绝，走 `ghost_release_phys()` 只归还物理页。

### 9.9 未实现的部分

- **不解析 dex**：模块不知道方法名、签名，只认 `ArtMethod*` 地址。
- **不做 ART 内部符号解析**：不依赖 `libart.so` 私有符号，所以不会被 ART
  版本变化打破，但也因此拿不到 `ArtMethod` 的运行时布局信息（靠候选偏移探测）。
- **不支持 AArch32**：只实现 ARM64。
- **不支持浮点参数/返回值的语义化输出**：`float`/`double` 参数在
  `v0..v7` 寄存器里，本模块只记录整型寄存器 `x0..x7`。
  如果方法参数是 `float`，ART 会把它放在 `v` 寄存器，`x` 里看不到。

### 9.10 被内联的方法 hook 不到（实测）

ART 会把**短小且热**的方法内联到调用者。内联后调用点是展开的代码，
不再经过 `ArtMethod.entry_point_`，所以策略 A 完全看不到这次调用。

真机验证：`obj.hot(6,7)` 直接调用时 hook 不生效；
`hotM.invoke(obj, 6, 7)` 反射调用时立刻生效。

验证/使用建议：
- **用反射调用目标方法**做验证（`Method.invoke`），它必然走方法入口；
- 或让目标方法"大"到超过内联阈值（加分支/循环）；
- 或 hook 调用者，而不是被内联的方法。

### 9.11 CFI：调用 kallsyms 解析的函数指针会 panic（重大坑）

`CONFIG_CFI_CLANG=y` 的内核里，通过 kallsyms 拿到函数指针后做**间接调用**，
编译器会在调用前插入 `__cfi_slowpath` 校验"被调函数"的类型签名 hash。
hash 是按**函数类型**算的，所以：

- 用 `void *` / `size_t` 之类**完整类型**做 typedef 的（如
  `__flush_dcache_area`、`apply_to_page_range`）通常能过；
- 但像 `struct break_hook *` 这种在模块内是**不完整类型**的，
  clang 算出的 hash 与内核编译时不同 → **直接 panic**：

```
Kernel panic - not syncing: CFI failure
  (target: unregister_user_break_hook+0x0/0x1ec)
  cleanup_module+0xa4/0x768 [pte_main]
```

即便 typedef 的写法与内核原型逐字一致也没用（hash 由类型定义决定，
不是由名字决定）。

**解决办法**（本项目采用）：用 `__nocfi` 函数 + 内联汇编 `blr` 直接调用，
跳过 `__cfi_slowpath`。安全性由我们自己保证（这些函数原型固定、单参数）。

```c
static __nocfi void jh_call1(unsigned long fn, void *arg0)
{
    register unsigned long x0 asm("x0") = (unsigned long)arg0;
    register unsigned long x9 asm("x9") = fn;
    asm volatile("blr %1" : "+r"(x0) : "r"(x9) : "x1", ..., "memory");
}
```

注意 clobber list 里**不能写 x18** —— `CONFIG_SHADOW_CALL_STACK=y` 时它是
影子栈指针，属于平台保留寄存器，写进去会报 "reserved registers" 警告。

**这不是只影响一个函数的问题**。同一份代码里踩了三次：

| 调用点 | 现象 |
| --- | --- |
| `unregister_user_break_hook` | 空载 `rmmod` panic（`cleanup_module+0xa4`） |
| `access_process_vm` | 装 hook 时 panic（`jh_find_task_by_name+0x318`） |
| `jh_name_match` / `jh_task_names`（LTO 后变成间接调用） | 同上 |

三处的崩溃地址都是 `0x5bfd0` —— `__cfi_slowpath` 失败的特征值。

**排查方法**（很有用）：直接数模块里 `__cfi_slowpath` 的调用次数：

```bash
llvm-objdump -dr pte_main.ko | grep -c __cfi_slowpath
# 目标：0
```

非 0 就意味着还有间接调用没被 `__nocfi` 覆盖，随时可能 panic。
本项目最终把这个数字降到了 0。

### 9.12 RCU 临界区内绝对不能睡眠

按包名扫进程表时踩到，**第一次写就 panic 重启**：

```c
rcu_read_lock();
for_each_process(task) {
    jh_task_names(task, ...);   // ← 内部 get_task_mm / kmalloc /
                                //    access_process_vm 全可能睡眠
}
rcu_read_unlock();
```

崩溃栈：`do_mem_abort` → `el1_abort` → `jh_find_task_by_name`
（在 RCU 读锁里睡眠，调度器检测到并炸掉了）。

**正确做法**：两阶段。

```c
// 阶段 1（RCU 内）：只读字段，收集候选 pid，不碰 mm / 不分配 / 不读用户内存
rcu_read_lock();
for_each_process(task) { ... cand[ncand++] = task_tgid_nr(task); }
rcu_read_unlock();

// 阶段 2（锁外）：重新 find，读 cmdline、拿 mm —— 都可以睡眠
for (i = 0; i < ncand; i++) {
    t = jh_get_task(cand[i]);
    jh_task_names(t, ...);
}
```

另外：候选数组不能用内核栈（512 个 pid = 2KB，内核栈只有 16KB），
用 `kmalloc_array`。

### 9.13 按名字找进程不能"第一个命中就采用"

按包名匹配时，**父 shell 的 cmdline 里也包含包名**：

```
sh -c "CLASSPATH=... app_process / pte.javatest.JavaHookTest"
         ^^^^^^^^^^^^^^^^^^^^^^^^ 这里也出现了包名
app_process / pte.javatest.JavaHookTest   ← 真正的目标
```

第一个版本取"第一个命中"，结果选中了父 `sh`：它 **没有 mm**，
`get_task_mm` 返回 NULL，hook 装不上（`-ESRCH`），而且看不出原因。

**解决**：用 rank 打分，扫完整个候选集取最高分：

| rank | 判定 |
| --- | --- |
| 3 | `comm` 直接等于包名（zygote fork 的 App 主进程） |
| 2 | cmdline 的 `argv[0]`（basename）等于包名 |
| 1 | `argv[0]` 是 `app_process` 且后面某个参数等于包名 |
| 0 | 不匹配 |

另外在打分前先**跳过没有 mm 的进程**，避免选出装不上的目标。

### 9.14 候选集不能设小上限

Android 有 400+ 进程。最初为了省事把候选上限设成 32，结果 32 个名额
全被 `init` / `logd` / `servicemounted` 这类早期进程占满，目标 App
排在后面**根本不进候选**，报"没有匹配的进程"但 `ps` 明明看得到。

现为 512（覆盖正常设备），并用 uid 先收窄：给了 `uid=` 时通常只剩几个候选。

---

## 10. 与参考项目 `pteHook` 的差异

`pteHook` 是早期原型，Java 相关只做了"裸 `java-hook` 命令"（直接写 `entry_point` 字段）。

| 方面 | pteHook | 本项目 |
| --- | --- | --- |
| 控制通道 | `/proc/ptehook` + 硬编码命令 | `/proc/pte_java`，`hook` 支持关键字选项 |
| trampoline | 无：直接写字段指向 `replace` | 生成 ARM64 trampoline，两种形态 |
| 策略 | 只有"写字段" | 写字段 **+** PTE/UXN 劫持 |
| 参数 | 无 | `arg<N>=print/set/add/or/and` |
| 返回值 | 无 | 用 `blr` 形态 + 出口观察点，`retop=*` |
| 输出通道 | 无 | 无锁捕获环 + `dump` |
| backup | 无 | 策略 A 给独立 backup trampoline；策略 B 给 ghost 副本地址 |
| 布局探测 | 无 | 候选偏移 + "是否指向可执行页"判定，自动探测 |
| 时序安全 | 无（先分配后写，中间有窗口） | 策略 A 原子切换；策略 B 两阶段升级 |
| 编码验证 | 无 | `tools/compare.sh` 用真实汇编器逐字节核对 |

---

## 11. 代码地图

| 文件 | 职责 |
| --- | --- |
| `javahook.h` | 用户态 ABI（`JavaHookReq` / `JavaHookResult` / `JavaArgRule`）、接口 |
| `javahook.c` | 核心：布局探测、策略 A/B、槽位管理、BRK 观察点、捕获环 |
| `jh_tramp.h` / `jh_tramp.c` | **trampoline 生成器**（纯函数，可在用户态验证） |
| `hookManager.c` | `repl[]` 字段（精确地址替换语义）、`hook_install_sync()` 等同步接口 |
| `main.c` | 符号解析、`/proc/pte_java` 命令解析、双 `break_hook` 注册 |
| `ghost.c` | ghost 页分配；PTE 清除 `PTE_CONT` 位（孤立页不能带连续块标志） |
| `tools/pte_java.c` | 用户态控制工具（支持 pid / pkg / uid 定位） |
| `tools/pte_java_resolve.c` | 类名+方法名 → ArtMethod* 的解析助手（离线扫描，兜底用） |
| `test/java/ArtMethodHelper.java` | JNI 助手：在目标进程内把 Method 换成 ArtMethod*（推荐方式） |
| `tools/tramp_selftest.c` | trampoline 生成的用例输出 |
| `tools/compare.sh` | 用真实汇编器逐字节核对生成器输出 |
| `tools/simtest.c` | 规则语义自测（print/改值/bits32/trampoline 形态） |
| `test/java/JavaHookTest.java` | 验证用测试 App |

### 关键数据结构

```c
/* 一条参数规则 */
struct JavaArgRule {
    __u32 idx;      /* 0..7 → x0..x7 */
    __u32 op;       /* NONE / PRINT / SET / OR / AND / ADD */
    __u64 val;      /* 操作数 */
};
```

槽位里保存一份请求快照 `rec->req`，BRK 观察点直接读它应用规则——
异常上下文里不能回用户态取数据。

### `hookManager` 的改动要点

原本一个槽位只记 `addrs[]`（"观察哪些地址"）。为支持 Java hook 的"精确地址替换"，
新增了与 `addrs[]` 一一对应的 `repl[]`：

```c
unsigned long addrs[HOOK_ADDRS_PER_PAGE];  /* 观察的地址 */
unsigned long repl[HOOK_ADDRS_PER_PAGE];   /* 对应的替换目标（0=观察语义） */
```

`hook_handle_fault()` 命中逻辑：

```c
for (j = 0; j < rec->n_addrs; j++) {
    if (rec->addrs[j] != far_va)
        continue;
    if (rec->repl[j]) {
        uregs->pc = rec->repl[j];   /* 精确替换：直接跳走 */
        return 1;
    }
    /* 观察语义：继续走下面的 ghost 重定向 */
}
```

同步接口（都跑在进程上下文，内部用 `g_install_lock` 串行化）：

| 函数 | 用途 |
| --- | --- |
| `hook_install_sync(pid, addr, repl)` | 同步安装；`repl=0` 为观察语义 |
| `hook_install_sync_ex(pid, addr, repl, probe)` | 同上，可关闭 ghost 内 BRK 探针 |
| `hook_uninstall_sync(pid, addr)` | 同步卸载指定地址 |
| `hook_lookup_ghost_pc(pid, addr)` | 查该地址在 ghost 里的重编译副本地址 |
| `hook_is_watched(pid, addr)` | 该地址是否已登记 |
| `hook_page_armed(pid, addr)` | 该地址所在页是否已被 UXN 武装 |

`bp_work_fn`（prctl 异步路径）也拿 `g_install_lock`，所以两条路径不会互相踩坏槽位表。
fault 路径（kprobe 原子上下文）**绝不**拿这把锁，只靠 `armed` 标志同步。

---

## 12. 排错指引

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `access_process_vm not found` | 符号未解析 | 检查 `dmesg`；Java hook 不可用但 native 层仍可用 |
| `probe ArtMethod 0x.. failed` | 候选偏移都不匹配 | 用 `entry=0x..` 显式指定；先用 `read` 逐个偏移看值 |
| `entry 0x.. is not executable` | 偏移错，或读到的是 `data_` 字段 | 确认 `entry=` 正确 |
| `no ghost pc for 0x..` | 策略 B 的 UXN 槽位没装上 | 看 `dmesg` 里 `pte_hook:` 前缀日志 |
| `uxn arm failed -ENOSPC` | 槽位满 / 找不到空洞 | `pte_java list` 看占用；先 `unhook` 旧的 |
| hook 装上但行为没变 | 入口是 ART 共享跳板，或被内联 | 见 9.1 / 9.2 |
| `dump` 一直是 `(no new records)` | 没加 `print` 规则，或 `capture off` | 用 `arg<N>=print`；`pte_java cap on` |
| 改参数改了没效果 | 改错了下标（x0 是 receiver/ArtMethod*） | 先 `arg0=print` 看清 x0 是什么 |
| 返回值改了没效果 | 方法返回 `float/double`（在 v0） | 本模块只处理整型寄存器 |
| App 崩在启动 | trampoline 被半初始化时调用 | 已用两阶段升级规避；若仍出现查 `dmesg` |
| `dmesg` 大量 `redirect far=..` | 正常（策略 B 每次进页都触发） | 无需处理 |

调试开关：

```bash
adb shell su -c 'dmesg -w | grep pte_'    # 实时内核日志
pte_java list                              # 槽位状态 + 规则摘要 + capture 开关
pte_java cap clear                         # 清空捕获环
```

### 自测脚本（不需要设备）

```bash
tools/compare.sh    # 用真实汇编器逐字节核对 trampoline 生成器
tools/simtest       # 规则语义自测（先编译：gcc -I. tools/simtest.c jh_tramp.c）
```

---

## 13. 安全边界声明

本模块是**内核态代码**，加载后拥有完整内核权限。请仅在**自己的设备 / 测试环境**上使用：

- 它不提供、也不要求任何 root 方案或注入框架；
- 它不绕过 SELinux（加载 `.ko` 本身需要写 `init_module` 的权限，通常意味着已经是 root）；
- 它不修改磁盘上的任何文件，不建立持久化；
- 策略 B 会让被 hook 的页上的执行流经过内核异常路径，**有崩溃风险**；
- 修改参数/返回值会改变目标程序的语义，可能触发其自身的完整性检查；
- 修改他人 App 的行为涉及法律与授权问题，请自行判断。
