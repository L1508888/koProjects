因为pte hook 过程中会涉及到很多内核操作，在test 目录下进行函数的测试。


用户态指定进程和地址，使用重编译的方式进行hook。

最终产物只有一个 `.ko` 文件，加载后即可使用，**不依赖任何 root 方案或注入框架**。


## 目录结构

| 文件 | 说明 |
| --- | --- |
| `main.c` | 模块入口：符号解析、kprobe 挂载、`/proc/pte_java` 控制通道 |
| `hookManager.c/.h` | native 层 PTE hook 的槽位管理与取指重定向 |
| `dbi.c/.h` | ARM64 指令级重编译（PC 相对寻址修正） |
| `ghost.c/.h` | "幽灵页"：无 VMA 的物理页映射进目标进程 |
| `callback.c/.h` | 命中时的用户态寄存器 dump |
| `javahook.c/.h` | **Java 层（ART 方法级）hook**：策略、槽位、BRK 观察点、捕获环 |
| `jh_tramp.c/.h` | **trampoline 生成器**（纯函数，可用真实汇编器验证） |
| `docs/JavaHook.md` | **Java 层 hook 的完整设计与使用文档** |
| `tools/` | 用户态控制工具、编译脚本、两个自测脚本 |
| `test/` | 内核侧测试用例 + Java 侧验证程序 |


## 总体流程

用户态只传入 pid、目标函数地址，hook prctl 得到数据。


## main.c

用来获取符号地址，注册函数 hook。


## hookmanager.c

用来管理 hook record。


## pte_m

pte_m 用于修改 pte、恢复 pte。


## do_mem_abort hook

AI 判断 kprobe 无法 hook do_mem_abort 这个函数，通过查看内核源码，在 arch/arm64/mm/fault.c 文件中确实存在 `NOKPROBE_SYMBOL(do_mem_abort);` 但是我在测试过程中，发现是可以直接使用 kprobe 对这个函数进行 hook 的。


## 页粒度的问题

设置 pte 不可执行是以页为单位的，如果目标函数和其他函数在同一页内，且其他函数先于目标函数执行，hook 就会出现问题，无法得到真实的 hook 结果。

本项目的解决办法：**整页重编译**。目标页被 UXN 武装后，页内**任何**地址的取指异常都
重定向到 ghost 页里对应的重编译副本，所以同页其它函数照样正常执行，hook 不会因为
"别的函数先跑过一遍"而失效。详见 `hookManager.c` 的 `hook_handle_fault()`。


## Java 层 hook

在 native 层 hook 之上新增了 **ART 方法级 hook**，两条策略：

- **策略 A（默认）**：改写 `ArtMethod.entry_point_` → 指向 ghost 页里的 trampoline → 跳到原入口。
- **策略 B（`uxn`）**：不动 `ArtMethod`，把编译代码入口所在页 PTE 置 UXN，由取指异常
  重定向到 trampoline。

trampoline 有两种形态：只改参数时是尾跳（`br x17`，最快）；需要看/改返回值时
是调用形态（`stp x29,x30` + `blr x17` + 出口观察点 + `ret`），这样原方法返回后
我们还能介入。它不碰参数寄存器、不碰 `sp` 之外的栈布局，所以对 ART 的调用 ABI 透明。

**四个核心能力**：

| 能力 | 命令 |
| --- | --- |
| 输出参数 | `arg<N>=print` |
| 修改参数 | `arg<N>=set/add/or/and:<v>` |
| 输出返回值 | `retop=print` |
| 修改返回值 | `retop=set/add/or/and:<v>` |

参数/返回值的输出走**无锁捕获环**（观察点在 BRK 异常上下文，不能 printk 刷屏），
用户态用 `dump` 批量取走。

**目标定位**：不需要事先知道 pid。

```bash
# 知道 pid
tools/pte_java hook 12345 0x7a1b2c3d40 arg1=print

# 只知道包名（pid 填 "-"，内核按包名找进程）
tools/pte_java hook - 0x7a1b2c3d40 arg1=print pkg=com.example.app

# 只知道 uid
tools/pte_java hook - 0x7a1b2c3d40 arg1=print uid=10123
tools/pte_java dump
```

安装结果会回显实际解析到的 pid，后续 `unhook` 用它即可：

```
[OK] ret=0 pid=6536 ...
  target     = pkg=com.example.app uid=0 -> pid 6536
```

> `ArtMethod` 地址仍需提供：它是**目标进程内**的地址，无法凭类名/方法名
> 在内核侧可靠算出（ART 内部结构逐版本变化）。用 `tools/pte_java_resolve`，
> 或在目标进程内用 JNI 取（`test/java/ArtMethodHelper.java`：
> ART 里 `jmethodID` **就是** `ArtMethod*`，`FromReflectedMethod` 直接拿到）。
> 这是刻意的分工：内核只做"找进程 + 装 hook"，不解析 ART 结构。

不需要设备的自测：

```bash
tools/compare.sh    # 用真实汇编器逐字节核对 trampoline 生成器（8 种形态）
```

> 完整说明（原理、ART 布局探测、trampoline 形态、捕获环、时序安全、
> **真机踩过的 5 个坑**、排错）见 **[`docs/JavaHook.md`](docs/JavaHook.md)**。
