# 测试用例

这里放内核侧与 Java 侧的验证代码。

## 目录

| 文件 | 说明 |
| --- | --- |
| `mem_test.c` | 主动对 `do_mem_abort` 函数进行 hook，查看进入这个函数时候的参数。主要为了后续的 pte 学习。 |
| `hook_test.c` | 对 `kretprobe`、`register_kretprobe` 的简单使用。 |
| `pte_m.c` | 和用户态程序进行配合，主动设置进程中某个地址所在页的 pte 为不可执行，然后在 `do_mem_abort` 中再将 pte 设置为可执行。 |
| `pte_tmp.c` | PTE 读写 / 临时改属性的一些实验代码。 |
| `java/JavaHookTest.java` | **Java 层 hook 验证程序**：打印各方法的 `ArtMethod` 地址并循环调用，配合 `/proc/pte_java` 观察 hook 是否生效。 |


## Java 层 hook 的手工验证流程

### 1. 编译并加载内核模块

```bash
make modules                                   # 产出 pte_main.ko
tools/build.sh                                 # 产出 tools/pte_java（arm64 静态）

adb push pte_main.ko tools/pte_java /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/pte_main.ko'
adb shell su -c 'dmesg | tail -20'
```

预期日志：

```
pte_hook: access_process_vm=...
pte_hook: get symbol success
pte_hook: user break hook success
pte_hook: /proc/pte_java ready
pte_hook: module load success
```

### 2. 跑测试 App，拿到 ArtMethod 地址

```bash
# 编译（需要 Android SDK 的 d8）
javac -source 8 -target 8 \
      -bootclasspath $ANDROID_HOME/platforms/android-33/android.jar \
      test/java/JavaHookTest.java -d /tmp/jout
d8 --lib $ANDROID_HOME/platforms/android-33/android.jar \
   /tmp/jout/pte/javatest/*.class --output /tmp/jout

adb push /tmp/jout/classes.dex /data/local/tmp/javatest.dex
adb shell 'CLASSPATH=/data/local/tmp/javatest.dex app_process / pte.javatest.JavaHookTest'
```

输出：

```
pid = 12345
add   ArtMethod = 0x7a1b2c3d40
greet ArtMethod = 0x7a1b2c3d50
tick  ArtMethod = 0x7a1b2c3d60
---- 用上面三个地址去 /proc/pte_java 装 hook ----
iter 0 add(3,4)=7 greet=hello, world tick=...
```

### 3. 装 hook

另开一个 shell：

```bash
# 先探测入口字段偏移
adb shell su -c '/data/local/tmp/pte_java probe 12345 0x7a1b2c3d40'

# 输出参数 + 输出返回值
adb shell su -c '/data/local/tmp/pte_java hook 12345 0x7a1b2c3d40 arg1=print arg2=print retop=print'

# 取走捕获到的记录
adb shell su -c '/data/local/tmp/pte_java dump'
```

预期输出：

```
#1 ARG slot=0 pid=12345 method=0x7a1b2c3d40 x0=7a1b2c3d40 x1=3 x2=4 x3=0 ...
#2 RET slot=0 pid=12345 method=0x7a1b2c3d40 x0=7 x1=0 x2=0 ...
#3 ARG slot=0 pid=12345 method=0x7a1b2c3d40 x0=7a1b2c3d40 x1=3 x2=4 x3=0 ...
...
```

`x1=3 x2=4` 就是 `add(3, 4)` 的两个参数，`RET ... x0=7` 是返回值。
**观察模式下 `iter` 输出里的 `add(3,4)=7` 保持不变。**

> 也可以加 `brk` 让 dmesg 直接打一遍（临时看一次用，高频方法别用）：
> `hook ... arg1=print brk`

### 4. 修改参数

```bash
adb shell su -c '/data/local/tmp/pte_java unhook 12345 0x7a1b2c3d40'
# 把第一个真实参数（x1）固定成 100
adb shell su -c '/data/local/tmp/pte_java hook 12345 0x7a1b2c3d40 arg1=set:0x64'
# 此时 iter 输出应变成 add(3,4)=104（100 + 4）
```

### 5. 修改返回值

```bash
adb shell su -c '/data/local/tmp/pte_java unhook 12345 0x7a1b2c3d40'
# 原方法照跑，返回值 +1
adb shell su -c '/data/local/tmp/pte_java hook 12345 0x7a1b2c3d40 retop=add:0x1 bits32'
# 此时 iter 输出应变成 add(3,4)=8
```

直接接管、不调用原方法：

```bash
adb shell su -c '/data/local/tmp/pte_java unhook 12345 0x7a1b2c3d40'
adb shell su -c '/data/local/tmp/pte_java hook 12345 0x7a1b2c3d40 skip ret=0x64'
# 此时 iter 输出应变成 add(3,4)=100
```

### 6. 一条命令边装边看

```bash
adb shell su -c '/data/local/tmp/pte_java watch 12345 0x7a1b2c3d40 \
                  arg1=print arg2=add:0x10 retop=print'
# 每 300ms 自动 dump 一次，Ctrl-C 停止
```

### 7. 换成 PTE 策略（不碰 ArtMethod）

```bash
adb shell su -c '/data/local/tmp/pte_java unhook 12345 0x7a1b2c3d40'
adb shell su -c '/data/local/tmp/pte_java hook 12345 0x7a1b2c3d40 uxn arg1=print retop=print'
```

策略 B 下参数/返回值规则同样有效（trampoline 里有同样的观察点）。

### 8. 卸载

```bash
adb shell su -c '/data/local/tmp/pte_java unhook 12345 0x7a1b2c3d40'
adb shell su -c '/data/local/tmp/pte_java list'
adb shell su -c 'rmmod pte_main'
```

## 不需要设备的自测

```bash
tools/compare.sh    # 用真实汇编器逐字节核对 trampoline 生成器（8 种形态）
gcc -I. -o /tmp/simtest tools/simtest.c jh_tramp.c && /tmp/simtest
                    # 规则语义自测：print/改值/bits32/trampoline 形态
```


## 常见失败

| 现象 | 原因 |
| --- | --- |
| `probe ... failed` | ArtMethod 布局不在候选偏移里 → 用 `entry=0x..` 显式指定 |
| hook 成功但行为不变 | 入口是 ART 共享跳板（`dmesg` 会打印 `r-x 文件映射`）→ 先把方法调"热"变 JIT（见 `docs/JavaHook.md` 9.1） |
| App 崩溃 | 查 `dmesg` 里 `pte_java:` / `pte_hook:` 的报错；策略 B 需确认 `do_mem_abort` kprobe 注册成功 |
