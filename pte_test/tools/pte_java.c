/*
 * pte_java.c —— /proc/pte_java 控制工具（Android / arm64 用户态）
 *
 * 用法：
 *   pte_java list
 *   pte_java probe   <pid|-> <art_method>
 *   pte_java read    <pid> <art_method> [off]
 *   pte_java write   <pid> <art_method> <off> <value>
 *   pte_java hook    <pid|-> <art_method> [选项...]
 *   pte_java unhook  <pid> <art_method>
 *   pte_java dump    [max]              取走捕获环里的参数/返回值记录
 *   pte_java cap     on|off|clear
 *   pte_java watch   <pid|-> <art_method> [选项...]
 *                                       循环 dump（实时看调用）
 *
 * 第一个位置参数是 pid。**不知道 pid 时填 "-"**，改用 pkg= / uid= 定位：
 *
 *   pte_java hook - 0x7a1b2c3d40 arg1=print pkg=com.example.app
 *   pte_java hook - 0x7a1b2c3d40 arg1=print uid=10123
 *   pte_java hook - 0x7a1b2c3d40 arg1=print pkg=com.example.app uid=10123
 *
 * 内核会遍历进程表按包名/uid 找到目标（pkg 匹配进程名或 cmdline，
 * 支持 com.foo:remote 这类私有进程；同时给 pkg 和 uid 时要求都满足）。
 * 安装结果里会回显"实际解析到的 pid"，后续 unhook 用它即可。
 *
 * 关于 art_method 地址：它是**目标进程内**的用户态地址，无法凭类名/
 * 方法名在内核侧可靠算出。用 tools/pte_java_resolve（或在目标进程内
 * 用 JNI，见 test/java/ArtMethodHelper）先拿到它。
 *
 * hook / watch 的选项：
 *
 *   —— 参数 ——
 *   arg<N>=print        输出第 N 个参数（N = x0..x7）
 *   arg<N>=set:<v>      把第 N 个参数设为 v
 *   arg<N>=add:<v>      第 N 个参数 += v
 *   arg<N>=or:<v>       第 N 个参数 |= v
 *   arg<N>=and:<v>      第 N 个参数 &= v
 *
 *   —— 返回值 ——
 *   retop=print         输出返回值
 *   retop=set:<v>       把返回值设为 v
 *   retop=add:<v>       返回值 += v
 *   retop=or:<v>        返回值 |= v
 *   retop=and:<v>       返回值 &= v
 *   bits32 / bits64     返回值按 32 位还是 64 位处理（默认 64）
 *
 *   —— 目标定位 ——
 *   pkg=com.example.app  按包名找进程（不需要 pid）
 *   uid=10123            按 App 的 userId 找进程
 *   （pid 位置填 "-" 时生效；两者都给则要求同时满足）
 *
 *   —— 策略 ——
 *   entry=0x20          显式指定 ArtMethod 入口字段偏移（默认自动探测）
 *   replace=0x..        替换函数地址（目标进程内）
 *   ret=0x..            skip 时的返回值
 *   uxn                 PTE/UXN 策略（不动 ArtMethod）
 *   brk                 额外用 dmesg 打印入口参数（调试用）
 *   skip                不调用原方法
 *   raw                 不做 trampoline，入口直接指向 replace
 *
 * 关于 x0 的语义（实测，很容易踩）：
 *   Pixel 6 / Android 13 上观察到的布局是：
 *     x0 = ArtMethod*
 *     x1 = receiver(this)  ← 实例方法的 this
 *     x2 = 第一个形参，x3 = 第二个，依此类推
 *   所以"改第一个形参"要写 arg2=...，而不是 arg0= 或 arg1=。
 *   不同调用路径/版本可能不同，**先 arg0=print 看一次最稳**。
 *
 * 另一个实测结论：被 ART 内联的方法 hook 不到（调用点不经过
 * entry_point_）。验证时用反射调用（Method.invoke）最可靠。
 *
 * 编译：tools/build.sh
 *
 * 约定：设备上需要能读写 /proc/pte_java（默认 0600）。
 * 本工具不做任何权限提升。
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROC_PATH "/proc/pte_java"
#define CMD_MAX   512

/* 把一条命令写进 /proc/pte_java，然后把结果读出来打印 */
static int run_cmd(const char *cmd)
{
    char buf[16384];
    int fd;
    ssize_t n;

    fd = open(PROC_PATH, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s failed: %s\n", PROC_PATH, strerror(errno));
        return 1;
    }
    if (write(fd, cmd, strlen(cmd)) != (ssize_t)strlen(cmd)) {
        fprintf(stderr, "write failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);

    fd = open(PROC_PATH, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "reopen %s failed: %s\n", PROC_PATH, strerror(errno));
        return 1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) {
        fprintf(stderr, "read failed: %s\n", strerror(errno));
        return 1;
    }
    buf[n] = 0;
    fputs(buf, stdout);
    return 0;
}

/*
 * 把 argv[from..] 拼成命令行尾部。
 *
 * 注意用调用方传入的 off 判断是否需要前导空格：这里 off 是**本函数
 * 写出去多少字节**的计数，不能拿它当"是否是第一段"的判据 —— 那样
 * 第一个参数会丢掉空格，与前一段粘在一起（实测把
 * "0x724a57b088 0x20" 拼成 "0x724a57b0880x20"，解析成 0x724a57b0880）。
 */
static int build_cmd(char *cmd, int cap, char **argv, int from, int argc)
{
    int i, off = 0;

    for (i = from; i < argc; i++) {
        int w = snprintf(cmd + off, (size_t)(cap - off), " %s", argv[i]);
        if (w < 0 || off + w >= cap)
            return -1;
        off += w;
    }
    return off;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage:\n"
        "  %s list\n"
        "  %s probe  <pid|-> <art_method>\n"
        "  %s read   <pid> <art_method> [off]\n"
        "  %s write  <pid> <art_method> <off> <value>\n"
        "  %s hook   <pid|-> <art_method> [选项...]\n"
        "  %s unhook <pid> <art_method>\n"
        "  %s dump   [max]\n"
        "  %s cap    on|off|clear\n"
        "  %s watch  <pid|-> <art_method> [选项...]\n"
        "\n"
        "第一个参数是 pid；不知道 pid 时填 \"-\"，改用 pkg= / uid= 定位。\n"
        "\n"
        "hook 选项（完整说明见文件头注释）：\n"
        "  pkg=<包名>   按包名找进程（不需要 pid）\n"
        "  uid=<userId> 按 App 的 userId 找进程\n"
        "  arg<N>=print|set:<v>|add:<v>|or:<v>|and:<v>\n"
        "  retop=print|set:<v>|add:<v>|or:<v>|and:<v>\n"
        "  bits32 | bits64 | entry=0x20 | replace=0x.. | ret=0x..\n"
        "  uxn | brk | skip | raw\n"
        "\n"
        "例：\n"
        "  %s hook - 0x7a1b2c3d40 arg1=print pkg=com.example.app\n"
        "  %s hook - 0x7a1b2c3d40 arg2=set:0x64 retop=print uid=10123\n"
        "  %s watch - 0x7a1b2c3d40 arg1=print pkg=com.example.app\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog, prog);
}

int main(int argc, char **argv)
{
    char cmd[CMD_MAX];
    int off;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    if (!strcmp(argv[1], "list"))
        return run_cmd("list");

    if (!strcmp(argv[1], "cap")) {
        off = snprintf(cmd, sizeof(cmd), "cap %s",
                       argc > 2 ? argv[2] : "");
        return run_cmd(cmd);
    }

    if (!strcmp(argv[1], "dump")) {
        off = snprintf(cmd, sizeof(cmd), "dump %s",
                       argc > 2 ? argv[2] : "");
        return run_cmd(cmd);
    }

    /* ---- watch：装 hook 然后循环 dump ---- */
    if (!strcmp(argv[1], "watch")) {
        if (argc < 4) {
            usage(argv[0]);
            return 2;
        }
        off = snprintf(cmd, sizeof(cmd), "hook %s %s", argv[2], argv[3]);
        if (build_cmd(cmd + off, sizeof(cmd) - (size_t)off, argv, 4, argc) < 0)
            return 2;
        if (run_cmd(cmd))
            return 1;

        printf("---- watching, Ctrl-C to stop ----\n");
        fflush(stdout);
        for (;;) {
            if (run_cmd("dump 64"))
                break;
            fflush(stdout);
            usleep(300 * 1000);
        }
        return 0;
    }

    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }

    /* 前三个位置参数固定：命令 pid art_method */
    off = snprintf(cmd, sizeof(cmd), "%s %s %s", argv[1], argv[2], argv[3]);
    if (build_cmd(cmd + off, sizeof(cmd) - (size_t)off, argv, 4, argc) < 0)
        return 2;

    return run_cmd(cmd);
}
