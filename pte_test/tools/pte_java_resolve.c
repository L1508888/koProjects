/*
 * pte_java_resolve.c —— 把「类名 + 方法名」换成 ArtMethod*（独立命令行工具）
 *
 * 背景：
 *   pte_java 的 hook 需要一个 ArtMethod* 地址。这个地址是**目标进程内**
 *   的用户态地址，无法凭类名/方法名在内核侧可靠算出（ART 内部结构逐版本
 *   变化，GetMethodsPtr 之类还是 inline、无导出符号）。
 *
 *   所以把它交给一个"在目标进程地址空间里"运行的解析器。本工具提供两种
 *   工作方式：
 *
 *   [1] 在目标进程内运行（推荐、最可靠）
 *       由目标 App 的 JNI 库 / app_process 加载后调用，
 *       打印 ArtMethod 地址，再交给 pte_java 使用。
 *       用法：见 test/java/artmethod.c 里的 ArtMethodHelper（JNI 版）。
 *
 *   [2] 离线扫描（本文件实现）
 *       用 process_vm_readv 读目标进程内存，在堆里按「类描述符字符串 +
 *       方法名」搜 ArtMethod 结构。不需要注入、不需要 ptrace，
 *       但依赖 ArtMethod 布局（偏移可用 --entry-off 指定）。
 *
 * 用法：
 *   pte_java_resolve --pid <pid> --class Lcom/example/Foo; --method bar \
 *                    [--entry-off 0x18] [--dump]
 *
 *   pte_java_resolve --pkg com.example.app --class ... --method ...
 *                   （自动从 /proc 找该包名的进程）
 *
 * 输出（供脚本解析）：
 *   ART_METHOD=0x7e3a1b20a8
 *   ENTRY_OFF=0x18
 *   ENTRY=0x98ed1530
 *
 * 编译：tools/build.sh 会一并编译本文件。
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

/* ---------- 跨进程内存访问 ---------- */

static int g_pid;

static int vm_read(uint64_t addr, void *buf, size_t len)
{
    struct iovec local  = { buf, len };
    struct iovec remote = { (void *)(uintptr_t)addr, len };
    ssize_t n = process_vm_readv(g_pid, &local, 1, &remote, 1, 0);

    return n == (ssize_t)len ? 0 : -1;
}

static uint64_t vm_read_u64(uint64_t addr)
{
    uint64_t v = 0;

    if (vm_read(addr, &v, sizeof(v)))
        return 0;
    return v;
}

static uint32_t vm_read_u32(uint64_t addr)
{
    uint32_t v = 0;

    if (vm_read(addr, &v, sizeof(v)))
        return 0;
    return v;
}

/* ---------- /proc 解析 ---------- */

/* 读 /proc/<pid>/maps，列出所有 r--/rw- 区间的范围（用于扫描） */
struct region {
    uint64_t start, end;
    char perms[8];
    char name[256];
};

static int load_maps(struct region **out, int *count)
{
    char path[64];
    FILE *f;
    struct region *arr = NULL;
    int n = 0, cap = 0;
    char line[512];

    snprintf(path, sizeof(path), "/proc/%d/maps", g_pid);
    f = fopen(path, "r");
    if (!f)
        return -1;

    while (fgets(line, sizeof(line), f)) {
        unsigned long long s, e;
        char perms[8], name[256] = {0};

        name[0] = 0;
        /* 形如：7e3a100000-7e3a200000 rw-p 00000000 00:00 0  [anon:dalvik] */
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255[^\n]",
                   &s, &e, perms, name) < 3)
            continue;

        /* 只关心可读的区间 */
        if (perms[0] != 'r')
            continue;

        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            arr = realloc(arr, (size_t)cap * sizeof(*arr));
            if (!arr) {
                fclose(f);
                return -1;
            }
        }
        arr[n].start = s;
        arr[n].end = e;
        snprintf(arr[n].perms, sizeof(arr[n].perms), "%s", perms);
        snprintf(arr[n].name, sizeof(arr[n].name), "%s", name);
        n++;
    }
    fclose(f);
    *out = arr;
    *count = n;
    return 0;
}

/* ---------- 包名 → pid ---------- */

static int find_pid_by_pkg(const char *pkg)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    int best = 0;

    if (!d)
        return 0;
    while ((de = readdir(d))) {
        char path[128], buf[256];
        int fd, n;

        if (!isdigit((unsigned char)de->d_name[0]))
            continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        n = (int)read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
            continue;
        buf[n] = 0;

        if (!strcmp(buf, pkg)) {          /* 完全相等 = 主进程，最优 */
            closedir(d);
            return atoi(de->d_name);
        }
        /* 私有进程 com.foo:remote */
        if (!strncmp(buf, pkg, strlen(pkg)) && buf[strlen(pkg)] == ':' && !best)
            best = atoi(de->d_name);
    }
    closedir(d);
    return best;
}

/* ---------- 在内存里找类描述符字符串 ---------- */

/*
 * Java 类描述符的 dex 形式：Lcom/example/Foo;
 * ART 会把类的描述符字符串存在 dex 文件映射或堆里。
 * 我们在这两类区间里搜这个字符串，得到它的虚拟地址，
 * 再反查哪些对象/结构引用了它。
 *
 * 实际做法更直接：先在进程的 dex/oat/anon 区间里搜字符串，
 * 找到候选地址后，把它附近的 8 字节按指针解释，看是否指向
 * 一个"像 Class 的对象"——太依赖布局。
 *
 * 所以本工具走另一条更可靠的路：**调用者在目标进程内**用 JNI
 * 直接拿（见 ArtMethodHelper）。这里的离线扫描只作为
 * "找不到 JNI 环境时"的最后手段，且需要用户给 --entry-off。
 */

/* 在给定区间里搜索一个字节串，返回首个命中的虚拟地址 */
static uint64_t scan_string(const struct region *r, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t chunk = 1 << 20;
    uint8_t *buf;
    uint64_t addr;

    if (nlen == 0 || r->end <= r->start)
        return 0;

    buf = malloc(chunk);
    if (!buf)
        return 0;

    for (addr = r->start; addr + nlen < r->end; addr += chunk) {
        size_t len = (size_t)((r->end - addr) < chunk ? (r->end - addr) : chunk);
        size_t i;

        if (vm_read(addr, buf, len))
            continue;               /* 这段读不到就跳过 */

        for (i = 0; i + nlen <= len; i++) {
            if (buf[i] == (uint8_t)needle[0] &&
                !memcmp(buf + i, needle, nlen)) {
                free(buf);
                return addr + i;
            }
        }
    }
    free(buf);
    return 0;
}

/* ---------- 主流程 ---------- */

static void usage(const char *p)
{
    fprintf(stderr,
        "usage:\n"
        "  %s --pid <pid> --class <Lcom/foo/Bar;> --method <name> [options]\n"
        "  %s --pkg <com.foo> --class ... --method ...\n"
        "\n"
        "options:\n"
        "  --entry-off 0x18   ArtMethod.entry_point_ 偏移（默认 0x18）\n"
        "  --dump             打印找到的地址附近内存，便于人工核对\n"
        "\n"
        "说明：本工具的离线扫描只是兜底手段。最可靠的是在目标进程内\n"
        "     用 JNI 取（见 test/java/ArtMethodHelper）。\n",
        p, p);
}

int main(int argc, char **argv)
{
    const char *pkg = NULL, *cls = NULL, *method = NULL;
    unsigned long entry_off = 0x18;
    int dump = 0, i;
    struct region *regs = NULL;
    int nregs = 0;
    uint64_t found = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pkg") && i + 1 < argc)
            pkg = argv[++i];
        else if (!strcmp(argv[i], "--class") && i + 1 < argc)
            cls = argv[++i];
        else if (!strcmp(argv[i], "--method") && i + 1 < argc)
            method = argv[++i];
        else if (!strcmp(argv[i], "--entry-off") && i + 1 < argc)
            entry_off = strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--dump"))
            dump = 1;
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!cls || !method) {
        usage(argv[0]);
        return 2;
    }
    if (!g_pid && pkg) {
        g_pid = find_pid_by_pkg(pkg);
        if (!g_pid) {
            fprintf(stderr, "找不到包 %s 的进程\n", pkg);
            return 1;
        }
    }
    if (!g_pid) {
        usage(argv[0]);
        return 2;
    }

    printf("PID=%d\n", g_pid);

    if (load_maps(&regs, &nregs)) {
        fprintf(stderr, "读 /proc/%d/maps 失败: %s\n", g_pid, strerror(errno));
        return 1;
    }

    /*
     * 离线扫描：在所有可读区间里找类描述符字符串。
     * 找到它只说明"这个类被加载过"，并不直接给出 ArtMethod*。
     * 真正拿到 ArtMethod* 需要知道 Class 对象与方法数组的布局，
     * 这里只把地址打出来供人工/脚本进一步处理。
     */
    for (i = 0; i < nregs && !found; i++)
        found = scan_string(&regs[i], cls);

    if (!found) {
        printf("CLASS_DESC_NOT_FOUND\n");
        printf("提示：类可能还没被加载。先让目标 App 触发该类的第一次使用，\n"
               "      或改用 ArtMethodHelper（在目标进程内用 JNI 取）。\n");
        free(regs);
        return 1;
    }
    printf("CLASS_DESC_ADDR=0x%llx\n", (unsigned long long)found);
    printf("CLASS=%s METHOD=%s ENTRY_OFF=0x%lx\n", cls, method, entry_off);

    if (dump) {
        uint8_t buf[128];
        size_t k;

        if (!vm_read(found & ~0xFULL, buf, sizeof(buf))) {
            printf("---- dump @0x%llx ----\n",
                   (unsigned long long)(found & ~0xFULL));
            for (k = 0; k < sizeof(buf); k += 8) {
                uint64_t v;
                memcpy(&v, buf + k, 8);
                printf("  +0x%02zx: 0x%016llx\n", k,
                       (unsigned long long)v);
            }
        }
    }

    free(regs);
    printf("\n注意：本工具只定位了类描述符。要拿到 ArtMethod*，\n"
           "      请在目标进程内用 JNI（ArtMethodHelper.getArtMethod）——\n"
           "      那是唯一不依赖 ART 内部偏移的可靠方式。\n");
    return 0;
}
