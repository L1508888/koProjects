#ifndef PTE_JAVAHOOK_H
#define PTE_JAVAHOOK_H

/*
 * javahook.h —— Java 层 hook（ART 方法级）
 *
 * 完整设计说明见 docs/JavaHook.md。这里只放接口与用户态 ABI。
 *
 * 内核模块不解析 dex、不依赖 libart 私有符号，只做三件事：
 *   1. 用 access_process_vm 读写目标进程里 ArtMethod 的字段；
 *   2. 在目标进程里"无 VMA"地生成一段 ARM64 trampoline（ghost 页）；
 *   3. 把方法入口指向 trampoline —— 可以改 ArtMethod.entry_point_，
 *      也可以用 PTE/UXN 直接劫持编译代码入口（不改 ART 数据结构）。
 *
 * trampoline 有两种形态（见 docs/JavaHook.md 第 4 节）：
 *   - 尾跳（br x17）      ：只需要在"入口"上做事（看/改参数）
 *   - 调用（blr x17）     ：需要在"返回后"做事（看/改返回值），
 *                           原方法正常返回后再进一次 BRK 才 ret
 *
 * 本文件同时被内核模块和用户态工具（tools/pte_java.c）include：
 * 上半部分的结构体/常量是 ABI，两边必须一致；函数声明只对内核有意义。
 */

/* ---------- 类型（内核 / 用户态两种编译环境） ---------- */

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#else
#include <stdint.h>
/*
 * 用户态：与 <asm-generic/int-ll64.h> 的底层类型保持一致（unsigned long long），
 * 否则与 <linux/types.h> 里的同名 typedef 冲突 —— 有些用户态文件会先
 * include <linux/types.h> 再 include 本头文件。
 */
#ifndef __u8
typedef unsigned char      __u8;
#endif
#ifndef __u16
typedef unsigned short     __u16;
#endif
#ifndef __u32
typedef unsigned int       __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif
#ifndef __s32
typedef int                __s32;
#endif
#endif

/* ======================================================================
 * 用户态 / 内核共享 ABI（改动须同步 docs/JavaHook.md）
 * ====================================================================== */

#define JAVA_HOOK_REQ_MAGIC   0x4A484F4BUL   /* 'JHOK'，用于版本校验 */
#define JAVA_HOOK_REQ_VERSION 2              /* v2：新增参数/返回值规则 */

/* flags 位定义 */
#define JH_FLAG_UXN           (1U << 0)  /* 用 PTE/UXN 劫持代码入口，不改 ArtMethod */
#define JH_FLAG_BRK           (1U << 1)  /* 入口 BRK 命中时额外 dmesg 打印 x0..x8 */
#define JH_FLAG_SKIP_ORIGINAL (1U << 2)  /* 不调用原方法，直接把 ret_val 作为返回值 */
#define JH_FLAG_NO_TRAMP      (1U << 3)  /* 不生成 trampoline，入口直接指向 replace */
#define JH_FLAG_VERBOSE       (1U << 4)  /* 额外打印 dbi / ghost 细节 */

/* 参数 / 返回值的处理动作 */
#define JH_OP_NONE   0   /* 不处理 */
#define JH_OP_PRINT  1   /* 输出到捕获环（用户态 dump 读取） */
#define JH_OP_SET    2   /* value = val */
#define JH_OP_OR     3   /* value |= val */
#define JH_OP_AND    4   /* value &= val */
#define JH_OP_ADD    5   /* value += val */

/* 一个参数（x0..x7）的处理规则 */
struct JavaArgRule {
    __u32 idx;      /* 0..7 → x0..x7 */
    __u32 op;       /* JH_OP_* */
    __u64 val;      /* SET/OR/AND/ADD 的操作数 */
};

#define JH_ARGS_MAX  8

/* 目标定位方式：pid 优先，没给 pid 时按 pkg / uid 解析 */
#define JH_TGT_PID  0
#define JH_TGT_PKG  1
#define JH_TGT_UID  2

/*
 * uid 的"是否指定"不能用 0 判断：root 进程（如 app_process 直接跑的
 * 场景）uid 就是 0，也应当是合法目标。所以用 flags 里的一位显式标记。
 */
#define JH_FLAG_HAS_UID  (1U << 5)

#define JH_PKG_MAX  128

/* 单个 Java hook 请求 */
struct JavaHookReq {
    __u32 magic;        /* JAVA_HOOK_REQ_MAGIC */
    __u32 version;      /* JAVA_HOOK_REQ_VERSION */
    __s32 pid;          /* 目标进程 tgid；0 = 按 pkg/uid 解析 */
    __u32 flags;        /* JH_FLAG_* */

    __u32 entry_off;    /* ArtMethod.entry_point_ 偏移；0 = 自动探测 */
    __u32 arg_cnt;      /* args[] 中有效项数，<= JH_ARGS_MAX */

    __u64 art_method;   /* ArtMethod*（目标进程内的用户态地址） */
    __u64 replace;      /* 替换函数地址（目标进程内，可为 0） */
    __u64 ret_val;      /* JH_FLAG_SKIP_ORIGINAL 时的返回值（x0） */
    __u64 seq;          /* 调用方序号，结果里回显 */

    /*
     * 目标定位（pid == 0 时生效）：
     *   target_uid 非 0 → 按 uid 匹配（即 App 的 userId，如 10123）
     *   pkg 非空         → 按进程名/cmdline 匹配包名
     * 两者都给时，要求同时满足（uid 命中 且 名字匹配）。
     */
    __u32 target_uid;
    __u32 tgt_resv;     /* 对齐用，填 0 */
    char  pkg[JH_PKG_MAX];  /* NUL 结尾的包名/进程名 */

    /*
     * 参数规则。只有 op != NONE 的项才会让 trampoline 带入口观察点。
     * 注意 x0 的语义：静态方法是 ArtMethod*，实例方法是 receiver。
     * 所以想改"第一个真实参数"，实例方法要改 idx=1。
     */
    struct JavaArgRule args[JH_ARGS_MAX];

    __u32 ret_op;       /* 返回值处理：JH_OP_* */
    __u32 ret_bits;     /* 32 或 64（仅影响输出格式）；0 = 按 64 处理 */
    __u64 ret_new;      /* ret_op 为 SET/OR/AND/ADD 时的操作数 */
};

/* 安装结果（内核 → 用户态） */
struct JavaHookResult {
    __u64 seq;
    __u64 trampoline;   /* 生成的 trampoline 地址（0 = 未生成） */
    __u64 orig_entry;   /* 原始入口（FIELD 策略 = ArtMethod 字段原值） */
    __u64 backup;       /* "调用原方法"应使用的地址 */
    __u64 enter_brk;    /* 入口观察点地址（0 = 无） */
    __u64 exit_brk;     /* 返回值观察点地址（0 = 无） */
    __u32 entry_off;    /* 实际使用的字段偏移 */
    __u32 flags;        /* 实际生效的 flags（含内核自动补齐的位） */
    __s32 ret;          /* 0 成功，负数为 -errno */
    __s32 pid;          /* 实际解析到的目标 pid（按 pkg/uid 定位时很有用） */
};

/* ======================================================================
 * 以下仅内核侧使用
 * ====================================================================== */
#ifdef __KERNEL__

/*
 * access_process_vm 未 EXPORT（GKI 5.10），由 main.c 经 kallsyms 解析后注入。
 * 它是本模块读写目标进程内存（ArtMethod 字段）的唯一通道：
 * 相比直接 kmap 物理页，它能正确处理 COW（不会写到共享页上）。
 * follow_pte 同样由 main.c 注入，用于判断入口是否可执行、取 PTE 模板。
 */
typedef int (*jh_access_process_vm_t)(struct task_struct *tsk, unsigned long addr,
                                      void *buf, int len, unsigned int gup_flags);
typedef int (*jh_follow_pte_t)(struct mm_struct *mm, unsigned long address,
                               pte_t **ptepp, spinlock_t **ptlp);

void javahook_init(jh_access_process_vm_t apv, jh_follow_pte_t follow);

/*
 * 安装 Java 方法 hook（进程上下文，可睡眠）。
 * 成功返回 0，结果写入 out。
 *
 * 失败返回 -errno：
 *   -ESRCH       进程 / ArtMethod 不存在
 *   -EINVAL      参数非法，或 ArtMethod 内容不像合法方法
 *   -ENOSPC      槽位已满，或找不到可用的 ghost 空洞
 *   -EOPNOTSUPP  该模式不支持（如 NO_TRAMP 但 replace 为 0）
 *   -EEXIST      该 (pid, art_method) 已经 hook 过
 */
int  java_hook_method(const struct JavaHookReq *req, struct JavaHookResult *out);

/*
 * 卸载（进程上下文）。entry_off 传 0 表示按 hook 记录里的偏移还原。
 * 幂等：不存在时返回 0。
 */
int  java_unhook_method(pid_t pid, unsigned long art_method,
                        unsigned int entry_off);

/* 只读 / 只写 ArtMethod 的入口字段（手工调试用） */
int  java_read_entry(pid_t pid, unsigned long art_method, unsigned int entry_off,
                     unsigned long *out);
int  java_write_entry(pid_t pid, unsigned long art_method, unsigned int entry_off,
                      unsigned long value);

/*
 * 探测 ArtMethod 布局。*entry_off 返回探测到的入口字段偏移。
 * 判定标准：候选偏移上的 8 字节落在目标进程某个可执行 VMA 内。
 */
int  java_probe_entry_off(pid_t pid, unsigned long art_method,
                          unsigned int *entry_off);

/* 列出当前全部 Java hook，返回写入 buf 的长度 */
int  javahook_list(char *buf, int size);

/* 目标进程退出后回收槽位（安装前会顺带调用） */
void javahook_reap(void);
/* 模块卸载时清理全部 */
void javahook_release_all(void);

/* ---------- 捕获环（参数 / 返回值输出） ---------- */

/*
 * 观察点跑在 BRK 异常上下文（关中断、不可睡眠），不能 printk 刷屏，
 * 也不该在那里申请内存。所以 PRINT 动作把寄存器现场写进一个
 * 预分配的定长环形缓冲区，用户态用 "dump" 命令批量取走。
 *
 * 写入是无锁的（atomic 递增游标 + 每项"写完才发布"），
 * 多个 CPU 同时命中也不会撕裂；极少情况下 reader 会跳过正在写的项。
 */
int  javahook_capture_enable(int on);   /* 1=开, 0=关，返回之前的开关状态 */
int  javahook_capture_clear(void);
/*
 * 从上次读到的位置开始，最多 dump max 条记录，追加到 buf。
 * 返回写入字节数。没有新记录时写入 "(no new records)"。
 */
int  javahook_capture_dump(char *buf, int size, int max);
int  javahook_capture_is_on(void);

/*
 * 用户态 BRK 回调（main.c 的 break_hook 里，在 hookManager 之后调用）。
 * 处理 trampoline 里的入口/返回值观察点。
 * 返回 1：已接管；返回 0：与本模块无关
 */
struct pt_regs;
int  javahook_handle_brk(struct pt_regs *uregs, unsigned int esr);

/* 捕获环的分配 / 释放（模块 init / exit 调用） */
int  javahook_capture_init(void);
void javahook_capture_exit(void);

#endif /* __KERNEL__ */

#endif /* PTE_JAVAHOOK_H */
