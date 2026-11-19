/*
 * main.c —— 模块入口与 kprobe 挂载层
 *
 * 职责：
 *   1. 解析内核符号（先 kprobe 拿 kallsyms_lookup_name，再查其余符号），
 *      分别注入 hookManager / ghost / javahook 三个模块；
 *   2. hook __arm64_sys_prctl：接收用户态下发的安装 / 卸载命令；
 *   3. hook do_mem_abort：目标页 UXN 取指异常时交给 hookManager 重定向；
 *   4. 注册用户态 BRK 钩子：ghost 探针与 Java trampoline 观察点共用；
 *   5. 导出 /proc/pte_java：Java 层 hook 的同步控制通道。
 *
 * 用户态命令约定（native 层，异步）：
 *   安装：        prctl(0xDEADBEEF, &HookTask, 0, 0, 0)
 *   卸载指定函数：prctl(0xDEADBEF0, &HookTask, 0, 0, 0)
 *   卸载全部：    prctl(0xDEADBEF0, 0, 0, 0, 0)
 *
 * 用户态命令约定（Java 层，同步，见 docs/JavaHook.md）：
 *   echo "hook <JavaHookReq 的十六进制>" > /proc/pte_java
 *   cat /proc/pte_java     # 读回 JavaHookResult
 *
 * kprobe 前置处理运行在 BRK 异常上下文（关中断、禁睡眠）：
 * 读用户态结构体只能用 copy_from_user_nofault（绝不缺页睡眠），
 * 安装/卸载也只登记请求并入队，真正的活在 kworker 进程上下文干。
 * 因此 native 层的安装/卸载是【异步】的，结果看 dmesg。
 * Java 层走 /proc，天然在进程上下文，所以是【同步】的。
 *
 * 注：内核源码里 do_mem_abort 标了 NOKPROBE_SYMBOL，
 * 但实测在本内核（android13-5.10）上 kprobe 可以正常注册。
 */

#include <asm/debug-monitors.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "hookManager.h"
#include "javahook.h"
#include "jh_tramp.h"

#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

/* 用户态 prctl 魔数 */
#define MAGIC_PRCTL_INSTALL 0xDEADBEEF
#define MAGIC_PRCTL_UNHOOK 0xDEADBEF0

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/*
 * ghost 模块的符号表。
 * 必须是 static 存储：init_ghost 保存的是这个结构体的指针，
 * 如果用栈变量，函数返回后指针立刻悬垂。
 */
static GhostSymbolData g_ghost_syms;

/*
 * D-cache 写回符号在不同内核里签名不一致：
 *   - android13-5.10：__flush_dcache_area(void *addr, size_t len)
 *   - 部分改名内核  ：caches_clean_inval_pou / dcache_clean_inval_poc
 *                     (unsigned long start, unsigned long end)
 * 用一个适配 shim 统一成 ghost 侧期望的 (addr, len) 语义再注入。
 */
typedef void (*flush_dcache_area_t)(void *addr, size_t len);
typedef void (*dcache_clean_pou_t)(unsigned long start, unsigned long end);

static flush_dcache_area_t g_flush_dcache_area; /* 5.10 (addr,len) 变体 */
static dcache_clean_pou_t g_dcache_clean_pou;   /* 改名后的 (start,end) 变体 */

static copy_from_user_nofault_t copy_from_fn;

/* 用户态 BRK 钩子注册/注销（未 EXPORT，kallsyms 解析注入）。
 *
 * ⚠️ CFI 陷阱（实测踩过，会直接 panic）：
 *   CONFIG_CFI_CLANG=y 的内核里，通过 kallsyms 解析的函数指针做间接调用时，
 *   编译器会在调用前插入 __cfi_slowpath 检查"被调用函数"的类型签名 hash。
 *   这里的 struct break_hook 在模块内是**不完整类型**，clang 算出的 hash
 *   与内核编译该函数时不同 → CFI failure → panic：
 *       Kernel panic - not syncing: CFI failure
 *       (target: unregister_user_break_hook+0x0/0x1ec)
 *   即便 typedef 的写法与内核原型逐字一致也无济于事（hash 是按类型定义算的）。
 *
 * 解决：用 __nocfi 函数 + 内联汇编做间接调用，跳过 __cfi_slowpath。
 * 安全性由我们自己保证：这些函数的原型是固定的、单参数指针，不会变。 */
static unsigned long g_register_brk_addr;
static unsigned long g_unregister_brk_addr;

/* 不经过 CFI 检查的间接调用：参数在 x0，目标地址在 x9。
 * 注意 clobber list 里不能写 x18 —— 它是平台保留寄存器
 * （CONFIG_SHADOW_CALL_STACK=y 时是影子栈指针），编译器会报
 * "reserved registers" 警告。x19..x28 是被调用者保存寄存器，
 * 由被调函数自己负责保护，无需列出。 */
static __nocfi void jh_call1(unsigned long fn, void *arg0) {
  register unsigned long x0 asm("x0") = (unsigned long)arg0;
  register unsigned long x9 asm("x9") = fn;

  asm volatile("blr %1"
               : "+r"(x0)
               : "r"(x9)
               : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x10", "x11",
                 "x12", "x13", "x14", "x15", "x16", "x17", "x30", "memory");
  (void)x0;
}

static __nocfi void pte_register_brk_hook(struct break_hook *hook) {
  if (g_register_brk_addr)
    jh_call1(g_register_brk_addr, hook);
}

static __nocfi void pte_unregister_brk_hook(struct break_hook *hook) {
  if (g_unregister_brk_addr)
    jh_call1(g_unregister_brk_addr, hook);
}

/*
 * 5 参数版本：给 access_process_vm 这类多参数函数用。
 *
 * 为什么也要绕 CFI：实测同一份代码里，调用 kallsyms 解析出的
 * access_process_vm 会在 jh_find_task_by_name 的 blr 处 panic
 * （Unable to handle kernel paging request at 0x5bfd0，正是
 * __cfi_slowpath 失败的特征）。typedef 里 unsigned int vs gfp_t、
 * 指针 const 与否都会让类型 hash 不同。
 *
 * 参数多于 5 个的函数不建议走这条路（要手工摆 6、7 号参数），
 * 本项目用到的都以 5 个为上限。
 */
static __nocfi long jh_call5(unsigned long fn, unsigned long a0,
                             unsigned long a1, unsigned long a2,
                             unsigned long a3, unsigned long a4) {
  register unsigned long x0 asm("x0") = a0;
  register unsigned long x1 asm("x1") = a1;
  register unsigned long x2 asm("x2") = a2;
  register unsigned long x3 asm("x3") = a3;
  register unsigned long x4 asm("x4") = a4;
  register unsigned long x9 asm("x9") = fn;

  asm volatile("blr %5"
               : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
               : "r"(x9)
               : "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14",
                 "x15", "x16", "x17", "x30", "memory");
  return (long)x0;
}

/* access_process_vm：未 EXPORT，Java 层读写目标进程内存走这里。
 *
 * 存成裸地址（unsigned long），调用时经 jh_call5 绕 CFI —— 见上面
 * jh_call5 的说明：直接用函数指针调会 panic。 */
static unsigned long g_apv_addr;

/*
 * 给 javahook 用的 __nocfi 包装。
 * javahook.c 自己也是 __nocfi 的，但它的函数指针类型声明会再触发一次
 * CFI 检查，所以这里统一把"实际调用"收口到本文件。
 */
static __nocfi int pte_access_process_vm(struct task_struct *tsk,
                                         unsigned long addr, void *buf, int len,
                                         unsigned int gup_flags) {
  if (!g_apv_addr)
    return -ENODEV;
  return (int)jh_call5(g_apv_addr, (unsigned long)tsk, addr, (unsigned long)buf,
                       (unsigned long)len, (unsigned long)gup_flags);
}

static __nocfi void flush_dcache_shim(void *addr, size_t len) {
  if (g_flush_dcache_area)
    g_flush_dcache_area(addr, len);
  else if (g_dcache_clean_pou)
    g_dcache_clean_pou((unsigned long)addr, (unsigned long)addr + len);
}

static unsigned long lookup_via_kprobe(const char *name) {
  struct kprobe k;
  unsigned long addr = 0;

  memset(&k, 0, sizeof(k));
  k.symbol_name = name;
  if (register_kprobe(&k) == 0) {
    addr = (unsigned long)k.addr;
    unregister_kprobe(&k);
  }
  return addr;
}

static __nocfi int resolve_kernel_symbols(void) {
  kallsyms_lookup_name_t kln;
  unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");
  follow_pte_t follow_pte_fn;

  if (!addr) {
    pr_err("pte_hook: can't get kallsyms_lookup_name\n");
    return -ENOENT;
  }
  kln = (kallsyms_lookup_name_t)addr;

  /* hookManager 需要 follow_pte 和 copy_from_user_nofault */
  follow_pte_fn = (follow_pte_t)kln("follow_pte");
  copy_from_fn = (copy_from_user_nofault_t)kln("copy_from_user_nofault");

  /*
   * ghost 模块需要的符号。
   * 注意：申请物理页的符号名是 __get_free_pages，
   * "get_free_pages" 这个名字在内核里不存在，查F了会返回 0。
   */
  g_ghost_syms.get_free_pages =
      (typeof(g_ghost_syms.get_free_pages))kln("__get_free_pages");
  g_ghost_syms.free_pages = (typeof(g_ghost_syms.free_pages))kln("free_pages");
  g_ghost_syms.find_vma = (typeof(g_ghost_syms.find_vma))kln("find_vma");
  g_ghost_syms.apply_to_page_range =
      (typeof(g_ghost_syms.apply_to_page_range))kln("apply_to_page_range");
  g_ghost_syms.on_each_cpu =
      (typeof(g_ghost_syms.on_each_cpu))kln("on_each_cpu");

  /*
   * flush_dcache_area：优先 5.10 的 __flush_dcache_area(addr,len)，
   * 找不到再退到改名内核的 (start,end) 变体，最后用 shim 注入。
   */
  g_flush_dcache_area = (flush_dcache_area_t)kln("__flush_dcache_area");
  if (!g_flush_dcache_area) {
    g_dcache_clean_pou = (dcache_clean_pou_t)kln("caches_clean_inval_pou");
    if (!g_dcache_clean_pou)
      g_dcache_clean_pou = (dcache_clean_pou_t)kln("dcache_clean_inval_poc");
  }
  g_ghost_syms.flush_dcache_area = flush_dcache_shim;

  /* 用户态 BRK 钩子（ghost 探针用）。可选：解析不到就关闭 BRK 探针功能 */
  g_register_brk_addr = kln("register_user_break_hook");
  g_unregister_brk_addr = kln("unregister_user_break_hook");
  pr_info("pte_hook: register_user_break_hook=%px unregister=%px\n",
          (void *)g_register_brk_addr, (void *)g_unregister_brk_addr);

  /* Java 层读写目标进程内存（ArtMethod 字段、trampoline 校验） */
  g_apv_addr = kln("access_process_vm");
  pr_info("pte_hook: access_process_vm=%px\n", (void *)g_apv_addr);

  /* 每个符号都打印出来，方便排查解析失败（显示 0 的就是没找到） */
  pr_info("pte_hook: follow_pte=%px __get_free_pages=%px free_pages=%px\n",
          (void *)follow_pte_fn, (void *)g_ghost_syms.get_free_pages,
          (void *)g_ghost_syms.free_pages);
  pr_info("pte_hook: find_vma=%px apply_to_page_range=%px on_each_cpu=%px\n",
          (void *)g_ghost_syms.find_vma,
          (void *)g_ghost_syms.apply_to_page_range,
          (void *)g_ghost_syms.on_each_cpu);
  pr_info("pte_hook: flush_dcache=%px(addr,len) / %px(start,end) cfun=%px\n",
          (void *)g_flush_dcache_area, (void *)g_dcache_clean_pou,
          (void *)copy_from_fn);

  if (!follow_pte_fn || !g_ghost_syms.get_free_pages ||
      !g_ghost_syms.free_pages || !g_ghost_syms.find_vma ||
      !g_ghost_syms.apply_to_page_range || !g_ghost_syms.on_each_cpu ||
      (!g_flush_dcache_area && !g_dcache_clean_pou) || !copy_from_fn) {
    pr_err("pte_hook: get symbol fail \n");
    return -ENOENT;
  }

  hook_manager_init(follow_pte_fn, copy_from_fn);
  init_ghost(&g_ghost_syms);
  javahook_init(pte_access_process_vm, follow_pte_fn);

  pr_info("pte_hook: get symbol success \n");
  return 0;
}

/* ---------- prctl 钩子：用户态命令通道 ---------- */

static struct kprobe kp;

static __nocfi int handler_pre(struct kprobe *p, struct pt_regs *kregs) {
  struct pt_regs *uregs;
  HookTask t;
  unsigned long arg2;
  unsigned int option;

  /* __arm64_sys_prctl(const struct pt_regs *)：x0 是系统调用寄存器帧 */
  uregs = (struct pt_regs *)kregs->regs[0];
  if (!uregs)
    return 0;

  option = (int)uregs->regs[0];

  /*
   * 注意这里是原子上下文，只能做"寄存器读取 + 登记请求"，
   * 真正的安装/卸载由工作队列在进程上下文完成。
   */
  if (option == MAGIC_PRCTL_INSTALL) {
    pr_info("pte_hook: option %d \n", option);

    /* x1 = 用户态 HookTask 结构体指针 */
    arg2 = (unsigned long)uregs->regs[1];
    if (!arg2)
      return 0;
    /* 必须走 nofault：原子上下文里普通 copy_from_user 可能缺页睡眠，
     * nofault 失败只是返回错误（符号未 EXPORT，经 kallsyms 解析注入） */
    if (!copy_from_fn || copy_from_fn(&t, (void __user *)arg2, sizeof(t))) {
      pr_err("pte_hook: read user sapce data fail \n");
      return 0;
    }
    pr_info("pte_hook: read user sapce data success \n");
    install_hook(&t); /* 仅入队，异步执行 */
  } else if (option == MAGIC_PRCTL_UNHOOK) {
    /* x1 = 可选的 HookTask 指针：给了就卸指定 (pid, address)，没给就全部卸载 */
    arg2 = (unsigned long)uregs->regs[1];
    if (arg2) {
      if (!copy_from_fn || copy_from_fn(&t, (void __user *)arg2, sizeof(t))) {
        pr_err("pte_hook: read user sapce data fail \n");
        return 0;
      }
      hook_request_uninstall(&t); /* 仅入队，异步执行 */
    } else {
      hook_request_uninstall(NULL); /* 全部卸载 */
    }
  }
  return 0;
}

/* ---------- do_mem_abort 钩子：fault 重定向 ---------- */

static struct kprobe mem_abort_kp;

static int mem_abort_pre(struct kprobe *p, struct pt_regs *regs) {
  /* do_mem_abort(far, esr, regs) 的三个参数 */
  unsigned long far = regs->regs[0];
  unsigned long esr = regs->regs[1];
  /* 第 3 个参数：异常发生时的用户态寄存器快照 */
  struct pt_regs *uregs = (struct pt_regs *)regs->regs[2];

  if (hook_handle_fault(far, esr, uregs)) {
    /*
     * 已接管：用户态 pc 已被改写为 ghost 地址，
     * 必须跳过原 do_mem_abort，否则它会对仍在 UXN 状态的
     * 原页发 SIGSEGV 杀死目标进程。
     *
     * 探针位于函数首指令处，此时 PACIASP 尚未执行，
     * x30 仍是未签名的原始返回地址，直接回跳是安全的。
     */
    regs->pc = regs->regs[30];
    return 1;
  }
  return 0; /* 与我们无关：永不改 pc，原函数照常执行 */
}

/* ---------- 用户态 BRK 钩子：ghost 内 BRK 探针 ----------
 *
 * 注意：绝不能 kprobe do_debug_exception——它在 kprobe 自身的 BRK 处理
 * 路径上（内核 BRK → el1_dbg → do_debug_exception → call_break_hook
 * → kprobe 处理器）。给它挂探针会导致每次 kprobe 触发都递归重入，
 * 设备直接挂死重启（踩过的坑）。
 *
 * 正确做法是 register_user_break_hook：内核给用户态 BRK 留的正规
 * 注册接口（未 EXPORT，经 kallsyms 解析）。内核按 imm/mask 匹配
 * BRK 的 imm16 后才回调，regs 直接是用户态寄存器快照，
 * 且 regs->pc = BRK 指令本身的地址。
 */

static int __nocfi pte_brk_handler(struct pt_regs *uregs, unsigned int esr) {
  /* ghost 观察点（hookManager 打的 BRK，magic 0xBE） */
  if (hook_handle_brk(uregs, esr))
    return DBG_HOOK_HANDLED;
  /* Java trampoline 观察点（javahook 打的 BRK，magic 0xBF） */
  if (javahook_handle_brk(uregs, esr))
    return DBG_HOOK_HANDLED;
  return DBG_HOOK_ERROR;
}

/*
 * break_hook 一次只能匹配一个 imm 模式，所以注册两个：
 *   imm=0xBE00 —— hookManager 的 ghost 探针
 *   imm=0xBF00 —— javahook 的 trampoline 探针
 * mask=0x00FF 表示只比较高字节（低字节是 "探针/槽位编号"，不参与匹配）。
 * 内核在 list 里找到第一个匹配的 hook 就停（见 call_break_hook 的实现），
 * 因此两个 imm 必须不重叠，否则后者永远收不到事件。
 */
static struct break_hook g_pte_brk_hook = {
    .fn = pte_brk_handler,
    .imm = 0xBE00,
    .mask = 0x00FF,
};

static struct break_hook g_java_brk_hook = {
    .fn = pte_brk_handler,
    .imm = 0xBF00,
    .mask = 0x00FF,
};

static int g_brk_hook_registered;

/* ---------- /proc/pte_java：Java 层 hook 控制通道 ----------
 *
 * native 层的命令走 prctl（kprobe 原子上下文，只能异步）。
 * Java 层的操作需要读写目标进程内存、申请物理页、拿 mmap 锁，
 * 全是可睡眠操作，所以给它一条在进程上下文执行的同步通道。
 *
 * 协议（纯文本，一行一条命令）：
 *
 *   hook <pid|-> <art_method> [选项]    pid 填 - 时按 pkg=/uid= 定位进程
 *   unhook <pid> <art_method>           卸载
 *   list                                列出全部 java hook
 *   probe <pid> <art_method>            探测入口字段偏移
 *   read <pid> <art_method> <off>       读字段（hex）
 *   write <pid> <art_method> <off> <val> 写字段（hex）
 *   help
 *
 * 安装命令支持的附加关键字（顺序任意）：
 *   entry=0x20        显式指定入口字段偏移
 *   replace=0x...     替换函数地址（目标进程内）
 *   ret=0x...         SKIP_ORIGINAL 的返回值
 *   uxn               PTE/UXN 策略（不改 ArtMethod）
 *   brk               在 trampoline 里插观察点（dmesg 打参数）
 *   skip              不调用原方法，直接返回 ret
 *   raw               不生成 trampoline，入口直接指向 replace
 *   name=xxx          便于识别的标签（只写进日志）
 *
 * 例：
 *   echo "hook 12345 0x7a1b2c3d40 entry=0x20 brk" > /proc/pte_java
 *   echo "unhook 12345 0x7a1b2c3d40" > /proc/pte_java
 *   cat /proc/pte_java
 *
 * 写命令后立刻读回结果（结果只保留最近一次）。
 */

#define PTE_JAVA_MAX_CMD 512

static struct proc_dir_entry *g_java_entry;
static DEFINE_MUTEX(g_java_lock);
static char g_java_out[4096];
static int g_java_out_len;

/* 解析十六进制/十进制数值（0x 前缀识别十六进制） */
static unsigned long java_parse_num(const char **sp) {
  const char *s = *sp;
  unsigned long v = 0;

  while (*s == ' ' || *s == '\t')
    s++;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    s += 2;
    while (*s) {
      char c = *s;
      unsigned int d;

      if (c >= '0' && c <= '9')
        d = (unsigned int)(c - '0');
      else if (c >= 'a' && c <= 'f')
        d = (unsigned int)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        d = (unsigned int)(c - 'A' + 10);
      else
        break;
      v = (v << 4) | d;
      s++;
    }
  } else {
    while (*s >= '0' && *s <= '9') {
      v = v * 10 + (unsigned long)(*s - '0');
      s++;
    }
  }
  *sp = s;
  return v;
}

/*
 * 操作名 → JH_OP_*。写成表是为了让 add/set/or/and/print 这些词
 * 在命令里和文档里完全一致，不用记数字。
 */
static const char *const java_op_names[] = {"none", "print", "set",
                                            "or",   "and",   "add"};

static int java_parse_op(const char **sp, __u32 *op) {
  const char *s = *sp;
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE(java_op_names); i++) {
    size_t len = strlen(java_op_names[i]);

    if (!strncmp(s, java_op_names[i], len)) {
      *op = i;
      *sp = s + len;
      return 0;
    }
  }
  return -EINVAL;
}

/*
 * 解析 arg<N>=<op>[:<value>] —— 追加一条参数规则。
 * 例：arg1=print  arg2=add:0x10  arg1=set:0x64
 */
static int java_parse_arg_rule(const char **sp, struct JavaHookReq *req) {
  const char *p = *sp + 3; /* 跳过 "arg" */
  unsigned long idx;
  __u32 op = JH_OP_NONE;

  idx = java_parse_num(&p);
  if (idx >= JH_ARGS_MAX || *p != '=')
    return -EINVAL;
  p++;

  if (java_parse_op(&p, &op))
    return -EINVAL;

  if (req->arg_cnt >= JH_ARGS_MAX)
    return -ENOSPC;

  req->args[req->arg_cnt].idx = (__u32)idx;
  req->args[req->arg_cnt].op = op;
  req->args[req->arg_cnt].val = 0;
  /* 带冒号才读操作数 */
  if (*p == ':') {
    p++;
    req->args[req->arg_cnt].val = (__u64)java_parse_num(&p);
  }
  req->arg_cnt++;
  *sp = p;
  return 0;
}

/* 解析 retop=<op>[:<value>] —— 返回值规则 */
static int java_parse_ret_rule(const char **sp, struct JavaHookReq *req) {
  const char *p = *sp + 6; /* 跳过 "retop=" */
  __u32 op = JH_OP_NONE;

  if (java_parse_op(&p, &op))
    return -EINVAL;

  req->ret_op = op;
  req->ret_new = 0;
  if (*p == ':') {
    p++;
    req->ret_new = (__u64)java_parse_num(&p);
  }
  *sp = p;
  return 0;
}

/* 把规则渲染成人类可读的一行，附在安装结果后面 */
static int java_fmt_rules(char *buf, int size, const struct JavaHookReq *r) {
  int off = 0;
  unsigned int i;
  int first = 1;

  if (!r->arg_cnt && !jh_rule_active(r->ret_op))
    return 0;

  off += scnprintf(buf + off, size - off, "  rules      = ");
  for (i = 0; i < r->arg_cnt && i < JH_ARGS_MAX; i++) {
    const struct JavaArgRule *a = &r->args[i];

    if (!jh_rule_active(a->op))
      continue;
    off += scnprintf(buf + off, size - off, "%sx%u:%s", first ? "" : " ",
                     a->idx, java_op_names[a->op]);
    first = 0;
    if (a->op != JH_OP_PRINT)
      off += scnprintf(buf + off, size - off, "=0x%llx",
                       (unsigned long long)a->val);
  }
  if (jh_rule_active(r->ret_op)) {
    off += scnprintf(buf + off, size - off, "%sret:%s", first ? "" : " ",
                     java_op_names[r->ret_op]);
    if (r->ret_op != JH_OP_PRINT)
      off += scnprintf(buf + off, size - off, "=0x%llx",
                       (unsigned long long)r->ret_new);
  }
  off += scnprintf(buf + off, size - off, "\n");
  return off;
}

/*
 * 解析 "<pid>|<->" 位置参数。
 * 用户可能不知道 pid，只给 pkg=/uid=；这种情况位置参数填 "-" 或 0。
 */
static pid_t java_parse_pid(const char **sp) {
  const char *s = *sp;

  while (*s == ' ' || *s == '\t')
    s++;
  if (*s == '-') { /* "-" 表示不指定 pid */
    *sp = s + 1;
    return 0;
  }
  return (pid_t)java_parse_num(sp);
}

/*
 * 命令分发。返回值只用于内部统计，输出一律写进 g_java_out。
 * 注意：这条路径在进程上下文，可以安全地 sleep —— 所有
 * hook_install_sync / ghost_alloc / access_process_vm 都能直接调用。
 */
static void java_cmd_dispatch(const char *cmd) {
  const char *p = cmd;
  int n = 0;

  g_java_out[0] = 0;

  while (*p == ' ' || *p == '\t')
    p++;

  /* ---- hook ---- */
  if (!strncmp(p, "hook ", 5) || !strcmp(p, "hook")) {
    struct JavaHookReq req;
    struct JavaHookResult res;
    pid_t pid;
    unsigned long method;
    int ret;

    p += 4;
    pid = java_parse_pid(&p);
    method = java_parse_num(&p);

    memset(&req, 0, sizeof(req));
    memset(&res, 0, sizeof(res)); /* 参数校验失败时内核不会填 out */
    req.magic = JAVA_HOOK_REQ_MAGIC;
    req.version = JAVA_HOOK_REQ_VERSION;
    req.pid = pid;
    req.art_method = (__u64)method;

    /* 关键字选项：逐个 token 扫，顺序无关 */
    while (*p) {
      while (*p == ' ' || *p == '\t')
        p++;
      if (!*p)
        break;

      if (!strncmp(p, "entry=", 6)) {
        p += 6;
        req.entry_off = (__u32)java_parse_num(&p);
      } else if (!strncmp(p, "replace=", 8)) {
        p += 8;
        req.replace = (__u64)java_parse_num(&p);
      } else if (!strncmp(p, "ret=", 4)) {
        p += 4;
        req.ret_val = (__u64)java_parse_num(&p);
      } else if (!strncmp(p, "uxn", 3)) {
        p += 3;
        req.flags |= JH_FLAG_UXN;
      } else if (!strncmp(p, "brk", 3)) {
        p += 3;
        req.flags |= JH_FLAG_BRK;
      } else if (!strncmp(p, "skip", 4)) {
        p += 4;
        req.flags |= JH_FLAG_SKIP_ORIGINAL;
      } else if (!strncmp(p, "raw", 3)) {
        p += 3;
        req.flags |= JH_FLAG_NO_TRAMP;
      } else if (!strncmp(p, "verbose", 7)) {
        p += 7;
        req.flags |= JH_FLAG_VERBOSE;
      } else if (!strncmp(p, "arg", 3)) {
        /* arg<N>=<op>[:<value>]  例：arg1=print  arg2=add:0x10 */
        if (java_parse_arg_rule(&p, &req))
          break;
      } else if (!strncmp(p, "retop=", 6)) {
        /* retop=<op>[:<value>]  例：retop=print  retop=set:0x64 */
        if (java_parse_ret_rule(&p, &req))
          break;
      } else if (!strncmp(p, "pkg=", 4)) {
        /* pkg=<包名> —— pid 没给（或已失效）时按包名定位进程 */
        int i = 0;

        p += 4;
        while (*p && *p != ' ' && *p != '\t' && i < JH_PKG_MAX - 1)
          req.pkg[i++] = *p++;
        req.pkg[i] = 0;
      } else if (!strncmp(p, "uid=", 4)) {
        /* uid=<userId> —— App 的 userId（如 10123） */
        p += 4;
        req.target_uid = (__u32)java_parse_num(&p);
        req.flags |= JH_FLAG_HAS_UID;
      } else if (!strncmp(p, "bits32", 6)) {
        p += 6;
        req.ret_bits = 32;
      } else if (!strncmp(p, "bits64", 6)) {
        p += 6;
        req.ret_bits = 64;
      } else if (!strncmp(p, "name=", 5)) {
        /* 只用于日志友好，内核侧不保存 */
        p += 5;
        while (*p && *p != ' ' && *p != '\t')
          p++;
      } else {
        /* 未知 token：跳过整个词，避免死循环 */
        while (*p && *p != ' ' && *p != '\t')
          p++;
      }
    }

    ret = java_hook_method(&req, &res);
    n = scnprintf(g_java_out, sizeof(g_java_out),
                  "[%s] ret=%d pid=%d method=0x%lx\n"
                  "  entry_off  = 0x%x\n"
                  "  orig_entry = 0x%llx\n"
                  "  trampoline = 0x%llx\n"
                  "  backup     = 0x%llx\n"
                  "  enter_brk  = 0x%llx\n"
                  "  exit_brk   = 0x%llx\n",
                  ret ? "FAIL" : "OK", ret, res.pid ? res.pid : pid, method,
                  res.entry_off, res.orig_entry, res.trampoline, res.backup,
                  res.enter_brk, res.exit_brk);
    if (req.pkg[0] || req.target_uid)
      n += scnprintf(g_java_out + n, (int)sizeof(g_java_out) - n,
                     "  target     = pkg=%s uid=%u -> pid %d\n",
                     req.pkg[0] ? req.pkg : "-", req.target_uid, res.pid);
    n += java_fmt_rules(g_java_out + n, (int)sizeof(g_java_out) - n, &req);
    g_java_out_len = n;
    return;
  }

  /* ---- unhook ---- */
  if (!strncmp(p, "unhook ", 7)) {
    pid_t pid;
    unsigned long method;
    int ret;

    p += 7;
    pid = (pid_t)java_parse_num(&p);
    method = java_parse_num(&p);

    ret = java_unhook_method(pid, method, 0);
    g_java_out_len = scnprintf(g_java_out, sizeof(g_java_out),
                               "[%s] ret=%d pid=%d method=0x%lx\n",
                               ret ? "FAIL" : "OK", ret, pid, method);
    return;
  }

  /* ---- probe ---- */
  if (!strncmp(p, "probe ", 6)) {
    pid_t pid;
    unsigned long method;
    unsigned int off = 0;
    int ret;

    p += 6;
    pid = (pid_t)java_parse_num(&p);
    method = java_parse_num(&p);

    ret = java_probe_entry_off(pid, method, &off);
    g_java_out_len = scnprintf(g_java_out, sizeof(g_java_out),
                               "[%s] ret=%d entry_off=0x%x\n",
                               ret ? "FAIL" : "OK", ret, off);
    return;
  }

  /* ---- read / write ---- */
  if (!strncmp(p, "read ", 5)) {
    pid_t pid;
    unsigned long method, off, val = 0;
    int ret;

    p += 5;
    pid = (pid_t)java_parse_num(&p);
    method = java_parse_num(&p);
    off = java_parse_num(&p);

    if (!off) {
      unsigned int po = 0;

      ret = java_probe_entry_off(pid, method, &po);
      if (ret) {
        g_java_out_len = scnprintf(g_java_out, sizeof(g_java_out),
                                   "[FAIL] probe failed %d\n", ret);
        return;
      }
      off = po;
    }
    ret = java_read_entry(pid, method, (unsigned int)off, &val);
    g_java_out_len = scnprintf(g_java_out, sizeof(g_java_out),
                               "[%s] ret=%d off=0x%lx val=0x%lx\n",
                               ret ? "FAIL" : "OK", ret, off, val);
    return;
  }

  if (!strncmp(p, "write ", 6)) {
    pid_t pid;
    unsigned long method, off, val;
    int ret;

    p += 6;
    pid = (pid_t)java_parse_num(&p);
    method = java_parse_num(&p);
    off = java_parse_num(&p);
    val = java_parse_num(&p);

    ret = java_write_entry(pid, method, (unsigned int)off, val);
    g_java_out_len = scnprintf(g_java_out, sizeof(g_java_out),
                               "[%s] ret=%d off=0x%lx val=0x%lx\n",
                               ret ? "FAIL" : "OK", ret, off, val);
    return;
  }

  /* ---- list ---- */
  if (!strcmp(p, "list")) {
    g_java_out_len = javahook_list(g_java_out, sizeof(g_java_out));
    return;
  }

  /* ---- dump：取走捕获环里的参数/返回值记录 ---- */
  if (!strncmp(p, "dump", 4)) {
    int max = 0;

    p += 4;
    if (*p)
      max = (int)java_parse_num(&p);
    g_java_out_len = javahook_capture_dump(g_java_out, sizeof(g_java_out), max);
    return;
  }

  /* ---- cap on|off|clear ：捕获开关 ---- */
  if (!strncmp(p, "cap", 3)) {
    const char *q = p + 3;

    while (*q == ' ')
      q++;
    if (!strcmp(q, "off")) {
      javahook_capture_enable(0);
      g_java_out_len =
          scnprintf(g_java_out, sizeof(g_java_out), "[OK] capture off\n");
    } else if (!strcmp(q, "on")) {
      javahook_capture_enable(1);
      g_java_out_len =
          scnprintf(g_java_out, sizeof(g_java_out), "[OK] capture on\n");
    } else if (!strcmp(q, "clear")) {
      javahook_capture_clear();
      g_java_out_len =
          scnprintf(g_java_out, sizeof(g_java_out), "[OK] capture cleared\n");
    } else {
      g_java_out_len =
          scnprintf(g_java_out, sizeof(g_java_out), "[%s] capture=%s\n", "INFO",
                    javahook_capture_is_on() ? "on" : "off");
    }
    return;
  }

  /* ---- help ---- */
  g_java_out_len = scnprintf(
      g_java_out, sizeof(g_java_out),
      "pte_java commands:\n"
      "  hook <pid|-> <art_method> [选项...]   pid 填 - 时用 pkg=/uid= 定位\n"
      "  unhook <pid> <art_method>\n"
      "  probe <pid> <art_method>\n"
      "  read <pid> <art_method> <off>\n"
      "  write <pid> <art_method> <off> <val>\n"
      "  list\n"
      "  dump [max]              取走捕获环里的参数/返回值记录\n"
      "  cap on|off|clear        捕获开关 / 清空\n"
      "\n"
      "hook 选项：\n"
      "  pkg=<包名>              按包名找进程（不需要 pid）\n"
      "  uid=<userId>            按 App 的 userId 找进程\n"
      "  arg<N>=print|<op>[:<v>] 对第 N 个参数（x0..x7）操作\n"
      "                          op = set / or / and / add / print\n"
      "  retop=print|<op>[:<v>]  对返回值操作（同上）\n"
      "  bits32 | bits64         返回值按 32 位还是 64 位处理（默认 64）\n"
      "  entry=0x20              显式指定入口字段偏移（默认自动探测）\n"
      "  replace=0x..            替换函数地址\n"
      "  ret=0x..                skip 时的返回值\n"
      "  uxn                     PTE/UXN 策略（不动 ArtMethod）\n"
      "  brk                     额外用 dmesg 打印入口参数（调试用）\n"
      "  skip                    不调用原方法\n"
      "  raw                     不做 trampoline，入口直接指向 replace\n"
      "\n"
      "例：\n"
      "  # 打印参数 + 把第 2 个参数加 16 + 打印返回值\n"
      "  hook 123 0x7a1b2c3d40 arg1=print arg2=add:0x10 retop=print\n"
      "  # 让方法固定返回 100（int）\n"
      "  hook 123 0x7a1b2c3d40 skip ret=0x64\n"
      "  # 只改返回值，不改行为\n"
      "  hook 123 0x7a1b2c3d40 retop=add:0x1 bits32\n");
}

static ssize_t pte_java_write(struct file *file, const char __user *ubuf,
                              size_t count, loff_t *ppos) {
  char cmd[PTE_JAVA_MAX_CMD];
  size_t n;

  if (!count)
    return 0;
  n = count < sizeof(cmd) - 1 ? count : sizeof(cmd) - 1;
  if (copy_from_user(cmd, ubuf, n))
    return -EFAULT;
  cmd[n] = 0;
  while (n > 0 && (cmd[n - 1] == '\n' || cmd[n - 1] == '\r'))
    cmd[--n] = 0;

  mutex_lock(&g_java_lock);
  java_cmd_dispatch(cmd);
  mutex_unlock(&g_java_lock);
  return count;
}

static ssize_t pte_java_read(struct file *file, char __user *ubuf, size_t count,
                             loff_t *ppos) {
  ssize_t ret;

  mutex_lock(&g_java_lock);
  ret = simple_read_from_buffer(ubuf, count, ppos, g_java_out, g_java_out_len);
  mutex_unlock(&g_java_lock);
  return ret;
}

static const struct proc_ops g_java_proc_ops = {
    .proc_read = pte_java_read,
    .proc_write = pte_java_write,
    .proc_lseek = default_llseek,
};

/* ---------- 模块初始化 / 退出 ---------- */

static int __init init_mod(void) {
  int ret;

  ret = resolve_kernel_symbols();
  if (ret)
    return ret;

  /* 工作队列：kprobe 前置是原子上下文，安装/卸载挪到 kworker 里干 */
  ret = hook_manager_wq_init();
  if (ret)
    return ret;

  /* 挂 prctl 钩子（用户态命令通道） */
  memset(&kp, 0, sizeof(kp));
  kp.symbol_name = "__arm64_sys_prctl";
  kp.pre_handler = handler_pre;
  ret = register_kprobe(&kp);
  if (ret < 0) {
    pr_err("pte_hook: register_kprobe(prctl) fail %d\n", ret);
    hook_manager_wq_exit();
    return ret;
  }
  pr_info("pte_hook: prctl hook success \n");

  /* 挂 do_mem_abort 钩子（fault 重定向） */
  memset(&mem_abort_kp, 0, sizeof(mem_abort_kp));
  mem_abort_kp.symbol_name = "do_mem_abort";
  mem_abort_kp.pre_handler = mem_abort_pre;
  ret = register_kprobe(&mem_abort_kp);
  if (ret < 0) {
    pr_err("pte_hook: register_kprobe(do_mem_abort) fail %d\n", ret);
    unregister_kprobe(&kp);
    hook_manager_wq_exit();
    return ret;
  }
  pr_info("pte_hook: do_mem_abort hook success \n");

  /* 注册用户态 BRK 钩子（ghost 内 BRK 探针 + Java trampoline 观察点）。
   * 符号缺失不致命：BRK 探针保持关闭，观察点退化为页入口 dump */
  if (g_register_brk_addr) {
    pte_register_brk_hook(&g_pte_brk_hook);
    pte_register_brk_hook(&g_java_brk_hook);
    g_brk_hook_registered = 1;
    hook_manager_brk_enable(1);
    pr_info("pte_hook: user break hook success \n");
  } else {
    hook_manager_brk_enable(0);
    pr_warn(
        "pte_hook: register_user_break_hook not found, brk probe disabled\n");
  }

  /*
   * /proc/pte_java：Java 层 hook 的同步控制通道。
   * 没有 access_process_vm 就装不了 Java hook，但仍注册入口，
   * 让调用方看到明确的错误而不是无声失败。
   */
  if (!g_apv_addr)
    pr_warn("pte_hook: access_process_vm not found, java hook unavailable\n");
  else if (javahook_capture_init())
    pr_warn("pte_hook: capture ring alloc failed, PRINT rules disabled\n");

  g_java_entry = proc_create("pte_java", 0600, NULL, &g_java_proc_ops);
  if (!g_java_entry)
    pr_warn("pte_hook: proc_create(pte_java) failed\n");
  else
    pr_info("pte_hook: /proc/pte_java ready\n");

  pr_info("pte_hook: module load success \n");
  return 0;
}

static void __exit exit_mod(void) {
  /* 顺序：先摘掉命令通道（不再接受新请求），
   * 再等工作队列把排队的请求做完并销毁，
   * 然后卸载已安装的 hook（恢复 PTE、释放 ghost），
   * 最后摘 do_mem_abort 钩子。
   *
   * 每步打一行日志：卸载崩溃时，最后一条日志就是崩溃点。 */
  pr_info("pte_hook: exit[1/9] enter\n");

  if (g_java_entry) {
    pr_info("pte_hook: exit[2/9] proc_remove\n");
    proc_remove(g_java_entry);
    g_java_entry = NULL;
  }
  pr_info("pte_hook: exit[3/9] unregister prctl kprobe\n");
  unregister_kprobe(&kp);

  if (g_brk_hook_registered && g_unregister_brk_addr) {
    pr_info("pte_hook: exit[4/9] unregister break hooks\n");
    pte_unregister_brk_hook(&g_pte_brk_hook);
    pte_unregister_brk_hook(&g_java_brk_hook);
    g_brk_hook_registered = 0;
  }

  pr_info("pte_hook: exit[5/9] flush workqueue\n");
  hook_manager_wq_exit();

  pr_info("pte_hook: exit[6/9] release java hooks\n");
  javahook_release_all();

  pr_info("pte_hook: exit[7/9] free capture ring\n");
  javahook_capture_exit();

  pr_info("pte_hook: exit[8/9] uninstall native hooks\n");
  uninstall_all_hooks();

  pr_info("pte_hook: exit[9/9] unregister do_mem_abort\n");
  unregister_kprobe(&mem_abort_kp);

  pr_info("pte_hook: module exit done\n");
}

MODULE_LICENSE("GPL");
module_init(init_mod);
module_exit(exit_mod);
