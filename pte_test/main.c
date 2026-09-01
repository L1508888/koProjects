/*
 * main.c —— 模块入口与 kprobe 挂载层
 *
 * 职责：
 *   1. 解析内核符号（先 kprobe 拿 kallsyms_lookup_name，再查其余符号），
 *      分别注入 hookManager / ghost 两个模块；
 *   2. hook __arm64_sys_prctl：接收用户态下发的安装 / 卸载命令；
 *   3. hook do_mem_abort：目标页 UXN 取指异常时交给 hookManager 重定向。
 *
 * 用户态命令约定：
 *   安装：        prctl(0xDEADBEEF, &HookTask, 0, 0, 0)
 *   卸载指定函数：prctl(0xDEADBEF0, &HookTask, 0, 0, 0)
 *   卸载全部：    prctl(0xDEADBEF0, 0, 0, 0, 0)
 *
 * kprobe 前置处理运行在 BRK 异常上下文（关中断、禁睡眠）：
 * 读用户态结构体只能用 copy_from_user_nofault（绝不缺页睡眠），
 * 安装/卸载也只登记请求并入队，真正的活在 kworker 进程上下文干。
 * 因此安装/卸载是【异步】的，结果看 dmesg。
 *
 * 注：内核源码里 do_mem_abort 标了 NOKPROBE_SYMBOL，
 * 但实测在本内核（android13-5.10）上 kprobe 可以正常注册。
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/debug-monitors.h>

#include "hookManager.h"

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

static flush_dcache_area_t g_flush_dcache_area;  /* 5.10 (addr,len) 变体 */
static dcache_clean_pou_t  g_dcache_clean_pou;   /* 改名后的 (start,end) 变体 */



static copy_from_user_nofault_t copy_from_fn;

/* 用户态 BRK 钩子注册/注销（未 EXPORT，kallsyms 解析注入）。
 * 注意 typedef 必须与内核原型逐字一致（CFI） */
typedef void (*register_user_break_hook_t)(struct break_hook *hook);
static register_user_break_hook_t g_register_brk;
static register_user_break_hook_t g_unregister_brk;

static __nocfi void flush_dcache_shim(void *addr, size_t len)
{
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
   * "get_free_pages" 这个名字在内核里不存在，查了会返回 0。
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
  g_register_brk = (register_user_break_hook_t)kln("register_user_break_hook");
  g_unregister_brk = (register_user_break_hook_t)kln("unregister_user_break_hook");
  pr_info("pte_hook: register_user_break_hook=%px unregister=%px\n",
          (void *)g_register_brk, (void *)g_unregister_brk);

  
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

static int __nocfi pte_brk_handler(struct pt_regs *uregs, unsigned int esr)
{
  if (hook_handle_brk(uregs, esr))
    return DBG_HOOK_HANDLED;
  return DBG_HOOK_ERROR;
}

/* imm=魔数高字节，mask=忽略低字节（探针编号不参与匹配） */
static struct break_hook g_pte_brk_hook = {
  .fn   = pte_brk_handler,
  .imm  = 0xBE00,
  .mask = 0x00FF,
};

static int g_brk_hook_registered;

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

  /* 注册用户态 BRK 钩子（ghost 内 BRK 探针）。
   * 符号缺失不致命：BRK 探针保持关闭，观察点退化为页入口 dump */
  if (g_register_brk) {
    g_register_brk(&g_pte_brk_hook);
    g_brk_hook_registered = 1;
    hook_manager_brk_enable(1);
    pr_info("pte_hook: user break hook success \n");
  } else {
    hook_manager_brk_enable(0);
    pr_warn("pte_hook: register_user_break_hook not found, brk probe disabled\n");
  }

  pr_info("pte_hook: module load success \n");
  return 0;
}

static void __exit exit_mod(void) {
  /* 顺序：先摘掉命令通道（不再接受新请求），
   * 再等工作队列把排队的请求做完并销毁，
   * 然后卸载已安装的 hook（恢复 PTE、释放 ghost），
   * 最后摘 do_mem_abort 钩子 */
  unregister_kprobe(&kp);
  if (g_brk_hook_registered && g_unregister_brk) {
    g_unregister_brk(&g_pte_brk_hook);
    g_brk_hook_registered = 0;
  }
  hook_manager_wq_exit();
  uninstall_all_hooks();
  unregister_kprobe(&mem_abort_kp);
  pr_info("pte_hook: module exit \n");
}

MODULE_LICENSE("GPL");
module_init(init_mod);
module_exit(exit_mod);
