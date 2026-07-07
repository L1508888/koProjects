

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/slab.h>



#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

MODULE_LICENSE("GPL");



/* ---- 通过 kallsyms 解析未导出符号 ---- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);


typedef int (*vsnprintf_t)(char *buf, size_t size, const char *fmt, va_list args);
static vsnprintf_t g_vsnprintf = 0;

/* 一些内核符号 */
typedef void *(*find_vpid_t)(int);
typedef struct task_struct *(*pid_task_t)(void *, int);
typedef int (*access_process_vm_t)(struct task_struct *tsk,
                                    unsigned long addr,
                                    void *buf, int len,
                                    unsigned int gup_flags);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
// typedef int (*pte_fn_t)(void *pte, unsigned long addr, void *data);
typedef int (*apply_to_page_range_t)(struct mm_struct *mm,
                                      unsigned long address,
                                      unsigned long size,
                                      pte_fn_t fn, void *data);
typedef unsigned long (*get_free_pages_t)(unsigned int, unsigned int);
typedef void (*free_pages_t)(unsigned long, unsigned int);
typedef void *(*find_vma_t)(struct mm_struct *, unsigned long);
typedef int (*task_pid_nr_ns_t)(struct task_struct *, int, void *);
typedef int (*schedule_work_t)(void *work);
typedef void (*rb_erase_t)(void *node, void *root);
typedef void (*on_each_cpu_t)(void (*fn)(void *), void *arg, int wait);
typedef int  (*send_sig_t)(int sig, struct task_struct *p, int priv);

static find_vpid_t           fn_find_vpid;
static pid_task_t            fn_pid_task;
static access_process_vm_t   fn_access_process_vm;
static get_task_mm_t         fn_get_task_mm;
static mmput_t               fn_mmput;
static apply_to_page_range_t fn_apply_to_page_range;
static get_free_pages_t      fn_get_free_pages;
static free_pages_t          fn_free_pages;
static find_vma_t            fn_find_vma;
static const int64_t        *ptr_physvirt_offset;
static task_pid_nr_ns_t      fn_task_pid_nr_ns;
static schedule_work_t       fn_schedule_work;
static rb_erase_t            fn_rb_erase;
static on_each_cpu_t         fn_on_each_cpu;
static send_sig_t            fn_send_sig;

static void *addr_do_mem_abort;
static void *addr_do_mmap;

#define FOLL_WRITE  0x01
#define FOLL_FORCE  0x10
#define PROT_EXEC   0x04




static unsigned long lookup_via_kprobe(const char *name)
{
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


static int __nocfi resolve_kernel_symbols(void)
{
    kallsyms_lookup_name_t kln;
    unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");

    if (!addr) {
        pr_err("break: cannot resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }
    kln = (kallsyms_lookup_name_t)addr;




    g_vsnprintf            = (vsnprintf_t)kln("vsnprintf");
    fn_find_vpid           = (find_vpid_t)kln("find_vpid");
    fn_pid_task            = (pid_task_t)kln("pid_task");
    fn_access_process_vm   = (access_process_vm_t)kln("access_process_vm");
    fn_get_task_mm         = (get_task_mm_t)kln("get_task_mm");
    fn_mmput               = (mmput_t)kln("mmput");
    fn_apply_to_page_range = (apply_to_page_range_t)kln("apply_to_page_range");
    fn_get_free_pages      = (get_free_pages_t)kln("__get_free_pages");
    fn_free_pages          = (free_pages_t)kln("free_pages");
    fn_find_vma            = (find_vma_t)kln("find_vma");
    ptr_physvirt_offset    = (const int64_t *)kln("physvirt_offset");
    addr_do_mem_abort      = (void *)kln("do_mem_abort");
    addr_do_mmap           = (void *)kln("do_mmap");
    fn_task_pid_nr_ns      = (task_pid_nr_ns_t)kln("__task_pid_nr_ns");
    fn_schedule_work       = (schedule_work_t)kln("schedule_work");
    fn_rb_erase            = (rb_erase_t)kln("rb_erase");
    fn_on_each_cpu         = (on_each_cpu_t)kln("on_each_cpu");
    fn_send_sig            = (send_sig_t)kln("send_sig");
    pr_info("hook syms: vsn=%lx vpid=%lx ptask=%lx apv=%lx "
             "gtm=%lx mp=%lx apr=%lx gfp=%lx frp=%lx fv=%lx pvo=%lx dma=%lx\n",
             (unsigned long)g_vsnprintf,
             (unsigned long)fn_find_vpid,
             (unsigned long)fn_pid_task,
             (unsigned long)fn_access_process_vm,
             (unsigned long)fn_get_task_mm,
             (unsigned long)fn_mmput,
             (unsigned long)fn_apply_to_page_range,
             (unsigned long)fn_get_free_pages,
             (unsigned long)fn_free_pages,
             (unsigned long)fn_find_vma,
             (unsigned long)ptr_physvirt_offset,
             (unsigned long)addr_do_mem_abort);
    return 0;
}



/* ---------- 模块初始化 / 退出 ---------- */
static int __init init_mod(void){
    int ret;

    ret = resolve_kernel_symbols();
    if (ret)
        return ret;
    return 0;
}



static void __nocfi __exit exit_mod(void){
    // unregister_kprobe(&kp);
    pr_info("hook: module exit\n");
}



module_init(init_mod);
module_exit(exit_mod);