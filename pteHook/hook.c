

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/slab.h>


/* 一些内核符号 */
typedef void *(*find_vpid_t)(int);
typedef struct task_struct *(*pid_task_t)(void *, int);
typedef int (*access_process_vm_t)(struct task_struct *tsk,
                                    unsigned long addr,
                                    void *buf, int len,
                                    unsigned int gup_flags);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef int (*pte_fn_t)(void *pte, unsigned long addr, void *data);
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