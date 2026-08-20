#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>


#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif



#define MAGIC_PRCTL_OPTION  0xDEADBEEF

typedef struct {
    
    unsigned long address;
    pid_t         pid;
}HookTask;


static struct kprobe kp;



typedef int (*follow_pte_t)(struct mm_struct *mm, unsigned long address,
	       pte_t **ptepp, spinlock_t **ptlp);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static follow_pte_t follow_pte_ptr;
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

static __nocfi __maybe_unused int resolve_kernel_symbols(){
    kallsyms_lookup_name_t kln;
    unsigned long addr = lookup_via_kprobe("kallsyms_lookup_name");

    if (!addr) {
        pr_err("pte_test: cannot resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }

    kln = (kallsyms_lookup_name_t)addr;

    /* 在模块初始化时查找符号 */
    follow_pte_ptr = (follow_pte_t)kln("follow_pte");
    if (!follow_pte_ptr) {
        pr_err("pte_test: follow_pte not found in kallsyms\n");
        return -1;
    }
    pr_info("pte_test: found symbol %p \n", (void*)follow_pte_ptr);
    return 0;

}


/*
 * 根据 PID 获取 task_struct（需 RCU 保护，并增加引用）
 */
static __nocfi struct task_struct *get_task_by_pid(pid_t pid)
{
    struct task_struct *task = NULL;
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    return task;
}


// #define PTE_UXN         (1UL << 54)

// 设置 UXN（禁止执行）
static inline pte_t pte_set_uxn(pte_t pte)
{
    pte_val(pte) |= PTE_UXN;
    return pte;
}

// 清除 UXN（允许执行）
static inline pte_t pte_clear_uxn(pte_t pte)
{
    pte_val(pte) &= ~PTE_UXN;
    return pte;
}

/* 全局数据，用于记录 hook 目标 */
static pid_t         g_hook_pid;    
static unsigned long g_hook_addr;
static bool          g_hook_armed;

int ptehook_handle_abort(unsigned long far, unsigned long esr, void *regs_vp){
    unsigned int ec, ifsc;
    unsigned long far_page;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    pte_t *ptep;
    spinlock_t *ptl;
    pte_t new_pte;
    //  先把三个字段都算出来
    ec = (esr >> 26) & 0x3F;
    ifsc = esr & 0x3F;
    far_page = far & ~0xFFFUL;

    // pr_info("pte_test: enter ptehook_handle_abort, ec is %d, ifsc is %d, far_page is %lx \n", ec, ifsc, far_page);
    //  不是目标页：立刻放行给内核（绝大多数异常走这里，开销最小）
    if (far_page != (g_hook_addr & ~0xFFFUL)){
        return 0;
    }

    //  ===== 到这里说明异常正好落在“目标页”上 =====
    pr_info("pte_test: abort@target far=0x%lx ec=0x%x ifsc=0x%x tgid=%d want=%d\n",
             far, ec, ifsc, task_tgid_nr(current), g_hook_pid);
    

    //  只接管“取指(EC=0x20) + 权限错误(IFSC=0b0011xx)”。
    //  其它情况（例如页被换出后的翻译错误 ifsc=0x7）交回内核：换入后是不带 UXN
    //  的新 pte，本来就不该被我们拦，硬拦反而会死循环。
    if (ec != 0x20 || (ifsc & 0x3C) != 0x0C)
        return 0;

    mm = current->mm;
    if (!mm)
        return 0;

    //  接管：无论如何都尝试清掉 UXN，任何失败都记录，绝不留 UXN 不清就返回
    mmap_read_lock(mm);
    vma = find_vma(mm, far);
    if (vma && far >= vma->vm_start &&
        follow_pte_ptr(mm, far, &ptep, &ptl) == 0) {
        new_pte = pte_clear_uxn(*ptep);
        set_pte(ptep, new_pte);
        spin_unlock(ptl);
        flush_tlb_page(vma, far);
        g_hook_armed = false;   //  一次性：清掉后不再拦，避免继续刷屏
        
        pr_info("pte_test: UXN cleared far=0x%lx, resume\n", far);
    } else {
        
        pr_info("pte_test: clear FAILED (vma=%px) far=0x%lx\n", vma, far);
    }
    mmap_read_unlock(mm);
    return 0;
}


static int mem_abort_pre(struct kprobe *p, struct pt_regs *regs)
{
    //  Fault Address Register、触发异常的虚拟地址
    unsigned long far = regs->regs[0];
    //  Exception Syndrome Register、包含详细的异常信息
    unsigned long esr = regs->regs[1];
    //  异常发生时的 CPU 寄存器快照
    void *user_regs = (void *)regs->regs[2];

    //  一次性诊断：确认 do_mem_abort 的 kprobe 确实被触发了
    static bool once;
    if (!once) {
        once = true;
        pr_info("pte_test: mem_abort_pre fired, far=0x%lx esr=0x%lx\n", far, esr);
    }

    /*
     * 命中时 ptehook_handle_abort 已经清掉 UXN。这里不再改 pc / 跳过 do_mem_abort
     * （避免 PAC 签名过的 x30 导致取指崩溃）：直接返回 0 让 do_mem_abort 正常走，
     * 此时 pte 已修好，会被当成 spurious fault 干净返回，指令重试即可执行。
     */
    ptehook_handle_abort(far, esr, user_regs);
    return 0;
}


static struct kprobe mem_abort_kp;


static int install_mem_abort_hook(){
    int ret;
    memset(&mem_abort_kp, 0, sizeof(mem_abort_kp));
    mem_abort_kp.symbol_name = "do_mem_abort";
    mem_abort_kp.pre_handler = mem_abort_pre;
    ret = register_kprobe(&mem_abort_kp);
    if(ret < 0){
        pr_err("pte_test: register_kprobe(do_mem_abort) failed %d\n", ret);
        return ret;
    }
    return 0;
}

int __nocfi modify_process_pte(HookTask* hooktask){

    struct task_struct *task;
    struct mm_struct *mm;
    pte_t *ptep;
    spinlock_t *ptl;
    int ret;
    pte_t old_pte, new_pte;
    struct vm_area_struct *vma;

    pr_info("pte_test: pid %d \n", hooktask->pid);
    pr_info("pte_test: address %lu \n", hooktask->address);

    //  获取目标进程的task
    task = get_task_by_pid(hooktask->pid);
    if(!task){
        pr_err("pte_test, task with %d not found\n", hooktask->pid);
        return -1;
    }
    pr_info("pte_test: get_task_by_pid success");
    

    //  获取task 对应的内存
    mm = get_task_mm(task);
    put_task_struct(task);
    if(!mm){
        pr_err("pte_test, mm_struct for %d id NULL\n", hooktask->pid);
        return -1;
    }
    pr_info("pte_test: get_task_mm success");
    
    mmap_read_lock(mm);


    /* flush_tlb_page 需要 vma，顺便校验地址合法性 */
    vma = find_vma(mm, hooktask->address);
    if (!vma || hooktask->address < vma->vm_start) {
        ret = -EFAULT;
        goto out_unlock;
    }

    /* 成功返回时 *持有* ptl 这把页表自旋锁 */
    ret = follow_pte_ptr(mm, hooktask->address, &ptep, &ptl);
    if (ret) {
        pr_err("pte_test: follow_pte failed for address 0x%lx, error %d\n",
               hooktask->address, ret);
        ret = -1;
        goto out_unlock;
    }
    pr_info("pte_test: follow_pte success");

    old_pte = *ptep;
    pr_info("pte_test: origin pte=0x%lx\n", pte_val(old_pte));
    new_pte = pte_set_uxn(*ptep);
    pr_info("pte_test: new pte=0x%lx\n", pte_val(new_pte));
    set_pte(ptep, new_pte);
    
    pr_info("pte_test: set_pte success\n");
    //  释放ptl 
    spin_unlock(ptl);

    // /* 刷新 TLB 并更新缓存 */
    flush_tlb_page(vma, hooktask->address);
    // update_mmu_cache(vma, hooktask->address, ptep);
    ret = 0;
    g_hook_pid   = hooktask->pid;
    g_hook_addr  = hooktask->address;
    g_hook_armed = true;
    
    out_unlock:
        mmap_read_unlock(mm);
        mmput(mm);
    return ret;
}



static __nocfi int handler_pre(struct kprobe *p, struct pt_regs *kregs){
    struct pt_regs *uregs;
    unsigned long arg2;
    HookTask myTask;
    unsigned long left;
     int option;
    uregs = (struct pt_regs *)kregs->regs[0];
    if (!uregs)
        return 0;


    option = (int)uregs->regs[0];
    if (option != MAGIC_PRCTL_OPTION){
        return 0;
    }

    arg2 = (unsigned long)uregs->regs[1];
    if (!arg2){
        return 0;
    }

    left = copy_from_user(&myTask, (void __user *)arg2, sizeof(myTask));
    if (left) {
        pr_err("pte_test: copy_from_user failed, %lu bytes left\n", left);
        return 0;
    }
    

    modify_process_pte(&myTask);
    return 0;
}



/* ---------- 模块初始化 / 退出 ---------- */
static int __init init_mod(void){
    int ret;


    kp.symbol_name = "__arm64_sys_prctl";
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("pte_test: register_kprobe(__arm64_sys_prctl) failed %d\n", ret);
        return ret;
    }

    ret = resolve_kernel_symbols();
    if (ret){
        return ret;
    }
    install_mem_abort_hook();
    install_hook_ptrace();
    pr_info("pte_test: module loaded");
    return 0;
}

static void __exit exit_mod(void){
    unregister_kprobe(&kp);
    unregister_kprobe(&mem_abort_kp);

    uninstall_hook_ptrace();
    pr_info("pte_test: module exit");
}


MODULE_LICENSE("GPL");

module_init(init_mod);
module_exit(exit_mod);
