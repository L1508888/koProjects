#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "anti/break.h"


#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif





static follow_pte_t follow_pte_ptr;



/* ---------- hook 目标 ---------- */
static pid_t         g_hook_pid;
static unsigned long g_hook_addr;   /* 精确函数入口（已 strip tag） */
static unsigned long g_hook_page;
static bool          g_hook_armed;

static inline unsigned long strip_user_tag(unsigned long addr)
{
	return addr & ((1UL << 48) - 1);
}

static inline unsigned long page_of(unsigned long addr)
{
	return strip_user_tag(addr) & PAGE_MASK;
}

static inline pte_t pte_set_uxn(pte_t pte)
{
	pte_val(pte) |= PTE_UXN;
	return pte;
}

static inline pte_t pte_clear_uxn(pte_t pte)
{
	pte_val(pte) &= ~PTE_UXN;
	return pte;
}





/*
 * 在 abort / kprobe 上下文里清 UXN：
 *  - 不能用 mmap_read_lock（会睡眠 / 死锁）
 *  - 权限错误说明页一定在页表里且 present，直接走页表即可
 *  - 只拿 pte 自旋锁
 */
static __nocfi int clear_uxn_nolock(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t old, new;
	unsigned long va = strip_user_tag(addr);

	if (!mm)
		return -EINVAL;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return -EFAULT;

	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		return -EFAULT;

	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		return -EFAULT;

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return -EFAULT;

	/* 大页/THP：本最简版不处理（5.10 无 pmd_leaf） */
	if (pmd_trans_huge(*pmd))
		return -EOPNOTSUPP;

	ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
	if (!ptep)
		return -EFAULT;

	old = *ptep;
	if (!pte_present(old)) {
		pte_unmap_unlock(ptep, ptl);
		return -EFAULT;
	}

	new = pte_clear_uxn(old);
	set_pte(ptep, new);
	pte_unmap_unlock(ptep, ptl);

	/* 无 vma 时用 mm 级刷 TLB，比死锁安全 */
	flush_tlb_mm(mm);
	return 0;
}

/* 武装路径：进程上下文相对宽松，可用 follow_pte + mmap 读 */
static __nocfi int set_uxn_locked(struct mm_struct *mm, unsigned long addr, bool set)
{
	struct vm_area_struct *vma;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t old_pte, new_pte;
	unsigned long va = strip_user_tag(addr);
	int ret;

	mmap_read_lock(mm);

	vma = find_vma(mm, va);
	if (!vma || va < vma->vm_start) {
		ret = -EFAULT;
		goto out;
	}

	ret = follow_pte_ptr(mm, va, &ptep, &ptl);
	if (ret)
		goto out;

	old_pte = *ptep;
	if (!pte_present(old_pte)) {
		spin_unlock(ptl);
		ret = -EFAULT;
		goto out;
	}

	new_pte = set ? pte_set_uxn(old_pte) : pte_clear_uxn(old_pte);
	set_pte(ptep, new_pte);
	spin_unlock(ptl);
	flush_tlb_page(vma, va);
	ret = 0;
out:
	mmap_read_unlock(mm);
	return ret;
}

/*
 * AArch64 AAPCS：整型/指针参数前 8 个在 x0..x7，对应 uregs->regs[0..7]。
 * 第 9 个及以后在用户栈上（uregs->sp）。
 * 浮点参数在 v0..v7，需要 fpsimd 状态，这里先不处理。
 *
 * 注意：UXN 是按“页”陷阱的。只有 far == 函数入口时，寄存器里才是该函数的入参；
 * 若先执行了同页其它代码，也会 fault，但那时 x0..x7 不是目标函数的参数。
 */
static void dump_user_args(struct pt_regs *uregs, unsigned long far)
{
	u8 buf[0x40];
	if (!uregs)
		return;

	pr_info("pte_test: args@0x%lx pc=0x%lx lr=0x%lx sp=0x%lx\n",
		far, uregs->pc, uregs->regs[30], uregs->sp);
	pr_info("pte_test: x0=%lx x1=%lx x2=%lx x3=%lx\n",
		uregs->regs[0], uregs->regs[1],
		uregs->regs[2], uregs->regs[3]);
	pr_info("pte_test: x4=%lx x5=%lx x6=%lx x7=%lx\n",
		uregs->regs[4], uregs->regs[5],
		uregs->regs[6], uregs->regs[7]);


	memset(buf, 0, sizeof(buf));
	if (copy_from_user(buf, (const void __user *)uregs->regs[1], 0x40)) {
		pr_info("binder_test: copy_from_user payload failed "
			"(buf=0x%lx len=%zu)\n", uregs->regs[1], 0x40);
		return;
	}

	print_hex_dump(KERN_INFO, "pte_test : ", DUMP_PREFIX_OFFSET,
		       16, 1, buf, 0x40, true);
}

/*
 * do_mem_abort(far, esr, regs) ：regs 是用户态寄存器快照。
 * 命中后可先读参数，再清 UXN；return 0 让原函数继续。
 */
static __nocfi int ptehook_handle_abort(unsigned long far, unsigned long esr,
					struct pt_regs *uregs)
{
	unsigned int ec = (esr >> 26) & 0x3F;
	unsigned int ifsc = esr & 0x3F;
	unsigned long far_va = strip_user_tag(far);
	unsigned long far_page = page_of(far_va);
	int ret;

	/* 未武装或不在目标页：尽快返回 */
	if (!g_hook_armed || far_page != g_hook_page)
		return 0;

	/* 只处理 EL0 取指 + 权限错误 */
	if (ec != 0x20 || (ifsc & 0x3C) != 0x0C)
		return 0;

	if (!current->mm)
		return 0;

	/*
	 * UXN 按页生效：同页里比目标更靠前的函数（例如 MD5Init）会先 fault。
	 * 只有 far == 函数入口时才读参数并解除陷阱；
	 * 其它同页地址也必须清 UXN，否则会死循环，但不会当成目标命中。
	 */
	if (far_va == g_hook_addr) {
		pr_info("pte_test: HIT func far=0x%lx esr=0x%lx tgid=%d\n",
			far_va, esr, task_tgid_nr(current));
		dump_user_args(uregs, far_va);
	} else {
		pr_info("pte_test: same-page early far=0x%lx want=0x%lx (not target)\n",
			far_va, g_hook_addr);
	}

	ret = clear_uxn_nolock(current->mm, far_va);
	if (ret == 0) {
		g_hook_armed = false; /* one-shot */
		pr_info("pte_test: UXN cleared, resume\n");
	} else {
		pr_err("pte_test: clear_uxn failed %d\n", ret);
	}
	return 0;
}



/**
	修改指定地址所在虚拟地址的 PTE 值
*/
int __nocfi modify_process_pte(HookTask *hooktask)
{
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long va = strip_user_tag(hooktask->address);
	int ret;

	task = get_task_by_pid(hooktask->pid);
	if (!task) {
		pr_err("pte_test: task %d not found\n", hooktask->pid);
		return -1;
	}

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) {
		pr_err("pte_test: mm NULL\n");
		return -1;
	}

	ret = set_uxn_locked(mm, va, true);
	if (ret) {
		pr_err("pte_test: set UXN failed %d\n", ret);
		mmput(mm);
		return ret;
	}

	g_hook_pid  = hooktask->pid;
	g_hook_addr = va;
	g_hook_page = page_of(va);
	smp_wmb();
	g_hook_armed = true;

	pr_info("pte_test: armed pid=%d addr=0x%lx page=0x%lx\n",
		g_hook_pid, g_hook_addr, g_hook_page);
	mmput(mm);
	return 0;
}



static int mem_abort_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long far = regs->regs[0];
	unsigned long esr = regs->regs[1];
	/* do_mem_abort 的第 3 个参数：用户态 pt_regs* */
	struct pt_regs *uregs = (struct pt_regs *)regs->regs[2];

	ptehook_handle_abort(far, esr, uregs);
	return 0; /* 永不改 pc，永不跳过原函数 */
}



//	用于hook do_mem_abort 函数
static struct kprobe mem_abort_kp;
static int install_mem_abort_hook(void)
{
	int ret;

	memset(&mem_abort_kp, 0, sizeof(mem_abort_kp));
	mem_abort_kp.symbol_name = "do_mem_abort";
	mem_abort_kp.pre_handler = mem_abort_pre;
	ret = register_kprobe(&mem_abort_kp);
	if (ret < 0) {
		pr_err("pte_test: register_kprobe(do_mem_abort) failed %d\n", ret);
		return ret;
	}
	pr_info("pte_test: do_mem_abort hooked\n");
	return 0;
}


