

#include "ghost.h"
#include <asm/barrier.h>
#include <asm/page.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <linux/module.h>

#define ARM64_PFN_MASK (0x0000FFFFFFFFF000UL) /* bits [47:12] */

void init_ghost() {}

GhostSymbolData ghost_symbol;

static int pages_to_order(int n) {
  int order = 0;
  while ((1 << order) < n)
    order++;
  return order;
}

struct install_ctx {
  uint64_t pte_val; //  用于写入的pte 值
  int written;
};

static int install_pte_cb(pte_t *pte, unsigned long addr, void *data) {
  struct install_ctx *c = (struct install_ctx *)data;
  uint64_t *p = (uint64_t *)pte;

  // pte 非0 并且可用的情况下进行修改，否则返回错误
  if (*p != 0 && (*p & PTE_VALID)) {
    return -EEXIST;
  }

  *p = c->pte_val;
  c->written = 1;
  return 0;
}

struct clear_ctx {
  int cleared;
};

static int clear_pte_cb(pte_t *pte, unsigned long addr, void *data) {
  struct clear_ctx *c = (struct clear_ctx *)data;
  uint64_t *p = (uint64_t *)pte;
  *p = 0;
  c->cleared = 1;
  return 0;
}

int ghost_alloc(struct task_struct *task, struct mm_struct *mm,
                unsigned long near, unsigned long range, uint64_t pte_template,
                int num_pages, GhostMemoryData *out) {

  int order, i, j, ret;
  unsigned long kva;

  struct install_ctx ictx; //  用于安装pte
  struct clear_ctx cctx;   //  用于清除安装的pte
  uint64_t asid;

  order = pages_to_order(num_pages);
  // 直接申请物理页
  kva = ghost_symbol.get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
  if (!kva) {

    return -ENOMEM;
  }

  pa_base = (uint64_t)virt_to_phys((void *)kva);

  //  在目标进程目标页面附近寻找空洞
  vaddr = find_hole_near(mm, near, range, 1 << order);
  if (!vaddr) {
    ghost_symbol.free_pages(kva, order);
    return -ENOSPC;
  }

  //  安装pte
  for (i = 0; i < (1 << order); i++) {
    uint64_t page_pa = pa_base + (uint64_t)i * 0x1000;
    //  保留模板 PTE 的所有属性位，仅替换物理页帧号（PFN）部分
    new_pte = (pte_template & ~ARM64_PFN_MASK) | (page_pa & ARM64_PFN_MASK);
    //  确保页表项有效（VALID）、类型为普通页（TYPE_PAGE）、访问标志置位（AF，避免首次访问触发缺页异常）
    new_pte |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF;
    //  清除 UXN（Unprivileged Execute Never）位
    new_pte &= ~PTE_UXN;
    //  清除 GP（Guarded Page）位
    new_pte &= ~(1UL << 50);

    ret = ghost_symbol.apply_to_page_range(mm, vaddr + () i * 0x1000, 0x1000,
                                           install_pte_cb, &ictx);
    //  如果安装不成功，需要进行回退，将已经安装好的卸载掉
    if (ret || !ictx.written) {

      for (j = 0; j < i; j++) {
        cctx.cleared = 0;
        ghost_symbol.apply_to_page_range(mm, vaddr + () j * 0x1000, 0x1000,
                                         clear_pte_cb, &cctx);
      }
      ghost_symbol.free_pages(kva, order);
      return ret;
    }
  }

  /* Step 5: TLB flush — 精确失效，避免全局核爆 */
  asid = mm->context.id & 0xFFFFUL;

  if (asid && (1 << order) > 8) {
    /* 页数较多时：按 ASID 刷新整个进程 */
    unsigned long arg = asid << 48;
    asm volatile("tlbi aside1is, %0\n\t"
                 "dsb ish\n\t"
                 "isb\n\t" ::"r"(arg)
                 : "memory");
  } else {
    /* 页数较少时：逐页精确刷新，All ASID, Last Level */
    for (j = 0; j < (1 << order); j++) {
      unsigned long va = vaddr + (unsigned long)j * PAGE_SIZE;
      asm volatile("tlbi vaale1is, %0\n\t" ::"r"(va >> 12));
    }
    asm volatile("dsb ish\n\t"
                 "isb\n\t" ::
                     : "memory");
  }

  out->task = task;
  out->mm = mm;
  out->vaddr = vaddr;
  out->kaddr = kva;
  out->pfn = pa_base >> 12;
  out->installed_pte = new_pte;
  out->order = order;
  out->alloc_size = (unsigned long)(1 << order) * 0x1000;
  out->installed = 1;
  return 0;
}

int ghost_free(GhostMemoryData *ghostMemory) {
  int page_count, i;
  uint64_t asid;
  if (!ghostMemory || !ghostMemory->installed) {
    return 0;
  }

  /* ---------- 1. 生命周期保护 ---------- */
  /* mmget_not_zero：防止目标进程在此期间退出并释放 mm_struct */
  if (!mmget_not_zero(mm)) {
        return -ESRCH;
  }

  page_count = 1 << (ghostMemory->order);
asid = mm->context.id & 0xFFFFUL;


/* ---------- 2. 页表锁 ---------- */
    /* apply_to_page_range 会修改页表（甚至分配/释放页表页），
     * 必须持有 mmap_write_lock，与目标进程的用户态 mmap/munmap 互斥 */
    mmap_write_lock(mm);

  for (i = 0; i < page_count; i++) {
    struct clear_ctx cctx;
    cctx.cleared = 0;
    ghost_symbol.apply_to_page_range(ghostMemory->mm,
                                     ghostMemory->vaddr + i * 0x1000, 0x1000,
                                     clear_pte_cb, &cctx);
  }

  /* ---------- 4. 精确 TLB 刷新（替代 vmalle1is） ---------- */
  if (asid && page_count > 8) {
    /* 页数较多时：按 ASID 刷新整个进程。
     * 只影响该 mm 的映射，其他进程/内核 TLB 完全不受影响。 */
    unsigned long asid_arg = asid << 48;
    asm volatile("tlbi aside1is, %0\n\t"
                 "dsb ish\n\t"
                 "isb\n\t" ::"r"(asid_arg)
                 : "memory");
  } else {
    /* 页数较少（或 ASID 未分配）：逐页 VA 刷新。
     * vaale1is = VA All ASID Last Level EL1 Inner Shareable
     * 只刷新这几页的最后一级 TLB（PTE），不碰中间页表 walk cache */
    for (i = 0; i < page_count; i++) {
      unsigned long va = ghostMemory->vaddr + (unsigned long)i * PAGE_SIZE;
      asm volatile("tlbi vaale1is, %0" ::"r"(va >> 12));
    }
    asm volatile("dsb ish\n\t"
                 "isb\n\t" ::
                     : "memory");
  }


  /* ---------- 5. I-cache 失效（释放执行中代码页的必要措施） ---------- */
    /* ARM64 没有"按物理地址失效 I-cache"的指令，也没有 ic ivau 的广播版本。
     * 由于 ghost 页可能正被任意 CPU 执行，必须确保所有 CPU 的 I-cache
     * 中不再缓存这些物理地址的指令。ic ialluis 是 Inner Shareable 域内
     * 唯一能让远程 CPU 失效 I-cache 的广播指令。 */
    asm volatile(
        "ic ialluis\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );


    /* ---------- 6. IPI Drain：强制所有 CPU 排空流水线 ---------- */
    /* ic ialluis 只保证 I-cache 内容被清掉，但不保证已进入流水线的
     * 指令被丢弃。IPI 强制所有 CPU 陷入异常入口，其硬件语义包含
     * 流水线刷新（等效于 isb）。此后没有任何 CPU 还能执行 ghost 页。 */
    ghost_symbol.on_each_cpu(ghost_drain_ipi, NULL, 1);

    mmap_write_unlock(mm);


    /* ---------- 7. 释放物理页 ---------- */
    ghost_symbol.free_pages(ghostMemory->kaddr, ghostMemory->order);

     /* ---------- 8. 清理元数据 ---------- */
    ghostMemory->installed = 0;
    ghostMemory->kaddr = 0;
    ghostMemory->vaddr = 0;
    ghostMemory->mm = NULL;
    ghostMemory->task = NULL;
    
    mmput(mm);
    return 0;
}