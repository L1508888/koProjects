#ifndef PTE_GHOST_H
#define PTE_GHOST_H

 #include <linux/types.h>
 #include <linux/mm.h>


typedef struct{
     /* 申请 / 释放连续物理页（实际解析的是 __get_free_pages / free_pages） */
    unsigned long (*get_free_pages)(unsigned int gfp_mask, unsigned int order);
    void (*free_pages)(unsigned long addr, unsigned int order);
    /* 查找 VMA（找空洞用） */
    struct vm_area_struct *(*find_vma)(struct mm_struct *mm, unsigned long addr);
    /* 遍历页表并回调（往空洞里安装 / 清除 PTE） */
    int (*apply_to_page_range)(struct mm_struct *mm, unsigned long addr,
                               unsigned long size, pte_fn_t fn, void *data);
    /* 在所有 CPU 上执行回调（释放前冲刷流水线用） */
    void (*on_each_cpu)(void (*func)(void *), void *info, int wait);
    /* D-cache 写回（实际解析的是 __flush_dcache_area，写代码后同步 i-cache 用） */
    void (*flush_dcache_area)(void *addr, size_t len);
}GhostSymbolData;



typedef struct{
    struct task_struct *task;           /* 目标进程 */
    struct mm_struct   *mm;             /* 目标进程地址空间（进程退出后悬垂，判活再用） */
    unsigned long       kaddr;          /* 物理页的内核线性映射地址（写代码走这里） */
    unsigned long       vaddr;          /* ghost 页在目标进程中的虚拟地址 */
    unsigned long       pfn;            /* 起始页帧号 */
    uint64_t            installed_pte;  /* 实际写入的 PTE 值 */
    int                 order;          /* 阶数：0=4KB, 1=8KB, 3=32KB... */
    unsigned long       alloc_size;     /* 申请的总字节数 */
    int                 installed;      /* 是否已安装 */
    int                 offsets[1024];  /* 原页第 i 条指令 → ghost 页第 offsets[i] 字 */
}GhostMemoryData;


void init_ghost(GhostSymbolData* ghostSymbol);


//  用于申请内存
int ghost_alloc(struct task_struct *task,
                 struct mm_struct   *mm,
                  unsigned long       near,
                 unsigned long       range,
                 uint64_t            pte_template,
                 int num_pages,
                GhostMemoryData* out);


//  用于释放内存
int ghost_free(GhostMemoryData *ghostMemory);

int ghost_sync_icache(GhostMemoryData *ghostMemory, unsigned long code_bytes);

void ghost_release_phys(GhostMemoryData *ghostMemory);
// int ghost_write();


#endif