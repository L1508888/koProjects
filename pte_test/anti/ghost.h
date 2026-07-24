

 #include <linux/types.h>
 #include <linux/mm.h>


typedef struct{
    unsigned long (*get_free_pages)(unsigned int gfp_mask, unsigned int order);
    void (*free_pages)(unsigned long addr, unsigned int order)
    void* find_vma;
    int (*apply_to_page_range)(struct mm_struct *mm, unsigned long addr, 
                        unsigned long size, pte_fn_t fn, void *data)
    void* on_each_cpu;
}GhostSymbolData;



typedef struct{

    struct task_struct *task;
    struct mm_struct   *mm;
    unsigned long       kaddr;          //  直接申请得到的物理地址
    unsigned long       vaddr;          //  物流地址转换得到的虚拟地址
    unsigned long       pfn;            //  pfn
    uint64_t            installed_pte;  //  写入的pte 值
    int                 order;          //  0=4KB, 1=8KB, etc.
    unsigned long       alloc_size;     //  申请的内存大小，以字节为单位
    int                 installed;      //  是否安装的标识

}GhostMemoryData;


void init_ghost();


//  用于申请内存
int ghost_alloc(struct task_struct *task,
                 struct mm_struct   *mm,
                  unsigned long       near,
                 unsigned long       range,
                 uint64_t            pte_template,
                 int num_pages,
                GhostMemoryData* out);


//  用于释放内存
int ghost_free();


int ghost_write();