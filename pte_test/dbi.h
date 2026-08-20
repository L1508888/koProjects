
#ifndef PTE_DBI_H
#define PTE_DBI_H

#include <linux/types.h>

#define DBI_TARGET_SIZE      4096
#define DBI_TARGET_INSNS     (DBI_TARGET_SIZE / 4)   /* 1024：单页指令条数 */
#define DBI_GHOST_MAX_INSNS  (DBI_TARGET_INSNS * 8)  /* ghost 最坏按 8 倍膨胀预留 */
#define DBI_GHOST_MAX_BYTES  (DBI_GHOST_MAX_INSNS * 4)


/* 前向分支回填队列容量（与 dbi_page_ctx.pending 数组一致） */
#define DBI_MAX_PENDING_BRANCHES 512

/* 远跳转使用的暂存寄存器（X17 / IP1） */
#define DBI_SCRATCH_REG      17


/* 前高地址分支占位记录：目标指令的 ghost 偏移尚未生成，先占位后回填 */
struct dbi_pending_branch {
    int       ghost_idx;        /* 占位符在 ghost 页中的位置（字索引） */
    uint32_t  enc_template;     /* 指令模板（imm 部分先填 0） */
    uint16_t  target_tidx;      /* 跳转目标在原始页中的指令索引 */
    uint8_t   kind;             /* 0=B.cond, 1=CBZ/CBNZ, 2=TBZ/TBNZ, 3=B */
};



struct dbi_page_ctx {
    uint64_t  target_page;      /* 原始页在用户空间的虚拟地址 */
    uint64_t  ghost_page;       /* ghost 页在用户空间的虚拟地址 */
    const uint32_t *orig;       /* 原始 1024 条指令的内核缓冲区 */
    uint32_t *ghost;            /* 重编译输出缓冲区 */
    int       ghost_capacity;   /* ghost 缓冲区容量（字数） */
    int       ghost_count;      /* 已写入 ghost 的字数 */

    uint16_t  offset_map[1024]; /* 核心映射表：原页第 i 条 → ghost 第 j 字 */

    struct dbi_pending_branch pending[DBI_MAX_PENDING_BRANCHES];
    int       n_pending;        /* pending 队列中已记录的条数 */

    /* 统计计数器 */
    int fixed;              /* 直接修正偏移成功的 */
    int expanded;           /* 被展开成多条指令的 */
    int passthrough;        /* 无需修改直接透传的 */
    int failed;             /* 处理失败回退为 NOP 的 */
    int intra_page_fixed;   /* 页内分支直接修正的 */
};



/* 重编译一整页：orig → ghost，并填充 offset_map */
int dbi_recompile_page(struct dbi_page_ctx *ctx);


/* 往 ghost 页中指定位置打补丁（后续插桩用） */
int dbi_patch_ghost(struct dbi_page_ctx *ctx,
                    unsigned target_off,
                    const uint32_t *patch,
                    int patch_count);

/* 原页 PC → ghost 页 PC 换算 */
uint64_t dbi_target_to_ghost_pc(const struct dbi_page_ctx *ctx,
                                uint64_t target_pc);
                                
                                

#endif