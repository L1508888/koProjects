


#include <linux/types.h>

#define DBI_TARGET_SIZE      4096
#define DBI_TARGET_INSNS     (DBI_TARGET_SIZE / 4)   /* 1024 */
#define DBI_GHOST_MAX_INSNS  (DBI_TARGET_INSNS * 8)  /* 8192 worst case */
#define DBI_GHOST_MAX_BYTES  (DBI_GHOST_MAX_INSNS * 4)


/* Scratch register used for far jumps (X17 / IP1) */
#define DBI_SCRATCH_REG      17