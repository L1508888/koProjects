
typedef struct {
	unsigned long address;
	pid_t         pid;
} HookTask;



typedef int (*follow_pte_t)(struct mm_struct *mm, unsigned long address,
			    pte_t **ptepp, spinlock_t **ptlp);




int init_pte_m(follow_pte_t func_ptr);



int modify_process_pte(HookTask *hooktask);