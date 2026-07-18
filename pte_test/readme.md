
因为pte hook 过程中会涉及到很多内核操作，在test 目录下进行函数的测试。




## do_mem_abort hook

AI 判断 kprobe 无法hook do_mem_abort 这个函数，通过查看内核源码， 在 arch/arm64/mm/fault.c  文件中确实存在 NOKPROBE_SYMBOL(do_mem_abort);  但是我在测试过程中，发现是可以直接使用 kprobe 对这个函数进行hook 的。





