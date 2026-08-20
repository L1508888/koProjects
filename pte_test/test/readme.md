



这里写一些测试用例


## mem_test.c

主动对 do_mem_abort 函数进行hook，查看进入这个函数时候的参数参数。主要是为了后续的pte 学习一下。


## hook_test.c

对 kretprobe、register_kretprobe 的简单使用。



## pte_m.c

和用户态程序进行配合，主动设置进程中的某个地址所在也的 pte 为不可执行，然后在 do_mem_abort 再将 pte 设置为可执行。