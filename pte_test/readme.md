
因为pte hook 过程中会涉及到很多内核操作，在test 目录下进行函数的测试。


用户态指定进程和地址，使用重编译的方式进行hook，这个hook 目前还是有问题，目前只实现了使用 hwbp 的方式进行hook，并没有实现 inline hook 的方式。



## 总体流程

用户态只传入 pid、目标函数地址，hook ptrcl 得到数据。


## main.c 

用来获取符号地址，注册函数 hook 




## hookmanager.c 
用来管理hook record，




## pte_m 

pte_m   用于修改pte、恢复pte。

## do_mem_abort hook

AI 判断 kprobe 无法hook do_mem_abort 这个函数，通过查看内核源码， 在 arch/arm64/mm/fault.c  文件中确实存在 NOKPROBE_SYMBOL(do_mem_abort);  但是我在测试过程中，发现是可以直接使用 kprobe 对这个函数进行hook 的。



## pte_test.c

这个文件中实现了一个简单的内核模块，用于对某个地址对应pte 设置不可执行，然后hook do_mem_abort 函数，在回调中修改pte 设置为可执行。

注意，设置pte 不可执行是以页为单位的，如果目标函数和其他其他函数在同一页内，且其他函数先于目标函数执行，hook 就会出现问题，无法得到真实的hook 结果。因为在目标函数执行之前，pte 已经被恢复成了正常。


