## 说明
这里的代码主要是为了防止用户态用来检测硬件断点，如果用户态自己使用ptrace 注册硬件断点，会主动返回注册结果，但实际上并不会进行注册，当用户态查询硬件断点注册情况的时候，会直接返回一个自己的记录。

如果用户态主动注册大于6个的硬件断点数量，返回一个错误。

这其实还是导致了一个问题，比如用户态主动注册一个硬件断点，用来判断某个函数的执行逻辑，但这里并不会进行实际注册就会产生问题。这种情况下只能具体问题具体分析了。


## ptrace 函数说明


~~~
#include <sys/ptrace.h>

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
~~~


NT_ARM_HW_BREAK     硬件断点寄存器              struct user_hwdebug_state
NT_ARM_HW_WATCH     硬件观察点寄存器            struct user_hwdebug_state


~~~
struct user_hwdebug_state {
    __u32 dbg_info;          // 数量信息（低 8 位为数量）
    __u32 pad;
    struct {
        __u64 addr;          // 断点地址
        __u32 ctrl;          // 控制寄存器（触发类型、长度、权限等）
        __u32 pad;
    } dbg_regs[0];           // 变长数组
};
~~~



