


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
