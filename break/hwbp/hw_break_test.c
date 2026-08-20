/*
 * 不依赖 APK 的命令行自测（推荐先用这个验证 ko）：
 *
 *   $NDK/toolchains/llvm/prebuilt/.../bin/aarch64-linux-android28-clang++ \
 *       standalone_test.cpp -o hwbptest_standalone -static-libstdc++
 *   adb push hwbptest_standalone /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/hwbptest_standalone
 *   adb shell /data/local/tmp/hwbptest_standalone
 *
 * 若普通 app 被 SELinux 拦住 ptrace，用 root 跑 standalone 更稳：
 *   adb shell su -c /data/local/tmp/hwbptest_standalone
 */

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>

#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

struct my_user_hwdebug_state {
    uint32_t dbg_info;
    uint32_t pad;
    struct {
        uint64_t addr;
        uint32_t ctrl;
        uint32_t pad;
    } dbg_regs[16];
};

static constexpr int kMaxBrps = 6;

static size_t state_len_for_slots(int slots) {
    return offsetof(my_user_hwdebug_state, dbg_regs) +
           (size_t)slots * sizeof(((my_user_hwdebug_state *)0)->dbg_regs[0]);
}

int main() {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        for (;;) pause();
    }

    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child not stopped\n");
        return 1;
    }

    my_user_hwdebug_state st{};
    struct iovec iov{&st, sizeof(st)};


    //  读取关于硬件断点的信息
    printf("== Test1 GETREGSET ==\n");
    if (ptrace(PTRACE_GETREGSET, child, (void *)(uintptr_t)NT_ARM_HW_BREAK, &iov) != 0) {
        perror("GETREGSET");
    } else {
        printf("dbg_info=0x%x slots=%u\n", st.dbg_info, st.dbg_info & 0xff);
    }


    //  先设置一个硬件断点，然后读硬件断点信息
    printf("== Test2 SET+GET magic ==\n");
    memset(&st, 0, sizeof(st));
    st.dbg_regs[0].addr = 0x1000deadULL;
    st.dbg_regs[0].ctrl = 0x1 | (0x2 << 1) | (0xf << 5);
    iov.iov_base = &st;
    iov.iov_len = state_len_for_slots(1);
    if (ptrace(PTRACE_SETREGSET, child, (void *)(uintptr_t)NT_ARM_HW_BREAK, &iov) != 0)
        perror("SETREGSET");
    else
        printf("SET ok\n");

    memset(&st, 0, sizeof(st));
    iov.iov_base = &st;
    iov.iov_len = sizeof(st);
    if (ptrace(PTRACE_GETREGSET, child, (void *)(uintptr_t)NT_ARM_HW_BREAK, &iov) != 0)
        perror("GET after SET");
    else
        printf("GET addr=0x%llx (expect 0x1000dead)\n",
               (unsigned long long)st.dbg_regs[0].addr);



    //  故意设置超过固定上限的硬件断点
    printf("== Test3 SET max+1 ENOSPC ==\n");
    memset(&st, 0, sizeof(st));
    for (int i = 0; i < kMaxBrps + 1; i++) {
        st.dbg_regs[i].addr = 0x2000 + (uint64_t)i * 0x10;
        st.dbg_regs[i].ctrl = 0x1 | (0x2 << 1) | (0xf << 5);
    }
    iov.iov_base = &st;
    iov.iov_len = state_len_for_slots(kMaxBrps + 1);
    errno = 0;
    if (ptrace(PTRACE_SETREGSET, child, (void *)(uintptr_t)NT_ARM_HW_BREAK, &iov) != 0)
        printf("SET overflow: %s (expect ENOSPC)\n", strerror(errno));
    else
        printf("SET overflow unexpectedly succeeded\n");

    ptrace(PTRACE_DETACH, child, nullptr, nullptr);
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    return 0;
}
