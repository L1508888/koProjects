# ============================================================================
# ecap_tls.ko —— Android GKI 5.10 (arm64) 内核模块构建
#
# 用法：
#   make            编译内核模块 ecap_tls.ko
#   make user       编译用户态 ecapctl（需要 NDK）
#   make all        两者都编
#   make clean      清理生成物
# ============================================================================

CLANG_PATH := /home/liuxin/pixelKernel/prebuilts/clang/host/linux-x86/clang-r450784e
export PATH := ${CLANG_PATH}/bin:${PATH}

# 内核源码树 与 已经编译好的 out 目录（必须提供 Module.symvers）
KER := /home/liuxin/pixelKernel/common
MOR := /home/liuxin/pixelKernel/out/android13-5.10/common

# ---------------------------------------------------------------------------
# 模块
# ---------------------------------------------------------------------------
obj-m += ecap_tls.o
ecap_tls-y := \
	kernel/ecap_main.o \
	kernel/ecap_ksym.o \
	kernel/ecap_dev.o \
	kernel/ecap_uprobe.o \
	kernel/ecap_nf.o

# 头文件目录：include/ 放 UAPI，kernel/ 放内核侧私有头
ccflags-y += -I$(src)/include -I$(src)/kernel

# GKI 的 CFI 与内核通用寄存器限制：模块不允许使用 FP/SIMD 寄存器
ccflags-y += -mgeneral-regs-only

# ---------------------------------------------------------------------------
# 用户态控制端
# ---------------------------------------------------------------------------
NDK := /home/liuxin/Android/Sdk/ndk/25.1.8937393
NDK_BIN := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin
# Android 10+ 才有 /apex/com.android.conscrypt，API 29 起可用
ANDROID_API := 29
CC_ANDROID := $(NDK_BIN)/aarch64-linux-android$(ANDROID_API)-clang

USER_SRC := user/ecapctl.c
USER_LIBS := user/ecap_elf.c user/ecap_xz.c user/ecap_lzma.c user/ecap_pcapng.c
USER_DEPS := $(USER_SRC) $(USER_LIBS) include/ecap_uapi.h \
	     user/ecap_elf.h user/ecap_xz.h user/ecap_pcapng.h
USER_OUT := user/ecapctl

# 目标设备是 aarch64 Android
user: $(USER_OUT)

$(USER_OUT): $(USER_DEPS)
	$(CC_ANDROID) -O2 -Wall -Wextra -Iinclude -Iuser -o $@ \
		$(USER_SRC) $(USER_LIBS) -ldl
	@echo "built: $@ (aarch64 android$(ANDROID_API))"

# 本机 x86_64 版本：只用于开发机上跑单元逻辑（不能连真机）
USER_HOST := user/ecapctl_host
host: $(USER_HOST)

$(USER_HOST): $(USER_DEPS)
	$(CC) -O2 -Wall -Wextra -Iinclude -Iuser -o $@ \
		$(USER_SRC) $(USER_LIBS) -ldl
	@echo "built: $@ (host x86_64, for testing only)"

# ---------------------------------------------------------------------------
# 设备侧测试程序
#
# tls_probe_test : 直接 dlopen 系统 libssl，造一个没有真实连接的 SSL 对象，
#                  用来验证 write 入口 hook 和 read 返回值为负时的处理。
# tls_read_test  : 本地回环 + 自签名证书，产生真实的 TLS 双向读写，
#                  用来验证 read 正向路径（能读到正数字节）。
# ---------------------------------------------------------------------------
DEV_TEST_SRCS := tests/tls_probe_test.c tests/tls_read_test.c
DEV_TESTS := $(patsubst tests/%.c,user/%,$(DEV_TEST_SRCS))

devtests: $(DEV_TESTS)

user/tls_probe_test: tests/tls_probe_test.c
	$(CC_ANDROID) -O2 -Wall -Wextra -o $@ $<
	@echo "built: $@ (aarch64 android$(ANDROID_API))"

user/tls_read_test: tests/tls_read_test.c
	$(CC_ANDROID) -O2 -Wall -Wextra -o $@ $< -ldl
	@echo "built: $@ (aarch64 android$(ANDROID_API))"

# ---------------------------------------------------------------------------
# 单元测试
#
# test_insn 直接 #include ../user/ecapctl.c，把 static 的
# a64_check_probeable() 拉进来做白盒测试。用 -Dmain=ecapctl_main
# 避免两个 main 冲突。
# ---------------------------------------------------------------------------
TEST_INSN := /tmp/ecap_test_insn
TEST_LZMA := /tmp/ecap_test_lzma

test: $(TEST_INSN) test-lzma
	@$(TEST_INSN) 2>/dev/null

$(TEST_INSN): tests/test_insn.c $(USER_SRC) $(USER_LIBS) include/ecap_uapi.h
	$(CC) -O2 -Wall -Wextra -Iinclude -Iuser -Dmain=ecapctl_main \
		-o $@ tests/test_insn.c $(USER_LIBS) -ldl

# ---------------------------------------------------------------------------
# LZMA 解压器测试
#
# 用例与比对逻辑都在 tests/run_lzma_tests.py 里（用 python 的 lzma 模块
# 当参照实现）。这里只负责编译出被测程序。
# ---------------------------------------------------------------------------
test-lzma: $(TEST_LZMA)
	@python3 tests/run_lzma_tests.py $(TEST_LZMA)

$(TEST_LZMA): tests/test_lzma.c user/ecap_lzma.c user/ecap_lzma.h
	$(CC) -O2 -Wall -Wextra -Iuser -o $@ tests/test_lzma.c user/ecap_lzma.c

# ---------------------------------------------------------------------------
# 内核模块
# ---------------------------------------------------------------------------
modules:
	$(MAKE) ARCH=arm64 -C $(KER) O=$(MOR) M=$(PWD) \
		CC=clang LLVM=1 LLVM_IAS=1 modules
	@# 清掉中间产物，只留 .ko
	rm -rf *.mod* *.sym* .*.cmd *.order *.o kernel/*.o kernel/.*.cmd

all: modules user devtests

clean:
	@rm -rf *.ko *.mod* *.sym* .*.cmd *.order *.o
	@rm -rf kernel/*.o kernel/.*.cmd
	@rm -f $(USER_OUT) $(USER_HOST)
	@rm -f $(DEV_TESTS)
	@rm -f $(TEST_INSN) $(TEST_LZMA)
	@rm -f /tmp/ecap_lzma_*.xz

.PHONY: modules all user host devtests clean test
