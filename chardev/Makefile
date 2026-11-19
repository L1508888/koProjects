CLANG_PATH := /home/liuxin/pixelKernel/prebuilts/clang/host/linux-x86/clang-r450784e
export PATH := ${CLANG_PATH}/bin:${PATH}




# 如果你的模块位于内核源码树之外，使用这个模板
# 将 KERNEL_DIR 指向你之前编译过的内核源码路径
KER := /home/liuxin/pixelKernel/common
MOR := /home/liuxin/pixelKernel/out/android13-5.10/common


obj-m += hello_chardev.o



ccflags-y += -I$(src)

.PHONY: all clean test tool

all:
	make ARCH=arm64 -C ${KER} O=${MOR} M=${PWD} CC=clang LLVM=1 LLVM_IAS=1 modules
	rm -rf *.mod* *.sym* .*.cmd *.order *.o

	
# 用户态测试程序
tool: test_hello

test_hello: test_hello.c hello_uapi.h
	make -O2 -Wall -Wextra -I. -o $@ test_hello.c

test: test_hello
	sudo insmod hello_chardev.ko || true
	sudo ./test_hello
	sudo rmmod hello_chardev || true

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
