CLANG_PATH := /home/liuxin/aosp13/prebuilts/clang/host/linux-x86/clang-r450784d
export PATH := ${CLANG_PATH}/bin:${PATH}
# export PATH=/data/workspace/gki/prebuilts/clang/host/linux-x86/clang-r450784e/bin:${PATH}

# export PATH=/home/liuxin/aosp13/prebuilts/clang/host/linux-x86/clang-r450784d/bin:$PATH


# 如果你的模块位于内核源码树之外，使用这个模板
# 将 KERNEL_DIR 指向你之前编译过的内核源码路径
KER := /home/liuxin/pixelKernel/common
obj-m := hello.o

# ccflags-y += -Wno-error=missing-attributes


all:

	make ARCH=arm64 -C ${KER} M=${PWD} CC=clang LLVM=1 LLVM_IAS=1    modules
	rm -rf *.mod* *.sym* .*.cmd *.order *.o
# 	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean