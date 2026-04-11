# CLANG_PATH := /data/workspace/gki/prebuilts/clang/host/linux-x86/clang-r450784e
# export PATH := ${CLANG_PATH}/bin:${PATH}
# export PATH=/data/workspace/gki/prebuilts/clang/host/linux-x86/clang-r450784e/bin:${PATH}



# 如果你的模块位于内核源码树之外，使用这个模板
# 将 KERNEL_DIR 指向你之前编译过的内核源码路径
KER := /home/liuxin/pixelKernel/common
obj-m := kprophook.o

# ccflags-y += -Wno-error=missing-attributes


all:

	rm -rf *.ko

	make CC=clang LLVM=1 LLVM_IAS=1  ARCH=arm64 -C ${KER}  M=${PWD} modules
	rm -rf *.mod* *.sym* .*.cmd *.order *.o
# 	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean