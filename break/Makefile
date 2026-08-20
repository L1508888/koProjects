
CLANG_PATH := /home/liuxin/pixelKernel/prebuilts/clang/host/linux-x86/clang-r450784e
export PATH := ${CLANG_PATH}/bin:${PATH}




# 如果你的模块位于内核源码树之外，使用这个模板
# 将 KERNEL_DIR 指向你之前编译过的内核源码路径
KER := /home/liuxin/pixelKernel/common
MOR := /home/liuxin/pixelKernel/out/android13-5.10/common
# KER := /home/liuxin/gitProjects/pixelKernel/private/gs-google/include





## 为redmi 设备编译内核模块
# CLANG_PATH := /home/liuxin/aosp_clang/bin
# export PATH := ${CLANG_PATH}/bin:${PATH}
# KERNEL_DIR := /home/liuxin/skyKernel/gki-common/out



obj-m := break.o


ccflags-y=-mgeneral-regs-only


modules:
# 	rm -rf *.ko
	make ARCH=arm64 -C ${KER} O=${MOR} M=${PWD} CC=clang LLVM=1 LLVM_IAS=1 modules
	rm -rf *.mod* *.sym* .*.cmd *.order *.o
	
# 	adb shell 'su echo 0 > /proc/sys/kernel/kptr_restrict'
# 	adb push break.ko /data/local/tmp/
# 	adb shell 'su insmod /data/local/tmp/break.ko'
# 	adb shell 'su dmesg | tail'

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean



# 如果你的模块位于内核源码树之外，使用这个模板
# 将 KERNEL_DIR 指向你之前编译过的内核源码路径
# KER := 
# obj-m := break.o



# ccflags-y += -Wno-error=missing-attributes
# all: modules

# modules:
# 	rm -rf *.ko
# 	$(MAKE) -C $(KER) M=$(PWD) LLVM=1 LLVM_IAS=1 \
# 		ARCH=$(ARCH) CC=clang \
# 		modules
# 	rm -rf *.mod* *.sym* .*.cmd *.order *.o


# clean:
# 	make -C $(KDIR) M=$(PWD) clean