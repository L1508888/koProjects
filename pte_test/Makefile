

CLANG_PATH := /home/liuxin/pixelKernel/prebuilts/clang/host/linux-x86/clang-r450784e
export PATH := ${CLANG_PATH}/bin:${PATH}



KER := /home/liuxin/pixelKernel/common
MOR := /home/liuxin/pixelKernel/out/android13-5.10/common

obj-m := pte_main.o

# 组成 pte_test.ko 的各个 .o（可继续追加）
pte_main-objs :=  main.o hookManager.o dbi.o ghost.o callback.o

ccflags-y=-mgeneral-regs-only

modules:
	make ARCH=arm64 -C ${KER} O=${MOR} M=${PWD} CC=clang LLVM=1 LLVM_IAS=1 modules
# 	make ARCH=arm64 -C ${KER} M=${PWD} CC=clang LLVM=1 LLVM_IAS=1 modules
	find . -type f \( -name '*.mod' -o -name '*.mod.c' -o -name '*.mod.o' \
	                -o -name '*.symvers' -o -name '*.order' \
	                -o -name '*.o' -o -name '.*.cmd' \) -delete
	
clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean