

CLANG_PATH := /home/liuxin/pixelKernel/prebuilts/clang/host/linux-x86/clang-r450784e
export PATH := ${CLANG_PATH}/bin:${PATH}



KER := /home/liuxin/pixelKernel/common
MOR := /home/liuxin/pixelKernel/out/android13-5.10/common



obj-m := pteHook.o




modules:
	make ARCH=arm64 -C ${KER} O=${MOR} M=${PWD} CC=clang LLVM=1 LLVM_IAS=1 modules
	rm -rf *.mod* *.sym* .*.cmd *.order *.o
	

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean