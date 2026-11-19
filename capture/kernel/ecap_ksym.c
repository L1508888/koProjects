// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_ksym.c - 解析 GKI 5.10 上未导出的内核符号
 *
 * 【问题】
 * Android GKI 5.10 打开了 CONFIG_TRIM_UNUSED_KSYMS=y，内核只导出
 * ABI 白名单里的符号。我们需要的两个核心函数
 *
 *     uprobe_register(inode, offset, uc)
 *     uprobe_unregister(inode, offset, uc)
 *
 * 都不在导出列表里（Module.symvers 里查不到），但它们在 System.map
 * 里是存在的（T uprobe_register / T uprobe_unregister）。
 * 也就是说：符号在，只是不能直接链接。
 *
 * 【解法：两级跳】
 *  1) 用 register_kprobe() 反查 kallsyms_lookup_name 的地址。
 *     register_kprobe 是 EXPORT_SYMBOL_GPL 的（可直接调用），它在
 *     内部会把 symbol_name 解析成地址并存进 kp.addr。注册成功后立刻
 *     unregister_kprobe()，我们就白拿到了 kallsyms_lookup_name 的地址。
 *  2) 用 kallsyms_lookup_name 去查 uprobe_register / uprobe_unregister。
 *
 * 【CFI 陷阱】
 * 本内核 CONFIG_CFI_CLANG=y 且 CONFIG_CFI_PERMISSIVE 未开，CFI 违规
 * 直接 panic（__cfi_check_fail）。我们在步骤 2 之后拿到的是"裸地址"，
 * 用类型化的函数指针去调用时，编译器会在调用点插入 CFI hash 校验，
 * 而我们自己算出的 type id 和目标函数在 vmlinux 里注册的 type id 不一定
 * 一致。所以：
 *   - 所有"间接调用未导出函数的转发函数"都标 __nocfi；
 *   - kallsyms_lookup_name 本身也是间接调用的，同样标 __nocfi。
 *
 * 这是本模块唯一一处"脏"的地方，其余代码全部走正常导出符号。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kallsyms.h>
#include <linux/uprobes.h>

#include "ecap_ksym.h"

#define KSYM_TAG "ecap_tls: "

/*
 * 编译器在 -fsanitize=cfi 下会为 __nocfi 生成"不做间接调用检查"的代码。
 * 内核已经定义了 __nocfi（include/linux/compiler-clang.h），这里只是
 * 兜底，防止在某些不开启 CONFIG_CFI_CLANG 的构建里编译不过。
 */
#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

/* ---- 函数指针类型 ---- */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef int (*uprobe_register_t)(struct inode *inode, loff_t offset,
				 struct uprobe_consumer *uc);
typedef void (*uprobe_unregister_t)(struct inode *inode, loff_t offset,
				    struct uprobe_consumer *uc);

static kallsyms_lookup_name_t fn_kallsyms_lookup_name;
static uprobe_register_t fn_uprobe_register;
static uprobe_unregister_t fn_uprobe_unregister;

/*
 * 用 register_kprobe 反查任意符号地址。
 *
 * 注意：这个函数只在模块初始化时调用（进程上下文，可睡眠），
 * 所以 kzalloc/memset 之类都没问题。
 *
 * 返回 0 表示没找到。kprobe 解析失败时 register_kprobe 一般返回
 * -ENOENT（符号不存在）；如果符号存在但地址不可探测（例如被标了
 * NOKPROBE_SYMBOL）则返回 -EINVAL。
 */
static unsigned long ecap_lookup_via_kprobe(const char *name)
{
	struct kprobe kp;
	unsigned long addr = 0;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = name;

	if (register_kprobe(&kp) == 0) {
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}
	return addr;
}

int __nocfi ecap_ksym_init(void)
{
	unsigned long addr;

	/* 第一级：拿到 kallsyms_lookup_name 本身 */
	addr = ecap_lookup_via_kprobe("kallsyms_lookup_name");
	if (!addr) {
		pr_err(KSYM_TAG "cannot resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}
	fn_kallsyms_lookup_name = (kallsyms_lookup_name_t)addr;
	pr_info(KSYM_TAG "kallsyms_lookup_name = %px\n", (void *)addr);

	/*
	 * 第二级：用 kallsyms_lookup_name 查目标符号。
	 *
	 * 这个调用点是"间接调用未导出函数"，必须 __nocfi。
	 * 由于整个 ecap_ksym_init 都标了 __nocfi，这里不需要额外处理。
	 */
	fn_uprobe_register =
		(uprobe_register_t)fn_kallsyms_lookup_name("uprobe_register");
	fn_uprobe_unregister =
		(uprobe_unregister_t)fn_kallsyms_lookup_name("uprobe_unregister");

	if (!fn_uprobe_register || !fn_uprobe_unregister) {
		pr_err(KSYM_TAG
		       "missing uprobe symbols: register=%px unregister=%px\n",
		       (void *)fn_uprobe_register, (void *)fn_uprobe_unregister);
		return -ENOENT;
	}

	pr_info(KSYM_TAG "uprobe_register = %px, uprobe_unregister = %px\n",
		(void *)fn_uprobe_register, (void *)fn_uprobe_unregister);
	return 0;
}

void ecap_ksym_exit(void)
{
	fn_uprobe_register = NULL;
	fn_uprobe_unregister = NULL;
	fn_kallsyms_lookup_name = NULL;
}

/*
 * 转发函数。
 *
 * 这两个函数体内的调用是"间接调用"，同样需要 __nocfi。
 * 调用方（ecap_uprobe.c）看到的只是普通函数，感知不到内部的技巧。
 */
int __nocfi ecap_uprobe_register(struct inode *inode, loff_t offset,
				 struct uprobe_consumer *uc)
{
	if (!fn_uprobe_register)
		return -ENOENT;
	return fn_uprobe_register(inode, offset, uc);
}

void __nocfi ecap_uprobe_unregister(struct inode *inode, loff_t offset,
				    struct uprobe_consumer *uc)
{
	if (!fn_uprobe_unregister)
		return;
	fn_uprobe_unregister(inode, offset, uc);
}


