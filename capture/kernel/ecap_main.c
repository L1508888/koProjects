// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_main.c - ecap_tls.ko 模块入口
 *
 * 这个文件只做一件事：按严格顺序装配和拆卸三个子系统。
 *
 *   ecap_ksym    未导出符号解析（kallsyms 两级跳，全程 __nocfi）
 *   ecap_uprobe  uprobe 探测点管理 + SSL_write handler
 *   ecap_dev     /dev/ecap_tls 字符设备与事件环形队列
 *
 * 【装配顺序】
 *   ksym -> dev -> uprobe
 * 必须先有符号（uprobe_register 的地址），才能注册 uprobe；
 * 必须先有设备（事件队列），handler 才有地方写。
 *
 * 【拆卸顺序 —— 反过来的镜像，而且这里一步都不能错】
 *   uprobe -> dev -> ksym
 *
 * 为什么 uprobe 必须先摘？
 *   handler 里会调 ecap_push() 往队列写数据。如果先 ecap_dev_exit()
 *   释放了 1MB 队列缓冲，而此刻还有用户线程正在 SSL_write 的 handler 里
 *   执行，它就会往已释放的内存写 —— 典型 use-after-free，直接 panic。
 *
 * 为什么 dev 要在 ksym 之前？
 *   ecap_uprobe_exit() 内部要调 uprobe_unregister，那是经 ksym 拿到的
 *   函数指针。把 ksym 清空的时机必须晚于最后一次 uprobe 注销。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "ecap_dev.h"
#include "ecap_uprobe.h"
#include "ecap_ksym.h"
#include "ecap_nf.h"

#define MAIN_TAG "ecap_tls: "

/*
 * 模块退出函数必须 __nocfi。
 *
 * 原因：ecap_uprobe_exit() -> ecap_probe_free() -> ecap_uprobe_unregister()
 * 这条链上存在"间接调用未导出函数"（uprobe_unregister）。LTO + CFI 会把
 * 这个调用图上所有函数的 type id 放在一起校验，历史上遇到过 module_exit
 * 在收尾时触发 __cfi_check_fail。给入口标 __nocfi 是最省事的兜底。
 */
static void __nocfi __exit ecap_exit(void)
{
	/*
	 * 1) 先停网络抓包。
	 *
	 * Netfilter hook 在软中断上下文运行，可能正在往队列写数据。
	 * 它必须比 uprobe 更早停 —— 因为 unregister 一个 hook 之后
	 * 内核保证再也不会有新调用（nf_unregister_net_hooks 内部有
	 * synchronize_rcu 类似的同步）。
	 */
	ecap_nf_disable();

	/* 2) 再摘所有 uprobe：此后不再有新 handler 访问队列 */
	ecap_uprobe_exit();

	/* 3) 然后销毁设备与队列 */
	ecap_dev_exit();

	/* 4) 最后清符号表 */
	ecap_ksym_exit();

	pr_info(MAIN_TAG "unloaded\n");
}

static int __init ecap_init(void)
{
	int ret;

	/*
	 * 第一步：解析未导出符号。
	 * 失败就直接返回，模块不会被加载 —— 比起"加载了但功能缺失"，
	 * 让 insmod 报错更容易定位问题。
	 */
	ret = ecap_ksym_init();
	if (ret) {
		pr_err(MAIN_TAG "ecap_ksym_init failed: %d\n", ret);
		return ret;
	}

	/* 第二步：建事件通道 */
	ret = ecap_dev_init();
	if (ret) {
		pr_err(MAIN_TAG "ecap_dev_init failed: %d\n", ret);
		goto err_ksym;
	}

	/* 第三步：探测点管理器（此刻还没有任何探测点） */
	ret = ecap_uprobe_init();
	if (ret) {
		pr_err(MAIN_TAG "ecap_uprobe_init failed: %d\n", ret);
		goto err_dev;
	}

	pr_info(MAIN_TAG "loaded, waiting for probes on /dev/ecap_tls\n");
	return 0;

err_dev:
	ecap_dev_exit();
err_ksym:
	ecap_ksym_exit();
	return ret;
}

module_init(ecap_init);
module_exit(ecap_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eCapture LKM prototype");
MODULE_DESCRIPTION("TLS plaintext capture via uprobe (LKM, no eBPF)");
MODULE_VERSION("0.3.0-m2");
