/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ecap_ksym.h - 未导出内核符号的解析层
 */
#ifndef _ECAP_KSYM_H_
#define _ECAP_KSYM_H_

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/uprobes.h>

/*
 * 解析并缓存本模块需要的未导出符号。
 * 返回 0 表示全部解析成功；否则返回 -ENOENT/-EINVAL。
 */
int ecap_ksym_init(void);

/* 仅打印用途：模块卸载时不需要做任何事，这里保留对称性 */
void ecap_ksym_exit(void);

/*
 * uprobe_register / uprobe_unregister 的转发。
 *
 * 这两个函数在本 GKI 上都没有 EXPORT_SYMBOL（CONFIG_TRIM_UNUSED_KSYMS=y），
 * 必须经 kallsyms 取到地址后间接调用。间接调用点会被 CFI 检查，
 * 因此实现内部用 __nocfi 关掉调用点的 CFI 校验。
 */
int ecap_uprobe_register(struct inode *inode, loff_t offset,
			 struct uprobe_consumer *uc);
void ecap_uprobe_unregister(struct inode *inode, loff_t offset,
			    struct uprobe_consumer *uc);

#endif /* _ECAP_KSYM_H_ */
