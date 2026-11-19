// SPDX-License-Identifier: GPL-2.0
/*
 * ecap_elf.c - ELF 符号查找（.dynsym + .gnu_debugdata）
 *
 * 【两级查找的原因】
 *
 * 一级：.dynsym（动态符号表）
 *   SSL_write / SSL_read 都是**导出符号**，App 要动态链接它们，
 *   所以一定在 .dynsym 里。这一级不需要任何外部依赖。
 *
 * 二级：.gnu_debugdata（XZ 压缩的 mini debug info）
 *   bssl::ssl_log_secret 是 **内部函数**，不导出。
 *   Android 的 BoringSSL 把一份"只有符号表的最小 ELF"用 XZ 压缩后
 *   塞在 .gnu_debugdata 节里。
 *
 *   实测 Pixel 6 (Android 13) 的 conscrypt libssl.so：
 *     .gnu_debugdata  节 0x2638 字节
 *     解压后          47832 字节的 ELF（no program header, not stripped）
 *     里面有 _ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE
 *     其 st_value = 0x3ecd0
 *
 * 【mini debug info 的 st_value 能不能直接用】
 * 能，但要注意：它**没有 program header**，所以不能用它自己的
 * PT_LOAD 做 vaddr→offset 换算。
 *
 * 好在它的 st_value 与主库的虚拟地址空间是同一套编号
 * （都是相对 .so 加载基址的偏移）。所以换算时必须用**主库**的
 * PT_LOAD 表。这是本文件最容易写错的一点。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ecap_elf.h"
#include "ecap_xz.h"

/* mini debug info 解压后的最大尺寸。实测 libssl 是 47KB，留足余量。 */
#define MINI_DEBUGINFO_MAX (4u << 20) /* 4 MB */

struct elf_blob {
	uint8_t *data;
	size_t size;
};

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */

static void elf_blob_free(struct elf_blob *b)
{
	free(b->data);
	b->data = NULL;
	b->size = 0;
}

/* 读整个文件到内存 */
static int elf_load_file(const char *path, struct elf_blob *out)
{
	int fd;
	struct stat sb;
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "ecapctl: open(%s): %s\n", path,
			strerror(errno));
		return -1;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "ecapctl: fstat(%s): %s\n", path,
			strerror(errno));
		close(fd);
		return -1;
	}
	if ((size_t)sb.st_size < sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "ecapctl: %s is too small to be an ELF\n", path);
		close(fd);
		return -1;
	}

	out->size = (size_t)sb.st_size;
	out->data = malloc(out->size);
	if (!out->data) {
		close(fd);
		return -1;
	}

	n = read(fd, out->data, out->size);
	close(fd);
	if (n != (ssize_t)out->size) {
		fprintf(stderr, "ecapctl: short read on %s\n", path);
		elf_blob_free(out);
		return -1;
	}
	return 0;
}

/* 校验 ELF 头。返回 0 表示是我们能处理的（64 位小端） */
static int elf_check_header(const struct elf_blob *b, const char *what,
			    const Elf64_Ehdr **out_eh)
{
	const Elf64_Ehdr *eh;

	if (b->size < sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "ecapctl: %s: too small for ELF header\n", what);
		return -1;
	}

	eh = (const Elf64_Ehdr *)b->data;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "ecapctl: %s: bad ELF magic\n", what);
		return -1;
	}
	if (eh->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr,
			"ecapctl: %s: not a 64-bit ELF (32-bit ABI is not "
			"supported on arm64 uprobe)\n",
			what);
		return -1;
	}
	if (eh->e_ident[EI_DATA] != ELFDATA2LSB) {
		fprintf(stderr, "ecapctl: %s: not little-endian\n", what);
		return -1;
	}
	if (eh->e_shoff == 0 || eh->e_shnum == 0) {
		fprintf(stderr,
			"ecapctl: %s: no section headers (fully stripped?)\n",
			what);
		return -1;
	}
	if (eh->e_shoff + (uint64_t)eh->e_shnum * eh->e_shentsize > b->size) {
		fprintf(stderr, "ecapctl: %s: section header table out of "
				"bounds\n",
			what);
		return -1;
	}

	*out_eh = eh;
	return 0;
}

/* 取节名字符串表中的第 off 项 */
static const char *elf_sh_name(const struct elf_blob *b, const Elf64_Shdr *sh,
			       unsigned int shstrndx, uint32_t off)
{
	const Elf64_Shdr *strsh = &sh[shstrndx];

	if (off >= strsh->sh_size)
		return "";
	if (strsh->sh_offset + strsh->sh_size > b->size)
		return "";
	return (const char *)(b->data + strsh->sh_offset + off);
}

/*
 * 把 st_value（虚拟地址）换算成文件偏移。
 *
 * 必须用**主库**的 PT_LOAD 表 —— 见文件头注释。
 *
 * 返回 true 成功。
 */
static bool elf_vaddr_to_offset(const struct elf_blob *lib,
				const Elf64_Ehdr *libr_eh, uint64_t vaddr,
				uint64_t *out)
{
	const Elf64_Phdr *ph;
	unsigned int i;

	if (libr_eh->e_phoff == 0 || libr_eh->e_phnum == 0)
		return false;
	if (libr_eh->e_phoff +
		    (uint64_t)libr_eh->e_phnum * sizeof(Elf64_Phdr) >
	    lib->size)
		return false;

	ph = (const Elf64_Phdr *)(lib->data + libr_eh->e_phoff);

	for (i = 0; i < libr_eh->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD)
			continue;
		if (vaddr < ph[i].p_vaddr)
			continue;
		if (vaddr >= ph[i].p_vaddr + ph[i].p_memsz)
			continue;
		/*
		 * 落在 .bss 段（p_memsz > p_filesz 的尾部）的符号没有
		 * 文件实体，不能作为 uprobe 目标。
		 */
		if (vaddr - ph[i].p_vaddr >= ph[i].p_filesz)
			return false;

		*out = vaddr - ph[i].p_vaddr + ph[i].p_offset;
		return true;
	}
	return false;
}

/*
 * 在一张符号表里扫描。
 *
 * @b       : 提供符号表的 blob（可能是主库，也可能是解压出的 mini ELF）
 * @sh      : 该 blob 的节头表
 * @sym_idx : 符号表节的索引
 * @symname : 要找的名字
 *
 * 返回找到的 st_value（非 0），没找到返回 0。
 */
static uint64_t elf_scan_symtab(const struct elf_blob *b,
				const Elf64_Shdr *sh, unsigned int sym_idx,
				const char *symname, char *out_found,
				size_t found_len)
{
	const Elf64_Shdr *symsh = &sh[sym_idx];
	const Elf64_Sym *syms;
	const char *strtab;
	size_t strsz, count, i;

	if (symsh->sh_link >= 0x10000 || symsh->sh_entsize == 0)
		return 0;

	/* sh_link 指向对应的字符串表节 */
	if (symsh->sh_link == 0)
		return 0;
	if (symsh->sh_offset + symsh->sh_size > b->size)
		return 0;

	{
		const Elf64_Shdr *strsh = &sh[symsh->sh_link];

		if (strsh->sh_offset + strsh->sh_size > b->size)
			return 0;
		strtab = (const char *)(b->data + strsh->sh_offset);
		strsz = strsh->sh_size;
	}

	syms = (const Elf64_Sym *)(b->data + symsh->sh_offset);
	count = symsh->sh_size / sizeof(Elf64_Sym);

	/*
	 * 线性扫描。符号表通常几百到几千条，一次性解析的开销可以忽略，
	 * 代码简单得多（不需要排序后二分）。
	 */
	for (i = 0; i < count; i++) {
		const Elf64_Sym *s = &syms[i];
		const char *name;
		size_t want;

		if (s->st_shndx == SHN_UNDEF)
			continue; /* 未定义的导入符号，跳过 */
		if (s->st_name >= strsz)
			continue;

		name = strtab + s->st_name;

		/*
		 * 名字匹配。
		 *
		 * 对 C 符号（SSL_write）：必须精确相等，或用 @ 分隔版本号。
		 * 因为 libssl 里同时存在 SSL_write / SSL_write_ex /
		 * SSL_write_early_data，纯前缀匹配会误命中。
		 *
		 * 对 C++ mangled 名字（_ZN4bssl14ssl_log_secret...）：
		 * mangled 名字本身就是唯一的，精确匹配即可。
		 */
		if (strcmp(name, symname) != 0) {
			want = strlen(symname);
			if (strncmp(name, symname, want) != 0 ||
			    (name[want] != '@' && name[want] != '\0'))
				continue;
		}

		if (out_found)
			snprintf(out_found, found_len, "%s", name);
		return s->st_value;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* 一级：.dynsym                                                       */
/* ------------------------------------------------------------------ */

static int elf_find_in_dynsym(const struct elf_blob *lib,
			      const Elf64_Ehdr *eh, const char *symname,
			      uint64_t *out_vaddr, char *out_found,
			      size_t found_len)
{
	const Elf64_Shdr *sh = (const Elf64_Shdr *)(lib->data + eh->e_shoff);
	unsigned int i;
	uint64_t v;

	for (i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type != SHT_DYNSYM)
			continue;

		v = elf_scan_symtab(lib, sh, i, symname, out_found, found_len);
		if (v) {
			*out_vaddr = v;
			return 0;
		}
	}
	return -1;
}

/* ------------------------------------------------------------------ */
/* 二级：.gnu_debugdata                                                */
/* ------------------------------------------------------------------ */

/*
 * 从主库里取出 .gnu_debugdata 节，解压成一个新的 ELF blob。
 *
 * 返回 0 成功并填充 *out。
 */
static int elf_extract_debugdata(const struct elf_blob *lib,
				 const Elf64_Ehdr *eh, struct elf_blob *out)
{
	const Elf64_Shdr *sh = (const Elf64_Shdr *)(lib->data + eh->e_shoff);
	uint8_t *plain = NULL;
	size_t plain_len = 0;
	unsigned int i;
	int ret = -1;

	memset(out, 0, sizeof(*out));

	if (eh->e_shstrndx >= eh->e_shnum) {
		fprintf(stderr, "ecapctl: bad e_shstrndx\n");
		return -1;
	}

	for (i = 0; i < eh->e_shnum; i++) {
		const char *name =
			elf_sh_name(lib, sh, eh->e_shstrndx, sh[i].sh_name);

		if (strcmp(name, ".gnu_debugdata") != 0)
			continue;

		if (sh[i].sh_offset + sh[i].sh_size > lib->size) {
			fprintf(stderr,
				"ecapctl: .gnu_debugdata out of bounds\n");
			return -1;
		}

		if (!ecap_xz_available()) {
			fprintf(stderr,
				"ecapctl: .gnu_debugdata found but liblzma "
				"not available\n");
			return -1;
		}

		plain = malloc(MINI_DEBUGINFO_MAX);
		if (!plain)
			return -1;

		if (ecap_xz_decompress(lib->data + sh[i].sh_offset,
				       sh[i].sh_size, plain,
				       MINI_DEBUGINFO_MAX, &plain_len) != 0) {
			fprintf(stderr,
				"ecapctl: failed to decompress "
				".gnu_debugdata\n");
			free(plain);
			return -1;
		}

		out->data = plain;
		out->size = plain_len;
		ret = 0;
		break;
	}

	if (ret != 0 && !out->data)
		fprintf(stderr,
			"ecapctl: no .gnu_debugdata section (library was "
			"stripped without mini debug info)\n");
	return ret;
}

static int elf_find_in_debugdata(const struct elf_blob *lib,
				 const Elf64_Ehdr *lib_eh, const char *symname,
				 uint64_t *out_vaddr, char *out_found,
				 size_t found_len)
{
	struct elf_blob mini = { 0 };
	const Elf64_Ehdr *mini_eh;
	const Elf64_Shdr *mini_sh;
	unsigned int i;
	uint64_t v = 0;
	int ret = -1;

	if (elf_extract_debugdata(lib, lib_eh, &mini) != 0)
		return -1;

	if (elf_check_header(&mini, ".gnu_debugdata", &mini_eh) != 0) {
		elf_blob_free(&mini);
		return -1;
	}

	mini_sh = (const Elf64_Shdr *)(mini.data + mini_eh->e_shoff);

	/*
	 * mini debug info 里通常只有 SHT_SYMTAB（不是 SHT_DYNSYM），
	 * 因为它不是"动态链接用"的符号表。两种都扫一遍更稳。
	 */
	for (i = 0; i < mini_eh->e_shnum; i++) {
		if (mini_sh[i].sh_type != SHT_SYMTAB &&
		    mini_sh[i].sh_type != SHT_DYNSYM)
			continue;

		v = elf_scan_symtab(&mini, mini_sh, i, symname, out_found,
				    found_len);
		if (v) {
			*out_vaddr = v;
			ret = 0;
			break;
		}
	}

	elf_blob_free(&mini);

	if (ret != 0)
		fprintf(stderr, "ecapctl: symbol '%s' not found in "
				".gnu_debugdata either\n",
			symname);
	return ret;
}

/* ------------------------------------------------------------------ */
/* 对外接口                                                            */
/* ------------------------------------------------------------------ */

int ecap_elf_find_symbol(const char *path, const char *symname,
			 uint64_t *out_offset, char *out_found,
			 size_t found_len, const char **out_from)
{
	struct elf_blob lib = { 0 };
	const Elf64_Ehdr *eh;
	uint64_t vaddr = 0;
	const char *from = NULL;

	if (elf_load_file(path, &lib) != 0)
		return -1;

	if (elf_check_header(&lib, path, &eh) != 0) {
		elf_blob_free(&lib);
		return -1;
	}

	/* 一级：.dynsym */
	if (elf_find_in_dynsym(&lib, eh, symname, &vaddr, out_found,
			      found_len) == 0) {
		from = "dynsym";
		goto found;
	}

	/* 二级：.gnu_debugdata */
	if (elf_find_in_debugdata(&lib, eh, symname, &vaddr, out_found,
				  found_len) == 0) {
		from = "debugdata";
		goto found;
	}

	fprintf(stderr, "ecapctl: symbol '%s' not found in %s\n", symname,
		path);
	elf_blob_free(&lib);
	return -1;

found:
	/*
	 * 换算时**必须用主库的 PT_LOAD 表**。
	 * mini debug info 的 ELF 没有 program header，
	 * 而且它的 st_value 用的是主库的虚拟地址编号。
	 */
	if (!elf_vaddr_to_offset(&lib, eh, vaddr, out_offset)) {
		fprintf(stderr,
			"ecapctl: %s: symbol %s (vaddr=0x%llx) not backed by "
			"a PT_LOAD segment of %s\n",
			path, symname, (unsigned long long)vaddr, path);
		elf_blob_free(&lib);
		return -1;
	}

	if (out_from)
		*out_from = from;

	elf_blob_free(&lib);
	return 0;
}

bool ecap_elf_is_aarch64(const char *path)
{
	int fd;
	Elf64_Ehdr eh;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	if (read(fd, &eh, sizeof(eh)) != (ssize_t)sizeof(eh)) {
		close(fd);
		return false;
	}
	close(fd);

	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
		return false;
	return eh.e_machine == EM_AARCH64;
}
