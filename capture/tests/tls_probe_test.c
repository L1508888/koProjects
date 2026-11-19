// SPDX-License-Identifier: GPL-2.0
/*
 * tls_probe_test.c - 在设备上触发 SSL_write / SSL_read，验证 uprobe 抓包链路
 *
 * 【为什么不直接用一个真实的 HTTPS 请求】
 * 真实请求要经过网络、要 App 参与，不可控。而我们要验证的只是
 * "uprobe handler 能不能在 SSL_write / SSL_read 处正确读到明文"。
 *
 * 所以这里直接 dlopen 系统 libssl.so，自己造一个最小的 SSL 对象：
 *   1. SSL_CTX_new(TLS_client_method())  建立上下文
 *   2. SSL_new(ctx)                       建立一个 SSL 实例
 *   3. SSL_write(ssl, buf, n)             触发写路径
 *   4. SSL_read(ssl, buf, n)              触发读路径
 *
 * 关键点：我们没有建立任何真实的 TCP 连接，所以这两个函数都会失败并返回
 * <= 0。但这**完全不影响验证**：
 *
 *   - SSL_write: uprobe 挂在函数**入口**，handler 在函数体执行之前
 *     就已经拿到了 buf 参数。只要被调用，handler 必然触发。
 *   - SSL_read : uprobe 挂在入口 + 返回。返回值为 -1 时，
 *     ret_handler 会走"n <= 0，不上报"的分支 —— 这本身也是要验证的
 *     行为（不能把错误码当长度去拷贝）。
 *
 * 也就是说，这个测试同时验证了：
 *   1. write 路径能抓到明文
 *   2. read  路径的 entry handler 会记录挂起项
 *   3. read  路径的 ret_handler 在返回值 <= 0 时正确跳过，
 *      并**把挂起项清理掉**（否则表会被慢慢填满）
 *
 * 【怎么确认抓到的是我们发的】
 * 每轮的 payload 都带一个唯一的序号和标记，从日志里搜这个标记
 * 就能确认是本次测试产生的。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>

typedef void SSL;
typedef void SSL_CTX;
typedef void SSL_METHOD;

typedef const SSL_METHOD *(*fn_tls_client_method)(void);
typedef SSL_CTX *(*fn_ssl_ctx_new)(const SSL_METHOD *);
typedef SSL *(*fn_ssl_new)(SSL_CTX *);
typedef int (*fn_ssl_write)(SSL *, const void *, int);
typedef int (*fn_ssl_read)(SSL *, void *, int);
typedef void (*fn_ssl_free)(SSL *);
typedef void (*fn_ssl_ctx_free)(SSL_CTX *);

#define LIBSSL "/apex/com.android.conscrypt/lib64/libssl.so"

int main(int argc, char **argv)
{
	void *h;
	fn_tls_client_method p_tls_client_method;
	fn_ssl_ctx_new p_ssl_ctx_new;
	fn_ssl_new p_ssl_new;
	fn_ssl_write p_ssl_write;
	fn_ssl_read p_ssl_read;
	fn_ssl_free p_ssl_free;
	fn_ssl_ctx_free p_ssl_ctx_free;
	SSL_CTX *ctx;
	SSL *ssl;
	int rounds = (argc > 1) ? atoi(argv[1]) : 3;
	int do_read = 1;
	int do_write = 1;
	int i;

	/* 第二个参数控制测哪个方向：w / r / wr（默认 wr） */
	if (argc > 2) {
		do_write = (strchr(argv[2], 'w') != NULL);
		do_read = (strchr(argv[2], 'r') != NULL);
	}

	h = dlopen(LIBSSL, RTLD_NOW);
	if (!h) {
		fprintf(stderr, "dlopen(%s) failed: %s\n", LIBSSL, dlerror());
		return 1;
	}

	p_tls_client_method = (fn_tls_client_method)dlsym(h, "TLS_client_method");
	p_ssl_ctx_new = (fn_ssl_ctx_new)dlsym(h, "SSL_CTX_new");
	p_ssl_new = (fn_ssl_new)dlsym(h, "SSL_new");
	p_ssl_write = (fn_ssl_write)dlsym(h, "SSL_write");
	p_ssl_read = (fn_ssl_read)dlsym(h, "SSL_read");
	p_ssl_free = (fn_ssl_free)dlsym(h, "SSL_free");
	p_ssl_ctx_free = (fn_ssl_ctx_free)dlsym(h, "SSL_CTX_free");

	if (!p_tls_client_method || !p_ssl_ctx_new || !p_ssl_new ||
	    !p_ssl_write || !p_ssl_read) {
		fprintf(stderr, "dlsym failed: %s\n", dlerror());
		return 1;
	}

	ctx = p_ssl_ctx_new(p_tls_client_method());
	if (!ctx) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return 1;
	}

	ssl = p_ssl_new(ctx);
	if (!ssl) {
		fprintf(stderr, "SSL_new failed\n");
		goto out_ctx;
	}

	printf("pid=%d tid=%ld ssl=%p ctx=%p mode=%s%s\n", getpid(),
	       (long)syscall(SYS_gettid), ssl, ctx,
	       do_write ? "write " : "", do_read ? "read" : "");

	for (i = 0; i < rounds; i++) {
		if (do_write) {
			char wbuf[512];
			int n, rc;

			n = snprintf(wbuf, sizeof(wbuf),
				     "ECAPTEST-W-%d-%d-GET /probe HTTP/1.1\r\n"
				     "Host: ecap.local\r\n\r\n",
				     (int)getpid(), i);
			memset(wbuf + n, 'W', sizeof(wbuf) - n - 1);
			wbuf[sizeof(wbuf) - 1] = '\0';

			rc = p_ssl_write(ssl, wbuf, n);
			printf("round %d: SSL_write(len=%d) -> %d\n", i, n, rc);
			fflush(stdout);
		}

		if (do_read) {
			/*
			 * 缓冲区先填一个可辨认的图案。
			 *
			 * 【为什么这很重要】
			 * SSL_read 在没有真实连接时会立刻失败返回 -1，
			 * 缓冲区内容不会变。如果我们的 ret_handler 错误地
			 * 按 num 而不是返回值去读，日志里就会出现一整片
			 * 'R'（0x52）—— 一眼就能看出 bug。
			 */
			char rbuf[512];
			int rc;

			memset(rbuf, 'R', sizeof(rbuf) - 1);
			rbuf[sizeof(rbuf) - 1] = '\0';

			rc = p_ssl_read(ssl, rbuf, (int)sizeof(rbuf) - 1);
			printf("round %d: SSL_read(len=%d) -> %d\n", i,
			       (int)sizeof(rbuf) - 1, rc);
			fflush(stdout);
		}

		usleep(200000);
	}

	if (p_ssl_free)
		p_ssl_free(ssl);
out_ctx:
	if (p_ssl_ctx_free)
		p_ssl_ctx_free(ctx);

	printf("done\n");
	return 0;
}
