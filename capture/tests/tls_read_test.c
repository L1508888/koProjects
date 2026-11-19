// SPDX-License-Identifier: GPL-2.0
/*
 * tls_read_test.c - 用本地回环 TLS 连接验证 SSL_read 抓包（不依赖外网）
 *
 * 【为什么不用真实外网服务器】
 * 外网依赖 WiFi/DNS，实测中会因网络抖动而失败。抓包功能的验证不该
 * 被外部因素干扰。用本地回环 + 自签名证书可以 100% 可重现。
 *
 * 【做法】
 *   1. 主线程建 SSL_CTX（server），装载内嵌的自签名证书/私钥
 *   2. 起一个线程当服务端：bind(127.0.0.1:0) → listen → accept
 *      → SSL_accept → SSL_read 读请求 → SSL_write 回响应
 *   3. 主线程当客户端：connect → SSL_connect → SSL_write 发请求
 *      → SSL_read 读响应
 *
 * 两端都用系统 libssl.so，所以 SSL_write 和 SSL_read 都会被真实调用，
 * 且都返回正数 —— 这正是要验证的正向路径。
 *
 * 【证书从哪来】
 *   用 SSL_CTX_use_certificate / use_PrivateKey 加载文件太麻烦，
 *   这里直接在运行时用 BoringSSL 的 API 生成一对临时自签名证书。
 *   但 BoringSSL 的证书生成 API 不稳定（不同版本差异大），
 *   所以改用最可靠的办法：证书由调用方预先用 openssl 生成并放在
 *   /data/local/tmp/ 下，本程序只负责加载。
 *
 *   如果证书不存在，程序会打印提示并降级为"只测 write 路径"。
 *
 * 用法：tls_read_test [cert.pem] [key.pem] [轮数]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>

typedef void SSL;
typedef void SSL_CTX;
typedef void SSL_METHOD;

typedef const SSL_METHOD *(*fn_tls_client_method)(void);
typedef const SSL_METHOD *(*fn_tls_server_method)(void);
typedef SSL_CTX *(*fn_ssl_ctx_new)(const SSL_METHOD *);
typedef SSL *(*fn_ssl_new)(SSL_CTX *);
typedef int (*fn_ssl_set_fd)(SSL *, int);
typedef int (*fn_ssl_connect)(SSL *);
typedef int (*fn_ssl_accept)(SSL *);
typedef int (*fn_ssl_write)(SSL *, const void *, int);
typedef int (*fn_ssl_read)(SSL *, void *, int);
typedef void (*fn_ssl_free)(SSL *);
typedef void (*fn_ssl_ctx_free)(SSL_CTX *);
typedef void (*fn_ssl_shutdown)(SSL *);
typedef int (*fn_ssl_use_cert)(SSL_CTX *, const char *, int);
typedef int (*fn_ssl_use_key)(SSL_CTX *, const char *, int);
typedef int (*fn_ssl_ctx_set_verify)(SSL_CTX *, int, void *);

/*
 * SSL_FILETYPE_PEM
 *
 * SSL_CTX_use_certificate_file / SSL_CTX_use_PrivateKey_file 都有
 * 第三个参数 type，表示文件格式。忘记传会读到栈上的随机值，
 * 导致"文件明明存在却加载失败" —— 实测踩过一次。
 */
#define SSL_FILETYPE_PEM 1

#define LIBSSL "/apex/com.android.conscrypt/lib64/libssl.so"
#define SSL_VERIFY_NONE 0

static struct {
	fn_tls_client_method tls_client_method;
	fn_tls_server_method tls_server_method;
	fn_ssl_ctx_new ssl_ctx_new;
	fn_ssl_new ssl_new;
	fn_ssl_set_fd ssl_set_fd;
	fn_ssl_connect ssl_connect;
	fn_ssl_accept ssl_accept;
	fn_ssl_write ssl_write;
	fn_ssl_read ssl_read;
	fn_ssl_free ssl_free;
	fn_ssl_ctx_free ssl_ctx_free;
	fn_ssl_shutdown ssl_shutdown;
	fn_ssl_use_cert ssl_use_cert;
	fn_ssl_use_key ssl_use_key;
	fn_ssl_ctx_set_verify ssl_ctx_set_verify;
} F;

static const char *g_cert;
static const char *g_key;
static int g_srv_port;
static volatile int g_ready;
static volatile int g_srv_ok;

static void *server_thread(void *arg)
{
	int lfd, cfd;
	struct sockaddr_in sa;
	socklen_t slen = sizeof(sa);
	SSL_CTX *ctx;
	SSL *ssl;
	char buf[1024];
	int n;

	(void)arg;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		return NULL;

	{
		int one = 1;
		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;

	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(lfd);
		return NULL;
	}
	if (listen(lfd, 4) < 0) {
		close(lfd);
		return NULL;
	}
	if (getsockname(lfd, (struct sockaddr *)&sa, &slen) == 0) {
		g_srv_port = ntohs(sa.sin_port);
		g_ready = 1;
	} else {
		close(lfd);
		return NULL;
	}

	cfd = accept(lfd, NULL, NULL);
	if (cfd < 0) {
		close(lfd);
		return NULL;
	}

	ctx = F.ssl_ctx_new(F.tls_server_method());
	if (!ctx) {
		close(cfd);
		close(lfd);
		return NULL;
	}

	if (!F.ssl_use_cert || !F.ssl_use_key ||
	    F.ssl_use_cert(ctx, g_cert, SSL_FILETYPE_PEM) != 1 ||
	    F.ssl_use_key(ctx, g_key, SSL_FILETYPE_PEM) != 1) {
		printf("[server] cannot load cert/key, handshake will fail\n");
		fflush(stdout);
	}

	ssl = F.ssl_new(ctx);
	F.ssl_set_fd(ssl, cfd);

	n = F.ssl_accept(ssl);
	printf("[server] SSL_accept -> %d\n", n);
	fflush(stdout);
	if (n != 1) {
		goto out;
	}
	g_srv_ok = 1;

	/* 读客户端请求 */
	n = F.ssl_read(ssl, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		printf("[server] SSL_read got %d bytes: %.40s...\n", n, buf);
		fflush(stdout);
	}

	/* 回一段带唯一标记的响应，让客户端的 SSL_read 能读到 */
	{
		const char *resp =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain\r\n"
			"X-Ecap-Dir: server-to-client\r\n"
			"Content-Length: 46\r\n"
			"\r\n"
			"ECAPTEST-R-FROM-SERVER-0123456789ABCDEFGHIJ\r\n";
		int w = F.ssl_write(ssl, resp, (int)strlen(resp));
		printf("[server] SSL_write -> %d\n", w);
		fflush(stdout);
	}

out:
	F.ssl_shutdown(ssl);
	F.ssl_free(ssl);
	F.ssl_ctx_free(ctx);
	close(cfd);
	close(lfd);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	void *h;
	SSL_CTX *ctx;
	SSL *ssl;
	int cfd, rc, i;
	struct sockaddr_in sa;
	int rounds;

	g_cert = (argc > 1) ? argv[1] : "/data/local/tmp/ecap_cert.pem";
	g_key = (argc > 2) ? argv[2] : "/data/local/tmp/ecap_key.pem";
	rounds = (argc > 3) ? atoi(argv[3]) : 1;

	h = dlopen(LIBSSL, RTLD_NOW);
	if (!h) {
		fprintf(stderr, "dlopen(%s) failed: %s\n", LIBSSL, dlerror());
		return 1;
	}

#define SYM(field, name) field = (void *)dlsym(h, name)
	SYM(F.tls_client_method, "TLS_client_method");
	SYM(F.tls_server_method, "TLS_server_method");
	SYM(F.ssl_ctx_new, "SSL_CTX_new");
	SYM(F.ssl_new, "SSL_new");
	SYM(F.ssl_set_fd, "SSL_set_fd");
	SYM(F.ssl_connect, "SSL_connect");
	SYM(F.ssl_accept, "SSL_accept");
	SYM(F.ssl_write, "SSL_write");
	SYM(F.ssl_read, "SSL_read");
	SYM(F.ssl_free, "SSL_free");
	SYM(F.ssl_ctx_free, "SSL_CTX_free");
	SYM(F.ssl_shutdown, "SSL_shutdown");
	SYM(F.ssl_use_cert, "SSL_CTX_use_certificate_file");
	SYM(F.ssl_use_key, "SSL_CTX_use_PrivateKey_file");
	SYM(F.ssl_ctx_set_verify, "SSL_CTX_set_verify");
#undef SYM

	if (!F.tls_client_method || !F.tls_server_method || !F.ssl_ctx_new ||
	    !F.ssl_new || !F.ssl_write || !F.ssl_read) {
		fprintf(stderr, "dlsym failed: %s\n", dlerror());
		return 1;
	}

	if (access(g_cert, R_OK) != 0 || access(g_key, R_OK) != 0) {
		fprintf(stderr, "cert/key not found (%s, %s)\n"
				"generate with:\n"
				"  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \\\n"
				"    -keyout %s -out %s -subj /CN=ecap.local\n",
			g_cert, g_key, g_key, g_cert);
		return 1;
	}

	if (pthread_create(&th, NULL, server_thread, NULL) != 0) {
		perror("pthread_create");
		return 1;
	}

	for (i = 0; i < 200 && !g_ready; i++)
		usleep(10000);
	if (!g_ready) {
		fprintf(stderr, "server not ready\n");
		return 1;
	}

	cfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(g_srv_port);
	if (connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect");
		close(cfd);
		return 1;
	}

	ctx = F.ssl_ctx_new(F.tls_client_method());
	if (F.ssl_ctx_set_verify)
		F.ssl_ctx_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	ssl = F.ssl_new(ctx);
	F.ssl_set_fd(ssl, cfd);

	printf("pid=%d tid=%ld port=%d\n", getpid(), (long)syscall(SYS_gettid),
	       g_srv_port);
	fflush(stdout);

	rc = F.ssl_connect(ssl);
	printf("client SSL_connect -> %d\n", rc);
	fflush(stdout);
	if (rc != 1) {
		fprintf(stderr, "handshake failed — cannot test SSL_read "
				"positive path\n");
		goto out;
	}

	for (i = 0; i < rounds; i++) {
		char req[256];
		char resp[512];
		int n, r;

		n = snprintf(req, sizeof(req),
			     "ECAPTEST-W-CLIENT-%d-GET / HTTP/1.1\r\n"
			     "Host: ecap.local\r\n\r\n", i);

		r = F.ssl_write(ssl, req, n);
		printf("client SSL_write(%d) -> %d\n", n, r);

		r = F.ssl_read(ssl, resp, sizeof(resp) - 1);
		if (r > 0) {
			resp[r] = '\0';
			printf("client SSL_read -> %d bytes\n", r);
		} else {
			printf("client SSL_read -> %d\n", r);
		}
		fflush(stdout);
	}

out:
	F.ssl_shutdown(ssl);
	F.ssl_free(ssl);
	F.ssl_ctx_free(ctx);
	close(cfd);
	pthread_join(th, NULL);
	printf("done (server handshake %s)\n", g_srv_ok ? "OK" : "FAILED");
	return 0;
}
