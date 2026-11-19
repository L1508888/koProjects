/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_hello.c - /dev/hello 的用户态测试程序
 *
 * 编译：
 *   gcc -O2 -Wall -o test_hello test_hello.c
 *   aarch64-linux-gnu-gcc -O2 -static -o test_hello test_hello.c
 *
 * 用法：
 *   ./test_hello            # 跑全部测试
 *   ./test_hello stats      # 只打印统计
 *   ./test_hello write      # 写 3 条消息再读回来
 *   ./test_hello nonblock   # 演示 O_NONBLOCK 下的 EAGAIN
 *   ./test_hello poll       # 演示 poll() 等待
 *   ./test_hello echo 1234  # 演示 ioctl SET_ECHO / GET_ECHO
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/ioctl.h>

#include "hello_uapi.h"

#define DEV_PATH "/dev/hello"

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(1);
}

static void dump_msg(const struct hello_msg *m)
{
	char text[HELLO_MSG_MAX + 1];
	unsigned int n = m->len < HELLO_MSG_MAX ? m->len : HELLO_MSG_MAX;

	memcpy(text, m->data, n);
	text[n] = '\0';
	printf("  seq=%u ts=%llu pid=%u len=%u data=\"%s\"\n",
	       m->seq, (unsigned long long)m->ts_ns, m->pid, m->len, text);
}

static int cmd_stats(void)
{
	struct hello_stats st;
	int fd = open(DEV_PATH, O_RDWR);

	if (fd < 0)
		die("open " DEV_PATH);

	if (ioctl(fd, HELLO_IOC_GET_STATS, &st) < 0)
		die("ioctl GET_STATS");

	printf("========== hello stats ==========\n");
	printf("open      : %llu\n", (unsigned long long)st.opens);
	printf("release   : %llu\n", (unsigned long long)st.releases);
	printf("read      : %llu\n", (unsigned long long)st.reads);
	printf("write     : %llu\n", (unsigned long long)st.writes);
	printf("ioctl     : %llu\n", (unsigned long long)st.ioctls);
	printf("msgs_in   : %llu\n", (unsigned long long)st.msgs_in);
	printf("msgs_out  : %llu\n", (unsigned long long)st.msgs_out);
	printf("dropped   : %llu\n", (unsigned long long)st.dropped);
	printf("queued    : %u / %u\n", st.queued, st.slots);
	printf("=================================\n");

	close(fd);
	return 0;
}

static int cmd_write(void)
{
	struct hello_msg msg;
	int fd, i;

	fd = open(DEV_PATH, O_RDWR);
	if (fd < 0)
		die("open " DEV_PATH);

	for (i = 0; i < 3; i++) {
		ssize_t n;

		memset(&msg, 0, sizeof(msg));
		snprintf((char *)msg.data, HELLO_MSG_MAX, "message #%d from test_hello", i);
		msg.len = (__u32)strlen((char *)msg.data);
		/* ts_ns / pid / seq 由内核填充，这里故意填垃圾值验证内核会覆盖 */
		msg.ts_ns = 0xDEADBEEF;
		msg.pid = 0xFFFF;
		msg.seq = 0xFFFF;

		n = write(fd, &msg, sizeof(msg));
		if (n < 0)
			die("write");
		printf("wrote %zd bytes (msg #%d)\n", n, i);
	}

	for (i = 0; i < 3; i++) {
		ssize_t n;

		memset(&msg, 0, sizeof(msg));
		n = read(fd, &msg, sizeof(msg));
		if (n < 0)
			die("read");
		printf("read %zd bytes:", n);
		dump_msg(&msg);
	}

	close(fd);
	return 0;
}

static int cmd_nonblock(void)
{
	struct hello_msg msg;
	int fd;

	fd = open(DEV_PATH, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		die("open " DEV_PATH " O_NONBLOCK");

	/* 先把队列读空 */
	while (read(fd, &msg, sizeof(msg)) > 0)
		;

	errno = 0;
	if (read(fd, &msg, sizeof(msg)) < 0) {
		if (errno == EAGAIN)
			printf("read on empty queue returned EAGAIN (expected)\n");
		else
			printf("unexpected errno: %s\n", strerror(errno));
	} else {
		printf("unexpected: read succeeded on empty queue\n");
	}

	close(fd);
	return 0;
}

static int cmd_poll(void)
{
	struct hello_msg msg;
	int fd, ret;
	struct pollfd pfd;

	fd = open(DEV_PATH, O_RDWR | O_NONBLOCK);
	if (fd < 0)
		die("open " DEV_PATH);

	/* 读空队列 */
	while (read(fd, &msg, sizeof(msg)) > 0)
		;

	pfd.fd = fd;
	pfd.events = POLLIN;

	ret = poll(&pfd, 1, 200);
	printf("poll on empty queue: ret=%d revents=0x%x (0 = timeout, expected)\n",
	       ret, pfd.revents);

	/* 写一条，再 poll，应立即就绪 */
	memset(&msg, 0, sizeof(msg));
	strcpy((char *)msg.data, "poll test");
	msg.len = 9;
	if (write(fd, &msg, sizeof(msg)) < 0)
		die("write");

	pfd.revents = 0;
	ret = poll(&pfd, 1, 200);
	printf("poll after write : ret=%d revents=0x%x (POLLIN set = ready)\n",
	       ret, pfd.revents);

	if (ret > 0 && (pfd.revents & POLLIN)) {
		read(fd, &msg, sizeof(msg));
		printf("consumed:");
		dump_msg(&msg);
	}

	close(fd);
	return 0;
}

static int cmd_echo(unsigned int value)
{
	__u32 v = value, got = 0;
	int fd = open(DEV_PATH, O_RDWR);

	if (fd < 0)
		die("open " DEV_PATH);

	if (ioctl(fd, HELLO_IOC_SET_ECHO, &v) < 0)
		die("ioctl SET_ECHO");
	if (ioctl(fd, HELLO_IOC_GET_ECHO, &got) < 0)
		die("ioctl GET_ECHO");

	printf("echo: set=%u got=%u %s\n", v, got, v == got ? "OK" : "MISMATCH");

	close(fd);
	return 0;
}

static int cmd_bad_ioctl(void)
{
	int fd = open(DEV_PATH, O_RDWR);

	if (fd < 0)
		die("open " DEV_PATH);

	/* 幻数错误的 cmd：应返回 ENOTTY */
	errno = 0;
	if (ioctl(fd, _IO('Z', 1), 0) < 0)
		printf("wrong magic -> %s (expected ENOTTY)\n", strerror(errno));
	else
		printf("unexpected: wrong magic accepted\n");

	/* 序号越界：应返回 ENOTTY */
	errno = 0;
	if (ioctl(fd, _IO(HELLO_IOC_MAGIC, 99), 0) < 0)
		printf("bad nr      -> %s (expected ENOTTY)\n", strerror(errno));
	else
		printf("unexpected: bad nr accepted\n");

	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *what = argc > 1 ? argv[1] : "all";

	if (!strcmp(what, "stats"))
		return cmd_stats();
	if (!strcmp(what, "write"))
		return cmd_write();
	if (!strcmp(what, "nonblock"))
		return cmd_nonblock();
	if (!strcmp(what, "poll"))
		return cmd_poll();
	if (!strcmp(what, "echo"))
		return cmd_echo(argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 0) : 42);
	if (!strcmp(what, "badioctl"))
		return cmd_bad_ioctl();

	if (strcmp(what, "all")) {
		fprintf(stderr, "unknown subcommand: %s\n", what);
		return 1;
	}

	printf("### 1. stats\n");
	cmd_stats();
	printf("\n### 2. write/read round-trip\n");
	cmd_write();
	printf("\n### 3. non-blocking EAGAIN\n");
	cmd_nonblock();
	printf("\n### 4. poll\n");
	cmd_poll();
	printf("\n### 5. ioctl echo\n");
	cmd_echo(4242);
	printf("\n### 6. invalid ioctl\n");
	cmd_bad_ioctl();
	printf("\n### 7. final stats\n");
	cmd_stats();
	return 0;
}
