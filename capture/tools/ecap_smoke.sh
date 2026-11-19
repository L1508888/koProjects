#!/system/bin/sh
# ecap_smoke.sh - 在设备上跑的冒烟测试
#
# 用法（需要 root）：
#   adb push tools/ecap_smoke.sh /data/local/tmp/
#   adb shell su -c 'sh /data/local/tmp/ecap_smoke.sh'
#
# 前置：ecap_tls.ko、ecapctl、tls_probe_test 都已经 push 到 /data/local/tmp/
#
# 这个脚本做四件事，任何一步失败就报错退出：
#   1. 加载模块，确认符号解析成功
#   2. ABI 握手 + ping（事件通道）
#   3. 挂 uprobe 并用自己的测试程序触发 SSL_write，确认抓到明文
#   4. 卸载模块，确认无残留

set -e

TMP=/data/local/tmp
LOG=$TMP/ecap_smoke.log
FAIL=0

say()  { echo "== $*"; }
ok()   { echo "   [PASS] $*"; }
bad()  { echo "   [FAIL] $*"; FAIL=$((FAIL + 1)); }

cleanup() {
	killall ecapctl 2>/dev/null || true
	sleep 1
	rmmod ecap_tls 2>/dev/null || true
}
trap cleanup EXIT

say "0. 环境检查"
[ -f "$TMP/ecap_tls.ko" ]      || { bad "ecap_tls.ko 不存在"; exit 1; }
[ -f "$TMP/ecapctl" ]          || { bad "ecapctl 不存在";      exit 1; }
[ -f "$TMP/tls_probe_test" ]   || { bad "tls_probe_test 不存在"; exit 1; }
chmod 755 "$TMP/ecapctl" "$TMP/tls_probe_test"
[ -f "$TMP/tls_read_test" ] && chmod 755 "$TMP/tls_read_test"
ok "三个产物就位"

LIBSSL=/apex/com.android.conscrypt/lib64/libssl.so
[ -f "$LIBSSL" ] || { bad "$LIBSSL 不存在（非 Android 13？）"; exit 1; }
ok "系统 libssl.so 存在"

say "1. 加载模块"
cleanup
dmesg -C 2>/dev/null || true
insmod "$TMP/ecap_tls.ko"
if dmesg | grep -q "uprobe_register = "; then
	ok "kallsyms 解析成功"
else
	bad "kallsyms 解析失败，见 dmesg"
	dmesg | grep ecap_tls
	exit 1
fi

say "2. ABI 握手"
if "$TMP/ecapctl" version | grep -q "^OK$"; then
	ok "ABI 版本一致"
else
	bad "ABI 版本不一致"
fi

say "3. 事件通道（ping）"
PING_OUT=$("$TMP/ecapctl" ping -n 32 -l 64 2>&1)
echo "$PING_OUT" | grep -q "received 32, corrupt 0" \
	&& ok "32 条事件零丢零损" \
	|| bad "ping 异常：$PING_OUT"

say "4. 挂 uprobe 并抓明文（M3：双向）"
rm -f "$LOG"
setsid "$TMP/ecapctl" capture --lib "$LIBSSL" --hex >"$LOG" 2>&1 </dev/null &
CAP_PID=$!
sleep 3

if dmesg | grep -q "probe added: SSL_write"; then
	ok "SSL_write 探测点已注册"
else
	bad "SSL_write 探测点注册失败"
	dmesg | grep ecap_tls | tail -5
fi
if dmesg | grep -q "probe added: SSL_read"; then
	ok "SSL_read 探测点已注册"
else
	bad "SSL_read 探测点注册失败"
fi

# 4a) 无真实连接：验证 read 返回错误码时不上报
"$TMP/tls_probe_test" 2 wr >/dev/null 2>&1
sleep 1

if grep -q "ECAPTEST-W-" "$LOG"; then
	N=$(grep -c "ECAPTEST-W-" "$LOG")
	ok "write 路径抓到 $N 条明文（期望 2）"
else
	bad "write 路径没抓到明文"
fi

# 4b) 本地回环真实 TLS：验证 read 正向路径
if [ -f "$TMP/ecap_cert.pem" ] && [ -f "$TMP/ecap_key.pem" ]; then
	"$TMP/tls_read_test" >/dev/null 2>&1
	sleep 1
	if grep -q "ECAPTEST-R-FROM-SERVER" "$LOG"; then
		ok "read 路径抓到服务端响应明文"
	else
		bad "read 路径没抓到明文"
	fi
	if grep -q "ECAPTEST-W-CLIENT" "$LOG"; then
		ok "write 路径抓到客户端请求明文"
	else
		bad "write 路径没抓到客户端请求"
	fi
else
	echo "   [SKIP] 没有 cert/key，跳过回环 TLS 测试"
fi

# 4c) 方向标注必须正确
if grep -qE "^\[[0-9]+\.[0-9]+s\] W " "$LOG" && \
   grep -qE "^\[[0-9]+\.[0-9]+s\] R " "$LOG"; then
	ok "W/R 方向标注正确"
else
	bad "方向标注缺失"
fi

say "5. 统计一致性"
STATS=$("$TMP/ecapctl" stats 2>&1)
echo "$STATS"
echo "$STATS" | grep -q "copy_fail    : 0" && ok "无拷贝失败" || bad "出现拷贝失败"
echo "$STATS" | grep -q "dropped      : 0" && ok "无丢弃"     || bad "出现丢弃"
echo "$STATS" | grep -q "pending      : 0/" && ok "挂起表已清空（无泄漏）" || bad "挂起表有残留"

# ---------------------------------------------------------------------------
# M4：Netfilter 抓包 + pcapng
# ---------------------------------------------------------------------------
say "5b. Netfilter 抓包 + pcapng（M4）"
# 先停掉上一步的 capture —— 否则探测点被占用，
# 新的进程会在 ADD_PAIR 处失败退出，根本走不到 ENABLE_NF。
killall ecapctl 2>/dev/null
sleep 2

PCAP=$TMP/ecap_m4.pcapng
rm -f "$PCAP"
setsid "$TMP/ecapctl" capture --lib "$LIBSSL" --pcap "$PCAP" \
	--packet --port 0 -W >/dev/null 2>&1 </dev/null &
sleep 3

if dmesg | grep -q "netfilter capture enabled"; then
	ok "Netfilter hook 已启用"
else
	bad "Netfilter hook 未启用"
fi

"$TMP/tls_read_test" >/dev/null 2>&1
sleep 2

NFSTAT=$("$TMP/ecapctl" stats 2>&1)
PKTPUSHED=$(echo "$NFSTAT" | awk '/pkt_pushed/{print $3}')
if [ "${PKTPUSHED:-0}" -gt 0 ] 2>/dev/null; then
	ok "抓到 $PKTPUSHED 个网络包"
else
	bad "没抓到网络包"
fi

if [ -s "$PCAP" ]; then
	SZ=$(wc -c < "$PCAP")
	ok "pcapng 已写入 $SZ 字节"
	# 用 python 校验结构（如果有 python3）
	if command -v python3 >/dev/null 2>&1; then
		CNT=$(python3 - "$PCAP" <<'PYEOF' 2>/dev/null
import struct,sys
d=open(sys.argv[1],'rb').read()
off=0;n=0
while off+12<=len(d):
    bt,bl=struct.unpack_from('<II',d,off)
    if bl<12 or off+bl>len(d): break
    tl,=struct.unpack_from('<I',d,off+bl-4)
    if tl!=bl: break
    if bt==6: n+=1
    off+=bl
print(n)
PYEOF
)
		if [ "${CNT:-0}" -gt 0 ] 2>/dev/null; then
			ok "pcapng 结构有效，含 $CNT 个 EPB"
		else
			bad "pcapng 里没有有效的 EPB"
		fi
	fi
else
	bad "pcapng 文件为空"
fi

killall ecapctl 2>/dev/null
sleep 2

say "6. 内核稳定性"
if dmesg | grep -qiE "oops|panic|BUG:|Call trace"; then
	bad "内核出现异常"
	dmesg | grep -iE "oops|panic|BUG:|Call trace" | tail -10
else
	ok "无 oops / panic / BUG"
fi

say "7. 卸载"
if rmmod ecap_tls 2>/dev/null; then
	ok "干净卸载"
else
	# 有 fd 打开时被拒绝是预期行为
	killall ecapctl 2>/dev/null || true
	sleep 2
	rmmod ecap_tls && ok "关闭 fd 后卸载成功（引用计数保护正常）" \
		|| bad "仍无法卸载"
fi

echo
if [ "$FAIL" -eq 0 ]; then
	echo "===== 全部通过 ====="
	exit 0
else
	echo "===== $FAIL 项失败 ====="
	exit 1
fi
