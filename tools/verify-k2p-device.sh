#!/bin/sh
# K2P 固件刷后验收测试（只读）
# 用法：sh verify-k2p.sh
# 在设备上运行，逐项检查 13 项代码修复与关键配置是否真的生效。
# 判定：PASS / FAIL / WARN / INFO；退出码 = FAIL 数量（>0 表示有未通过项）。

fails=0; warns=0
pass() { printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; fails=$((fails+1)); }
warn() { printf '  [WARN] %s\n' "$*"; warns=$((warns+1)); }
info() { printf '  [INFO] %s\n' "$*"; }

echo "===== K2P 验收测试 $(date '+%F %T') ====="
info "firmver=$(nvram get firmver) kernel=$(uname -r) uptime=$(cut -d. -f1 /proc/uptime)s"

echo "--- 1. dnsmasq 2.93 与配置兼容 ---"
v=$(dnsmasq --version 2>/dev/null | head -1)
case "$v" in *2.93*) pass "dnsmasq 版本: $v";; *) fail "dnsmasq 不是 2.93: $v";; esac
if dnsmasq --test -C /etc/dnsmasq.conf >/dev/null 2>&1; then
	pass "dnsmasq --test 通过（设备真实配置可解析）"
else
	fail "dnsmasq --test 失败（配置无法解析）"
fi
grep -aq 'min-ttl' /usr/sbin/dnsmasq 2>/dev/null && pass "二进制含 min-ttl 别名" || fail "二进制缺少 min-ttl 别名"
grep -aq 'filter-aaaa' /usr/sbin/dnsmasq 2>/dev/null && pass "二进制含 filter-aaaa 小写别名" || fail "二进制缺少 filter-aaaa 别名"
[ -f /etc/storage/dnsmasq/dnsmasq.conf ] && grep -q '^gfwlist=' /etc/storage/dnsmasq/dnsmasq.conf && warn "仍有未注释的 gfwlist= 行（启动脚本应会处理）" || pass "无残留 gfwlist 行"

echo "--- 2. OpenSSH 10.6p1 与 DSA 迁移 ---"
v=$(ssh -V 2>&1 | head -1)
case "$v" in *OpenSSH_10.6*) pass "ssh: $v";; *) fail "ssh 版本不是 10.6: $v";; esac
[ -x /usr/libexec/sshd-auth ] && pass "sshd-auth 存在" || fail "缺少 /usr/libexec/sshd-auth（10.x 必需）"
[ -x /usr/libexec/sshd-session ] && pass "sshd-session 存在" || fail "缺少 /usr/libexec/sshd-session"
if sshd -t >/dev/null 2>&1; then pass "sshd -t 通过"; else fail "sshd -t 失败"; fi
if grep -q 'ssh_host_dsa_key' /etc/storage/openssh/sshd_config 2>/dev/null; then
	fail "sshd_config 仍引用 DSA 主机密钥（迁移未生效）"
else
	pass "sshd_config 无 DSA 悬空行"
fi

echo "--- 3. miniupnpd 加固 ---"
grep -aq 'Content-Length overflow' /usr/bin/miniupnpd 2>/dev/null && pass "含 Content-Length 溢出钳制" || fail "缺少 Content-Length 钳制"
grep -aq 'Content-Length over limit' /usr/bin/miniupnpd 2>/dev/null && pass "含 1 MiB 上限 + 413" || fail "缺少 1 MiB 上限/413"

echo "--- 4. UPnP DSCP ---"
if lsmod 2>/dev/null | grep -q '^xt_DSCP'; then
	pass "xt_DSCP 已加载"
	if iptables -t mangle -A POSTROUTING -p tcp --dport 65530 -j DSCP --set-dscp 0 2>/dev/null; then
		iptables -t mangle -D POSTROUTING -p tcp --dport 65530 -j DSCP --set-dscp 0 2>/dev/null
		pass "DSCP 规则可写入"
	else
		fail "DSCP 规则写入失败"
	fi
else
	fail "xt_DSCP 未加载（UPnP 映射会失败）"
fi

echo "--- 5. udpxy ---"
u=$(ps w 2>/dev/null | grep '[u]dpxy -m' | head -1)
if [ -n "$u" ]; then
	info "udpxy: $u"
	case "$u" in *'-M 55'*) pass "组播续约 -M 55";; *) warn "udpxy 未使用 -M 55";; esac
	curl -s -m 3 -o /dev/null "http://127.0.0.1:2048/status" && pass "udpxy 状态页可达" || fail "udpxy 状态页不可达"
else
	warn "udpxy 未运行（IPTV 关闭或未启用）"
fi

echo "--- 6. 内核加固 ---"
[ "$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)" = "1" ] && pass "kptr_restrict=1" || fail "kptr_restrict != 1"
[ "$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)" = "1" ] && pass "dmesg_restrict=1" || fail "dmesg_restrict != 1"

echo "--- 7. 镜像与脚本 ---"
[ -L /init ] && pass "/init 是符号链接" || fail "/init 不是符号链接"
h=$(sha256sum /etc_ro/ca-certificates.crt 2>/dev/null | cut -d' ' -f1)
[ "$h" = "a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505" ] && pass "CA 包哈希一致" || warn "CA 哈希不同: $h"
[ -x /usr/bin/openvpn-cert.sh ] && pass "openvpn-cert.sh 可执行" || fail "openvpn-cert.sh 不可执行"

echo "--- 8. 安全姿态（非固件项，供参考） ---"
[ "$(nvram get sshd_wbfp)" != "0" ] && pass "SSH 防爆破已开" || warn "SSH 防爆破关闭"
[ "$(nvram get udpxy_wopen)" = "0" ] && pass "udpxy 未对公网开放" || warn "udpxy 对公网开放（测试期可接受）"
[ "$(nvram get https_wopen)" = "1" ] && pass "HTTPS(WAN) 已启用" || warn "HTTPS(WAN) 未启用"
[ "$(nvram get misc_http_x)" = "0" ] && pass "明文 HTTP(WAN) 已关闭" || warn "明文 HTTP(WAN) 仍开放"

echo "--- 9. IPTV 链路 ---"
info "viptv_mode=$(nvram get viptv_mode) wan_stb_x=$(nvram get wan_stb_x) iso=$(nvram get wan_stb_iso)"
[ -e /sys/class/net/eth3.99 ] && pass "MAN 接口 eth3.99 存在" || warn "MAN 接口不存在（IPTV 关闭）"
ps w 2>/dev/null | grep -q '[i]gmpproxy' && pass "igmpproxy 运行" || warn "igmpproxy 未运行"

echo
echo "===== 结果: FAIL=$fails WARN=$warns ====="
exit "$fails"
