#!/bin/sh
# K2P 运行态只读验收：不写 sysctl/firewall，不打开 /dev/watchdog，不重启服务。
# 用法：sh verify-k2p.sh；VERIFY_ROOT 可指向离线测试夹具，默认检查当前设备。
# PASS 只代表该条明确断言；WARN/INFO 不能作为固件功能完整通过的证据。
# 版本和 flavor 只报告事实，不将未来版本或未编入的可选组件判为故障。

fails=0; warns=0
root=${VERIFY_ROOT:-}
pass() { printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; fails=$((fails+1)); }
warn() { printf '  [WARN] %s\n' "$*"; warns=$((warns+1)); }
info() { printf '  [INFO] %s\n' "$*"; }
# 此固件裁剪了 command builtin；已确认 type builtin 可用。
has() { type "$1" >/dev/null 2>&1; }
link_target() {
    # 只读取固定路径的链接元数据；永不打开链接所指设备。
    if has readlink; then
        link_value=$(readlink "$1" 2>/dev/null) || link_value=
        if [ -n "$link_value" ]; then printf '%s\n' "$link_value"; return 0; fi
    fi
    if has ls && has sed; then
        # 固定 /init 或 /proc/PID/fd/N；裁剪系统无 readlink 时仅解析箭头后的已知目标。
        # shellcheck disable=SC2012
        link_value=$(LC_ALL=C ls -ld "$1" 2>/dev/null | sed -n 's/^.* -> //p')
        if [ -n "$link_value" ]; then printf '%s\n' "$link_value"; return 0; fi
    fi
    return 1
}
nv() { nvram get "$1" 2>/dev/null; }
read_value() { cat "$root$1" 2>/dev/null; }
check_value() {
    value=$(read_value "$1")
    if [ -z "$value" ]; then warn "$1 不可读（未验证）"
    elif [ "$value" = "$2" ]; then pass "$1=$value"
    else warn "$1=${value}，当前审计基准=$2；需结合 flavor/自定义配置核实"; fi
}

printf '===== K2P 只读验收 %s =====\n' "$(date '+%F %T')"
kernel=$(read_value /proc/sys/kernel/osrelease)
[ -n "$kernel" ] || kernel=$(uname -r)
case "$kernel" in 4.4*) flavor=k2p-4.4;; 3.4*) flavor=k2p-susu;; *) flavor=unknown;; esac
info "kernel=$kernel flavor=$flavor uptime=$(read_value /proc/uptime)"
if has nvram; then info "firmver=$(nv firmver)"; else warn "缺少 nvram，配置相关项目未验证"; fi

printf '\n--- 1. DNS 真实配置 ---\n'
if has dnsmasq; then
    info "$(dnsmasq --version 2>/dev/null | head -n 1)"
    if [ ! -r "$root/etc/dnsmasq.conf" ]; then fail "dnsmasq 配置不存在/不可读"
    elif dnsmasq --test -C "$root/etc/dnsmasq.conf" >/dev/null 2>&1; then pass "dnsmasq 当前配置语法通过"
    else fail "dnsmasq 当前配置语法失败"; fi
else warn "未安装 dnsmasq，DNS 功能未验证"; fi
if [ -r "$root/etc/storage/dnsmasq/dnsmasq.conf" ] && grep -q '^gfwlist=' "$root/etc/storage/dnsmasq/dnsmasq.conf"; then
    warn "用户 dnsmasq 配置仍有 gfwlist=；需核实运行配置迁移结果"
fi

printf '\n--- 2. SSH 配置与实际编译组件 ---\n'
if has ssh; then info "$(ssh -V 2>&1 | head -n 1)"; fi
if has sshd; then
    server_banner=$(sshd -V 2>&1 || true)
    case "$server_banner" in OpenSSH_10.6*) known_helpers=1;; *) known_helpers=0;; esac
    if sshd -t >/dev/null 2>&1; then pass "sshd 当前配置语法通过"; else fail "sshd 当前配置语法失败"; fi
    for helper in sshd-auth sshd-session; do
        if [ -x "$root/usr/libexec/$helper" ]; then pass "$helper 可执行"
        elif [ "$known_helpers" = 1 ]; then fail "OpenSSH 10.6 缺少必需可执行文件 $helper"
        else info "$helper 未提供；该服务器版本的拆分组件需求未判定，需真实登录验证"; fi
    done
    if [ -r "$root/etc/storage/openssh/sshd_config" ] && grep -Eq '^[[:space:]]*HostKey[[:space:]].*ssh_host_dsa_key' "$root/etc/storage/openssh/sshd_config"; then
        warn "sshd_config 含有效 DSA HostKey 行；需按实际 OpenSSH 能力核实"
    fi
else warn "未安装 OpenSSH sshd（可能使用其他 SSH 实现），未验证"; fi

printf '\n--- 3. miniupnpd 与 DSCP（纯只读） ---\n'
if [ -e "$root/usr/bin/miniupnpd" ]; then
    info "miniupnpd 已安装；本脚本不以字符串存在判定解析器修复或边界处理通过"
fi
if [ -r "$root/proc/net/ip_tables_targets" ]; then
    if grep -Eq '^[[:space:]]*DSCP[[:space:]]*$' "$root/proc/net/ip_tables_targets"; then pass "DSCP target 已向内核注册（不写测试规则）"
    else warn "DSCP target 未注册；若 UPnP 使用 DSCP 需进一步检查"; fi
else warn "无法读取 ip_tables_targets，DSCP 未验证"; fi

printf '\n--- 4. udpxy / IPTV ---\n'
if has pidof && pidof udpxy >/dev/null 2>&1; then
    pass "udpxy 进程存在（不代表端到端播放可用）"
    if [ -n "$root" ] && [ "${VERIFY_HTTP_CHECK:-0}" != 1 ]; then
        info "离线夹具模式跳过本机 HTTP 请求"
    elif has curl; then
        if curl --noproxy '*' --fail --silent --show-error --max-time 3 --output /dev/null http://127.0.0.1:2048/status; then pass "udpxy /status 返回成功 HTTP 状态"
        else fail "udpxy /status 请求失败或 HTTP 错误"; fi
    else warn "缺少 curl，状态页未验证"; fi
else info "udpxy 未运行；是否需要运行取决于 IPTV 配置"; fi
if [ -e "$root/sys/class/net/eth3.99" ]; then pass "MAN eth3.99 接口存在"; else info "MAN eth3.99 不存在（可能未启用 IPTV）"; fi
if has pidof && pidof igmpproxy >/dev/null 2>&1; then pass "igmpproxy 进程存在"; fi

printf '\n--- 5. 内核只读加固状态 ---\n'
check_value /proc/sys/kernel/kptr_restrict 1
check_value /proc/sys/kernel/dmesg_restrict 1

printf '\n--- 6. init 入口与可选脚本 ---\n'
if [ ! -r "$root/sbin/rc" ]; then fail "/sbin/rc 缺失或不可读"
elif [ -L "$root/init" ]; then
    if target=$(link_target "$root/init"); then
        case "$target" in
            sbin/rc|./sbin/rc|/sbin/rc) pass "/init 链接目标为 $target";;
            *) fail "/init 链接目标异常: $target";;
        esac
    else warn "/init 链接元数据无法读取，目标未验证"; fi
elif [ -r "$root/init" ] && has cmp && cmp -s "$root/init" "$root/sbin/rc"; then pass "/init 为与 /sbin/rc 字节一致的副本"
else fail "/init 不是有效 rc 入口"; fi
if [ ! -x "$root/sbin/rc" ]; then fail "/sbin/rc 不可执行"; fi
if [ -e "$root/usr/sbin/openvpn" ] || [ -e "$root/usr/bin/openvpn" ]; then
    if [ -x "$root/usr/bin/openvpn-cert.sh" ]; then pass "OpenVPN 证书脚本可执行"
    else fail "已安装 OpenVPN，但证书脚本缺失/不可执行"; fi
else info "未编入 OpenVPN，跳过其可选证书脚本"; fi
if [ -r "$root/etc_ro/ca-certificates.crt" ] && has sha256sum; then
    info "CA SHA256=$(sha256sum "$root/etc_ro/ca-certificates.crt" | cut -d' ' -f1)；需与本次构建 provenance 比较"
else warn "CA 包不可读或无哈希工具，未验证"; fi

printf '\n--- 7. DDNS 凭据文件权限 ---\n'
if [ -e "$root/etc/inadyn.conf" ]; then
    mode=$(stat -c '%a' "$root/etc/inadyn.conf" 2>/dev/null)
    owner=$(stat -c '%u' "$root/etc/inadyn.conf" 2>/dev/null)
    if [ -z "$mode" ] || [ -z "$owner" ]; then warn "stat 无法读取 inadyn.conf 权限，未验证"
    elif [ "$mode" = 600 ] && [ "$owner" = 0 ]; then pass "inadyn.conf root:0600"
    else fail "inadyn.conf 权限/属主不安全: mode=$mode uid=$owner"; fi
else info "inadyn.conf 不存在；DDNS 可能未启用"; fi

printf '\n--- 8. 硬件看门狗（不打开设备） ---\n'
held=0
if has pidof; then
    for pid in $(pidof watchdog 2>/dev/null); do
        case "$pid" in *[!0-9]*|'') continue;; esac
        for fd in "$root/proc/$pid/fd/"*; do
            [ -L "$fd" ] || continue
            target=$(link_target "$fd")
            case "$target" in /dev/watchdog|/dev/watchdog0) held=1;; esac
        done
    done
    if [ "$held" = 1 ]; then pass "watchdog 进程持有硬件看门狗 fd（未验证持续喂狗/超时恢复）"
    elif [ "$flavor" = k2p-4.4 ]; then warn "未观察到 watchdog 硬件 fd；需核实部署版本、权限与启动日志"
    else info "$flavor 未观察到硬件看门狗 fd；不假定已移植 4.4 修复"; fi
else warn "缺少 pidof，看门狗 fd 未验证"; fi
if [ -r "$root/sys/class/watchdog/watchdog0/timeout" ]; then
    info "硬件看门狗 timeout=$(read_value /sys/class/watchdog/watchdog0/timeout)s（只读回读）"
else info "内核未提供可读 timeout；不以历史日志推定当前值"; fi

printf '\n--- 9. RPS/RFS 实际参数（不推断性能收益） ---\n'
check_value /proc/sys/net/core/rps_sock_flow_entries 32768
check_value /proc/sys/net/core/netdev_max_backlog 3000
queues=0
for queue in "$root/sys/class/net/eth2/queues/"rx-* "$root/sys/class/net/eth3/queues/"rx-*; do
    [ -d "$queue" ] || continue
    queues=$((queues+1))
    for name in rps_cpus rps_flow_cnt; do
        if [ -r "$queue/$name" ]; then
            value=$(cat "$queue/$name")
            info "${queue#"$root"}/$name=$value"
            if [ "$name" = rps_flow_cnt ] && [ "$flavor" = k2p-4.4 ] && [ "$value" != 2048 ]; then
                warn "该4.4队列 rps_flow_cnt=${value}，当前审计基准=2048；需核实自定义配置"
            elif [ "$name" = rps_cpus ] && [ -z "$(printf '%s' "$value" | tr -d '0,')" ]; then
                warn "该队列 RPS CPU 掩码为0；RPS 未在此队列启用"
            fi
        else warn "${queue#"$root"}/$name 不可读"; fi
    done
done
[ "$queues" -gt 0 ] || warn "未找到 eth2/eth3 接收队列；RPS 每队列状态未验证"

printf '\n--- 10. 管理面安全姿态 ---\n'
if has nvram; then
    case "$(nv sshd_wbfp)" in ''|0) warn "SSH 防爆破未启用或未配置";; *) info "SSH 防爆破配置=$(nv sshd_wbfp)，有效规则仍需核查";; esac
    if [ "$(nv udpxy_wopen)" = 0 ]; then pass "udpxy_wopen=0"; else warn "udpxy_wopen 非0/未配置"; fi
    if [ "$(nv https_wopen)" = 1 ]; then info "HTTPS WAN 配置已启用，证书与连接仍需验证"; else warn "HTTPS WAN 未启用或未配置"; fi
    if [ "$(nv misc_http_x)" = 0 ]; then pass "HTTP WAN 开关为0（上游映射仍需独立核查）"; else warn "HTTP WAN 非0/未配置"; fi
fi
info "未执行破坏性边界测试、真实 SSH 新会话、跨01:00播放、看门狗超时或吞吐A/B；这些项目仍待独立验收"
printf '\n===== 结果: FAIL=%s WARN=%s =====\n' "$fails" "$warns"
[ "$fails" -eq 0 ] || exit 1
