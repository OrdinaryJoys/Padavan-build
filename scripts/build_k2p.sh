#!/bin/bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
flavor=${1:?Pass k2p-4.4 or k2p-susu}
diagnostics="$root/diagnostics"
dist="$root/dist"
mkdir -p "$diagnostics" "$dist"

record_result() {
  local status=$?
  trap - EXIT
  printf '{"exit_code":%d,"flavor":"%s"}\n' "$status" "$flavor" > "$diagnostics/result.json"
  if [ -f "$root/source/trunk/.config" ]; then
    cp "$root/source/trunk/.config" "$diagnostics/firmware.config"
  fi
  exit "$status"
}
trap record_result EXIT

IFS=$'\t' read -r repository branch ref kernel toolchain_directory toolchain_url toolchain_sha256 < <(
  python3 - "$root/sources.lock.json" "$flavor" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))[sys.argv[2]]
print('\t'.join(value[key] for key in ['repository','branch','ref','kernel','toolchain_directory','toolchain_url','toolchain_sha256']))
PY
)

git init "$root/source"
git -C "$root/source" remote add origin "https://github.com/$repository.git"
git -C "$root/source" fetch --depth=1 origin "$ref"
git -C "$root/source" checkout --detach FETCH_HEAD
source_commit=$(git -C "$root/source" rev-parse HEAD)
test "$source_commit" = "$ref"
build_commit=$(git -C "$root" rev-parse HEAD)
trunk="$root/source/trunk"
python3 "$root/scripts/configure_k2p.py" "$trunk"

# Verify that the selected source includes the maintenance changes before building.
grep -q '^SRC_NAME=curl-8.23.0$' "$trunk/libs/libcurl/Makefile"
grep -q '^SRC_NAME=openssl-3.5.9$' "$trunk/libs/libssl/Makefile"
grep -q 'secure-ssl = true' "$trunk/user/rc/services_ex.c"
printf '%s  %s\n' a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505 \
  "$trunk/user/scripts/ca-certificates.crt" | sha256sum -c -

curl --fail --location --retry 3 --connect-timeout 20 --max-time 600 \
  "$toolchain_url" -o "$root/toolchain.tar.xz"
printf '%s  %s\n' "$toolchain_sha256" "$root/toolchain.tar.xz" | sha256sum -c -
toolchain="$root/source/toolchain-mipsel/$toolchain_directory"
mkdir -p "$toolchain"
tar -xJf "$root/toolchain.tar.xz" -C "$toolchain"
test -x "$toolchain/bin/mipsel-linux-uclibc-gcc"
"$toolchain/bin/mipsel-linux-uclibc-gcc" --version > "$diagnostics/compiler.txt"

python3 - "$diagnostics/provenance.json" "$flavor" "$repository" "$source_commit" "$build_commit" "$kernel" "$toolchain_sha256" <<'PY'
import json,sys
keys=['flavor','source_repository','source_commit','build_commit','kernel','toolchain_sha256']
value=dict(zip(keys,sys.argv[2:]))
value['firmware_partition_bytes']=15925248
value['tls_library_status']='OpenSSL 3.5.9 LTS; minimal built-in provider profile'
json.dump(value,open(sys.argv[1],'w'),indent=2)
PY

cd "$trunk"
# A nonempty second argument keeps the explicit profile; 0 is not a flash size.
fakeroot ./build_firmware_modify K2P 0

# Inspect the actual target programs without starting a router or network service.
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/curl" --version > "$diagnostics/curl-version.txt"
grep -q '^curl 8.23.0 ' "$diagnostics/curl-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/openssl" version > "$diagnostics/openssl-version.txt"
grep -q '^OpenSSL 3.5.9 ' "$diagnostics/openssl-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/ssh" -V 2> "$diagnostics/openssh-version.txt"
grep -q '^OpenSSH_10.6p1' "$diagnostics/openssh-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/sbin/openvpn" --version > "$diagnostics/openvpn-version.txt"
grep -q '^OpenVPN 2.6.23 ' "$diagnostics/openvpn-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/wg" --version > "$diagnostics/wireguard-version.txt"
grep -q 'wireguard-tools v1.0.20260223' "$diagnostics/wireguard-version.txt"

# dnsmasq serves the whole LAN. It cannot be started under qemu-user (getrandom()
# returns 0 there, so it aborts before parsing arguments), so verify the binary
# statically: version tag plus every option Padavan's generated config uses.
strings "$trunk/romfs/usr/sbin/dnsmasq" > "$diagnostics/dnsmasq-version.txt"
grep -qx 'dnsmasq-2.93' "$diagnostics/dnsmasq-version.txt"
for opt in no-poll bogus-priv no-negcache clear-on-reload cache-size \
           dns-forward-max min-port expand-hosts dhcp-authoritative \
           dhcp-range dhcp-option servers-file dhcp-hostsfile bind-dynamic \
           min-ttl filter-aaaa; do
  grep -q -- "$opt" "$diagnostics/dnsmasq-version.txt" || {
    echo "dnsmasq no longer supports option: $opt" >&2; exit 1; }
done

# xt_DSCP is a module on this kernel and nothing loaded it at boot, which made
# every miniupnpd mapping fail with iptc_commit() ENOENT. The module must ship
# and start_upnp() must register the target before miniupnpd runs.
find "$trunk/romfs/lib/modules" -name 'xt_DSCP.ko' -print -quit | grep -q .
# miniupnpd hardening: Content-Length parsing must reject non-digits and clamp.
strings "$trunk/romfs/usr/bin/miniupnpd" > "$diagnostics/miniupnpd-strings.txt"
grep -q 'Content-Length overflow : %lu' "$diagnostics/miniupnpd-strings.txt"
# ... and the 1 MiB body limit must answer 413 instead of buffering forever.
grep -q 'Content-Length over limit' "$diagnostics/miniupnpd-strings.txt"
grep -q 'CONTENT_LENGTH_LIMIT' "$trunk/user/miniupnpd/miniupnpd-2.x/upnphttp.c"
grep -q 'BuildResp2_upnphttp(h, 413' "$trunk/user/miniupnpd/miniupnpd-2.x/upnphttp.c"
# miniupnpd: upstream 2017 SSDP/SOAP parsing fixes must be present in the tree.
grep -q 'p->xmlend >= (p->xml + (9 + 3))' "$trunk/user/miniupnpd/miniupnpd-2.x/minixml.c"
grep -q 'memset(data, 0, sizeof(struct NameValueParserData))' "$trunk/user/miniupnpd/miniupnpd-2.x/upnpreplyparse.c"
grep -q 'atoi_buffer' "$trunk/user/miniupnpd/miniupnpd-2.x/minissdp.c"
# udpxy must not be started when the IPTV/MAN interface does not exist.
grep -q 'udpxy: %s not present, skip start' "$trunk/user/rc/net.c"
# K2P-09: the legacy RT28xx radio-off stub is a no-op for HIF_MT and must not
# be called from RTMPDrvClose on mt7615 (it only produced a false failure log).
# Match the negated guard, not the plain IS_HIF_TYPE() that already existed.
if [ "$flavor" = "k2p-4.4" ]; then
  grep -q '!IS_HIF_TYPE(pAd, HIF_MT)' "$trunk/linux-4.4.x/drivers/net/wireless/mediatek/mt7615/embedded/common/rtmp_init_inf.c"
else
  grep -q '!IS_HIF_TYPE(pAd, HIF_MT)' "$trunk/proprietary/rt_wifi/rtpci/5.0.4.0/mt7615/embedded/common/rtmp_init_inf.c"
fi

# SUSU is the roaming/performance line: its defaults must actually enable the
# features the driver exposes (802.11r, RSSI kick/threshold, band steering) and
# hardware NAT must not stay at the vendor's "disabled" mode 2.
if [ "$flavor" = "k2p-susu" ]; then
  grep -q '"wl_HT_80211R", "1"' "$trunk/user/shared/defaults.c"
  grep -q '"rt_HT_80211R", "1"' "$trunk/user/shared/defaults.c"
  grep -q '"wl_KickStaRssiLow", "-75"' "$trunk/user/shared/defaults.c"
  grep -q '"rt_KickStaRssiLow", "-75"' "$trunk/user/shared/defaults.c"
  grep -q '"wl_AssocReqRssiThres", "-80"' "$trunk/user/shared/defaults.c"
  grep -q '"rt_AssocReqRssiThres", "-80"' "$trunk/user/shared/defaults.c"
  grep -q '"wl_BandSteering", "1"' "$trunk/user/shared/defaults.c"
  grep -q '"rt_BandSteering", "1"' "$trunk/user/shared/defaults.c"
  grep -q 'nvram_wlan_get_int(is_aband, "BandSteering")' "$trunk/user/rc/ralink.c"
  grep -q '"hw_nat_mode", "3"' "$trunk/user/shared/defaults.c"
  grep -q 'CONFIG_FIRMWARE_WIFI_DRIVER=5.0.4.0' "$trunk/configs/templates/K2P.config"
  MT7615_KO=$(find "$trunk/romfs/lib/modules" -name 'mt_7615e.ko' -print -quit)
  [ -n "$MT7615_KO" ] || { echo "mt_7615e.ko missing" >&2; exit 1; }
  strings "$MT7615_KO" | grep -q 'RRMEnable'
  strings "$MT7615_KO" | grep -q 'WNMEnable'
  strings "$MT7615_KO" | grep -q 'BandSteering'
  test -x "$trunk/romfs/sbin/ralinkiappd"
  test -x "$trunk/romfs/bin/hw_nat"
  find "$trunk/romfs/lib/modules" -name 'hw_nat.ko' -print -quit | grep -q .
fi
grep -q 'disabled stale gfwlist= line' "$trunk/user/dnsmasq/dnsmasq.sh"
grep -q 'ssh -Q key' "$trunk/user/openssh/sshd.sh"
grep -q 'ssh-dss' "$trunk/user/openssh/sshd.sh"
grep -q 'modprobe xt_DSCP' "$trunk/user/rc/services_ex.c"
# The shipped rc must really carry the DSCP load (source grep alone is not enough).
strings "$trunk/romfs/sbin/rc" | grep -q 'modprobe xt_DSCP'
# Kernel hardening must be part of the generated start_script template.
grep -q 'kptr_restrict' "$trunk/user/scripts/reset_ss.sh"
# Boot-time guards must ship: a broken stored config must not take DNS/SSH down.
grep -q 'custom config moved to dnsmasq.conf.bad' "$trunk/user/dnsmasq/dnsmasq.sh"
grep -q 'kept sshd_config.bad' "$trunk/user/openssh/sshd.sh"
# The DDNS config carries the password; it must not be world readable.
grep -q 'chmod("/etc/inadyn.conf", 0600)' "$trunk/user/rc/services_ex.c"

# 4.4 hardening: firmware upload must fail cleanly without /tmp space and must
# not silently truncate; the hardware watchdog must be armed; RPS defaults must
# be written at boot instead of relying on manual runtime tuning.
if [ "$flavor" = "k2p-4.4" ]; then
  grep -q 'not enough free space in /tmp' "$trunk/user/httpd/upload.c"
  grep -q 'short write' "$trunk/user/httpd/upload.c"
  grep -q '/dev/watchdog' "$trunk/user/rc/watchdog.c"
  strings "$trunk/romfs/sbin/rc" | grep -q '/dev/watchdog'
  grep -q 'rps_sock_flow_entries' "$trunk/user/rc/smp.c"
  grep -q 'get_login_valid' "$trunk/user/httpd/httpd.c"
  grep -q 'get_login_safe() || get_login_valid()' "$trunk/user/httpd/web_ex.c"
  grep -q 'unlink("/tmp/fwcheck.log")' "$trunk/user/httpd/upload.c"
  grep -q '32768' "$trunk/user/rc/smp.c"
  strings "$trunk/romfs/sbin/rc" | grep -q 'rps_sock_flow_entries'
  strings "$trunk/romfs/sbin/rc" | grep -q 'rps_flow_cnt'
fi
# Hardening must be applied by rc on every boot (storage may predate it).
grep -q 'fput_int("/proc/sys/kernel/kptr_restrict", 1)' "$trunk/user/rc/init.c"
grep -q 'fput_int("/proc/sys/kernel/dmesg_restrict", 1)' "$trunk/user/rc/init.c"
# zlib carries fixes for CVE-2018-25032 / CVE-2022-37434 (1.2.11 is affected).
grep -q 'SRC_NAME=zlib-1.3.2' "$trunk/libs/libz/Makefile"
printf '%s  %s\n' bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16 \
  "$trunk/libs/libz/zlib-1.3.2.tar.gz" | sha256sum -c -
# pppd security backports: CVE-2020-8597 (already fixed in this tree) plus
# CVE-2026-85495 (lcp_reqci nak_buffer) and the MS-CHAP challenge length checks.
grep -q 'len - vallen >= sizeof (rhostname)' "$trunk/user/pppd/pppd/eap.c"
! grep -q 'vallen >= len + sizeof' "$trunk/user/pppd/pppd/eap.c"
grep -q 'nakp - nak_buffer > PPP_MRU - 8' "$trunk/user/pppd/pppd/lcp.c"
grep -q 'at least 8 bytes' "$trunk/user/pppd/pppd/chap_ms.c"
grep -q 'at least 16 bytes' "$trunk/user/pppd/pppd/chap_ms.c"
grep -q 'dmesg_restrict' "$trunk/user/scripts/reset_ss.sh"

# Exercise the built-in RSA and SHA-256 providers with the target executable.
# Ephemeral test keys stay outside diagnostics and uploaded artifacts.
crypto_check="$root/source/crypto-check"
mkdir -p "$crypto_check"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/openssl" req \
  -newkey rsa:2048 -nodes -x509 -sha256 -days 1 \
  -config "$trunk/romfs/etc_ro/openssl.cnf" -subj /CN=K2P-build-check \
  -keyout "$crypto_check/key.pem" -out "$crypto_check/cert.pem" \
  > "$diagnostics/crypto-check.txt" 2>&1
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/openssl" verify \
  -auth_level 2 -CAfile "$crypto_check/cert.pem" "$crypto_check/cert.pem" \
  >> "$diagnostics/crypto-check.txt" 2>&1
rm -f "$crypto_check/key.pem" "$crypto_check/cert.pem"
rmdir "$crypto_check"
printf '%s  %s\n' a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505 \
  "$trunk/romfs/etc_ro/ca-certificates.crt" | sha256sum -c -

shopt -s nullglob
images=("$trunk"/images/*.trx)
if [ "${#images[@]}" -ne 1 ]; then
  echo "Expected exactly one firmware image, found ${#images[@]}" >&2
  exit 1
fi
python3 "$root/scripts/validate_firmware.py" "${images[0]}" --kernel "$kernel" --output "$diagnostics/image-validation.json"

# Read the shipped rootfs back: a header/CRC-valid image is not necessarily a
# usable one (unreadable SquashFS, missing or non-executable helpers).
python3 - "${images[0]}" "$diagnostics/rootfs.squashfs" <<'PY'
import pathlib, struct, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
kernel_size = struct.unpack('>I', data[60:64])[0]
pathlib.Path(sys.argv[2]).write_bytes(data[kernel_size:])
PY
unsquashfs -l "$diagnostics/rootfs.squashfs" > "$diagnostics/rootfs-list.txt"
grep -qx 'squashfs-root/usr/bin/openvpn-cert.sh' "$diagnostics/rootfs-list.txt"
grep -qx 'squashfs-root/usr/libexec/sshd-session' "$diagnostics/rootfs-list.txt"
grep -qx 'squashfs-root/usr/libexec/sshd-auth' "$diagnostics/rootfs-list.txt"
# The /init symlink is created by a romfs rule that used to race; make the
# source rule atomic and keep asserting the resulting image.
grep -q 'ln -sfn sbin/rc init' "$trunk/user/rc/Makefile"
grep -qx 'squashfs-root/etc_ro/ca-certificates.crt' "$diagnostics/rootfs-list.txt"
unsquashfs -ll "$diagnostics/rootfs.squashfs" | grep -Eq -- '-rwxr-xr-x .*usr/bin/openvpn-cert.sh'
if ! unsquashfs -ll "$diagnostics/rootfs.squashfs" | grep -Eq 'init -> sbin/rc'; then
  # Some trees materialise /init as a byte copy of rc (the staging copy loses
  # the symlink). Accept it only when the contents are identical.
  init_hash=$(unsquashfs -cat "$diagnostics/rootfs.squashfs" init | sha256sum | cut -d' ' -f1)
  rc_hash=$(unsquashfs -cat "$diagnostics/rootfs.squashfs" sbin/rc | sha256sum | cut -d' ' -f1)
  [ -n "$init_hash" ] && [ "$init_hash" = "$rc_hash" ]
fi
rm -f "$diagnostics/rootfs.squashfs"

cp "${images[0]}" "$dist/K2P-$flavor-${source_commit:0:12}.trx"
cp "$diagnostics/"{provenance.json,image-validation.json,curl-version.txt,openssl-version.txt,openssh-version.txt,openvpn-version.txt,wireguard-version.txt,dnsmasq-version.txt,miniupnpd-strings.txt,crypto-check.txt,compiler.txt} "$dist/"
cp .config "$dist/firmware.config"
cd "$dist"
sha256sum -- *.trx > SHA256SUMS
echo "Validated K2P firmware is available in $dist"
