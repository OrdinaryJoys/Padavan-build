#!/bin/bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
flavor=${1:?Pass k2p-4.4 or k2p-susu}
case "$flavor" in
  k2p-4.4|k2p-susu) ;;
  *) echo "Unsupported flavor: $flavor" >&2; exit 64 ;;
esac
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
# Configuration/build generation may dirty the source later. The initial
# checkout must still be exactly the published, locked commit.
test -z "$(git -C "$root/source" status --porcelain --untracked-files=all)"
build_commit=$(git -C "$root" rev-parse HEAD)
trunk="$root/source/trunk"
python3 "$root/scripts/configure_k2p.py" "$trunk"

# Exercise the selected source, including short-write/flush and auth failures,
# before an expensive target build. Missing regression sources fail closed.
for required_test in test_independent_http_edges test_real_http_io test_request_guards \
                     test_startup_config_policy test_miniupnp_global_limits \
                     test_storage_regressions test_runtime_audit_nvram; do
  test -f "$root/source/tests/$required_test.py"
done
if [ "$flavor" = "k2p-4.4" ]; then
  for required_test in test_config_publish test_upgrade_storage_gate test_startup_capacity_linux \
                       test_dns_dynamic_config test_firmware_writer_protocol test_upgrade_upload_no_public_writer; do
    test -f "$root/source/tests/$required_test.py"
  done
fi
# Keep Linux /tmp rewriting exercised even if the runner sets another temp dir.
TMPDIR=/tmp python3 -m unittest discover -s "$root/source/tests" -p 'test_*.py' \
  2>&1 | tee "$diagnostics/source-host-tests.txt"
if grep -Eq '^OK \(skipped=[1-9]' "$diagnostics/source-host-tests.txt"; then
  echo "Required source tests were skipped; check host dependencies" >&2
  exit 1
fi

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
if [ "$flavor" = "k2p-4.4" ]; then
  python3 "$root/scripts/preflight_target_writer.py" --trunk "$trunk" \
    --compiler "$toolchain/bin/mipsel-linux-uclibc-gcc" --output "$diagnostics/target-writer-preflight.json"
fi

write_provenance() {
  python3 - "$diagnostics/provenance.json" "$flavor" "$repository" "$source_commit" "$build_commit" "$kernel" "$toolchain_sha256" "$branch" "$root/source" "$root" "$trunk/.config" "$1" <<'PY'
import hashlib,json,os,pathlib,subprocess,sys
keys=['flavor','source_repository','source_commit','build_commit','kernel','toolchain_sha256','source_branch']
value=dict(zip(keys,sys.argv[2:9]))
output=pathlib.Path(sys.argv[1])
for prefix,root in [('source',sys.argv[9]),('build',sys.argv[10])]:
    status=subprocess.check_output(['git','-C',root,'status','--porcelain','--untracked-files=normal'])
    patch=subprocess.check_output(['git','-C',root,'diff','--binary','HEAD','--'])
    value[prefix+'_worktree_dirty']=bool(status)
    value[prefix+'_worktree_status']=status.decode('utf-8')
    value[prefix+'_tracked_diff_sha256']=hashlib.sha256(patch).hexdigest()
    value[prefix+'_commit_role']='base_revision'
    (output.parent/(prefix+'-worktree.patch')).write_bytes(patch)
value['firmware_config_sha256']=hashlib.sha256(pathlib.Path(sys.argv[11]).read_bytes()).hexdigest()
value['capture_stage']=sys.argv[12]
value['source_lock_sha256']=hashlib.sha256((pathlib.Path(sys.argv[10])/'sources.lock.json').read_bytes()).hexdigest() if (pathlib.Path(sys.argv[10])/'sources.lock.json').exists() else None
value['ci']={name:os.environ.get(name) for name in ['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_OS','RUNNER_ARCH']}
value['firmware_partition_bytes']=15925248
value['tls_library_status']='OpenSSL 3.5.9 LTS; minimal built-in provider profile'
encoded=json.dumps(value,indent=2)+'\n'
output.write_text(encoded,encoding='utf-8')
output.with_name('provenance.'+sys.argv[12]+'.json').write_text(encoded,encoding='utf-8')
for prefix in ['source','build']:
    patch=output.parent/(prefix+'-worktree.patch')
    patch.with_name(prefix+'-worktree.'+sys.argv[12]+'.patch').write_bytes(patch.read_bytes())
PY
}
write_provenance configured_input
cp "$trunk/.config" "$diagnostics/firmware-configured.config"

cd "$trunk"
# A nonempty second argument keeps the explicit profile; 0 is not a flash size.
fakeroot ./build_firmware_modify K2P 0

# Prefix only target libraries: a full fakeroot romfs can contain regular empty
# placeholders for /dev/urandom, which QEMU would otherwise select over the real
# host device. Parser-only checks need real entropy, not fake device files.
qemu_root="$root/qemu-runtime"
mkdir -p "$qemu_root/usr"
ln -s "$trunk/romfs/lib" "$qemu_root/lib"
ln -s "$trunk/romfs/usr/lib" "$qemu_root/usr/lib"

# Exercise the actual shipped libc interfaces and archive parser, not just host
# replacements. All smoke-test writes stay in private ephemeral directories.
"$toolchain/bin/mipsel-linux-uclibc-gcc" -Wall -Wextra -Werror \
  "$root/scripts/target_abi_probe.c" -o "$diagnostics/target-abi-probe" -lrt
qemu-mipsel -L "$qemu_root" "$diagnostics/target-abi-probe" > "$diagnostics/target-abi.txt"
"$toolchain/bin/mipsel-linux-uclibc-gcc" -Wall -Wextra -Werror \
  "$root/scripts/target_http_io_probe.c" "$trunk/user/httpd/http_client_io.o" \
  -o "$diagnostics/target-http-io-probe" -lrt
qemu-mipsel -L "$qemu_root" "$diagnostics/target-http-io-probe" > "$diagnostics/target-http-io.txt"
python3 "$root/scripts/check_target_storage.py" "$trunk/romfs" \
  --sysroot "$qemu_root" --profile "$flavor" --output "$diagnostics/target-storage.json"
python3 "$root/scripts/check_target_services.py" "$trunk/romfs" \
  --sysroot "$qemu_root" --output "$diagnostics/target-services.json"
if [ "$flavor" = "k2p-4.4" ]; then
  python3 "$root/scripts/check_target_config_publish.py" --rootfs "$trunk/romfs" \
    --sysroot "$qemu_root" --output "$diagnostics/target-config-publish.json"
  python3 "$root/scripts/check_target_upgrade.py" --trunk "$trunk" \
    --compiler "$toolchain/bin/mipsel-linux-uclibc-gcc" --sysroot "$qemu_root" \
    --output "$diagnostics/target-upgrade.json"
  python3 "$root/scripts/check_target_dynamic_dns.py" --rootfs "$trunk/romfs" \
    --trunk "$trunk" --sysroot "$qemu_root" --output "$diagnostics/target-dynamic-dns.json"
  python3 "$root/scripts/check_target_writer.py" --trunk "$trunk" --rootfs "$trunk/romfs" \
    --compiler "$toolchain/bin/mipsel-linux-uclibc-gcc" --sysroot "$qemu_root" \
    --output "$diagnostics/target-writer.json"
  strings "$trunk/romfs/sbin/rc" | grep -F 'Storage save failed before upgrade' > /dev/null
  strings "$trunk/romfs/sbin/storage_validate" | grep -F 'Startup config publish:' > /dev/null
  strings "$trunk/romfs/bin/mtd_write" | grep -F -- '--upgrade-write' > /dev/null
  strings "$trunk/romfs/usr/sbin/dnsmasq" | grep -F 'conf-script time budget exceeded' > /dev/null
fi

# Inspect the actual target programs without starting a router or network service.
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/bin/curl" --version > "$diagnostics/curl-version.txt"
grep -q '^curl 8.23.0 ' "$diagnostics/curl-version.txt"
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/bin/openssl" version > "$diagnostics/openssl-version.txt"
grep -q '^OpenSSL 3.5.9 ' "$diagnostics/openssl-version.txt"
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/bin/ssh" -V 2> "$diagnostics/openssh-version.txt"
grep -q '^OpenSSH_10.6p1' "$diagnostics/openssh-version.txt"
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/sbin/openvpn" --version > "$diagnostics/openvpn-version.txt"
grep -q '^OpenVPN 2.6.23 ' "$diagnostics/openvpn-version.txt"
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/bin/wg" --version > "$diagnostics/wireguard-version.txt"
grep -q 'wireguard-tools v1.0.20260223' "$diagnostics/wireguard-version.txt"

# Also verify version tags and every option generated by Padavan. The actual
# parser is exercised above with --test, without starting a DNS/DHCP service.
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
  strings "$MT7615_KO" | grep -F 'RRMEnable' > /dev/null
  strings "$MT7615_KO" | grep -F 'WNMEnable' > /dev/null
  strings "$MT7615_KO" | grep -F 'BandSteering' > /dev/null
  test -x "$trunk/romfs/sbin/ralinkiappd"
  test -x "$trunk/romfs/bin/hw_nat"
  find "$trunk/romfs/lib/modules" -name 'hw_nat.ko' -print -quit | grep -q .
fi
grep -q 'validated legacy migration; pre-migration config kept' "$trunk/user/dnsmasq/dnsmasq.sh"
grep -q 'ssh -Q key' "$trunk/user/openssh/sshd.sh"
grep -q 'ssh-dss' "$trunk/user/openssh/sshd.sh"
grep -q 'modprobe xt_DSCP' "$trunk/user/rc/services_ex.c"
# The shipped rc must really carry the DSCP load (source grep alone is not enough).
strings "$trunk/romfs/sbin/rc" | grep -F 'modprobe xt_DSCP' > /dev/null
# Kernel hardening must be part of the generated start_script template.
grep -q 'kptr_restrict' "$trunk/user/scripts/reset_ss.sh"
# Invalid user policy must not silently become permissive defaults. Supported
# legacy migrations are validated before installation and retain a backup.
if [ "$flavor" = "k2p-4.4" ]; then
  grep -Fq 'invalid custom config or bounded validation failed; original preserved; automatic defaults disabled' "$trunk/user/dnsmasq/dnsmasq.sh"
  grep -Fq 'invalid stored config or bounded validation failed; original preserved; automatic defaults disabled' "$trunk/user/openssh/sshd.sh"
else
  grep -Fq 'invalid custom config; original preserved; automatic defaults disabled' "$trunk/user/dnsmasq/dnsmasq.sh"
  grep -Fq 'invalid stored config; original preserved; automatic defaults disabled' "$trunk/user/openssh/sshd.sh"
fi
# The DDNS config must be private before the first password byte is written.
# Source-presence checks complement the helper's host-side failure-path tests.
grep -Fq 'fp = open_private_config(conf_file)' "$trunk/user/rc/services_ex.c"
grep -Fq 'fchmod(fd, 0600)' "$trunk/user/rc/services_ex.c"

# 4.4 hardening: firmware upload must fail cleanly without /tmp space and must
# not silently truncate; the hardware watchdog must be armed; RPS defaults must
# be written at boot instead of relying on manual runtime tuning.
if [ "$flavor" = "k2p-4.4" ]; then
  grep -q 'not enough free space in /tmp' "$trunk/user/httpd/upload.c"
  grep -Fq 'if (fp && fclose(fp) != 0)' "$trunk/user/httpd/upload.c"
  grep -q '/dev/watchdog' "$trunk/user/rc/watchdog.c"
  strings "$trunk/romfs/sbin/rc" | grep -F '/dev/watchdog' > /dev/null
  grep -q 'rps_sock_flow_entries' "$trunk/user/rc/smp.c"
  grep -q 'get_login_valid' "$trunk/user/httpd/httpd.c"
  grep -q 'get_login_safe() || get_login_valid()' "$trunk/user/httpd/web_ex.c"
  grep -q 'unlink("/tmp/fwcheck.log")' "$trunk/user/httpd/upload.c"
  grep -q '32768' "$trunk/user/rc/smp.c"
  strings "$trunk/romfs/sbin/rc" | grep -F 'rps_sock_flow_entries' > /dev/null
  strings "$trunk/romfs/sbin/rc" | grep -F 'rps_flow_cnt' > /dev/null
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
if grep -q 'vallen >= len + sizeof' "$trunk/user/pppd/pppd/eap.c"; then
  echo "Unsafe legacy EAP length check is still present" >&2
  exit 1
fi
grep -q 'nakp - nak_buffer > PPP_MRU - 8' "$trunk/user/pppd/pppd/lcp.c"
grep -q 'at least 8 bytes' "$trunk/user/pppd/pppd/chap_ms.c"
grep -q 'at least 16 bytes' "$trunk/user/pppd/pppd/chap_ms.c"
grep -q 'dmesg_restrict' "$trunk/user/scripts/reset_ss.sh"

# Exercise the built-in RSA and SHA-256 providers with the target executable.
# Ephemeral test keys stay outside diagnostics and uploaded artifacts.
crypto_check="$root/source/crypto-check"
mkdir -p "$crypto_check"
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/bin/openssl" req \
  -newkey rsa:2048 -nodes -x509 -sha256 -days 1 \
  -config "$trunk/romfs/etc_ro/openssl.cnf" -subj /CN=K2P-build-check \
  -keyout "$crypto_check/key.pem" -out "$crypto_check/cert.pem" \
  > "$diagnostics/crypto-check.txt" 2>&1
qemu-mipsel -L "$qemu_root" "$trunk/romfs/usr/bin/openssl" verify \
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
# Read every shipped regular file without extracting device nodes or following
# image links on the host. Verify executable helpers, /init target and CA bytes
# from the compressed artifact, not only the romfs staging directory.
python3 "$root/scripts/validate_firmware.py" "${images[0]}" --kernel "$kernel" \
  --rootfs-check --output "$diagnostics/image-validation.json"
grep -q 'ln -sfn sbin/rc init' "$trunk/user/rc/Makefile"

write_provenance validated_output

cp "${images[0]}" "$dist/K2P-$flavor-${source_commit:0:12}.trx"
cp "$diagnostics/"{provenance.json,image-validation.json,curl-version.txt,openssl-version.txt,openssh-version.txt,openvpn-version.txt,wireguard-version.txt,dnsmasq-version.txt,miniupnpd-strings.txt,crypto-check.txt,compiler.txt,target-abi.txt,target-http-io.txt,target-storage.json,target-services.json} "$dist/"
cp "$diagnostics/"{source-worktree.patch,build-worktree.patch,source-host-tests.txt} "$dist/"
if [ "$flavor" = "k2p-4.4" ]; then
  cp "$diagnostics/"{target-config-publish.json,target-upgrade.json,target-upgrade-probe.c,target-upgrade-probe,target-dynamic-dns.json,target-writer.json,target-writer-probe.c,target-writer-probe} "$dist/"
fi
cp "$diagnostics/"{provenance.configured_input.json,provenance.validated_output.json,firmware-configured.config,source-worktree.configured_input.patch,build-worktree.configured_input.patch} "$dist/"
cp .config "$dist/firmware.config"
cd "$dist"
sha256sum -- *.trx > SHA256SUMS
echo "Validated K2P firmware is available in $dist"
