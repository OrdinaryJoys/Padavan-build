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

git clone --depth=1 --branch "$branch" "https://github.com/$repository.git" "$root/source"
git -C "$root/source" checkout --detach "$ref"
source_commit=$(git -C "$root/source" rev-parse HEAD)
test "$source_commit" = "$ref"
build_commit=$(git -C "$root" rev-parse HEAD)
trunk="$root/source/trunk"
python3 "$root/scripts/configure_k2p.py" "$trunk"

# Verify that the selected source includes the maintenance changes before building.
grep -q '^SRC_NAME=curl-8.22.0$' "$trunk/libs/libcurl/Makefile"
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
grep -q '^curl 8.22.0 ' "$diagnostics/curl-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/openssl" version > "$diagnostics/openssl-version.txt"
grep -q '^OpenSSL 3.5.9 ' "$diagnostics/openssl-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/bin/ssh" -V 2> "$diagnostics/openssh-version.txt"
grep -q '^OpenSSH_9.9p2' "$diagnostics/openssh-version.txt"
qemu-mipsel -L "$trunk/romfs" "$trunk/romfs/usr/sbin/openvpn" --version > "$diagnostics/openvpn-version.txt"
grep -q '^OpenVPN 2.6.23 ' "$diagnostics/openvpn-version.txt"

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
cp "${images[0]}" "$dist/K2P-$flavor-${source_commit:0:12}.trx"
cp "$diagnostics/"{provenance.json,image-validation.json,curl-version.txt,openssl-version.txt,openssh-version.txt,openvpn-version.txt,crypto-check.txt,compiler.txt} "$dist/"
cp .config "$dist/firmware.config"
cd "$dist"
sha256sum -- *.trx > SHA256SUMS
echo "Validated K2P firmware is available in $dist"
