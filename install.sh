#!/bin/sh

set -eu

repository="EasyTier/etcat"
install_dir=${ETCAT_INSTALL_DIR:-/usr/local/bin}
version=${ETCAT_VERSION:-}

fail() {
    printf 'etcat installer: %s\n' "$1" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
    Linux) os="unknown-linux-musl" ;;
    Darwin) os="apple-darwin" ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$version" ]; then
    version=$(curl --proto '=https' --tlsv1.2 --fail --location \
        --silent --show-error --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/$repository/releases/latest")
    version=${version##*/}
else
    case "$version" in
        v*) ;;
        *) version="v$version" ;;
    esac
fi

printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    || fail "invalid release version: $version"

target="$arch-$os"
package_name="etcat-$version-$target"
archive_name="$package_name.tar.gz"
release_url="https://github.com/$repository/releases/download/$version"
etcat_tmp=$(mktemp -d 2>/dev/null || mktemp -d -t etcat)
trap 'rm -rf "$etcat_tmp"' EXIT HUP INT TERM

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --output "$etcat_tmp/$archive_name" "$release_url/$archive_name"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --output "$etcat_tmp/SHA256SUMS" "$release_url/SHA256SUMS"

expected_checksum=$(awk -v archive="$archive_name" \
    '$2 == archive { print $1; exit }' "$etcat_tmp/SHA256SUMS")
[ -n "$expected_checksum" ] \
    || fail "checksum not found for $archive_name"

if command -v sha256sum >/dev/null 2>&1; then
    actual_checksum=$(sha256sum "$etcat_tmp/$archive_name" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$etcat_tmp/$archive_name" | awk '{ print $1 }')
else
    fail "sha256sum or shasum is required"
fi

[ "$actual_checksum" = "$expected_checksum" ] \
    || fail "checksum verification failed for $archive_name"

tar -xzf "$etcat_tmp/$archive_name" -C "$etcat_tmp"
source_binary="$etcat_tmp/$package_name/etcat"
[ -f "$source_binary" ] || fail "release archive does not contain etcat"

if mkdir -p "$install_dir" 2>/dev/null && [ -w "$install_dir" ]; then
    install -m 0755 "$source_binary" "$install_dir/etcat"
elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$install_dir"
    sudo install -m 0755 "$source_binary" "$install_dir/etcat"
else
    fail "cannot write to $install_dir and sudo is unavailable"
fi

printf 'Installed etcat %s to %s/etcat\n' "$version" "$install_dir"
