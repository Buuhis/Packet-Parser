#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
VERSION=1.0.0
ARCH=$(dpkg --print-architecture)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION=${2:?missing version}; shift 2 ;;
        -h|--help) echo "Usage: $0 [--version VERSION]"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }

make -C "$PROJECT_DIR" all
DAEMON="$PROJECT_DIR/bin/pqc"
SCRYPT_LIB="$PROJECT_DIR/lib/libscrypt.so"
[[ -f "$DAEMON" && -f "$SCRYPT_LIB" ]] || { echo "Missing build artifact" >&2; exit 1; }

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT
PKG_DIR="$STAGE_DIR/pqc-keygen"
DIST_DIR="$PROJECT_DIR/dist"
PACKAGE="$DIST_DIR/pqc-keygen_${VERSION}_${ARCH}.deb"

install -d "$PKG_DIR/DEBIAN" "$PKG_DIR/usr/local/bin" "$PKG_DIR/usr/local/lib/pqc" "$PKG_DIR/usr/lib/systemd/system"
install -m 0755 "$DAEMON" "$PKG_DIR/usr/local/bin/pqc"
install -m 0755 "$SCRYPT_LIB" "$PKG_DIR/usr/local/lib/pqc/libscrypt.so"
install -m 0644 "$PROJECT_DIR/pqc.service" "$PKG_DIR/usr/lib/systemd/system/pqc.service"

sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" "$SCRIPT_DIR/debian/control.in" > "$PKG_DIR/DEBIAN/control"
install -m 0755 "$SCRIPT_DIR/debian/postinst" "$PKG_DIR/DEBIAN/postinst"

mkdir -p "$DIST_DIR"
dpkg-deb --root-owner-group --build "$PKG_DIR" "$PACKAGE"
sha256sum "$PACKAGE" > "$PACKAGE.sha256"
echo "Created clean package: $PACKAGE"
