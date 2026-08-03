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

is_core_library() {
    case "$(basename "$1")" in
        libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libutil.so.1|ld-linux*.so.*|ld-musl-*.so.*) return 0 ;;
        *) return 1 ;;
    esac
}

bundle_deps() {
    local lib_dir=$1 candidate resolved source_name target_name child
    shift
    local -a queue=("$@")
    local -A visited=()
    while ((${#queue[@]})); do
        candidate=${queue[0]}; queue=("${queue[@]:1}")
        while read -r candidate; do
            [[ -f "$candidate" ]] || continue
            resolved=$(readlink -f -- "$candidate")
            [[ -n ${visited[$resolved]+x} ]] && continue
            visited[$resolved]=1
            while read -r child; do queue+=("$child"); done < <(ldd "$resolved" 2>/dev/null | awk '/=> \// {print $3} /^\// {print $1}')
            [[ "$resolved" == "$lib_dir/"* ]] && continue
            is_core_library "$resolved" && continue
            source_name=$(basename -- "$candidate"); target_name=$(basename -- "$resolved")
            install -m 0644 "$resolved" "$lib_dir/$target_name"
            [[ "$source_name" == "$target_name" ]] || ln -sfn "$target_name" "$lib_dir/$source_name"
        done < <(ldd "$candidate" 2>/dev/null | awk '/=> \// {print $3} /^\// {print $1}')
    done
}

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }
make -C "$PROJECT_DIR" all
DAEMON="$PROJECT_DIR/bin/pqc"
SCRYPT_LIB="$PROJECT_DIR/lib/libscrypt.so"
[[ -f "$DAEMON" && -f "$SCRYPT_LIB" ]] || { echo "Missing build artifact" >&2; exit 1; }

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT
PKG_DIR="$STAGE_DIR/pqc-keygen"
SCAN_LIB_DIR="$STAGE_DIR/runtime-libs"
VENDORED_LIB_DIR="$PROJECT_DIR/lib"
DIST_DIR="$PROJECT_DIR/dist"
PACKAGE="$DIST_DIR/pqc-keygen_${VERSION}_${ARCH}.deb"

install -d "$PKG_DIR/DEBIAN" "$PKG_DIR/usr/bin" "$PKG_DIR/usr/lib/pqc" "$PKG_DIR/usr/lib/systemd/system" "$SCAN_LIB_DIR"
install -m 0755 "$DAEMON" "$PKG_DIR/usr/bin/pqc"
install -m 0644 "$SCRYPT_LIB" "$SCAN_LIB_DIR/libscrypt.so"
export LD_LIBRARY_PATH="$SCAN_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bundle_deps "$SCAN_LIB_DIR" "$PKG_DIR/usr/bin/pqc" "$SCAN_LIB_DIR/libscrypt.so"
cp -a "$SCAN_LIB_DIR/." "$VENDORED_LIB_DIR/"
cp -a "$VENDORED_LIB_DIR/." "$PKG_DIR/usr/lib/pqc/"
install -m 0644 "$PROJECT_DIR/pqc.service" "$PKG_DIR/usr/lib/systemd/system/pqc.service"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" "$SCRIPT_DIR/debian/control.in" > "$PKG_DIR/DEBIAN/control"
install -m 0755 "$SCRIPT_DIR/debian/postinst" "$PKG_DIR/DEBIAN/postinst"
mkdir -p "$DIST_DIR"
dpkg-deb --root-owner-group --build "$PKG_DIR" "$PACKAGE"
sha256sum "$PACKAGE" > "$PACKAGE.sha256"
echo "Created: $PACKAGE"
