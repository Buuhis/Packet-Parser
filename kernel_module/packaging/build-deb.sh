#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
VERSION="1.0.0"
KERNEL_RELEASE=$(uname -r)
ARCH=$(dpkg --print-architecture)

usage() {
    echo "Usage: $0 [--version VERSION] [--kernel-release RELEASE]"
}

# Core libraries are supplied by the target distro's dynamic loader and are
# deliberately not bundled.  Everything else reported by ldd is copied into
# the package, recursively, so apt does not need network access for runtime
# dependencies such as libpq, libnl, OpenSSL, Kerberos, or compression libs.
is_core_system_library() {
    case "$(basename "$1")" in
        libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libutil.so.1|ld-linux*.so.*|ld-musl-*.so.*)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

bundle_runtime_dependencies() {
    local library_dir=$1
    shift
    local -a queue=("$@")
    local candidate resolved source_name target_name
    local -A visited=()

    while ((${#queue[@]})); do
        candidate=${queue[0]}
        queue=("${queue[@]:1}")

        while read -r candidate; do
            [[ -n "$candidate" && -f "$candidate" ]] || continue
            resolved=$(readlink -f -- "$candidate")
            [[ -n "$resolved" && -f "$resolved" ]] || continue
            [[ -n ${visited[$resolved]+x} ]] && continue
            visited[$resolved]=1

            # Recurse before filtering: a core library is not copied, but a
            # non-core child of it may still be required by the application.
            while read -r child; do
                queue+=("$child")
            done < <(ldd "$resolved" 2>/dev/null | awk '/=> \// {print $3} /^\// {print $1}')

            # libscrypt.so was placed in the staging directory before this
            # scan; do not attempt to install that same file onto itself.
            if [[ "$resolved" == "$library_dir/"* ]]; then
                continue
            fi

            if is_core_system_library "$resolved"; then
                continue
            fi

            source_name=$(basename -- "$candidate")
            target_name=$(basename -- "$resolved")
            install -m 0644 "$resolved" "$library_dir/$target_name"
            if [[ "$source_name" != "$target_name" ]]; then
                ln -sfn "$target_name" "$library_dir/$source_name"
            fi
        done < <(ldd "$candidate" 2>/dev/null | awk '/=> \// {print $3} /^\// {print $1}')
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION=${2:?missing version}; shift 2 ;;
        --kernel-release) KERNEL_RELEASE=${2:?missing kernel release}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$KERNEL_RELEASE" != "$(uname -r)" ]]; then
    echo "This binary-only builder can only build the running kernel ($(uname -r))." >&2
    echo "Boot the target kernel first, then rerun this script." >&2
    exit 1
fi

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }

make -C "$PROJECT_DIR" all

DAEMON="$PROJECT_DIR/sd-wan"
MODULE="$PROJECT_DIR/kernel/mwan_kmod.ko"
SCRYPT_LIB="$PROJECT_DIR/sig_encrypt/lib/libscrypt.so"
for artifact in "$DAEMON" "$MODULE" "$SCRYPT_LIB"; do
    [[ -f "$artifact" ]] || { echo "Missing build artifact: $artifact" >&2; exit 1; }
done

MODULE_VERMAGIC=$(modinfo -F vermagic "$MODULE" | awk '{print $1}')
if [[ "$MODULE_VERMAGIC" != "$KERNEL_RELEASE" ]]; then
    echo "Module vermagic '$MODULE_VERMAGIC' does not match '$KERNEL_RELEASE'." >&2
    exit 1
fi

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT
PKG_DIR="$STAGE_DIR/sd-wan"
PACKAGE_NAME="sd-wan_${VERSION}_${ARCH}_linux-${KERNEL_RELEASE}.deb"
DIST_DIR="$PROJECT_DIR/dist"
VENDORED_LIB_DIR="$PROJECT_DIR/lib"
SCAN_LIB_DIR="$STAGE_DIR/runtime-libs"

install -d \
    "$PKG_DIR/DEBIAN" \
    "$PKG_DIR/usr/sbin" \
    "$PKG_DIR/usr/lib/sd-wan" \
    "$PKG_DIR/usr/lib/systemd/system" \
    "$PKG_DIR/usr/share/sd-wan" \
    "$PKG_DIR/lib/modules/$KERNEL_RELEASE/extra"

install -d "$SCAN_LIB_DIR" "$VENDORED_LIB_DIR"

install -m 0755 "$DAEMON" "$PKG_DIR/usr/sbin/sd-wan"
install -m 0644 "$SCRYPT_LIB" "$SCAN_LIB_DIR/libscrypt.so"
install -m 0644 "$MODULE" "$PKG_DIR/lib/modules/$KERNEL_RELEASE/extra/mwan_kmod.ko"
install -m 0644 "$PROJECT_DIR/systemd/sd-wan.service" "$PKG_DIR/usr/lib/systemd/system/sd-wan.service"
install -m 0644 "$SCRIPT_DIR/sd-wan.env.example" "$PKG_DIR/usr/share/sd-wan/sd-wan.env.example"

# Refresh the persistent, reviewable runtime bundle in kernel_module/lib.
# It contains libscrypt plus every non-core transitive dependency.  The package
# is then assembled from this directory, so an offline target needs no apt
# library packages.
export LD_LIBRARY_PATH="$SCAN_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bundle_runtime_dependencies "$SCAN_LIB_DIR" \
    "$PKG_DIR/usr/sbin/sd-wan" "$SCAN_LIB_DIR/libscrypt.so"
cp -a "$SCAN_LIB_DIR/." "$VENDORED_LIB_DIR/"
cp -a "$VENDORED_LIB_DIR/." "$PKG_DIR/usr/lib/sd-wan/"

sed \
    -e "s/@VERSION@/$VERSION/g" \
    -e "s/@ARCH@/$ARCH/g" \
    -e "s/@KERNEL_RELEASE@/$KERNEL_RELEASE/g" \
    "$SCRIPT_DIR/debian/control.in" > "$PKG_DIR/DEBIAN/control"
sed "s/@KERNEL_RELEASE@/$KERNEL_RELEASE/g" \
    "$SCRIPT_DIR/debian/postinst" > "$PKG_DIR/DEBIAN/postinst"
chmod 0755 "$PKG_DIR/DEBIAN/postinst"

mkdir -p "$DIST_DIR"
dpkg-deb --root-owner-group --build "$PKG_DIR" "$DIST_DIR/$PACKAGE_NAME"
sha256sum "$DIST_DIR/$PACKAGE_NAME" > "$DIST_DIR/$PACKAGE_NAME.sha256"
echo "Created: $DIST_DIR/$PACKAGE_NAME"
