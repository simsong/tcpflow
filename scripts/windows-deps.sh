#!/usr/bin/env bash
# Build tcpflow's pinned, static MinGW dependencies on Linux or macOS.
# vcpkg supplies Boost ICL plus target OpenSSL, zlib and TRE archives.
# The target triplet always produces x64 Windows code without application DLLs.
# Host tools are built for the actual build machine, not the target platform.
# The isolated prefix is consumed by Makefile.ci's windows compilation target.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export VCPKG_ROOT=${VCPKG_ROOT:-"$root/.build/vcpkg"}
revision=${VCPKG_COMMIT:-40f3c709db80acf154ac4b17a1f83c564ebd022e}
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) host=arm64-osx;;
    Darwin-x86_64) host=x64-osx;;
    Linux-aarch64) host=arm64-linux;;
    Linux-x86_64) host=x64-linux;;
    *) echo 'Unsupported vcpkg build host' >&2; exit 2;;
esac
if [[ ! -d "$VCPKG_ROOT/.git" ]]; then
    git init "$VCPKG_ROOT"
    git -C "$VCPKG_ROOT" remote add origin https://github.com/microsoft/vcpkg.git
fi
test "$(git -C "$VCPKG_ROOT" remote get-url origin)" = https://github.com/microsoft/vcpkg.git
git -C "$VCPKG_ROOT" fetch --depth 1 origin "$revision"
git -C "$VCPKG_ROOT" checkout --detach FETCH_HEAD
"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
"$VCPKG_ROOT/vcpkg" install boost-icl:x64-mingw-static openssl:x64-mingw-static zlib:x64-mingw-static tre:x64-mingw-static \
    --host-triplet="$host" --clean-after-build
