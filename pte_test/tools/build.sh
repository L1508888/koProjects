#!/usr/bin/env bash
#
# build.sh —— 编译 /proc/pte_java 控制工具（arm64 Android）
#
# 用法：
#   tools/build.sh                 # 自动找 NDK 并编译
#   NDK=/path/to/ndk tools/build.sh
#
# 产物：tools/pte_java （静态链接，可直接 push 到设备跑）
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(cd "$HERE/.." && pwd)"

# 找 clang：优先用 NDK 的，其次用内核构建用的 clang（也能编静态 arm64）
find_clang() {
    local candidates=()
    if [[ -n "${NDK:-}" ]]; then
        candidates+=("$NDK"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang)
    fi
    candidates+=(
        "$HOME"/Android/Sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang
        "$PROJ"/../pixelKernel/prebuilts/clang/host/linux-x86/clang-*/bin/clang
    )
    local c
    for c in "${candidates[@]}"; do
        [[ -x "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

CC="$(find_clang)" || {
    echo "找不到 aarch64 clang，请设置 NDK=/path/to/ndk" >&2
    exit 1
}

echo "CC = $CC"
"$CC" --target=aarch64-linux-android30 -O2 -static -Wall -Wextra \
      -Wno-unicode-homoglyph \
      "$HERE/pte_java.c" -o "$HERE/pte_java"

echo "built: $HERE/pte_java"

# 解析助手：类名+方法名 → ArtMethod*（离线扫描，兜底用）
"$CC" --target=aarch64-linux-android30 -O2 -static -Wall -Wextra \
      -Wno-unicode-homoglyph \
      "$HERE/pte_java_resolve.c" -o "$HERE/pte_java_resolve"
echo "built: $HERE/pte_java_resolve"

file "$HERE/pte_java" "$HERE/pte_java_resolve" 2>/dev/null || true
