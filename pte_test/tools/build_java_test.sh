#!/usr/bin/env bash
#
# build_java_test.sh —— 编译 Java 层 hook 的验证程序
#
# 产物（都推到 /data/local/tmp/）：
#   javatest.dex        —— JavaHookTest + ArtMethodHelper
#   libartmethod.so     —— JNI 助手，负责把 Method 换成 ArtMethod*
#
# 用法：
#   tools/build_java_test.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(cd "$HERE/.." && pwd)"
SRC="$PROJ/test/java"
OUT="${OUT:-/tmp/jout}"

SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
JAR="$(ls "$SDK"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
D8="$(ls "$SDK"/build-tools/*/d8 2>/dev/null | sort -V | tail -1)"
[[ -n "$JAR" && -f "$JAR" ]] || { echo "找不到 android.jar（设 ANDROID_HOME）" >&2; exit 1; }
[[ -n "$D8"  && -x "$D8"  ]] || { echo "找不到 d8（装 build-tools）" >&2; exit 1; }

NDK="${NDK:-$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)}"
[[ -n "$NDK" ]] || { echo "找不到 NDK（设 NDK=/path/to/ndk）" >&2; exit 1; }
CC="$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang | head -1)"

echo "android.jar = $JAR"
echo "d8          = $D8"
echo "clang       = $CC"

rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"

# 1. Java → class
javac -source 8 -target 8 -bootclasspath "$JAR" \
      -d "$OUT/classes" \
      "$SRC/JavaHookTest.java" "$SRC/ArtMethodHelper.java" 2>&1 \
    | grep -v 'bootstrap class path' || true
[[ -f "$OUT/classes/pte/javatest/JavaHookTest.class" ]] \
    || { echo "javac 失败" >&2; exit 1; }

# 2. class → dex
"$D8" --lib "$JAR" --min-api 30 --output "$OUT/dex" \
      "$OUT"/classes/pte/javatest/*.class

# 3. JNI .so（需要 jni.h）
JNI_INC="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/sysroot/usr/include | head -1)"
"$CC" --target=aarch64-linux-android30 -O2 -fPIC -shared \
      -I"$JNI_INC" "$SRC/artmethod.c" -o "$OUT/libartmethod.so"

echo
echo "built:"
echo "  $OUT/dex/classes.dex      → /data/local/tmp/javatest.dex"
echo "  $OUT/libartmethod.so      → /data/local/tmp/libartmethod.so"
echo
echo "推送到设备："
echo "  adb push $OUT/dex/classes.dex     /data/local/tmp/javatest.dex"
echo "  adb push $OUT/libartmethod.so     /data/local/tmp/"
echo "  adb shell su -c 'CLASSPATH=/data/local/tmp/javatest.dex app_process / pte.javatest.JavaHookTest'"
