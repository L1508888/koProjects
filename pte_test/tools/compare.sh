#!/usr/bin/env bash
#
# compare.sh —— 用真实汇编器核对 trampoline 生成器的输出
#
# 做法（双向验证）：
#   每个用例既有一份"生成器产出的十六进制"，也有一份"人写的等价汇编"。
#   把等价汇编交给 clang 汇编，取出 .text 的字节；再和生成器的输出逐字
#   比对。只要生成器有一位写错，比对就会失败。
#
# 用法：tools/compare.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

CLANG="${CLANG:-}"
if [[ -z "$CLANG" ]]; then
    for c in "$HOME"/Android/Sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/clang \
             "$HERE"/../../pixelKernel/prebuilts/clang/host/linux-x86/clang-*/bin/clang; do
        [[ -x "$c" ]] && { CLANG="$c"; break; }
    done
fi
[[ -x "$CLANG" ]] || { echo "找不到 clang，请设置 CLANG=/path/to/clang" >&2; exit 1; }
BIN="$(dirname "$CLANG")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

gcc -I"$HERE/.." -o "$TMP/selftest" "$HERE/tramp_selftest.c" "$HERE/../jh_tramp.c" || exit 1
"$TMP/selftest" > "$TMP/gen.txt" || exit 1

# 取"等价汇编"汇编后的 .text 字节序列（小端，连续 hex 串）
asm_bytes() {
    local name="$1" body="$2"
    printf '  .text\n%s\n' "$body" > "$TMP/exp.s"
    if ! "$CLANG" --target=aarch64-linux-gnu -c "$TMP/exp.s" -o "$TMP/exp.o" 2>"$TMP/err"; then
        echo "ASM_ERROR"
        sed 's/^/           /' "$TMP/err" >&2
        return
    fi
    "$BIN/llvm-objcopy" -O binary --only-section=.text "$TMP/exp.o" "$TMP/exp.bin" 2>/dev/null \
        || { echo "OBJCOPY_ERROR"; return; }
    od -An -tx1 -v "$TMP/exp.bin" | tr -d ' \n'
}

# 把生成器的字（0xAABBCCDD）转成小端字节串（ddccbbaa）
words_to_bytes() {
    local w
    for w in $1; do
        printf '%s%s%s%s' "${w:6:2}" "${w:4:2}" "${w:2:2}" "${w:0:2}"
    done
}

# 每个用例的等价汇编：与 jh_build_tramp 生成的结构一一对应
declare -A EXPECT=(
  [tail_only]="  movz x17, #0x1234
  br   x17"

  [tail_enter]="  brk  #0xbf00
  movz x17, #0x1234
  br   x17"

  [call_enter_exit]="  brk  #0xbf00
  stp  x29, x30, [sp, #-16]!
  movz x17, #0x1234
  blr  x17
  brk  #0xbf01
  ldp  x29, x30, [sp], #16
  ret"

  [call_exit_only]="  stp  x29, x30, [sp, #-16]!
  movz x17, #0x1234
  blr  x17
  brk  #0xbf01
  ldp  x29, x30, [sp], #16
  ret"

  [skip_ret]="  movz x0, #0x64
  movz x1, #0
  ret"

  [skip_ret_brk]="  movz x0, #0xffff
  movk x0, #0xffff, lsl #16
  movk x0, #0xffff, lsl #32
  movk x0, #0xffff, lsl #48
  movz x1, #0
  brk  #0xbf01
  ret"

  [tail_bigaddr]="  movz x17, #0x5678
  movk x17, #0x1234, lsl #16
  movk x17, #0x7fff, lsl #32
  br   x17"

  [flag_brk_only]="  brk  #0xbf00
  movz x17, #0x1234
  br   x17"
)

echo "=== 生成器输出 ==="
cat "$TMP/gen.txt"
echo
echo "=== 与等价汇编逐字比对 ==="

fail=0
while IFS= read -r line; do
    name="${line%% *}"
    gen="$(sed -E "s/.*words=[0-9]+ enter@-?[0-9]+ exit@-?[0-9]+://" <<<"$line")"
    gen_b="$(words_to_bytes "$gen")"

    if [[ -z "${EXPECT[$name]:-}" ]]; then
        echo "[SKIP] $name（脚本里没有对应汇编）"
        continue
    fi

    exp_b="$(asm_bytes "$name" "${EXPECT[$name]}")"
    if [[ "$exp_b" == "ASM_ERROR" || "$exp_b" == "OBJCOPY_ERROR" ]]; then
        echo "[FAIL] $name: 汇编/提取失败"
        fail=1
        continue
    fi

    if [[ "$gen_b" == "$exp_b" ]]; then
        echo "[ OK ] $name"
        echo "         $gen"
    else
        echo "[FAIL] $name"
        echo "         gen: $gen_b"
        echo "         exp: $exp_b"
        fail=1
    fi
done < "$TMP/gen.txt"

echo
if [[ $fail -eq 0 ]]; then
    echo "全部通过：生成器的输出与真实汇编器逐字节一致。"
else
    echo "存在不一致，请检查 jh_tramp.c 的编码位域。" >&2
fi
exit $fail
