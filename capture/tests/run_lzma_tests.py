#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
run_lzma_tests.py - 自实现 XZ 解压器的回归测试

用 python 的 lzma 模块生成一组覆盖不同解码路径的 .xz 文件，
调用 ecap_xz_unpack 解压，逐字节比对。

【为什么不把用例内嵌进 C 测试】
内嵌 xz 字节流会让测试源码不可读、也无法人工检查。
现生成 + 现比对，既保证覆盖，又保持源码干净；而且用 python 的
lzma 模块当参照实现，比自己写的期望值可信得多。

【覆盖的解码路径】
  lit1/2/3   极小输入 —— xz 会选"未压缩 chunk"
  litA       100 个相同字节 —— literal + rep match（距离 0 的重复）
  litrep     重复序列 —— new match（跨块回引）
  litseq     序列数据 —— 几乎全是 literal
  big        200KB 混合数据 —— 多个 LZMA2 chunk

用法：
  ./run_lzma_tests.py /path/to/ecap_test_lzma
"""

import lzma
import os
import shutil
import subprocess
import sys
import tempfile

CASES = {
    "lit1": b"X",
    "lit2": b"XY",
    "lit3": b"XYZ",
    "litA": b"A" * 100,
    "litrep": bytes(range(100)) * 2,
    "litseq": bytes(range(256)) * 4,
    "big": bytes((i * 7 + (i >> 3)) & 0xFF for i in range(200000)),
}


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <ecap_test_lzma binary>", file=sys.stderr)
        return 2

    binary = sys.argv[1]
    tmpdir = tempfile.mkdtemp(prefix="ecap_lzma_")
    fails = 0

    print("== ecap_xz_unpack() regression test ==\n")

    for name, data in CASES.items():
        path = os.path.join(tmpdir, f"{name}.xz")
        with open(path, "wb") as f:
            f.write(lzma.compress(data, format=lzma.FORMAT_XZ))

        proc = subprocess.run([binary, path], capture_output=True)
        got = proc.stdout

        ok = proc.returncode == 0 and got == data
        detail = ""
        if not ok:
            fails += 1
            if proc.returncode != 0:
                detail = "decode error"
            elif len(got) != len(data):
                detail = f"length mismatch {len(got)} != {len(data)}"
            else:
                idx = next(i for i in range(len(data)) if got[i] != data[i])
                detail = f"first diff at {idx}"

        print(
            f"  {'OK  ' if ok else 'FAIL'}  {name:10s} "
            f"in={len(data):7d} out={len(got):7d}"
            + ("" if ok else f"   ({detail})")
        )

    total = len(CASES)
    if shutil.which("xz"):
        multiblock_cases = [
            ("multi2", 32768, bytes((i * 17 + (i >> 3)) & 0xFF for i in range(47832))),
            ("multi3", 16384, bytes((i * 31 + (i >> 5)) & 0xFF for i in range(50000))),
        ]
        for name, bsz, data in multiblock_cases:
            total += 1
            path = os.path.join(tmpdir, f"{name}.xz")
            xz_out = subprocess.run(
                ["xz", "-z", "-c", f"--block-size={bsz}"],
                input=data,
                capture_output=True,
                check=True,
            ).stdout
            with open(path, "wb") as f:
                f.write(xz_out)

            proc = subprocess.run([binary, path], capture_output=True)
            got = proc.stdout
            ok = proc.returncode == 0 and got == data
            detail = ""
            if not ok:
                fails += 1
                if proc.returncode != 0:
                    detail = "decode error"
                elif len(got) != len(data):
                    detail = f"length mismatch {len(got)} != {len(data)}"
                else:
                    idx = next(i for i in range(len(data)) if got[i] != data[i])
                    detail = f"first diff at {idx}"

            print(
                f"  {'OK  ' if ok else 'FAIL'}  {name:10s} "
                f"in={len(data):7d} out={len(got):7d}"
                + ("" if ok else f"   ({detail})")
            )

    print()
    if fails:
        print(f"{fails} failure(s) out of {total} case(s)")
        return 1

    print(f"{total} case(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
