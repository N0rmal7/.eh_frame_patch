#!/usr/bin/env bash
# Behavioural verification for eh_frame_patch.
#
# Runs under WSL/Linux (the sample binaries are ELF).  It proves, without IDA,
# that the pieces the plugin generates really work at run time:
#
#   1. unpatched binary still performs the UAF write      -> rc 0
#   2. patched binary refuses the write (pointer cleared) -> rc -1, "(null)"
#   3. the .eh_frame PT_LOAD really is executable in the copy
#   4. the original file is untouched
#   5. an over-long stub is rejected by the planner
#
# Prints RUNTIME-OK at the end so the Python test can assert on it.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PY="${PYTHON:-python3}"
fail() { echo "FAIL: $*"; exit 1; }

cd "$ROOT" || fail "cannot cd to $ROOT"

for name in uaf_demo64 uaf_demo32; do
    src="samples/$name"
    [ -f "$src" ] || fail "missing $src"

    echo "== $name =="

    before=$(sha256sum "$src" | cut -d" " -f1)

    # 1. baseline: the bug is present
    out="$("$src")" || fail "baseline $name crashed"
    echo "$out" | grep -q "post-free write returned 0" \
        || fail "baseline $name did not reproduce the UAF"

    # 2. patch a copy
    fixed="$WORK/$name.fixed"
    "$PY" examples/uaf_fix_demo.py "$src" "$fixed" > "$WORK/$name.log" 2>&1 \
        || { cat "$WORK/$name.log"; fail "patching $name failed"; }

    out="$("$fixed")" || { cat "$WORK/$name.log"; fail "patched $name crashed"; }
    echo "$out" | grep -q "post-free write returned -1" \
        || { echo "$out"; fail "$name still vulnerable after patch"; }
    echo "$out" | grep -q "data=(null" \
        || { echo "$out"; fail "$name pointer was not cleared"; }

    # 3. PF_X present on the .eh_frame PT_LOAD only
    readelf -lW "$fixed" | grep -q "0x002000.*R E" \
        || fail "$name: .eh_frame PT_LOAD is not executable in the copy"
    readelf -lW "$src" | grep -q "0x002000.*R E" \
        && fail "$name: original unexpectedly executable"

    # 4. original untouched
    [ "$before" = "$(sha256sum "$src" | cut -d" " -f1)" ] || fail "$name: original file was modified"

    echo "   ok: baseline UAF, patched clean, PF_X set, original intact"
done

# 5. planner rejects an over-long stub (pure Python, same code path as IDA)
"$PY" - "$ROOT" <<'PYEOF' || exit 1
import os, sys
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "plugins"))
sys.path.insert(0, os.path.join(root, "tests"))
from test_plan import ElfMemory
from ehp.plan import build_plan

mem = ElfMemory(os.path.join(root, "samples", "uaf_demo64"))
eh = mem.img.section(".eh_frame")
plan = build_plan(mem, eh.addr, "nop\n" * 200, bits=64, budget=16)
assert not plan.ok, "over-long stub was accepted"
assert any("only 16 byte(s) fit" in c.text for c in plan.errors), plan.summary()
print("   ok: over-long stub rejected by the planner")
PYEOF

echo "RUNTIME-OK"
