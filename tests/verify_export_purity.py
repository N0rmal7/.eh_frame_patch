# -*- coding: utf-8 -*-
"""Check whether 1.0.1's export enumeration picks up loader fixups.

`collect_all_db_changes()` uses `visit_patched_bytes`, which is supposed to
enumerate *explicit* patches only. This script proves it on the real sample by
comparing, before and after patching:

  * the number of enumerated byte runs
  * whether the PLT/GOT region appears at all

Run::

    ida.exe -A -S"verify_export_purity.py" samples/main
"""

import os
import sys
import traceback

import idaapi
import ida_bytes
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_export_purity.log")

STUB_EA = 0x22EF
STUB_LEN = 37
JUMP_EA = 0x16C0
JUMP_LEN = 12


def log(msg):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(str(msg) + "\n")
        fh.flush()


def wait_ready(timeout=120.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if ida_segment.get_segm_qty() > 0:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def main():
    log("=== verify export purity ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    sys.path.insert(0, os.path.join(PKG, "plugins"))
    import eh_frame_patch as EHP

    # ---- baseline: no explicit patches yet -----------------------------
    try:
        base = EHP.collect_all_db_changes()
        log("baseline runs: %d" % len(base))
        for ea, blob in base[:10]:
            log("   0x%X %d bytes" % (ea, len(blob)))
    except Exception:
        log("baseline raised:\n" + traceback.format_exc())
        idaapi.qexit(1)
        return

    # ---- apply two explicit patches ------------------------------------
    ida_bytes.patch_bytes(STUB_EA, b"\x90" * STUB_LEN)
    ida_bytes.patch_bytes(JUMP_EA, b"\xCC" * JUMP_LEN)
    log("applied 2 explicit patches via ida_bytes.patch_bytes")

    after = EHP.collect_all_db_changes()
    log("after-patch runs: %d" % len(after))
    for ea, blob in after:
        log("   0x%X %d bytes" % (ea, len(blob)))

    # ---- assertions ----------------------------------------------------
    starts = sorted(ea for ea, _ in after)
    log("RESULT new_runs=%d" % (len(after) - len(base)))
    log("RESULT contains_stub=%s" % (STUB_EA in starts))
    log("RESULT contains_jump=%s" % (JUMP_EA in starts))

    # GOT lives around 0x3F60..0x4000 in this sample; it must NOT show up.
    got_like = [ea for ea, _ in after if 0x3F60 <= ea < 0x4008]
    log("RESULT got_runs=%d %s" % (len(got_like), [hex(x) for x in got_like]))
    log("RESULT GOT_CLEAN=%s" % (not got_like))

    # total bytes must equal exactly what we wrote
    total = sum(len(b) for _, b in after)
    log("RESULT total_bytes=%d expected=%d" % (total, STUB_LEN + JUMP_LEN))
    log("DONE")
    idaapi.qexit(0)


main()
