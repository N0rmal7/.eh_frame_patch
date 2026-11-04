# -*- coding: utf-8 -*-
"""Verify the manual's claim: export includes Keypatch-style patches too.

The manual (section 6) states the export contains *all* explicit patches in the
IDB, "including the entry jump written by Keypatch".  Keypatch writes through
`ida_bytes.patch_byte`, exactly like this plugin, so `visit_patched_bytes`
should see both.  This script proves it.

Run::

    ida.exe -A -S"verify_keypatch_export.py" samples/main
"""

import os
import sys
import traceback

import idaapi
import ida_bytes
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_keypatch_export.log")

# pretend Keypatch patched the entry (5-byte near jmp + 7 NOP)
KP_EA = 0x16C0
KP_BYTES = bytes([0xE9, 0x2A, 0x0C, 0x00, 0x00] + [0x90] * 7)
# our own stub in .eh_frame, written byte by byte like Keypatch does
STUB_EA = 0x22EF
STUB_BYTES = bytes.fromhex(
    "8b45fc4898488d15651d000048c704c2"
    "00000000488d3d76fdffffe801eeffffe9b8f3ffff"
)


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
    log("=== verify keypatch export ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    sys.path.insert(0, os.path.join(PKG, "plugins"))
    import eh_frame_patch as EHP

    # write both patches *byte by byte*, the way Keypatch does
    for i, b in enumerate(KP_BYTES):
        ida_bytes.patch_byte(KP_EA + i, b)
    for i, b in enumerate(STUB_BYTES):
        ida_bytes.patch_byte(STUB_EA + i, b)
    log("wrote 2 patches via patch_byte (Keypatch-equivalent)")

    changes = EHP.collect_all_db_changes()
    log("collect_all_db_changes -> %d run(s)" % len(changes))
    for ea, blob in changes:
        log("   0x%X %d bytes" % (ea, len(blob)))

    starts = {ea: blob for ea, blob in changes}
    log("RESULT has_entry_jump=%s" % (KP_EA in starts))
    log("RESULT has_stub=%s" % (STUB_EA in starts))
    if KP_EA in starts:
        log("RESULT entry_bytes_match=%s" % (bytes(starts[KP_EA]) == KP_BYTES))
    if STUB_EA in starts:
        log("RESULT stub_bytes_match=%s" % (bytes(starts[STUB_EA]) == STUB_BYTES))
    log("RESULT got_polluted=%s"
        % any(0x3F60 <= ea < 0x4008 for ea in starts))
    log("DONE")
    idaapi.qexit(0)


main()
