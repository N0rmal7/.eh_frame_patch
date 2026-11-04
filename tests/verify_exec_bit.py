# -*- coding: utf-8 -*-
"""Verify `Add exec bit` makes the WHOLE .eh_frame segment executable.

Both layers must change:

* IDA segment permission  -> segments window shows R-X
* ELF p_flags PF_X        -> the kernel actually allows execution

Run::

    ida.exe -A -S"verify_exec_bit.py" samples/exec_test
"""

import os
import sys

import idaapi
import idc
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_exec_bit.log")


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
    log("=== verify exec bit ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    sys.path.insert(0, os.path.join(PKG, "plugins"))
    for n in list(sys.modules):
        if n == "eh_frame_patch" or n == "ehp" or n.startswith("ehp."):
            del sys.modules[n]
    import eh_frame_patch as EHP
    from ehp import elf_image

    seg = ida_segment.get_segm_by_name(".eh_frame")
    if seg is None:
        log("FATAL: no .eh_frame")
        idaapi.qexit(1)
        return

    ea = int(seg.start_ea)
    log(".eh_frame = %#x-%#x" % (ea, int(seg.end_ea)))

    perm_before = idc.get_segm_attr(ea, idc.SEGATTR_PERM)
    log("IDA perm before      : %s (%d)" % (EHP.SegPerm.text(perm_before), perm_before))

    path = idaapi.get_input_file_path()
    img_before = elf_image.ElfImage.from_file(path)
    log("ELF PT_LOAD before   : %s" % img_before.load_at(ea).perm_text)

    # ---- exercise the same helper the menu action uses -----------------
    changed = EHP._set_ida_segment_exec(seg)
    log("_set_ida_segment_exec -> %s" % (changed,))

    perm_after = idc.get_segm_attr(ea, idc.SEGATTR_PERM)
    log("IDA perm after       : %s (%d)" % (EHP.SegPerm.text(perm_after), perm_after))
    log("RESULT ida_exec=%s"
        % bool(perm_after & ida_segment.SEGPERM_EXEC))
    log("RESULT ida_read_still=%s"
        % bool(perm_after & ida_segment.SEGPERM_READ))

    # ---- the ELF side -------------------------------------------------
    img = elf_image.ElfImage.from_file(path)
    sec = img.section(".eh_frame")
    img.set_exec_flag(sec.addr, True)
    img.write(path, allow_in_place=True)
    after = elf_image.ElfImage.from_file(path)
    load = after.load_at(sec.addr)
    log("ELF PT_LOAD after    : %s" % load.perm_text)
    log("RESULT elf_exec=%s" % after.is_executable(sec.addr))
    log("RESULT pf_x_bit=%s" % bool(load.flags & elf_image.PF_X))

    # whole segment, not just a byte
    first = after.is_executable(int(seg.start_ea))
    last = after.is_executable(int(seg.end_ea) - 1)
    log("RESULT whole_segment=%s (start=%s end=%s)" % (first and last, first, last))

    # idempotent: running again should report no change
    again = EHP._set_ida_segment_exec(seg)
    log("RESULT idempotent=%s (%s)" % (again is not None and again[0] == again[1], again))

    log("DONE")
    idaapi.qexit(0)


main()
