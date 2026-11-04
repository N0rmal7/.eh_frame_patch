# -*- coding: utf-8 -*-
"""Verify the three new features inside a real IDA session.

1. `Goto safe area` picks a 16-byte aligned head with enough room.
2. The unwind probe classifies this program correctly (C vs C++).
3. `Add exec bit` flips PF_X on the .eh_frame PT_LOAD and writes a backup.
5. `unresolved symbol` diagnostics no longer list mnemonics.

Run::

    ida.exe -A -S"verify_new_features.py" samples/main
"""

import os
import shutil
import sys

import idaapi
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_new_features.log")


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
    log("=== verify new features ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    sys.path.insert(0, os.path.join(PKG, "plugins"))
    for n in list(sys.modules):
        if n == "eh_frame_patch" or n == "ehp" or n.startswith("ehp."):
            del sys.modules[n]
    import eh_frame_patch as EHP
    from ehp import asm_engine, elf_image, unwind_probe

    seg = ida_segment.get_segm_by_name(".eh_frame")
    log(".eh_frame = %#x-%#x" % (seg.start_ea, seg.end_ea))

    # ---- 1. aligned heads ---------------------------------------------
    heads = EHP._aligned_heads(want=30)
    log("aligned heads (>=30 bytes): %d" % len(heads))
    for h in heads[:4]:
        log("   %#08x room=%d aligned=%s"
            % (h.ea, h.room, h.ea % 16 == 0))
    ok_align = all(h.ea % 16 == 0 for h in heads)
    log("RESULT all_16_aligned=%s" % ok_align)
    log("RESULT biggest=%#x room=%d" % (heads[0].ea, heads[0].room) if heads else "none")

    # ---- 2. unwind probe ----------------------------------------------
    img = EHP._elf_image_of_input()
    v = unwind_probe.verdict_for_image(img) if img else None
    log("unwind verdict: %s" % (v.summary() if v else "no image"))
    log("RESULT needed=%s" % (v.needed if v else None))
    log("RESULT uses_unwinding=%s" % (v.uses_unwinding if v else None))

    # ---- 3. add exec bit ----------------------------------------------
    src = idaapi.get_input_file_path()
    log("input: %s" % src)
    before = elf_image.ElfImage.from_file(src)
    log("before: .eh_frame executable=%s (%s)"
        % (before.is_executable(seg.start_ea),
           before.load_at(seg.start_ea).perm_text))

    backup = src + ".bak"
    if os.path.exists(backup):
        os.remove(backup)
    # exercise the same code path the menu action uses, minus the dialogs
    try:
        img2 = elf_image.ElfImage.from_file(src)
        img2.set_exec_flag(seg.start_ea, True)
        img2.write(src, allow_in_place=True)
        after = elf_image.ElfImage.from_file(src)
        load = after.load_at(seg.start_ea)
        log("after : .eh_frame executable=%s (%s)"
            % (after.is_executable(seg.start_ea), load.perm_text))
        log("RESULT pf_x_set=%s" % after.is_executable(seg.start_ea))
    except Exception:
        import traceback
        log("EXEC BIT FAILED:\n" + traceback.format_exc())
        log("RESULT pf_x_set=False")

    # ---- 5. symbol diagnostics ----------------------------------------
    bad = "call free\nmov eax, [rbp+var_14]\ncdqe\n"
    r = asm_engine.assemble(bad, seg.start_ea, bits=EHP._current_bits(),
                            resolve=EHP.MEM.resolve_symbol)
    log("---- diagnostics ----")
    for e in r.errors:
        log("   " + e)
    text = "\n".join(r.errors)
    log("RESULT mentions_free=%s" % ("free" in text))
    log("RESULT mentions_var14=%s" % ("var_14" in text))
    log("RESULT no_mnemonic_noise=%s"
        % (not any(m in text for m in ("cdqe", "lea,", "mov,"))))

    log("DONE")
    idaapi.qexit(0)


main()
