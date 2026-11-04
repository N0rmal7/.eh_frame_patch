# -*- coding: utf-8 -*-
"""Check that the editor template is *generic*, not tuned to one binary.

What we assert:

1. Without a prior entry patch the template contains explicit placeholders
   instead of a hard-coded private address (the old behaviour emitted
   ``jmp 0x11C0``, which is only correct for one sample).
2. The template never hard-codes a stack slot such as ``[rbp-4]`` unless the
   analysis actually found one; otherwise it says so in a TODO comment.
3. Placeholders are rejected by the assembler, so the user cannot apply a
   half-filled fix by accident (the preview shows a syntax error mentioning the
   placeholder line).
4. After an entry patch is recorded, the resume hint points just past it.
5. The 64/32-bit pointer width and element size follow the database.

Run::

    ida.exe -A -S"verify_template_generic.py" samples/main
"""

import os
import sys

import idaapi
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_template_generic.log")


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
    log("=== verify template (generic) ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    src = os.path.join(PKG, "plugins")
    sys.path.insert(0, src)
    for name in list(sys.modules):
        if name == "eh_frame_patch" or name == "ehp" or name.startswith("ehp."):
            del sys.modules[name]
    import eh_frame_patch as EHP
    from ehp import asm_engine

    seg = ida_segment.get_segm_by_name(".eh_frame")
    best = EHP.suggest_stub_address(want=25)
    ea = best[0] if best else seg.start_ea

    EHP._patch_history.clear()

    # ---- 1. no prior patch: no invented addresses ----------------------
    tpl = EHP._suggest_source(ea)
    log("---- template (no prior patch) ----")
    for line in tpl.splitlines():
        log("   " + line)
    log("---- end ----")

    log("RESULT has_placeholder=%s" % ("<" in tpl and ">" in tpl))
    log("RESULT has_todo=%s" % ("TODO" in tpl))
    # a hard-coded rbp slot *inside an instruction* would be sample-specific;
    # mentioning it in a TODO example comment is fine.
    code_lines = [
        l for l in tpl.splitlines() if l.strip() and not l.strip().startswith("#")
    ]
    hard = any(("[rbp-4]" in l or "[rbp+var" in l) for l in code_lines)
    log("RESULT hardcodes_rbp_slot=%s" % hard)

    res = asm_engine.assemble(tpl, ea, bits=EHP._current_bits(),
                              resolve=EHP.MEM.resolve_symbol)
    log("RESULT assembles_with_placeholder=%s" % res.ok)
    if not res.ok:
        log("   (expected) first error: %s" % res.errors[0].splitlines()[0])

    # ---- 2. after an entry patch, resume points past it ----------------
    entry_ea = 0x16C0
    fake_src = "jmp 0x%X" % ea
    EHP._patch_history.append(
        {"ea": entry_ea, "orig": b"\x00" * 5, "new": b"\xe9" + b"\x00" * 4,
         "source": fake_src}
    )
    tpl2 = EHP._suggest_source(ea)
    log("---- template (after entry patch) ----")
    for line in tpl2.splitlines():
        log("   " + line)
    log("---- end ----")
    log("RESULT resume_is_past_entry=%s" % (("jmp 0x%X" % (entry_ea + 5)) in tpl2))

    # ---- 3. width follows the database ---------------------------------
    bits = EHP._current_bits()
    want_ptr = "qword ptr" if bits == 64 else "dword ptr"
    want_scale = "*8]" if bits == 64 else "*4]"
    log("RESULT pointer_width_ok=%s" % (want_ptr in tpl2))
    log("RESULT element_scale_ok=%s" % (want_scale in tpl2))

    EHP._patch_history.clear()
    log("DONE")
    idaapi.qexit(0)


main()
