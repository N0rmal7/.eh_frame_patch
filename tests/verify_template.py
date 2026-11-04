# -*- coding: utf-8 -*-
"""Check the pre-filled UAF template and the empty-editor hint.

1. `_suggest_source(".eh_frame address")` must return an *assemblable* stub
   (no `<placeholder>` left in the common case).
2. An empty editor must not report an error.
3. The preview must show the hint text instead.

Run::

    ida.exe -A -S"verify_template.py" samples/main
"""

import os
import sys

import idaapi
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_template.log")


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
    log("=== verify template ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    src_plugins = os.path.join(PKG, "plugins")
    sys.path.insert(0, src_plugins)
    for name in list(sys.modules):
        if name == "eh_frame_patch" or name == "ehp" or name.startswith("ehp."):
            del sys.modules[name]
    import eh_frame_patch as EHP
    from ehp import asm_engine, plan as plan_mod

    seg = ida_segment.get_segm_by_name(".eh_frame")
    best = EHP.suggest_stub_address(want=25)
    ea = best[0] if best else seg.start_ea
    log("target candidate: %#x" % ea)

    # ---- 1. the pre-filled template ------------------------------------
    tpl = EHP._suggest_source(ea)
    log("---- template ----")
    for line in tpl.splitlines():
        log("   " + line)
    log("---- end ----")

    has_placeholder = "<" in tpl and ">" in tpl
    log("RESULT template_has_placeholder=%s" % has_placeholder)

    res = asm_engine.assemble(tpl, ea, bits=EHP._current_bits(),
                              resolve=EHP.MEM.resolve_symbol)
    log("RESULT template_assembles=%s size=%d" % (res.ok, res.size))
    if not res.ok:
        for e in res.errors:
            log("   error: " + e)

    # does it really clear the pointer?
    log("RESULT clears_memory=%s" % ("mov qword ptr [rdx + rax*8], 0" in tpl
                                     or "mov dword ptr [rdx + eax*4], 0" in tpl))

    # ---- 2. empty editor is not an error -------------------------------
    empty = asm_engine.assemble("", ea, bits=EHP._current_bits())
    log("RESULT empty_is_empty_flag=%s errors=%d"
        % (getattr(empty, "empty", None), len(empty.errors)))

    plan = plan_mod.build_plan(
        EHP.MEM, ea, "", bits=EHP._current_bits(), budget=32,
        resolve=EHP.MEM.resolve_symbol,
    )
    text = EHP.render_preview(plan)
    log("RESULT empty_plan_has_error=%s" % bool(plan.errors))
    log("RESULT preview_has_hint=%s" % ("nothing to assemble yet" in text))
    log("RESULT preview_suggests_fix=%s" % ("array[idx] = NULL" in text))
    log("RESULT preview_marks_ERROR=%s" % ("[ERROR]" in text))

    log("DONE")
    idaapi.qexit(0)


main()
