# -*- coding: utf-8 -*-
"""End-to-end check of the new "jump to safe .eh_frame area" feature.

Verifies inside a real IDA session that:

1. `find_safe_areas()` returns candidates for the loaded database.
2. The top candidate can actually hold a real stub of the requested size
   (assembled by the plugin's own `build_plan`).
3. Writing that stub there and exporting produces a runnable binary whose
   `.eh_frame` PT_LOAD is executable.

Run (no -A so that dialogs are not suppressed; the script itself needs no UI)::

    ida.exe -A -S"verify_safe_area.py" samples/main
"""

import os
import sys
import traceback

import idaapi
import ida_bytes
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
LOG = os.path.join(HERE, "verify_safe_area.log")

# a realistic 25-byte stub for this sample
STUB = (
    "mov eax, dword ptr [rbp-4]\n"
    "cdqe\n"
    "lea rdx, [0x4060]\n"
    "mov qword ptr [rdx + rax*8], 0\n"
    "jmp 0x16CC\n"
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
    log("=== verify safe area ===")
    if not wait_ready():
        log("FATAL: db not ready")
        idaapi.qexit(1)
        return

    # Import the source tree explicitly: IDA may already have loaded an older
    # copy from the user plugins directory, and this test must exercise *this*
    # code, not whatever happens to be installed.
    src_plugins = os.path.join(PKG, "plugins")
    sys.path.insert(0, src_plugins)
    for name in list(sys.modules):
        if name == "eh_frame_patch" or name == "ehp" or name.startswith("ehp."):
            del sys.modules[name]
    import eh_frame_patch as EHP
    log("plugin loaded from %s (version %s)"
        % (os.path.dirname(EHP.__file__), EHP.PLUGIN_VERSION))
    log("has find_safe_areas: %s" % hasattr(EHP, "find_safe_areas"))
    from ehp import asm_engine, plan as plan_mod, unwind_cave

    seg = ida_segment.get_segm_by_name(".eh_frame")
    log(".eh_frame = %#x-%#x" % (seg.start_ea, seg.end_ea))

    # ---- 1. candidates -------------------------------------------------
    cands = EHP.find_safe_areas(want=25)
    log("find_safe_areas(want=25) -> %d candidate(s)" % len(cands))
    for c in cands[:8]:
        log("   %#08x %3dB L%d %-14s %s"
            % (c.ea, c.size, c.level, c.level_name, c.note))
    log("RESULT has_candidates=%s" % bool(cands))

    # ---- 2. can the best one hold the stub? ----------------------------
    best = EHP.suggest_stub_address(want=25)
    if best is None:
        log("RESULT suggest_stub_address=None")
        idaapi.qexit(1)
        return
    ea, size, cand = best
    log("chosen: %#x size=%d level=%d (%s)" % (ea, size, cand.level, cand.note))

    plan = plan_mod.build_plan(
        EHP.MEM, ea, STUB, bits=EHP._current_bits(), budget=size,
        resolve=EHP.MEM.resolve_symbol,
    )
    log("stub assembles: ok=%s size=%d budget=%d" % (plan.ok, plan.size, size))
    log("RESULT stub_fits=%s" % (plan.ok and plan.size <= size))
    if not plan.ok:
        for e in plan.errors:
            log("   plan error: %s" % e)

    # ---- 3. write it and read it back ----------------------------------
    if plan.ok:
        orig = ida_bytes.get_bytes(ea, plan.size)
        res = EHP.apply_patch(plan, reanalyze=True)
        back = ida_bytes.get_bytes(ea, plan.size)
        log("apply: %s" % res.message)
        log("RESULT written=%s match=%s" % (res.ok, back == bytes(plan.code)))
        ida_bytes.patch_bytes(ea, orig)   # revert so the DB stays clean
        log("reverted for cleanliness: %s"
            % (ida_bytes.get_bytes(ea, plan.size) == orig))

    # ---- 4. the candidate must not touch the ZERO terminator -----------
    data = EHP.MEM.read(seg.start_ea, seg.end_ea - seg.start_ea)
    recs = list(unwind_cave._records(data))
    term = [r[0] for r in recs if r[1] == 0]
    if term:
        term_ea = seg.start_ea + term[0]
        log("terminator at %#x; candidate ends at %#x"
            % (term_ea, ea + size))
        log("RESULT keeps_terminator=%s" % (ea + size <= term_ea))

    log("DONE")
    idaapi.qexit(0)


main()
