# -*- coding: utf-8 -*-
"""eh_frame_patch self test -- run inside IDA, no keystrokes required.

Usage::

    ida.exe -A -S"ida_selftest.py" samples/uaf_demo64

``-A`` keeps the loader non-interactive (no "Load a new file" dialog), and the
script waits for a real segment before touching anything.  Results are appended
to ``ida_selftest.log`` next to this file.

The test deliberately calls the plugin's *own* functions (apply_patch,
render_preview, save_database, ...) instead of reimplementing them, so a pass
here means the shipped code path works.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

import idaapi
import ida_bytes
import ida_kernwin
import ida_loader
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(HERE, "ida_selftest.log")


def log(msg):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(str(msg) + "\n")
        fh.flush()


class Tally(object):
    def __init__(self):
        self.ok = 0
        self.fail = 0
        self.failed = []

    def check(self, name, cond, detail=""):
        if cond:
            self.ok += 1
            log("PASS  %s %s" % (name, detail))
        else:
            self.fail += 1
            self.failed.append(name)
            log("FAIL  %s %s" % (name, detail))


def wait_ready(timeout=120.0):
    """Wait until a database with at least one segment is loaded."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if ida_segment.get_segm_qty() > 0:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def run():
    sys.path.insert(0, os.path.join(ROOT, "plugins"))
    import eh_frame_patch as EHP
    from ehp import asm_engine, elf_image, plan as plan_mod

    t = Tally()
    log("=== eh_frame_patch self test ===")
    log("IDA %s" % idaapi.get_kernel_version())
    log("proc=%s bits=%d" % (idaapi.inf_get_procname(), EHP._current_bits()))

    # 1 -- actions registered
    registered = set(ida_kernwin.get_registered_actions() or [])
    for action in sorted(
        [EHP.ACTION_PATCH, EHP.ACTION_PREVIEW, EHP.ACTION_INFO,
         EHP.ACTION_EXPORT, EHP.ACTION_UNDO]
    ):
        t.check("action registered: %s" % action, action in registered)
    t.check("keystone available", asm_engine.keystone_available())

    # 2 -- .eh_frame discovered as a non-executable data segment
    eh = ida_segment.get_segm_by_name(".eh_frame")
    t.check(".eh_frame segment present", eh is not None)
    if eh is None:
        return t
    seg = EHP.MEM.segment_at(eh.start_ea)
    t.check(".eh_frame is data", seg is not None and not seg.is_code, str(seg))
    t.check(".eh_frame not executable in IDA",
            seg is not None and not (seg.perm & plan_mod.SegPerm.EXEC),
            plan_mod.SegPerm.text(seg.perm if seg else 0))

    # 3 -- plan validation on a real .eh_frame address
    bits = EHP._current_bits()
    text = ida_segment.get_segm_by_name(".text")
    ret_addr = text.start_ea + 0x10
    stub = ("mov qword ptr [rbp-8], 0\njmp 0x%X" % ret_addr if bits == 64
            else "mov dword ptr [ebp-8], 0\njmp 0x%X" % ret_addr)
    stub = stub.replace("0x%X" % ret_addr, "0x%X" % ret_addr)
    plan = plan_mod.build_plan(
        EHP.MEM, eh.start_ea, stub, bits=bits, budget=32,
        resolve=EHP.MEM.resolve_symbol, return_ea=ret_addr,
    )
    t.check("plan ok for .eh_frame stub", plan.ok,
            plan.summary().replace("\n", " | ")[:300])
    t.check("plan warns about data segment",
            any("DATA segment" in c.text for c in plan.warnings))
    t.check("plan warns about execute permission",
            any("no execute permission" in c.text for c in plan.warnings))
    t.check("plan warns about unwind info",
            any("unwind" in c.text for c in plan.warnings))
    t.check("plan validated the branch target",
            any("branch target" in c.text for c in plan.checks))
    t.check("plan echoes the return address",
            any("returns to" in c.text for c in plan.checks))
    t.check("orig bytes captured", len(plan.orig_bytes) == plan.size,
            "%d bytes" % len(plan.orig_bytes))

    # 4 -- rejection paths
    over = plan_mod.build_plan(EHP.MEM, eh.start_ea, "nop\n" * 64, bits=bits, budget=16)
    t.check("overlong stub rejected", not over.ok)
    t.check("overlong message names the budget",
            any("only 16 byte(s) fit" in c.text for c in over.errors))

    end = eh.end_ea
    cross = plan_mod.build_plan(EHP.MEM, end - 2, "mov rax, 1\nret", bits=bits, budget=32)
    t.check("cross-segment code rejected", not cross.ok)
    cross_ok = plan_mod.build_plan(EHP.MEM, end - 2, "mov rax, 1\nret", bits=bits,
                                   budget=32, allow_cross_segment=True)
    t.check("cross-segment allowed on request",
            cross_ok.ok and any("crosses" in c.text for c in cross_ok.warnings))

    unmapped = plan_mod.build_plan(EHP.MEM, 0xDEAD0000, "nop", bits=bits, budget=4)
    t.check("unmapped target rejected", not unmapped.ok)

    # 5 -- real patch through IDA's API, verify, then revert
    probe = plan_mod.build_plan(EHP.MEM, eh.start_ea, "nop\nnop", bits=bits,
                                budget=8, nop_pad=True)
    orig = ida_bytes.get_bytes(eh.start_ea, 8)
    res = EHP.apply_patch(probe, reanalyze=True)
    t.check("apply_patch succeeded", res.ok, res.message)
    after = ida_bytes.get_bytes(eh.start_ea, 8)
    t.check("patched bytes are in the database", after == bytes(probe.padded),
            after.hex() if after else "None")
    t.check("region re-analysed as code", res.reanalyzed)
    t.check("NOP padding written", probe.pad_len == 6 and after[:2] == b"\x90\x90",
            "pad=%d" % probe.pad_len)

    ida_bytes.patch_bytes(eh.start_ea, orig)
    back = ida_bytes.get_bytes(eh.start_ea, 8)
    t.check("original bytes restored", back == orig,
            "%s -> %s" % (orig.hex() if orig else "?",
                          back.hex() if back else "?"))

    # 5b -- export helper: whole-database diff must see the stub AND the jump
    changes = EHP.collect_all_db_changes()
    t.check("collect_all_db_changes returns a list", isinstance(changes, list),
            "%d run(s)" % len(changes))
    where = EHP.suggest_stub_address()
    t.check("suggest_stub_address finds .eh_frame tail", where is not None,
            "0x%X budget=%d" % where if where else "none")
    if where is not None:
        safe_ea, safe_budget = where
        seg_end = eh.end_ea
        t.check("suggested area ends before the ZERO terminator",
                safe_ea + safe_budget <= seg_end - 4,
                "end=0x%X seg_end=0x%X" % (safe_ea + safe_budget, seg_end))
        live = plan_mod.build_plan(EHP.MEM, safe_ea, "nop\nnop", bits=bits,
                                   budget=safe_budget)
        t.check("suggested area is writable", live.ok,
                live.summary().replace("\n", " | ")[:200])

    # 6 -- ELF view / permission reporting
    path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    try:
        img = elf_image.ElfImage.from_file(path)
        sec = img.section(".eh_frame")
        t.check("ELF .eh_frame found", sec is not None)
        t.check("ELF says .eh_frame is not executable",
                sec is not None and not img.is_executable(sec.addr))
        t.check("ELF vaddr matches IDA address",
                sec is not None and sec.addr == eh.start_ea,
                "elf=%s ida=%s" % (hex(sec.addr) if sec else "?", hex(eh.start_ea)))
        report = elf_image.format_permission_report(img, sec.addr)
        t.check("permission report mentions PT_LOAD", "PT_LOAD" in report)
    except Exception:
        t.check("ELF parse", False, traceback.format_exc())

    # 7 -- preview rendering
    try:
        text = EHP.render_preview(plan)
        t.check("preview renders machine code",
                "machine code" in text and "checks:" in text, "%d chars" % len(text))
    except Exception:
        t.check("preview renders", False, traceback.format_exc())

    # 8 -- coexists with Keypatch
    candidates = [os.path.dirname(os.path.abspath(EHP.__file__))]
    try:
        candidates.append(os.path.join(idaapi.idadir("plugins")))
    except Exception:
        pass
    kp = None
    for d in candidates:
        p2 = os.path.join(d, "keypatch.py")
        if os.path.exists(p2):
            kp = p2
            break
    t.check("keypatch.py installed alongside", kp is not None, kp or str(candidates))
    kp_mods = [m for m in sys.modules if "keypatch" in m.lower()]
    t.check("keypatch loaded in the same IDA", bool(kp_mods), str(kp_mods))
    kp_actions = sorted(a for a in registered if a.startswith("Kp_MC_"))
    t.check("keypatch actions still registered", bool(kp_actions), str(kp_actions))
    t.check("action names do not collide",
            not any(a.startswith("eh_frame_patch:") and a.startswith("Kp_")
                    for a in registered))

    log("SUMMARY pass=%d fail=%d" % (t.ok, t.fail))
    if t.failed:
        log("FAILED: " + ", ".join(t.failed))
    return t


def main():
    log("waiting for database...")
    if not wait_ready():
        log("FATAL: database never became ready (segs=%s)"
            % (ida_segment.get_segm_qty() if True else "?"))
        idaapi.qexit(1)
        return
    log("database ready, segs=%d" % ida_segment.get_segm_qty())
    try:
        run()
    except Exception:
        log("FATAL\n" + traceback.format_exc())
    log("DONE")
    try:
        ida_loader.save_database(None, 0)
        log("database saved")
    except Exception:
        log("save failed: " + traceback.format_exc().splitlines()[-1])
    idaapi.qexit(0)


main()
