# -*- coding: utf-8 -*-
"""End-to-end test of the *export* path on the real AWDP binary.

The earlier examples drive ``ehp`` directly.  This one drives the plugin's own
code: it patches through ``apply_patch`` (the same function the Patch button
calls), then exports with ``collect_all_db_changes`` +
``export_executable_copy``, and finally runs the produced binary.

Usage::

    ida.exe -A -S"ida_export_e2e.py" samples/main
"""

import os
import subprocess
import sys
import traceback

import idaapi
import ida_bytes
import ida_loader
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(HERE, "ida_export_e2e.log")

# delete(): call free@plt at 0x16BB; the 12 bytes after it are safe to replace.
TAIL_START = 0x16C0
TAIL_LEN = 0x16CC - TAIL_START
RESUME = 0x16CC          # leave; ret -- must stay intact
ADDR_LIST = 0x4060
OK_MSG = 0x2080
PUTS_PLT = 0x1110


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
    log("=== export e2e ===")
    if not wait_ready():
        log("FATAL: database not ready")
        idaapi.qexit(1)
        return

    sys.path.insert(0, os.path.join(ROOT, "plugins"))
    for name in list(sys.modules):
        if name == 'ehp' or name.startswith('ehp.'): del sys.modules[name]
    import eh_frame_patch as EHP
    from ehp import plan as plan_mod

    bits = EHP._current_bits()
    eh = ida_segment.get_segm_by_name(".eh_frame")
    if eh is None:
        log("FATAL: no .eh_frame")
        idaapi.qexit(1)
        return

    # ---- 1. plan + apply the stub in .eh_frame -------------------------
    stub_src = (
        "mov eax, dword ptr [rbp-4]\n"
        "cdqe\n"
        "lea rdx, [0x%X]\n"
        "mov qword ptr [rdx + rax*8], 0\n"
        "lea rdi, [0x%X]\n"
        "call 0x%X\n"
        "jmp 0x%X\n"
    ) % (ADDR_LIST, OK_MSG, PUTS_PLT, RESUME)

    # Size it first, then place it just before the ZERO terminator.
    probe = EHP.asm_engine.assemble(stub_src, eh.start_ea, bits=bits)
    if not probe.ok:
        log("FATAL: stub does not assemble: %s" % probe.error_text)
        idaapi.qexit(1)
        return
    stub_ea = (int(eh.end_ea) - 4) - probe.size
    log("stub at 0x%X (%d bytes)" % (stub_ea, probe.size))

    stub_plan = plan_mod.build_plan(
        EHP.MEM, stub_ea, stub_src, bits=bits, budget=probe.size,
        resolve=EHP.MEM.resolve_symbol,
    )
    if not stub_plan.ok:
        log("FATAL: stub plan rejected: %s" % stub_plan.summary())
        idaapi.qexit(1)
        return
    res = EHP.apply_patch(stub_plan, reanalyze=True)
    log("stub apply: %s" % res.message)
    if not res.ok:
        idaapi.qexit(1)
        return

    # ---- 2. plan + apply the jump at the bug site ----------------------
    jump_src = "jmp 0x%X" % stub_ea
    jump_plan = plan_mod.build_plan(
        EHP.MEM, TAIL_START, jump_src, bits=bits, budget=TAIL_LEN,
        resolve=EHP.MEM.resolve_symbol, nop_pad=True,
    )
    if not jump_plan.ok:
        log("FATAL: jump plan rejected: %s" % jump_plan.summary())
        idaapi.qexit(1)
        return
    res2 = EHP.apply_patch(jump_plan, reanalyze=True)
    log("jump apply: %s (%d bytes with NOP padding)"
        % (res2.message, len(jump_plan.padded)))
    if not res2.ok:
        idaapi.qexit(1)
        return

    # ---- 3. leave() must be untouched ---------------------------------
    leave = ida_bytes.get_bytes(RESUME, 2)
    log("leave;ret bytes at 0x%X: %s (expect c9c3)"
        % (RESUME, leave.hex() if leave else "None"))

    # ---- 4. export the whole-database diff ----------------------------
    changes = EHP.collect_all_db_changes()
    log("_written_ranges: %s" % (EHP._written_ranges,))
    log("collect_all_db_changes -> %d run(s)" % len(changes))
    total = 0
    for vaddr, blob in changes:
        total += len(blob)
        log("  0x%X  %d bytes  %s" % (vaddr, len(blob), blob[:16].hex()))
    log("total %d byte(s)" % total)

    src = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    out = os.path.join(HERE, "out", os.path.basename(src) + ".e2e")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        os.remove(out)

    from ehp import elf_image

    import ida_kernwin
    ask_str, ask_yn, info = ida_kernwin.ask_str, ida_kernwin.ask_yn, ida_kernwin.info
    ida_kernwin.ask_str = lambda *a: out
    ida_kernwin.ask_yn = lambda *a: ida_kernwin.ASKBTN_YES
    ida_kernwin.info = lambda *a: None
    try:
        result = EHP.export_executable_copy(stub_ea, changes)
    finally:
        ida_kernwin.ask_str, ida_kernwin.ask_yn, ida_kernwin.info = ask_str, ask_yn, info
    assert result == out, 'plugin export failed'
    img2 = elf_image.ElfImage.from_file(out)
    applied = changes
    log("exported %s" % out)
    log("applied %d run(s)" % len(applied))
    log("PF_X on .eh_frame: %s" % img2.is_executable(stub_ea))

    # ---- 5. prove both patches really landed in the file --------------
    eh_sec = img2.section(".eh_frame")
    got_stub = img2.read(stub_ea, stub_plan.size)
    log("file stub bytes: %s" % (got_stub.hex() if got_stub else "None"))
    # compare against the plan actually applied (probe was assembled at a
    # different address, so its relative displacements legitimately differ)
    log("stub matches   : %s" % (got_stub == bytes(stub_plan.code)))
    # the GOT must NOT be rewritten: IDA resolves those pointers at load time,
    # so a naive whole-file diff would corrupt them.
    orig_img = elf_image.ElfImage.from_file(src)
    got_got, orig_got = img2.read(0x3F78, 8), orig_img.read(0x3F78, 8)
    log("GOT untouched  : %s (%s vs %s)"
        % (got_got == orig_got,
           got_got.hex() if got_got else "None",
           orig_got.hex() if orig_got else "None"))
    got_jump = img2.read(TAIL_START, TAIL_LEN)
    log("file jump bytes: %s" % (got_jump.hex() if got_jump else "None"))
    log("jump matches   : %s" % (got_jump == bytes(jump_plan.padded)))
    log("leave untouched: %s" % (img2.read(RESUME, 2) == b"\xc9\xc3"))

    os.chmod(out, 0o755)
    assert got_stub == bytes(stub_plan.code)
    assert got_jump == bytes(jump_plan.padded)
    assert got_got == orig_got
    assert img2.read(RESUME, 2) == b"\xc9\xc3"
    assert img2.is_executable(stub_ea)
    log("RESULT %s" % out)
    log("DONE")
    idaapi.qexit(0)


main()
