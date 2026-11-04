#!/usr/bin/env python3
"""End-to-end demonstration of the UAF fix this plugin is built for.

It performs, without IDA, exactly what eh_frame_patch does inside IDA:

1. assemble a stub ``mov qword ptr [rbp-8], 0 ; jmp <back>`` for .eh_frame,
2. assemble the 5-byte ``jmp <stub>`` that replaces the vulnerable
   ``jmp/leave/ret`` tail right after ``call free``,
3. write both into a *copy* of the binary and set PF_X on the .eh_frame
   PT_LOAD,
4. run the patched copy and check that the dangling pointer is gone.

Usage::

    python3 examples/uaf_fix_demo.py samples/uaf_demo64
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "plugins"))

from ehp import asm_engine, elf_image  # noqa: E402

#: address of the `call free@plt` instruction, per binary (from objdump).
#: The patch point is the instruction right after it.
FREE_CALL_64 = 0x11A2
FREE_CALL_32 = 0x1208


def build(path, out_path):
    print("WARNING: example overwrites live unwind records; not a verified code cave")
    img = elf_image.ElfImage.from_file(path)
    bits = img.bits
    free_call = FREE_CALL_64 if bits == 64 else FREE_CALL_32

    # Directly after `call free` the compiler emitted `jmp +1 / nop / leave /
    # ret`, i.e. exactly 5 bytes -- enough for a `jmp rel32` and nothing else.
    patch_site = free_call + 5

    eh = img.section(".eh_frame")
    # Keep the 4-byte ZERO terminator at the end of .eh_frame intact: glibc's
    # __register_frame_info walks the table at startup and a destroyed
    # terminator makes it read past the section.
    terminator = 4
    # IMPORTANT: zero the *slot that actually holds the dangling pointer*.
    # obj_free(o) received &o in rdi/[ebp+8]; the stale pointer is o->buf,
    # i.e. the first field of the struct, NOT a register and NOT this frame's
    # local copy of `o`.  Zeroing [rbp-8] would look right in a debugger and
    # still leave the caller with a dangling pointer.
    if bits == 64:
        stub_src = (
            "mov rax, qword ptr [rbp-8]   ; rax = o  (the caller's obj_t *)\n"
            "mov qword ptr [rax], 0       ; o->buf = NULL\n"
            "leave\n"
            "ret"
        )
    else:
        stub_src = (
            "mov eax, dword ptr [ebp+8]   ; eax = o  (the caller's obj_t *)\n"
            "mov dword ptr [eax], 0       ; o->buf = NULL\n"
            "leave\n"
            "ret"
        )

    probe = asm_engine.assemble(stub_src, eh.addr, bits=bits)
    if not probe.ok:
        raise SystemExit("stub assembly failed: %s" % probe.error_text)
    stub_ea = (eh.addr + eh.size) - terminator - probe.size

    stub = asm_engine.assemble(stub_src, stub_ea, bits=bits)
    if stub_ea + stub.size > eh.addr + eh.size - terminator:
        raise SystemExit("stub does not fit in .eh_frame")

    jump_src = "jmp 0x%X" % stub_ea
    jump = asm_engine.assemble(jump_src, patch_site, bits=bits)
    if not jump.ok:
        raise SystemExit("jump assembly failed: %s" % jump.error_text)
    if jump.size != 5:
        raise SystemExit("jump must be exactly 5 bytes, got %d" % jump.size)

    print("bits        : %d" % bits)
    print("patch site  : 0x%X  <- jmp 0x%X  (%s)" % (patch_site, stub_ea, jump.code.hex()))
    print("stub        : 0x%X  %d bytes  %s" % (stub_ea, stub.size, stub.code.hex()))
    print("stub does   : zero the saved pointer, then leave/ret to the caller")
    print("eh_frame    : 0x%X-0x%X (terminator at 0x%X kept)"
          % (eh.addr, eh.addr + eh.size, eh.addr + eh.size - terminator))

    img2, applied = elf_image.clone_with_patches(
        path,
        out_path,
        [(stub_ea, stub.code), (patch_site, jump.code)],
        make_exec=eh.addr,
    )
    print("written     : %s" % out_path)
    print("PF_X on .eh_frame PT_LOAD: %s" % img2.is_executable(eh.addr))
    return out_path


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    src = argv[1]
    out = argv[2] if len(argv) > 2 else src + ".fixed"
    if not os.path.exists(src):
        print("no such file: %s" % src)
        return 2

    print("--- before ---")
    subprocess.call([src])
    build(src, out)
    os.chmod(out, 0o755)
    print("--- after ---")
    rc = subprocess.call([out])
    print("--- exit code: %d ---" % rc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
