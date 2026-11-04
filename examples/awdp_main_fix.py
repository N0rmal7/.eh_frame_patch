#!/usr/bin/env python3
"""Real-target demo: fix the AWDP `main` UAF with an .eh_frame stub.

Vulnerability
-------------
``delete()`` frees the heap chunk stored in the global ``addrList[idx]`` but
never clears the slot, so the menu hands the same pointer out again: classic
use-after-free / double-free.

Why a stub is needed
--------------------
Directly after ``call free@plt`` there are only 14 bytes before ``leave; ret``::

    16BB  call free@plt
    16C0  lea  rdi, [rip+0x9b9]     ; 7 bytes
    16C7  call puts@plt             ; 5 bytes
    16CC  leave                     ; 1 byte   <-- also the target of the
    16CD  ret                       ; 1 byte       "Invalid Index" jmp 0x16CC

There is no room for ``mov [addrList+idx*8], 0`` in place, so we relocate the
"print success" tail into .eh_frame:

    patch site (0x16C0) : jmp <stub>            (5 bytes + 7 NOP)
    stub                : addrList[idx] = NULL
                          print the same message
                          jmp 0x16CC             (back to delete()'s own
                                                  leave/ret)

Key detail: ``leave; ret`` at 0x16CC is **left untouched** because the error
path (``Invalid Index``) jumps to it.  NOPing it turns a harmless error into a
control-flow fall-through into the next function.

Usage::

    python3 examples/awdp_main_fix.py samples/main /tmp/main_fixed
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "plugins"))

from ehp import asm_engine, elf_image  # noqa: E402

FREE_CALL = 0x16BB   # call free@plt
TAIL_START = 0x16C0  # lea rdi,[rip+0x9b9]   <- we overwrite from here
TAIL_LEN = 0x16CC - TAIL_START          # 12 bytes: lea(7) + call(5)
RESUME = 0x16CC      # leave; ret  -- untouched, also the "Invalid Index" target


def build(src, dst):
    print("WARNING: example overwrites live unwind records; not a verified code cave")
    img = elf_image.ElfImage.from_file(src)
    bits = img.bits
    eh = img.section(".eh_frame")
    addr_list = 0x4060               # global addrList[32]
    ok_msg = 0x2080                  # "delete success" string
    puts_plt = 0x1110

    # Leave the 4-byte ZERO terminator intact: glibc walks the table at startup.
    terminator = 4

    # Absolute addresses only: Keystone re-encodes `[0x4060]` as an operand
    # relative to the stub's own address, which is what makes the stub PIE/ASLR
    # safe.  Never paste the raw `rip+disp` displacement from objdump.
    stub_src = (
        "mov eax, dword ptr [rbp-4]        ; idx, still live on delete()'s frame\n"
        "cdqe\n"
        "lea rdx, [0x%X]                   ; &addrList   (RIP-relative)\n"
        "mov qword ptr [rdx + rax*8], 0    ; addrList[idx] = NULL  <-- the fix\n"
        "lea rdi, [0x%X]                   ; the message delete() printed\n"
        "call 0x%X                          ; puts@plt\n"
        "jmp 0x%X                           ; back to delete()'s leave/ret\n"
    ) % (addr_list, ok_msg, puts_plt, RESUME)

    probe = asm_engine.assemble(stub_src, eh.addr, bits=bits)
    if not probe.ok:
        raise SystemExit("stub assembly failed:\n%s" % probe.error_text)
    stub_ea = (eh.addr + eh.size) - terminator - probe.size
    stub = asm_engine.assemble(stub_src, stub_ea, bits=bits)
    if not stub.ok:
        raise SystemExit("stub assembly failed:\n%s" % stub.error_text)

    jump = asm_engine.assemble("jmp 0x%X" % stub_ea, TAIL_START, bits=bits)
    if not jump.ok:
        raise SystemExit("jump assembly failed: %s" % jump.error_text)
    if jump.size > TAIL_LEN:
        raise SystemExit("jump does not fit in %d bytes" % TAIL_LEN)
    # NOP-pad the rest of the covered bytes (the same thing the plugin's
    # "NOP-pad" option does).
    jump_padded = jump.code + b"\x90" * (TAIL_LEN - jump.size)

    print("binary      : %s (ELF%d)" % (os.path.basename(src), bits))
    print("vuln site   : 0x%X  free() without clearing addrList[idx]" % FREE_CALL)
    print("patch site  : 0x%X  %d bytes  <- jmp 0x%X + %d NOP  [%s]"
          % (TAIL_START, TAIL_LEN, stub_ea, TAIL_LEN - jump.size, jump_padded.hex()))
    print("stub        : 0x%X  %d bytes  [%s]" % (stub_ea, stub.size, stub.code.hex()))
    print("stub does   : addrList[idx] = 0, print message, jmp 0x%X" % RESUME)
    print("kept intact : 0x%X leave; ret (the Invalid-Index path jumps here)" % RESUME)
    print(".eh_frame   : 0x%X-0x%X (terminator at 0x%X kept)"
          % (eh.addr, eh.addr + eh.size, eh.addr + eh.size - terminator))

    img2, _ = elf_image.clone_with_patches(
        src, dst, [(stub_ea, stub.code), (TAIL_START, jump_padded)], make_exec=eh.addr
    )
    print("written     : %s" % dst)
    print("PF_X on .eh_frame PT_LOAD: %s" % img2.is_executable(eh.addr))
    return dst


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src + ".fixed"
    build(src, dst)
    os.chmod(dst, 0o755)
