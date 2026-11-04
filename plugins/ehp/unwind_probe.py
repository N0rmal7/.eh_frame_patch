"""Decide whether overwriting .eh_frame can hurt the running program.

The plugin is used for AWDP fixes, where the priority is "pass the checker",
not "keep DWARF perfect".  But whether overwriting .eh_frame is harmless depends
entirely on whether the program ever *unwinds*:

* A pure C program linked only against libc never walks .eh_frame at run time
  (``__register_frame_info`` only records the pointer).  Overwriting CIE/FDE
  entries is then invisible to the checker.
* A C++ program (or anything with ``-fexceptions``, ``backtrace``,
  ``pthread_cancel``, ``.gcc_except_table``) walks it on every throw/backtrace,
  and a destroyed CIE usually means SIGSEGV.

This module inspects the ELF and returns a verdict plus the evidence, so the
plugin can say *why* it considers a large overwrite acceptable.
"""

from __future__ import annotations

import re
import struct

#: symbols / sections that imply the program actually unwinds at run time
_UNWIND_MARKERS = (
    b"__cxa_throw",
    b"__cxa_rethrow",
    b"_Unwind_RaiseException",
    b"_Unwind_Resume",
    b"__gxx_personality",
    b"__gcc_personality",
    b"backtrace",
    b"_Unwind_Backtrace",
    b"pthread_cancel",
    b"__cxa_begin_catch",
)

#: dynamic dependencies that bring in the unwinder
_UNWIND_LIBS = ("libstdc++", "libgcc_s")

_NEEDED_RE = re.compile(rb"NEEDED[^\[]*\[([^\]]+)\]")


class UnwindVerdict(object):
    """Result of the analysis."""

    __slots__ = ("uses_unwinding", "evidence", "needed")

    def __init__(self, uses_unwinding, evidence, needed):
        self.uses_unwinding = uses_unwinding
        #: list of human readable reasons
        self.evidence = evidence
        #: NEEDED entries found in .dynamic
        self.needed = needed

    def summary(self):
        if self.uses_unwinding:
            head = "program MAY unwind at run time"
        else:
            head = "program does NOT unwind at run time"
        return "%s (%s)" % (head, "; ".join(self.evidence) if self.evidence else "no markers")


def _needed_libs(img):
    """Read DT_NEEDED strings via the .dynamic / .dynstr sections."""
    needed = []
    dyn = img.section(".dynamic")
    dynstr = img.section(".dynstr")
    if dyn is None or dynstr is None:
        return needed
    strtab = bytes(img.data[dynstr.offset : dynstr.offset + dynstr.size])
    ent = 16 if img.is64 else 8
    fmt = img.endian + ("qQ" if img.is64 else "iI")
    off = dyn.offset
    end = min(off + dyn.size, len(img.data))
    while off + ent <= end:
        tag, val = struct.unpack_from(fmt, img.data, off)
        off += ent
        if tag == 0:  # DT_NULL
            break
        if tag != 1:  # DT_NEEDED
            continue
        if val >= len(strtab):
            continue
        stop = strtab.find(b"\0", val)
        if stop < 0:
            stop = len(strtab)
        needed.append(strtab[val:stop].decode("latin-1", "replace"))
    return needed


def analyse(data, is64=True, endian="<", img=None):
    """Inspect raw ELF bytes and decide whether unwinding is in play.

    :param data: whole file bytes
    :param is64: ELF64 vs ELF32
    :param endian: '<' or '>'
    :param img: optional :class:`ElfImage`; when given, DT_NEEDED is read
        properly from ``.dynamic`` instead of by scanning for strings.
    """
    evidence = []

    # ---- 1. unwind-related symbol names anywhere in the file -----------
    hits = [m.decode("ascii", "replace") for m in _UNWIND_MARKERS if m in data]
    if hits:
        evidence.append("symbols: " + ", ".join(sorted(set(hits))))

    # ---- 2. NEEDED libraries ------------------------------------------
    needed = _needed_libs(img) if img is not None else [
        m.group(1).decode("latin-1", "replace") for m in _NEEDED_RE.finditer(data)
    ]
    for lib in needed:
        for marker in _UNWIND_LIBS:
            if marker in lib:
                evidence.append("needs %s" % lib)
                break

    # ---- 3. C++ exception tables ---------------------------------------
    if b".gcc_except_table" in data:
        evidence.append("has .gcc_except_table (C++ exception tables)")

    uses = bool(evidence)
    return UnwindVerdict(uses, evidence, needed)


def verdict_for_image(img):
    """Convenience wrapper for an :class:`ehp.elf_image.ElfImage`."""
    return analyse(bytes(img.data), is64=img.is64, endian=img.endian, img=img)
