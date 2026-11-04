"""Optional Capstone based disassembly preview.

The plugin works without Capstone (the preview pane then shows the raw bytes
only).  When Capstone is present we can show the user what the freshly
assembled bytes will look like as instructions -- which is the fastest way to
catch a wrong operand size or a short-jump that silently became a near jump.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

try:  # pragma: no cover
    import capstone

    HAVE_CAPSTONE = True
except Exception:  # pragma: no cover
    capstone = None  # type: ignore
    HAVE_CAPSTONE = False


def capstone_available():
    return HAVE_CAPSTONE


def _md(bits):
    mode = {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32, 64: capstone.CS_MODE_64}[bits]
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = False
    md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    return md


def disassemble(blob, ea, bits=64, count=0):
    """Disassemble *blob* at *ea*.

    Returns ``[(address, size, text, raw_bytes)]``.  Trailing bytes that do not
    decode are returned with ``text='<bad>'`` so the caller can warn.
    """
    if not HAVE_CAPSTONE or not blob:
        return []
    md = _md(bits)
    out = []  # type: List[Tuple[int, int, str, bytes]]
    consumed = 0
    for insn in md.disasm(bytes(blob), ea):
        out.append((insn.address, insn.size, "%s %s" % (insn.mnemonic, insn.op_str), insn.bytes))
        consumed += insn.size
        if count and len(out) >= count:
            break
    if consumed < len(blob) and not count:
        out.append((ea + consumed, len(blob) - consumed, "<undecoded>", bytes(blob[consumed:])))
    return out


def format_disassembly(blob, ea, bits=64):
    rows = disassemble(blob, ea, bits)
    if not rows:
        return ""
    lines = []
    for addr, size, text, raw in rows:
        lines.append(
            "%016X  %-24s  %s" % (addr, " ".join("%02X" % b for b in raw), text)
        )
    return "\n".join(lines)


def decode_length(blob, bits=64):
    """Number of bytes Capstone can decode from the start of *blob*."""
    rows = disassemble(blob, 0, bits)
    total = 0
    for _addr, size, text, _raw in rows:
        if text == "<undecoded>":
            break
        total += size
    return total
