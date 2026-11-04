"""Keystone backed assembler used by eh_frame_patch.

Design notes
------------
* Only x86 / x86-64, Intel syntax (the scope agreed for v1).
* The user's text is *not* modified in place; we build a "rendered" source that
  Keystone actually sees, so error messages can point back at the original line.
* Keystone has no comment support for the Intel syntax and no ``db``/``dd``
  directives, so we normalise those first.
* Symbol names coming from IDA (``main``, ``free@plt``, ``dword_404010`` ...)
  are resolved through a caller supplied callback and substituted with a
  numeric literal.  Labels defined *inside* the snippet are never substituted.
* Keystone reports an error code but not the offending line, therefore we
  locate the line ourselves by assembling growing prefixes.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

try:  # pragma: no cover - exercised implicitly
    from keystone import (
        Ks,
        KsError,
        KS_ARCH_X86,
        KS_MODE_16,
        KS_MODE_32,
        KS_MODE_64,
        KS_OPT_SYNTAX_INTEL,
    )

    HAVE_KEYSTONE = True
except Exception:  # pragma: no cover
    HAVE_KEYSTONE = False
    Ks = None  # type: ignore

    class KsError(Exception):  # type: ignore
        def __init__(self, errno=0, count=0):
            super().__init__("keystone unavailable")
            self.errno = errno


#: Keystone "symbol missing" errno.  Used to ignore forward references while
#: hunting for the real syntax error.
KS_ERR_ASM_SYMBOL_MISSING = 144

X86_NOP = 0x90

_MODE_BY_BITS = {16: "16", 32: "32", 64: "64"}

#: ``db 0x90`` style directives -> keystone native ones.
_DIRECTIVE_ALIASES = {
    "db": ".byte",
    "dw": ".word",
    "dd": ".long",
    "dq": ".quad",
}

#: Keystone accepts ``.byte``, ``.word``, ``.long``, ``.quad`` only.
_UNSUPPORTED_DIRECTIVES = {".dword": ".long", ".int": ".long", ".qword": ".quad"}

_LABEL_RE = re.compile(r"^\s*([A-Za-z_.$?@][\w.$?@]*)\s*:(?P<rest>.*)$")
_LABEL_ONLY_RE = re.compile(r"^\s*[A-Za-z_.$?@][\w.$?@]*\s*:\s*$")
_IDENT_RE = re.compile(r"(?<![\w])(?:[A-Za-z_.$?@][\w.$?@]*)")

#: Operand keywords that must never be treated as symbols.
_KEYWORDS = frozenset(
    """
    byte word dword qword tbyte xmmword ymmword zmmword oword fword
    ptr offset short near far flat cs ds es fs gs ss
    and or xor not shl shr mod
    """.split()
)

_REGISTER_RE = re.compile(
    r"^(?:"
    r"[re]?(?:ax|bx|cx|dx|si|di|bp|sp|ip)"
    r"|[abcd][lh]"
    r"|r(?:[89]|1[0-5])[dwb]?"
    r"|(?:x|y|z)mm\d{1,2}"
    r"|st(?:\(\d\))?"
    r"|mm[0-7]"
    r"|(?:dr|cr|tr)\d{1,2}"
    r"|k[0-7]"
    r"|bnd\d?"
    r")$",
    re.IGNORECASE,
)


class AsmResult(object):
    """Outcome of :func:`assemble`."""

    __slots__ = (
        "ok",
        "code",
        "size",
        "errors",
        "warnings",
        "labels",
        "rendered",
        "source_lines",
        "pieces",
        "targets",
        "empty",
    )

    def __init__(self):
        self.ok = False
        self.code = b""
        self.size = 0
        self.errors = []  # type: List[str]
        self.warnings = []  # type: List[str]
        self.labels = {}  # type: Dict[str, int]
        #: resolved text handed to keystone (useful for debugging)
        self.rendered = ""
        #: original user lines, 1:1 with what we assembled
        self.source_lines = []  # type: List[str]
        #: list of (offset, length, source_line) for each assembled statement
        self.pieces = []  # type: List[Tuple[int, int, str]]
        #: absolute branch targets referenced by the code
        self.targets = []  # type: List[int]
        #: True when the source had no instructions at all (not an error)
        self.empty = False

    def add_error(self, msg):
        self.errors.append(msg)

    @property
    def error_text(self):
        return "\n".join(self.errors)


def keystone_available():
    return HAVE_KEYSTONE


def strip_comment(line):
    """Remove ``;`` / ``//`` comments the way a human expects.

    Keystone's Intel syntax has no comment character, so ``nop ; fill`` would
    otherwise fail to assemble.
    """
    quote = None
    out = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == ";":
            break
        if ch == "#":
            break
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _normalise_line(line):
    """Translate directives and strip comments from one source line."""
    text = strip_comment(line).strip()
    if not text:
        return ""
    m = _LABEL_RE.match(text)
    prefix = ""
    rest = text
    if m:
        prefix = m.group(1) + ":"
        rest = m.group("rest").strip()
    if rest:
        parts = rest.split(None, 1)
        head, tail = parts[0], parts[1] if len(parts) > 1 else ""
        low = head.lower()
        if low in _DIRECTIVE_ALIASES:
            head = _DIRECTIVE_ALIASES[low]
            rest = (head + " " + tail).strip()
        elif low in _UNSUPPORTED_DIRECTIVES:
            rest = (_UNSUPPORTED_DIRECTIVES[low] + " " + tail).strip()
        elif low in ("nop", "ret", "retn") and not tail:
            rest = head
    return (prefix + (" " + rest if rest else "")).strip()


def collect_labels(lines):
    """Return ``{label: index}`` for labels defined in *lines*."""
    labels = {}
    for idx, line in enumerate(lines):
        m = _LABEL_RE.match(line)
        if m:
            labels[m.group(1)] = idx
    return labels


def resolve_symbols(line, labels, resolve, warnings):
    """Replace IDA symbol names in *line* with numeric literals."""
    if resolve is None:
        return line

    def _sub(match):
        name = match.group(0)
        if name in labels:
            return name
        low = name.lower()
        if low in _KEYWORDS or _REGISTER_RE.match(name):
            return name
        if name in ("$", "."):
            return name
        try:
            value = resolve(name)
        except Exception:
            value = None
        if value is None:
            return name
        if value < 0:
            return name
        return "0x%X" % value

    # Only touch the operand part: keep the label and the mnemonic intact.
    m = _LABEL_RE.match(line)
    head = ""
    body = line
    if m:
        head = line[: m.start("rest")]
        body = m.group("rest")
    # Do not rewrite the mnemonic itself.
    parts = body.split(None, 1)
    if not parts:
        return head + body
    if len(parts) == 1:
        return head + body
    mnem, operands = parts[0], parts[1]
    # Quoted literals and numeric tokens are not IDA symbol names.
    chunks = re.split(r"(\"[^\"]*\"|'[^']*')", operands)
    new_operands = "".join(chunk if i % 2 else _IDENT_RE.sub(_sub, chunk)
                           for i, chunk in enumerate(chunks))
    if new_operands != operands:
        warnings.append(None)  # sentinel, filtered by caller
    return head + mnem + " " + new_operands


def _new_ks(bits, endian=None):
    if not HAVE_KEYSTONE:
        raise RuntimeError(
            "Keystone engine is not available. Install the 'keystone-engine' "
            "package into IDA's Python (see docs/INSTALL.md)."
        )
    mode = {16: KS_MODE_16, 32: KS_MODE_32, 64: KS_MODE_64}[bits]
    if endian is not None:
        mode |= endian
    ks = Ks(KS_ARCH_X86, mode)
    ks.syntax = KS_OPT_SYNTAX_INTEL
    return ks


def _asm(ks, text, ea):
    encoding, count = ks.asm(text, ea)
    if encoding is None:
        raise KsError(0, 0)
    return bytes(bytearray(encoding))


def locate_error_line(ks, rendered_lines, ea):
    """Best effort: return the 1-based index of the first line that fails.

    Forward references make prefixes fail with ``SYMBOL_MISSING``; those are
    skipped because they may still be valid in the full snippet.
    """
    for i in range(1, len(rendered_lines) + 1):
        chunk = "\n".join(rendered_lines[:i])
        try:
            _asm(ks, chunk, ea)
        except KsError as exc:
            if getattr(exc, "errno", 0) == KS_ERR_ASM_SYMBOL_MISSING:
                continue
            return i
        except Exception:
            continue
    return None


def _extract_targets(text):
    """Find absolute branch targets mentioned in the snippet.

    Only ``jmp``/``call``/``jcc`` with a plain numeric operand are considered,
    which is what the UAF "jump back to the original flow" stub looks like.
    """
    targets = []
    for raw in text.splitlines():
        line = strip_comment(raw).strip()
        if not line:
            continue
        m = _LABEL_RE.match(line)
        if m:
            line = m.group("rest").strip()
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        mnem = parts[0].lower()
        if not (mnem == "jmp" or mnem == "call" or mnem.startswith("j")):
            continue
        operand = parts[1].strip()
        if operand.lower().startswith(("short ", "near ", "far ")):
            operand = operand.split(None, 1)[1].strip()
        try:
            targets.append(int(operand, 0))
        except ValueError:
            continue
    return targets


def assemble(
    source, ea, bits=64, resolve=None, endian=None, label_offsets=True
):
    """Assemble *source* as if it were placed at *ea*.

    :param source: multi line assembly text (Intel syntax).
    :param ea: address the first byte will live at; relative jumps and
        RIP-relative operands are computed from it.
    :param bits: 16 / 32 / 64.
    :param resolve: ``callable(name) -> int | None`` used to turn IDA symbols
        into numbers.
    :param endian: optional keystone endian flag.
    :param label_offsets: also compute ``{label: offset}`` inside the block.
    """
    result = AsmResult()
    result.targets = _extract_targets(source or "")

    raw_lines = (source or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    normalised = [_normalise_line(line) for line in raw_lines]
    # Drop blank lines but keep a mapping so messages can quote the original.
    lines = []
    origin = []
    for idx, line in enumerate(normalised):
        if line:
            lines.append(line)
            origin.append(idx + 1)

    if not lines:
        # Not an error: the editor starts empty on purpose.  The caller decides
        # how to present an empty program (the plugin shows a hint, not a red
        # ERROR, so an untouched dialog does not look broken).
        result.empty = True
        return result

    if bits not in (16, 32, 64):
        result.add_error("unsupported bitness %r" % (bits,))
        return result

    labels = collect_labels(lines)
    try:
        ks = _new_ks(bits, endian)
    except Exception as exc:  # keystone missing
        result.add_error(str(exc))
        return result

    warnings = []
    rendered = []
    for line in lines:
        rendered.append(resolve_symbols(line, labels, resolve, warnings))

    text = "\n".join(rendered)
    result.targets = _extract_targets(text)
    result.rendered = text
    result.source_lines = [raw_lines[i - 1] for i in origin]

    try:
        result.code = _asm(ks, text, ea)
    except KsError as exc:
        lineno = locate_error_line(ks, rendered, ea)
        msg = str(exc)
        if lineno is not None:
            src = origin[lineno - 1]
            result.add_error(
                "line %d: %s\n    %s" % (src, msg, raw_lines[src - 1].strip())
            )
        else:
            result.add_error(msg)
        # Surface symbol problems clearly -- but only identifiers that actually
        # sit in an *operand* position.  Scanning the whole text also matches
        # mnemonics (mov/call/lea/...) and register names, which produced the
        # useless "unresolved symbol(s): call, cdqe, lea, mov" message.
        if getattr(exc, "errno", 0) == KS_ERR_ASM_SYMBOL_MISSING:
            unknown = _unknown_operand_symbols(rendered, labels)
            if unknown:
                result.add_error("unresolved symbol(s): %s" % ", ".join(unknown))
                for name in unknown[:4]:
                    hint = _symbol_hint(name)
                    if hint:
                        result.add_error("  %s -> %s" % (name, hint))
        return result

    result.ok = True
    result.size = len(result.code)

    if label_offsets:
        _compute_layout(result, ks, rendered, labels, ea)

    return result


def _operand_part(line):
    """Return the operand text of one source line ('' if it has none).

    ``mov eax, dword ptr [rbp-4]`` -> ``eax, dword ptr [rbp-4]``
    ``cdqe``                      -> ``
    """
    m = _LABEL_RE.match(line)
    body = m.group("rest") if m else line
    parts = body.split(None, 1)
    return parts[1] if len(parts) == 2 else ""


def _unknown_operand_symbols(rendered_lines, labels):
    """Identifiers that look like unresolved symbols, in operand position only."""
    found = []
    for line in rendered_lines:
        operands = _operand_part(line)
        if not operands:
            continue
        for name in _IDENT_RE.findall(operands):
            if name in labels:
                continue
            low = name.lower()
            if low in _KEYWORDS or _REGISTER_RE.match(name):
                continue
            if name.startswith(".") or name in ("$", "."):
                continue
            if low in ("ptr", "offset", "short", "near", "far", "flat"):
                continue
            if name not in found:
                found.append(name)
    return found


def _symbol_hint(name):
    """Explain the most common reasons a symbol does not resolve."""
    low = name.lower()
    if low.startswith("var_") or low.startswith("arg_"):
        return (
            "this is an IDA pseudo-name, not a symbol; use the real offset, "
            "e.g. [rbp-0x14] for var_14, and add a size (dword/qword ptr)"
        )
    if low in ("free", "malloc", "puts", "printf", "read", "write", "atoi"):
        return (
            "imported functions appear as '%s@plt' in IDA; write the address "
            "instead, e.g. 'call 0x1100'" % name
        )
    return "not defined in this database; use its address instead"


def _compute_layout(result, ks, rendered, labels, ea):
    """Fill ``result.labels`` / ``result.pieces`` for an already valid block.

    Labels are first located by appending ``.quad <label>`` probes to the whole
    block (the probe area is then read back as absolute addresses).  Prefixes
    are then sized with forward labels substituted by their now known address,
    because Keystone refuses to assemble a prefix that still references an
    undefined label.
    """
    if not labels:
        _compute_piece_sizes(result, ks, rendered, ea)
        return

    probe_lines = [".quad %s" % name for name in labels]
    probe = "\n" + "\n".join(probe_lines)
    try:
        total = len(_asm(ks, "\n".join(rendered) + probe, ea))
    except Exception:
        total = None

    label_addrs = {}
    if total is not None:
        probe_size = total - result.size
        if probe_size == len(probe_lines) * 8:
            tail = _asm(ks, "\n".join(rendered) + probe, ea)[result.size :]
            for i, name in enumerate(labels):
                chunk = tail[i * 8 : (i + 1) * 8]
                label_addrs[name] = int.from_bytes(chunk, "little" if _is_le(ks) else "big")

    # Size every prefix.  Forward labels are replaced by their (already known)
    # absolute address so Keystone does not reject a half-finished prefix;
    # for x86 this yields the same encoding length as the symbolic form.
    def _resolve_all(name):
        return label_addrs.get(name)

    resolved_lines = [
        resolve_symbols(line, {}, _resolve_all, []) for line in rendered
    ]

    sizes = []
    for idx in range(len(resolved_lines)):
        prefix = resolved_lines[: idx + 1]
        try:
            sizes.append(len(_asm(ks, "\n".join(prefix), ea)))
        except Exception:
            sizes.append(None)

    _emit_layout(result, rendered, sizes, labels)


def _compute_piece_sizes(result, ks, rendered, ea):
    """Piece layout for a snippet without internal labels."""
    sizes = []
    for idx in range(len(rendered)):
        try:
            sizes.append(len(_asm(ks, "\n".join(rendered[: idx + 1]), ea)))
        except Exception:
            sizes.append(None)
    _emit_layout(result, rendered, sizes, {})


def _emit_layout(result, rendered, sizes, labels):
    last = 0
    for idx, size in enumerate(sizes):
        if size is None:
            sizes[idx] = last
        else:
            last = size
    for idx in range(len(sizes) - 1, -1, -1):
        if sizes[idx] is None:
            sizes[idx] = last
        last = sizes[idx]

    for name, idx in labels.items():
        result.labels[name] = sizes[idx] if idx < len(sizes) else 0

    prev = 0
    for idx, _line in enumerate(rendered):
        length = sizes[idx] - prev
        if length < 0:
            length = 0
        # A line that only declares a label produces no bytes; keep it out of
        # the listing so the preview reads like real disassembly.
        if length or not _LABEL_ONLY_RE.match(_line):
            if idx < len(result.source_lines):
                result.pieces.append((prev, length, result.source_lines[idx]))
        prev = sizes[idx]


def _is_le(ks):
    """Keystone does not expose the mode; x86 in this plugin is little endian."""
    return True


def instruction_offsets(source, ea, bits=64, resolve=None):
    """Return ``[(offset, length, source_line)]`` for the assembled block."""
    res = assemble(source, ea, bits, resolve=resolve)
    if not res.ok:
        return res, []
    if res.pieces:
        return res, res.pieces
    # No labels were present: rebuild boundaries the same way.
    rendered = [ln for ln in res.rendered.split("\n") if ln]
    ks = _new_ks(bits)
    pieces = []
    prev = 0
    for idx, _line in enumerate(rendered):
        chunk = "\n".join(rendered[: idx + 1])
        try:
            size = len(_asm(ks, chunk, ea))
        except Exception:
            break
        pieces.append((prev, size - prev, res.source_lines[idx]))
        prev = size
    return res, pieces
