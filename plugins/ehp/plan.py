"""Patch planning: budget, segment and cross-segment validation.

The planner is intentionally IDA agnostic.  It talks to a *memory map* object
that answers three questions:

``is_mapped(ea)``            -> bool
``segment_at(ea)``           -> Segment | None
``read(ea, size)``           -> bytes | None

``Segment`` is a small value object with ``name``, ``start``, ``end``,
``perm`` (bitmask, see :class:`SegPerm`) and ``is_code``.

The IDA side implements the same protocol in ``eh_frame_patch.py``; the test
suite implements it on top of :mod:`ehp.elf_image`.
"""

from __future__ import annotations

from typing import List, Optional

from .asm_engine import assemble

X86_NOP = 0x90


class SegPerm(object):
    """Permission bits, mirroring IDA's SEGPERM_* values."""

    EXEC = 1
    WRITE = 2
    READ = 4

    @classmethod
    def text(cls, perm):
        if perm is None:
            return "?"
        out = ""
        out += "R" if perm & cls.READ else "-"
        out += "W" if perm & cls.WRITE else "-"
        out += "X" if perm & cls.EXEC else "-"
        return out


class Segment(object):
    __slots__ = ("name", "start", "end", "perm", "is_code", "class_name")

    def __init__(self, name, start, end, perm, is_code=False, class_name=""):
        self.name = name
        self.start = start
        self.end = end
        self.perm = perm
        self.is_code = is_code
        self.class_name = class_name

    @property
    def size(self):
        return max(0, self.end - self.start)

    def __repr__(self):  # pragma: no cover - debug helper
        return "<Segment %s %#x-%#x %s>" % (
            self.name,
            self.start,
            self.end,
            SegPerm.text(self.perm),
        )


class Check(object):
    """One validation result."""

    OK = "ok"
    WARN = "warn"
    ERROR = "error"

    __slots__ = ("level", "text")

    def __init__(self, level, text):
        self.level = level
        self.text = text

    def __repr__(self):  # pragma: no cover
        return "<%s %s>" % (self.level, self.text)


class Plan(object):
    """Everything the UI needs to show about a pending patch."""

    def __init__(self):
        self.ea = 0
        self.bits = 64
        self.budget = 0
        self.source = ""
        self.segment = None
        self.orig_bytes = b""
        self.code = b""
        self.padded = b""
        self.size = 0
        self.pad_len = 0
        self.checks = []  # type: List[Check]
        self.asm = None
        self.pieces = []
        self.targets = []
        self.cross_segment = False
        self.entry = 0
        self.return_ea = None

    # -- convenience ----------------------------------------------------
    def add(self, level, text):
        self.checks.append(Check(level, text))

    @property
    def errors(self):
        return [c for c in self.checks if c.level == Check.ERROR]

    @property
    def warnings(self):
        return [c for c in self.checks if c.level == Check.WARN]

    @property
    def ok(self):
        return not self.errors

    def summary(self):
        return "\n".join(
            {Check.OK: "[ok]   ", Check.WARN: "[warn] ", Check.ERROR: "[error]"}[c.level]
            + " "
            + c.text
            for c in self.checks
        )


def build_plan(
    mem,
    ea,
    source,
    bits=64,
    budget=None,
    resolve=None,
    nop_pad=False,
    require_exec=False,
    allow_cross_segment=False,
    entry=None,
    return_ea=None,
):
    """Assemble *source* at *ea* and validate it against the memory map."""
    plan = Plan()
    plan.ea = ea
    plan.bits = bits
    plan.source = source
    plan.entry = ea if entry is None else entry
    plan.return_ea = return_ea

    seg = mem.segment_at(ea)
    plan.segment = seg
    if seg is None:
        plan.add(Check.ERROR, "address 0x%X is not mapped in the database" % ea)
        return plan

    if not mem.is_mapped(ea):
        plan.add(Check.ERROR, "address 0x%X is not mapped" % ea)
        return plan

    # Budget: default to "rest of the segment", which is what a user means by
    # "how much room do I have here".
    if budget is None:
        budget = seg.end - ea
    if budget <= 0:
        plan.add(Check.ERROR, "no room at 0x%X (budget is %d byte(s))" % (ea, budget))
        return plan
    if nop_pad and budget > 1024 * 1024:
        plan.add(Check.ERROR, "NOP padding budget exceeds 1 MiB; select a smaller range")
        return plan
    plan.budget = budget

    # --- assemble -------------------------------------------------------
    res = assemble(source, ea, bits=bits, resolve=resolve)
    plan.asm = res
    plan.targets = list(res.targets)
    if not res.ok:
        for line in res.errors:
            plan.add(Check.ERROR, line)
        return plan
    plan.code = res.code
    plan.size = res.size
    plan.pieces = res.pieces
    plan.labels = res.labels

    # --- budget check ---------------------------------------------------
    if plan.size > budget:
        plan.add(
            Check.ERROR,
            "assembled code is %d byte(s) but only %d byte(s) fit at 0x%X "
            "(over by %d)" % (plan.size, budget, ea, plan.size - budget),
        )

    # --- cross segment check -------------------------------------------
    end = ea + plan.size
    limit = ea + budget
    if end > seg.end:
        plan.cross_segment = True
        nxt = mem.segment_at(seg.end)
        if not allow_cross_segment:
            plan.add(
                Check.ERROR,
                "code crosses the end of %s (0x%X > 0x%X); move the stub or "
                "allow crossing explicitly" % (seg.name, end, seg.end),
            )
        else:
            plan.add(
                Check.WARN,
                "code crosses %s boundary into %s (0x%X > 0x%X)"
                % (
                    seg.name,
                    nxt.name if nxt else "<unmapped>",
                    end,
                    seg.end,
                ),
            )
    if limit > seg.end and not plan.cross_segment:
        # Budget was clamped by the caller to something larger than the segment.
        plan.add(
            Check.WARN,
            "budget %d byte(s) reaches past the end of %s, clamping to %d"
            % (budget, seg.name, seg.end - ea),
        )
        plan.budget = seg.end - ea
        budget = plan.budget

    # --- NOP padding ----------------------------------------------------
    plan.padded = plan.code
    if nop_pad and plan.size < budget and plan.ok:
        plan.pad_len = budget - plan.size
        plan.padded = plan.code + bytes([X86_NOP]) * plan.pad_len

    # --- original bytes -------------------------------------------------
    read_len = min(len(plan.padded) if plan.padded else plan.size, budget)
    plan.orig_bytes = mem.read(ea, read_len)
    if plan.orig_bytes is None or len(plan.orig_bytes) != read_len:
        plan.orig_bytes = b""
        plan.add(Check.ERROR, "cannot read the complete patch range")
    if not all(mem.is_mapped(addr) for addr in range(ea, ea + read_len)):
        plan.add(Check.ERROR, "patch range contains unmapped bytes")

    # --- informational checks ------------------------------------------
    if seg.is_code:
        plan.add(Check.OK, "target %s is a code segment" % seg.name)
    else:
        plan.add(
            Check.WARN,
            "target %s is a DATA segment: IDA will not disassemble it by "
            "default, but bytes are still patchable" % seg.name,
        )
    if not (seg.perm & SegPerm.EXEC):
        plan.add(
            Check.WARN,
            "%s has no execute permission in IDA (perm=%s); whether the CPU "
            "may run this code depends on the ELF PT_LOAD flags, see the "
            "ELF section of the report" % (seg.name, SegPerm.text(seg.perm)),
        )
    if require_exec and not (seg.perm & SegPerm.EXEC):
        plan.add(Check.ERROR, "execute permission required but not present")

    if seg.name == ".eh_frame":
        plan.add(
            Check.WARN,
            "the bytes you are about to overwrite may be live .eh_frame "
            "unwind data; damaged CIE/FDE data can break unwinding/backtraces and "
            "can crash a C++ program that throws through this frame",
        )

    # --- branch targets -------------------------------------------------
    for tgt in plan.targets:
        tseg = mem.segment_at(tgt)
        if tseg is None:
            plan.add(Check.ERROR, "branch target 0x%X is not mapped" % tgt)
        elif not (tseg.perm & SegPerm.EXEC):
            plan.add(
                Check.WARN,
                "branch target 0x%X lies in %s which is not executable in IDA"
                % (tgt, tseg.name),
            )
        else:
            plan.add(Check.OK, "branch target 0x%X -> %s" % (tgt, tseg.name))

    if plan.return_ea is not None:
        rseg = mem.segment_at(plan.return_ea)
        if rseg is None:
            plan.add(Check.ERROR, "return address 0x%X is not mapped" % plan.return_ea)
        else:
            plan.add(
                Check.OK,
                "declared return address 0x%X (%s); not control-flow verified" % (plan.return_ea, rseg.name),
            )

    if plan.ok and plan.padded:
        plan.add(
            Check.OK,
            "%d byte(s) of code, %d byte(s) NOP padding, %d byte(s) total"
            % (plan.size, plan.pad_len, len(plan.padded)),
        )
    return plan


def instruction_map(plan):
    """Human readable listing of the stub, used by the preview pane."""
    if plan.asm is None or not plan.asm.ok:
        return []
    rows = []
    for off, length, line in plan.pieces:
        rows.append((plan.ea + off, length, line.strip()))
    return rows
