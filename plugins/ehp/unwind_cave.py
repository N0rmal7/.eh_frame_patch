"""Locate addresses inside .eh_frame that can be safely overwritten.

Why the old "trailing padding only" search finds nothing
--------------------------------------------------------
A modern `.eh_frame` ends with a 4-byte ZERO terminator that is almost always
the last thing in the section, so "bytes after the terminator" is 0.  The real
slack lives *inside* records, at the end of their instruction streams:

* FDE/CIE instruction streams are padded with ``DW_CFA_nop`` (0x00) so that the
  next record starts aligned.  ``readelf --debug-dump=frames`` prints these as
  ``DW_CFA_nop`` lines; they carry no information.
* Those zeros look like free space but they are *inside* a live record: writing
  there corrupts that record's length/structure and breaks unwinding for the
  function it describes.

So "safe" is a spectrum, and this module ranks candidates by actual
consequence rather than by byte value:

Level 0  FREE_TAIL      bytes after the ZERO terminator            (best)
Level 1  DEAD_RECORD    a whole record that no longer describes a
                        real function (its pc_range is 0 or points
                        outside any executable segment)
Level 2  PADDING        trailing DW_CFA_nop run of one record      (loses
                        only that record's *tail padding*; the record still
                        parses if the writer keeps the length prefix intact)
Level 3  RECORD_END     last N bytes of a record's instruction stream

Only levels 0-2 are offered by default; level 3 requires the caller to ask for
it explicitly.
"""

from __future__ import annotations

#: 0x00 is DW_CFA_nop in the .eh_frame compact instruction encoding.
DW_CFA_NOP = 0x00

#: DW_EH_PE_* values that mean "this field is a fixed absolute/relative value"
#: (as opposed to an indirect/omitted pointer).  Used to sanity-check pc_begin.
_DW_EH_PE_ABSPTR = 0x00
_DW_EH_PE_UDATA4 = 0x03
_DW_EH_PE_SDATA4 = 0x0B
_DW_EH_PE_OPCODE_MASK = 0x0F
_DW_EH_PE_OMIT = 0xFF


class Candidate(object):
    """One proposed overwrite site."""

    FREE_TAIL = 0
    DEAD_RECORD = 1
    PADDING = 2
    RECORD_END = 3

    __slots__ = ("ea", "size", "level", "note", "record_off")

    def __init__(self, ea, size, level, note, record_off=None):
        self.ea = ea
        self.size = size
        self.level = level
        self.note = note
        self.record_off = record_off

    @property
    def level_name(self):
        return {
            self.FREE_TAIL: "free-tail",
            self.DEAD_RECORD: "dead-record",
            self.PADDING: "record-padding",
            self.RECORD_END: "record-end",
        }[self.level]

    def __repr__(self):
        return "<Candidate %#x+%d %s %s>" % (
            self.ea,
            self.size,
            self.level_name,
            self.note,
        )


def _records(data):
    """Walk .eh_frame and yield (offset, header_len, length, body) tuples.

    ``length`` is the record length field (excluding itself).  A record whose
    length is 0 marks the terminator; it is yielded with header_len 0 so the
    caller can see where it is.
    """
    pos = 0
    while pos + 4 <= len(data):
        length = int.from_bytes(data[pos : pos + 4], "little")
        if length == 0:
            yield (pos, 0, 0, b"")
            return
        header = 4
        if length == 0xFFFFFFFF:
            if pos + 12 > len(data):
                return
            length = int.from_bytes(data[pos + 4 : pos + 12], "little")
            header = 12
        end = pos + header + length
        if length < 4 or end > len(data):
            return
        yield (pos, header, length, data[pos + header : end])
        pos = end


def _trailing_nops(body):
    """Number of DW_CFA_nop bytes at the end of an instruction stream."""
    n = 0
    for byte in reversed(body):
        if byte == DW_CFA_NOP:
            n += 1
        else:
            break
    return n


def _fde_pc(body, body_ea):
    """Return (pc_begin, pc_range) of an FDE, or None for a CIE.

    ``pc_begin`` in .eh_frame is a *signed* offset relative to the address of
    the ``pc_begin`` field itself (DW_EH_PE_pcrel|sdata4 for gcc/clang on
    x86-64), NOT an absolute address.  Reading it unsigned silently produces
    huge bogus values, which is why this helper takes ``body_ea``.
    """
    if len(body) < 12:
        return None
    cie_ptr = int.from_bytes(body[0:4], "little")
    if cie_ptr == 0:
        return None  # CIE, not an FDE
    pc_begin_field_ea = body_ea + 4
    rel = int.from_bytes(body[4:8], "little", signed=True)
    pc_begin = (pc_begin_field_ea + rel) & 0xFFFFFFFFFFFFFFFF
    pc_range = int.from_bytes(body[8:12], "little")
    return pc_begin, pc_range


def find_candidates(data, base_ea, is_pc_live=None, max_size=256, min_size=8):
    """Return candidates sorted best-first.

    :param data: the raw .eh_frame bytes.
    :param base_ea: virtual address of ``data[0]``.
    :param is_pc_live: ``callable(pc_begin, pc_range) -> bool`` telling whether
        an FDE still describes a real function.  When omitted, every FDE is
        assumed live (conservative).
    :param max_size: ignore candidates larger than this (a huge "cave" is
        usually a parse artifact, and the caller rarely needs it).
    :param min_size: ignore candidates smaller than this.

    Levels, best first:

    0 (FREE_TAIL)   bytes after the ZERO terminator.  Overwriting them costs
                    nothing.
    1 (DEAD_RECORD) a record whose FDE no longer describes a live function.
                    Overwriting the whole record costs nothing.
    2 (PADDING)     the trailing ``DW_CFA_nop`` run of one live FDE.  Costs
                    that FDE's tail padding only; the record still parses.
    3 (RECORD_END)  the tail of a live FDE's instruction stream.  Costs that
                    function's unwinding.
    """
    out = []

    # ---- walk records; remember where each one lives -------------------
    records = []
    terminator_off = None
    last_end = 0
    for (off, header, length, body) in _records(data):
        if header == 0:
            terminator_off = off
            break
        records.append((off, header, length, body))
        last_end = off + header + length

    # ---- level 0: everything after the ZERO terminator ------------------
    if terminator_off is not None:
        tail_start = terminator_off + 4
        tail_len = len(data) - tail_start
        if tail_len >= min_size:
            out.append(
                Candidate(
                    base_ea + tail_start,
                    min(tail_len, max_size),
                    Candidate.FREE_TAIL,
                    "%d byte(s) after the ZERO terminator" % tail_len,
                )
            )
    else:
        tail_len = len(data) - last_end
        if tail_len >= min_size:
            out.append(
                Candidate(
                    base_ea + last_end,
                    min(tail_len, max_size),
                    Candidate.FREE_TAIL,
                    "%d unused byte(s) after the last record" % tail_len,
                )
            )

    # ---- per-record candidates -----------------------------------------
    for (off, header, length, body) in records:
        rng = _fde_pc(body, base_ea + off + header)
        live = True
        if rng is not None and is_pc_live is not None:
            live = is_pc_live(rng[0], rng[1])

        if not live:
            out.append(
                Candidate(
                    base_ea + off,
                    min(header + length, max_size),
                    Candidate.DEAD_RECORD,
                    "FDE no longer describes a live function (pc=%#x range=%#x)"
                    % rng,
                    off,
                )
            )
            continue

        nops = _trailing_nops(body)
        if nops >= min_size:
            out.append(
                Candidate(
                    base_ea + off + header + length - nops,
                    min(nops, max_size),
                    Candidate.PADDING,
                    "%d trailing DW_CFA_nop byte(s) of one FDE" % nops,
                    off,
                )
            )
        elif length >= min_size:
            out.append(
                Candidate(
                    base_ea + off + header,
                    min(length, max_size),
                    Candidate.RECORD_END,
                    "tail of a live FDE (breaks this function's unwinding)",
                    off,
                )
            )

    out.sort(key=lambda c: (c.level, -c.size))
    return out


def find_merged_padding(data, base_ea, want=0, min_size=8, max_size=256):
    """Spans that merge padding across adjacent records.

    A single FDE often has only a handful of ``DW_CFA_nop`` bytes, but several
    padded records usually sit back-to-back, separated only by the next
    record's *header*::

        [ 11 x DW_CFA_nop ][ next FDE header 12B ][ 11 x DW_CFA_nop ] ...

    There is no run of ``min_size`` contiguous zeros in such a layout, yet
    writing from the start of one padding run to the end of the next is
    perfectly feasible -- it simply costs the FDEs that get covered.

    ``want`` is the number of bytes the caller needs.  When it is non-zero the
    span stops growing as soon as it is large enough, so the collateral damage
    is kept to the minimum number of records.  Without ``want`` the spans grow
    as far as possible (useful for "how much room is there at worst").

    These spans are reported at level 3: the caller must accept losing the
    unwind info of the covered records.
    """
    records = []
    for (off, header, length, body) in _records(data):
        if header == 0:
            break
        records.append((off, header, length, body))

    spans = []
    n_rec = len(records)
    for i in range(n_rec):
        off, header, length, body = records[i]
        nops = _trailing_nops(body)
        if nops == 0:
            continue
        start = off + header + length - nops
        end = off + header + length
        covered = 1
        j = i + 1
        while j < n_rec:
            if want and (end - start) >= want:
                break
            noff, nheader, nlength, nbody = records[j]
            if noff != end:
                break
            next_nops = _trailing_nops(nbody)
            if next_nops == 0:
                break
            end = noff + nheader + nlength
            covered += 1
            j += 1
        size = end - start
        if size >= max(min_size, want or 0):
            spans.append(
                Candidate(
                    base_ea + start,
                    min(size, max_size),
                    Candidate.RECORD_END,
                    "%d byte(s) of merged padding covering %d unwind record(s); "
                    "those FDEs lose their unwind info" % (size, covered),
                )
            )
    spans.sort(key=lambda c: (-c.size, c.ea))
    return spans


def best_candidate(data, base_ea, is_pc_live=None, max_level=2, min_size=8):
    """First candidate at or below *max_level*, or None."""
    for cand in find_candidates(data, base_ea, is_pc_live, min_size=min_size):
        if cand.level <= max_level:
            return cand
    return None
