"""16-byte aligned writable heads inside .eh_frame.

The user's rule of thumb: "start writing at a 16-byte aligned address; as long
as the space up to the end of the section is big enough, the write itself will
not fail".  That is correct as far as *mechanical* feasibility goes, so this
module enumerates exactly those heads and reports, for each one, how many bytes
are available before the .eh_frame ZERO terminator.

It also reports what a write at that head would damage, because "does not fail"
is not the same as "does not affect the program": covering a CIE invalidates
every FDE that references it, and covering an FDE kills that function's unwind
info.

Nothing here writes to the database; it only computes.
"""

from __future__ import annotations

#: .eh_frame records are padded so that the next record starts on a 4- or
#: 8-byte boundary, but 16 is the alignment the user asked for and is also the
#: natural boundary for a code stub.
ALIGN = 16

#: keep this many bytes at the end: the ZERO terminator glibc walks at startup
TERMINATOR_SIZE = 4

#: do not report heads with less room than this; a stub rarely fits below it
MIN_ROOM = 16


class WritableHead(object):
    """One 16-byte aligned candidate inside .eh_frame."""

    __slots__ = ("ea", "room", "records", "note")

    def __init__(self, ea, room, records=None, note=""):
        self.ea = ea
        self.room = room
        #: list of (record_ea, length, kind, pc, is_live) the write would cover
        self.records = records or []
        self.note = note

    def __repr__(self):
        return "<WritableHead %#x room=%d covers=%d>" % (
            self.ea,
            self.room,
            len(self.records),
        )


def _iter_records(data):
    """Yield (offset, header_len, length, body) for every record."""
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


def find_terminator(data):
    """Byte offset of the ZERO terminator, or None."""
    for (off, header, length, body) in _iter_records(data):
        if header == 0:
            return off
    return None


def _record_kind(body, body_ea):
    """Return (kind, pc) where kind is 'CIE' or 'FDE'."""
    if len(body) < 4:
        return ("?", 0)
    cie_ptr = int.from_bytes(body[0:4], "little")
    if cie_ptr == 0:
        return ("CIE", 0)
    if len(body) < 12:
        return ("FDE", 0)
    # pc_begin is a signed pcrel offset from the field itself
    rel = int.from_bytes(body[4:8], "little", signed=True)
    pc = (body_ea + 4 + rel) & 0xFFFFFFFFFFFFFFFF
    return ("FDE", pc)


def find_writable_heads(data, base_ea, align=ALIGN, min_room=MIN_ROOM,
                        is_pc_live=None, keep_terminator=True):
    """Enumerate 16-byte aligned heads and what each would cover.

    :param data: raw .eh_frame bytes
    :param base_ea: virtual address of data[0]
    :param align: alignment of the reported heads (default 16)
    :param min_room: skip heads with less usable room than this
    :param is_pc_live: optional ``callable(pc) -> bool`` used only for the note
    :param keep_terminator: leave the ZERO terminator untouched (recommended)
    :returns: list of :class:`WritableHead`, sorted by head address
    """
    term = find_terminator(data)
    limit = (term if (keep_terminator and term is not None) else len(data))
    if limit <= 0:
        return []

    # records, for the "what would I damage" note
    recs = []
    for (off, header, length, body) in _iter_records(data):
        if header == 0:
            break
        kind, pc = _record_kind(body, base_ea + off + header)
        recs.append((off, off + header + length, kind, pc))

    heads = []
    first = (base_ea + align - 1) & ~(align - 1)
    ea = first
    while ea + min_room <= base_ea + limit:
        off = ea - base_ea
        room = limit - off
        covered = []
        for (r_off, r_end, kind, pc) in recs:
            if r_off < off + room and r_end > off:
                live = True
                if kind == "FDE" and is_pc_live is not None:
                    live = is_pc_live(pc)
                covered.append((base_ea + r_off, r_end - r_off, kind, pc, live))
        heads.append(WritableHead(ea, room, covered))
        ea += align
    return heads


def describe(head):
    """One-line human summary of a head."""
    if not head.records:
        return "%#x  %d bytes  (no record affected)" % (head.ea, head.room)
    cies = sum(1 for r in head.records if r[2] == "CIE")
    fdes = sum(1 for r in head.records if r[2] == "FDE")
    dead = sum(1 for r in head.records if r[2] == "FDE" and not r[4])
    parts = []
    if cies:
        parts.append("%d CIE" % cies)
    if fdes:
        parts.append("%d FDE" % fdes)
    if dead:
        parts.append("%d already-dead FDE" % dead)
    return "%#x  %4d bytes  covers %s" % (
        head.ea,
        head.room,
        ", ".join(parts) if parts else "nothing",
    )
