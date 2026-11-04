"""Minimal dependency free ELF32/ELF64 reader and patched-copy writer.

Only what the plugin needs:

* enumerate PT_LOAD segments with their **file** permissions (the thing that
  actually decides whether the CPU may execute .eh_frame),
* map virtual addresses <-> file offsets through PT_LOAD,
* write a patched *copy* of the file (never the original),
* optionally flip the PF_X flag of the PT_LOAD that contains a given address,
  which is the "make .eh_frame executable" export feature.

Everything is pure ``struct`` work so it can run in IDA's bundled Python as
well as in a normal CPython.
"""

from __future__ import annotations

import os
import struct
import tempfile
import stat
from typing import List, Optional, Tuple

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551

SHT_NOBITS = 8
SHT_PROGBITS = 1

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


class ElfError(Exception):
    pass


class LoadSegment(object):
    """A PT_LOAD entry."""

    __slots__ = (
        "index",
        "phoff",
        "offset",
        "vaddr",
        "paddr",
        "filesz",
        "memsz",
        "flags",
        "align",
    )

    def __init__(self, index, phoff, offset, vaddr, paddr, filesz, memsz, flags, align):
        self.index = index
        self.phoff = phoff
        self.offset = offset
        self.vaddr = vaddr
        self.paddr = paddr
        self.filesz = filesz
        self.memsz = memsz
        self.flags = flags
        self.align = align

    @property
    def end_vaddr(self):
        return self.vaddr + self.memsz

    @property
    def perm(self):
        return self.flags

    @property
    def perm_text(self):
        return "%s%s%s" % (
            "R" if self.flags & PF_R else "-",
            "W" if self.flags & PF_W else "-",
            "X" if self.flags & PF_X else "-",
        )

    def contains(self, vaddr, size=1):
        return self.vaddr <= vaddr and vaddr + size <= self.end_vaddr

    def __repr__(self):  # pragma: no cover
        return "<PT_LOAD #%d %#x-%#x %s>" % (
            self.index,
            self.vaddr,
            self.end_vaddr,
            self.perm_text,
        )


class Section(object):
    __slots__ = ("index", "name", "type", "flags", "addr", "offset", "size", "entsize")

    def __init__(self, index, name, type_, flags, addr, offset, size, entsize):
        self.index = index
        self.name = name
        self.type = type_
        self.flags = flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.entsize = entsize

    def __repr__(self):  # pragma: no cover
        return "<Section %s %#x+%#x>" % (self.name, self.addr, self.size)


class ElfImage(object):
    """Parsed ELF file kept in memory (bytearray so patches are cheap)."""

    def __init__(self, data, path=None):
        self.path = path
        self.data = bytearray(data)
        self.is64 = False
        self.endian = "<"
        self.e_type = 0
        self.e_machine = 0
        self.entry = 0
        self.phoff = 0
        self.phentsize = 0
        self.phnum = 0
        self.shoff = 0
        self.shentsize = 0
        self.shnum = 0
        self.shstrndx = 0
        self.loads = []  # type: List[LoadSegment]
        self.sections = []  # type: List[Section]
        self._parse()

    # -- construction ---------------------------------------------------
    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as fh:
            data = fh.read()
        return cls(data, path=path)

    # -- parsing --------------------------------------------------------
    def _parse(self):
        if len(self.data) < 64:
            raise ElfError("file too small to be an ELF")
        if self.data[:4] != b"\x7fELF":
            raise ElfError("not an ELF file (bad magic)")
        ei_class = self.data[4]
        ei_data = self.data[5]
        if ei_class not in (1, 2):
            raise ElfError("unsupported EI_CLASS %d" % ei_class)
        if ei_data not in (1, 2):
            raise ElfError("unsupported EI_DATA %d" % ei_data)
        self.is64 = ei_class == 2
        self.endian = "<" if ei_data == 1 else ">"
        e = self.endian

        if self.is64:
            (
                self.e_type,
                self.e_machine,
                _version,
                self.entry,
                self.phoff,
                self.shoff,
                _flags,
                _ehsize,
                self.phentsize,
                self.phnum,
                self.shentsize,
                self.shnum,
                self.shstrndx,
            ) = struct.unpack_from(e + "HHIQQQIHHHHHH", self.data, 16)
        else:
            (
                self.e_type,
                self.e_machine,
                _version,
                self.entry,
                self.phoff,
                self.shoff,
                _flags,
                _ehsize,
                self.phentsize,
                self.phnum,
                self.shentsize,
                self.shnum,
                self.shstrndx,
            ) = struct.unpack_from(e + "HHIIIIIHHHHHH", self.data, 16)

        phsize, shsize = (56, 64) if self.is64 else (32, 40)
        if self.phnum == 0xFFFF or (self.shoff and self.shnum == 0) or self.shstrndx == 0xFFFF:
            raise ElfError("extended ELF numbering is not supported")
        for name, offset, count, stride, minimum in (
            ("program", self.phoff, self.phnum, self.phentsize, phsize),
            ("section", self.shoff, self.shnum, self.shentsize, shsize),
        ):
            if count and (not offset or stride < minimum or offset + count * stride > len(self.data)):
                raise ElfError("invalid or truncated %s header table" % name)
        self._parse_phdrs()
        self._parse_shdrs()

    def _parse_phdrs(self):
        e = self.endian
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if off + self.phentsize > len(self.data):
                break
            if self.is64:
                (
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_align,
                ) = struct.unpack_from(e + "IIQQQQQQ", self.data, off)
            else:
                (
                    p_type,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    p_align,
                ) = struct.unpack_from(e + "IIIIIIII", self.data, off)
            if p_type == PT_LOAD:
                if p_filesz > p_memsz or p_offset + p_filesz > len(self.data):
                    raise ElfError("invalid PT_LOAD file/memory range")
                self.loads.append(
                    LoadSegment(
                        i, off, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
                    )
                )

    def _parse_shdrs(self):
        if not self.shoff or not self.shnum:
            return
        e = self.endian
        raw = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            if off + self.shentsize > len(self.data):
                break
            if self.is64:
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    _sh_info,
                    _sh_addralign,
                    sh_entsize,
                ) = struct.unpack_from(e + "IIQQQQIIQQ", self.data, off)
            else:
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    _sh_info,
                    _sh_addralign,
                    sh_entsize,
                ) = struct.unpack_from(e + "IIIIIIIIII", self.data, off)
            raw.append((i, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_entsize, sh_link))

        strtab = b""
        if self.shstrndx < len(raw):
            ent = raw[self.shstrndx]
            strtab = bytes(self.data[ent[5] : ent[5] + ent[6]])
        for (i, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_entsize, _link) in raw:
            name = ""
            if strtab and sh_name < len(strtab):
                end = strtab.find(b"\0", sh_name)
                if end < 0:
                    end = len(strtab)
                name = strtab[sh_name:end].decode("latin-1")
            self.sections.append(
                Section(i, name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_entsize)
            )

    # -- queries --------------------------------------------------------
    @property
    def bits(self):
        return 64 if self.is64 else 32

    def section(self, name):
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def load_at(self, vaddr):
        for seg in self.loads:
            if seg.vaddr <= vaddr < seg.end_vaddr:
                return seg
        return None

    def is_executable(self, vaddr):
        seg = self.load_at(vaddr)
        return bool(seg and seg.flags & PF_X)

    def vaddr_to_offset(self, vaddr):
        seg = self.load_at(vaddr)
        if seg is None:
            return None
        delta = vaddr - seg.vaddr
        if delta >= seg.filesz:
            return None
        return seg.offset + delta

    def offset_to_vaddr(self, offset):
        for seg in self.loads:
            if seg.offset <= offset < seg.offset + seg.filesz:
                return seg.vaddr + offset - seg.offset
        return None

    def _file_range(self, vaddr, size):
        seg = self.load_at(vaddr)
        if size < 0 or seg is None or vaddr + size > seg.vaddr + seg.filesz:
            return None
        off = seg.offset + vaddr - seg.vaddr
        return off if off + size <= len(self.data) else None

    def read(self, vaddr, size):
        off = self._file_range(vaddr, size)
        if off is None:
            return None
        if off + size > len(self.data):
            return None
        return bytes(self.data[off : off + size])

    def describe(self):
        lines = []
        lines.append(
            "ELF%d %s, machine=%d, entry=0x%X"
            % (
                self.bits,
                "LSB" if self.endian == "<" else "MSB",
                self.e_machine,
                self.entry,
            )
        )
        for seg in self.loads:
            lines.append(
                "  PT_LOAD #%d off=0x%06X vaddr=0x%08X filesz=0x%X memsz=0x%X %s"
                % (
                    seg.index,
                    seg.offset,
                    seg.vaddr,
                    seg.filesz,
                    seg.memsz,
                    seg.perm_text,
                )
            )
        return "\n".join(lines)

    # -- mutation -------------------------------------------------------
    def patch(self, vaddr, data):
        """Overwrite bytes at *vaddr* inside the in-memory image."""
        off = self._file_range(vaddr, len(data))
        if off is None:
            raise ElfError("address 0x%X is not backed by file data" % vaddr)
        if off + len(data) > len(self.data):
            raise ElfError("patch runs past end of file")
        self.data[off : off + len(data)] = data
        return off

    def set_exec_flag(self, vaddr, enable=True):
        """Set/clear PF_X on the PT_LOAD that contains *vaddr*.

        Returns the modified :class:`LoadSegment`.
        """
        seg = self.load_at(vaddr)
        if seg is None:
            raise ElfError("address 0x%X is not inside any PT_LOAD" % vaddr)
        # p_flags lives at +4 for ELF64 and at +24 for ELF32.
        flags_off = seg.phoff + (4 if self.is64 else 24)
        fmt = self.endian + "I"
        (cur,) = struct.unpack_from(fmt, self.data, flags_off)
        new = (cur | PF_X) if enable else (cur & ~PF_X & 0xFFFFFFFF)
        struct.pack_into(fmt, self.data, flags_off, new)
        seg.flags = new
        return seg

    def write(self, path, allow_in_place=False):
        """Write the image to *path*.

        Overwriting the file the image was loaded from is refused unless
        ``allow_in_place`` is true, because a silent in-place overwrite is how
        people lose their original binary.  The one legitimate in-place edit is
        flipping ``p_flags`` (adding PF_X); the caller is expected to have
        written a backup first.
        """
        path = os.fspath(path)
        same = self.path and (
            os.path.realpath(path) == os.path.realpath(self.path)
            or (os.path.exists(path) and os.path.samefile(path, self.path))
        )
        if same and not allow_in_place:
            raise ElfError("refusing to overwrite the input ELF")
        fd, tmp = tempfile.mkstemp(prefix=".ehp-", dir=os.path.dirname(os.path.abspath(path)))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(self.data)
            if self.path:
                os.chmod(tmp, stat.S_IMODE(os.stat(self.path).st_mode))
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return path


def clone_with_patches(src_path, dst_path, patches, make_exec=None):
    """Copy *src_path* to *dst_path*, apply patches, optionally add PF_X.

    :param patches: iterable of ``(vaddr, bytes)``.
    :param make_exec: virtual address whose containing PT_LOAD should get PF_X.
    :returns: (ElfImage, list of applied (vaddr, size))
    """
    img = ElfImage.from_file(src_path)
    applied = []
    for vaddr, blob in patches:
        img.patch(vaddr, blob)
        applied.append((vaddr, len(blob)))
    if make_exec is not None:
        img.set_exec_flag(make_exec, True)
    img.write(dst_path)
    return img, applied


def format_permission_report(img, vaddr, section_name=".eh_frame"):
    """Explain IDA-segment-permission vs ELF-file-permission for *vaddr*."""
    seg = img.load_at(vaddr)
    lines = []
    if seg is None:
        lines.append("0x%X is not covered by any PT_LOAD" % vaddr)
        return "\n".join(lines)
    lines.append(
        "PT_LOAD #%d contains 0x%X: vaddr=0x%X filesz=0x%X memsz=0x%X flags=%s"
        % (seg.index, vaddr, seg.vaddr, seg.filesz, seg.memsz, seg.perm_text)
    )
    if seg.flags & PF_X:
        lines.append(
            "The CPU *can* execute code at 0x%X at run time (PF_X set)." % vaddr
        )
    else:
        lines.append(
            "The CPU *cannot* execute code at 0x%X: this PT_LOAD has no PF_X.\n"
            "IDA's segment flags are only a database hint; the kernel uses the "
            "PT_LOAD flags.  Use 'Export executable copy' to produce a new "
            "binary whose %s PT_LOAD is marked executable."
            % (vaddr, section_name)
        )
    if seg.filesz != seg.memsz:
        lines.append(
            "Note: this PT_LOAD has memsz > filesz (%#x > %#x); bytes beyond "
            "filesz are zero-filled at load time and cannot be patched in the "
            "file." % (seg.memsz, seg.filesz)
        )
    return "\n".join(lines)


def find_unwind_padding(data):
    """Return unused zero bytes AFTER a valid .eh_frame terminator, or None.

    Record payloads, including zero runs inside them, are never candidates.
    The terminator itself is retained. This does not prove a global code cave.
    """
    pos = 0
    while pos + 4 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "little")
        if length == 0:
            start = pos + 4
            if len(data) - start >= 5 and not any(data[start:]):
                return start, len(data) - start
            return None
        header = 4
        if length == 0xFFFFFFFF:
            if pos + 12 > len(data):
                return None
            length = int.from_bytes(data[pos + 4:pos + 12], "little")
            header = 12
        if length < 4 or pos + header + length > len(data):
            return None
        pos += header + length
    return None
