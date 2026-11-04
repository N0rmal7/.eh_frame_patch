"""Plan / budget / segment tests driven by the real sample binaries.

These tests do **not** need IDA: they build a memory map out of
``ehp.elf_image`` and exercise exactly the same ``ehp.plan.build_plan`` code the
plugin calls inside IDA.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _path  # noqa
from ehp import elf_image
from ehp.plan import SegPerm, Segment, build_plan, Check

ROOT = _path.ROOT
SAMPLES = os.path.join(ROOT, "samples")


class ElfMemory(object):
    """Memory map protocol backed by an ELF file."""

    def __init__(self, path, eh_frame_exec=False):
        self.img = elf_image.ElfImage.from_file(path)
        if eh_frame_exec:
            self.img.set_exec_flag(self.img.section(".eh_frame").addr, True)

    def is_mapped(self, ea):
        return self.img.load_at(ea) is not None

    def segment_at(self, ea):
        sec = self._section_at(ea)
        if sec is not None:
            load = self.img.load_at(sec.addr)
            perm = 0
            if load is not None:
                if load.flags & elf_image.PF_R:
                    perm |= SegPerm.READ
                if load.flags & elf_image.PF_W:
                    perm |= SegPerm.WRITE
                if load.flags & elf_image.PF_X:
                    perm |= SegPerm.EXEC
            is_code = bool(sec.flags & elf_image.SHF_EXECINSTR)
            return Segment(sec.name, sec.addr, sec.addr + sec.size, perm, is_code)
        load = self.img.load_at(ea)
        if load is None:
            return None
        perm = 0
        if load.flags & elf_image.PF_R:
            perm |= SegPerm.READ
        if load.flags & elf_image.PF_W:
            perm |= SegPerm.WRITE
        if load.flags & elf_image.PF_X:
            perm |= SegPerm.EXEC
        return Segment("<load%d>" % load.index, load.vaddr, load.end_vaddr, perm, False)

    def _section_at(self, ea):
        for sec in self.img.sections:
            if sec.size and sec.addr <= ea < sec.addr + sec.size:
                return sec
        return None

    def read(self, ea, size):
        return self.img.read(ea, size) or b""

    def resolve_symbol(self, name):
        return None


class Plan64(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(SAMPLES, "uaf_demo64")
        if not os.path.exists(self.path):
            self.skipTest("sample missing: %s" % self.path)
        self.mem = ElfMemory(self.path)
        self.eh = self.mem.img.section(".eh_frame")
        self.text = self.mem.img.section(".text")

    def test_eh_frame_is_data_and_not_executable(self):
        seg = self.mem.segment_at(self.eh.addr)
        self.assertEqual(seg.name, ".eh_frame")
        self.assertFalse(seg.is_code)
        self.assertFalse(seg.perm & SegPerm.EXEC)

    def test_stub_into_eh_frame(self):
        src = "mov qword ptr [rbp-0x8], 0\njmp 0x1200"
        plan = build_plan(self.mem, self.eh.addr, src, bits=64, budget=32)
        self.assertTrue(plan.ok, plan.summary())
        self.assertEqual(plan.size, 13)
        self.assertEqual(plan.pad_len, 0)  # NOP padding is opt-in
        self.assertEqual(plan.padded, plan.code)
        texts = [c.text for c in plan.warnings]
        self.assertTrue(any("DATA segment" in t for t in texts))
        self.assertTrue(any("no execute permission" in t for t in texts))

    def test_overlong_rejected(self):
        src = "nop\n" * 40
        plan = build_plan(self.mem, self.eh.addr, src, bits=64, budget=16)
        self.assertFalse(plan.ok)
        self.assertTrue(any("only 16 byte(s) fit" in c.text for c in plan.errors))

    def test_nop_padding(self):
        plan = build_plan(self.mem, self.eh.addr, "nop\nnop", bits=64, budget=8, nop_pad=True)
        self.assertTrue(plan.ok, plan.summary())
        self.assertEqual(len(plan.padded), 8)
        self.assertEqual(plan.padded[:2], b"\x90\x90")
        self.assertEqual(plan.padded[2:], b"\x90" * 6)
        self.assertEqual(plan.pad_len, 6)

    def test_cross_segment_rejected(self):
        end = self.eh.addr + self.eh.size
        plan = build_plan(self.mem, end - 2, "mov rax, 1\nret", bits=64, budget=64)
        self.assertFalse(plan.ok)
        self.assertTrue(any("crosses the end" in c.text for c in plan.errors))

    def test_cross_segment_allowed(self):
        end = self.eh.addr + self.eh.size
        plan = build_plan(
            self.mem, end - 2, "mov rax, 1\nret", bits=64, budget=64, allow_cross_segment=True
        )
        self.assertFalse(plan.ok, plan.summary())  # crossing cannot permit an unmapped hole
        self.assertTrue(any("crosses" in c.text for c in plan.warnings))

    def test_orig_bytes_shown(self):
        # Without padding only the bytes actually written are reported.
        plan = build_plan(self.mem, self.eh.addr, "nop", bits=64, budget=4)
        self.assertEqual(len(plan.orig_bytes), 1)
        self.assertEqual(plan.orig_bytes, self.mem.img.read(self.eh.addr, 1))
        plan = build_plan(self.mem, self.eh.addr, "nop", bits=64, budget=4, nop_pad=True)
        self.assertEqual(len(plan.orig_bytes), 4)
        self.assertEqual(plan.orig_bytes, self.mem.img.read(self.eh.addr, 4))

    def test_unmapped_target(self):
        plan = build_plan(self.mem, 0xDEAD0000, "nop", bits=64, budget=4)
        self.assertFalse(plan.ok)
        self.assertTrue(any("not mapped" in c.text for c in plan.errors))

    def test_branch_target_validation(self):
        plan = build_plan(self.mem, self.eh.addr, "jmp 0xDEAD0000", bits=64, budget=16)
        self.assertFalse(plan.ok)
        self.assertTrue(any("branch target" in c.text and "not mapped" in c.text
                            for c in plan.errors))

    def test_return_address_check(self):
        ret = self.text.addr + 0x10
        plan = build_plan(self.mem, self.eh.addr, "ret", bits=64, budget=4, return_ea=ret)
        self.assertTrue(plan.ok, plan.summary())
        self.assertTrue(any("declared return address" in c.text for c in plan.checks))

    def test_require_exec(self):
        plan = build_plan(
            self.mem, self.eh.addr, "ret", bits=64, budget=4, require_exec=True
        )
        self.assertFalse(plan.ok)


class Plan32(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(SAMPLES, "uaf_demo32")
        if not os.path.exists(self.path):
            self.skipTest("sample missing: %s" % self.path)
        self.mem = ElfMemory(self.path)
        self.eh = self.mem.img.section(".eh_frame")

    def test_bits32_stub(self):
        plan = build_plan(self.mem, self.eh.addr, "mov dword ptr [ebp-4], 0\njmp 0x8049000",
                          bits=32, budget=32)
        # 0x8049000 is not mapped in a PIE, so only check the encoding part
        self.assertEqual(plan.size, 12)
        self.assertTrue(any("branch target" in c.text for c in plan.errors))

    def test_bits32_ok(self):
        text = self.mem.img.section(".text")
        target = text.addr + 8
        plan = build_plan(self.mem, self.eh.addr,
                          "mov dword ptr [ebp-4], 0\njmp 0x%X" % target, bits=32, budget=32)
        self.assertTrue(plan.ok, plan.summary())
        self.assertEqual(plan.size, 12)


if __name__ == "__main__":
    unittest.main(verbosity=2)
