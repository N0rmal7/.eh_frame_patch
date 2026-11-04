import os
import struct
import tempfile
import unittest
from pathlib import Path
import _path
from ehp import asm_engine, elf_image
from ehp.plan import Segment, build_plan

SAMPLE = os.path.join(_path.ROOT, 'samples', 'uaf_demo64')

class RegressionTests(unittest.TestCase):
    def test_source_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'source')
            original = Path(SAMPLE).read_bytes()
            with open(path, 'wb') as f: f.write(original)
            with self.assertRaises(elf_image.ElfError):
                elf_image.clone_with_patches(path, path, [])
            self.assertEqual(Path(path).read_bytes(), original)

    def test_symlink_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, 'src'), os.path.join(d, 'link')
            with open(src, 'wb') as f: f.write(Path(SAMPLE).read_bytes())
            try: os.symlink(src, dst)
            except OSError: self.skipTest('symlink privilege unavailable')
            with self.assertRaises(elf_image.ElfError):
                elf_image.clone_with_patches(src, dst, [])

    def test_bss_crossing_patch_rejected(self):
        img = elf_image.ElfImage.from_file(SAMPLE)
        seg = next(s for s in img.loads if s.memsz > s.filesz)
        end = seg.vaddr + seg.filesz
        with self.assertRaises(elf_image.ElfError): img.patch(end-1, b'XX')
        self.assertIsNone(img.read(end-1, 2))

    def test_small_program_header_rejected(self):
        data = bytearray(Path(SAMPLE).read_bytes())
        struct.pack_into('<H', data, 54, 1)
        with self.assertRaises(elf_image.ElfError): elf_image.ElfImage(data)

    def test_truncated_program_table_rejected(self):
        data = bytearray(Path(SAMPLE).read_bytes())
        struct.pack_into('<Q', data, 32, len(data)-1)
        with self.assertRaises(elf_image.ElfError): elf_image.ElfImage(data)

    def test_file_offset_roundtrip(self):
        img = elf_image.ElfImage.from_file(SAMPLE)
        for seg in img.loads:
            self.assertEqual(img.offset_to_vaddr(seg.offset), seg.vaddr)

    def test_mode_preserved(self):
        if os.name == 'nt': self.skipTest('POSIX mode only')
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, 'src'), os.path.join(d, 'dst')
            with open(src, 'wb') as f: f.write(Path(SAMPLE).read_bytes())
            os.chmod(src, 0o751)
            elf_image.clone_with_patches(src,dst,[])
            self.assertEqual(os.stat(dst).st_mode & 0o777, 0o751)

    def test_live_unwind_tail_not_padding(self):
        # A valid record payload full of zeroes is still live.
        self.assertIsNone(elf_image.find_unwind_padding(struct.pack('<I',68)+bytes(68)+bytes(4)))

    def test_padding_after_terminator(self):
        self.assertEqual(elf_image.find_unwind_padding(struct.pack('<I',8)+bytes(8)+bytes(4)+bytes(16)), (16,16))

    def test_malformed_unwind_not_padding(self):
        self.assertIsNone(elf_image.find_unwind_padding(struct.pack('<I',1000)+bytes(64)))

    def test_tab_directive(self):
        self.assertEqual(asm_engine.assemble('db\t0x90',0x1000).code,b'\x90')

    def test_numeric_tokens_not_resolved(self):
        res = asm_engine.assemble('mov eax, 0x10',0x1000, resolve=lambda n: 99 if n=='x10' else None)
        self.assertEqual(res.code,bytes.fromhex('b810000000'))

    def test_resolved_branch_target(self):
        res = asm_engine.assemble('jmp missing_segment',0x1000,resolve=lambda n: 0x4000)
        self.assertTrue(res.ok,res.errors)
        self.assertEqual(res.targets,[0x4000])

    def test_read_failure_rejected(self):
        class Mem:
            def segment_at(self,ea): return Segment('.eh_frame',0x1000,0x2000,4)
            def is_mapped(self,ea): return True
            def read(self,ea,size): return None
        self.assertFalse(build_plan(Mem(),0x1000,'nop',budget=8).ok)

    def test_gap_inside_range_rejected(self):
        class Mem:
            def segment_at(self,ea): return Segment('.eh_frame',0x1000,0x2000,4)
            def is_mapped(self,ea): return ea != 0x1001
            def read(self,ea,size): return bytes(size)
        self.assertFalse(build_plan(Mem(),0x1000,'nop\nnop\nnop',budget=8).ok)

    def test_huge_nop_budget_rejected(self):
        class Mem:
            def segment_at(self,ea): return Segment('.data',0,1<<40,4)
            def is_mapped(self,ea): return True
        plan=build_plan(Mem(),0x1000,'nop',budget=1<<32,nop_pad=True)
        self.assertFalse(plan.ok)
