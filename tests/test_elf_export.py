"""ELF export tests: patched copy + PF_X, verified with the real binaries.

The strong check here is behavioural: we patch a stub into .eh_frame, mark the
PT_LOAD executable, and then *run* the resulting binary.  If PF_X or the code
placement is wrong the process dies with SIGSEGV, so a successful exit plus the
expected stdout is real evidence that the trick works at run time.
"""

import os
import shutil
import struct
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _path  # noqa
from ehp import elf_image
from ehp.plan import SegPerm, build_plan
from test_plan import ElfMemory

ROOT = _path.ROOT
SAMPLES = os.path.join(ROOT, "samples")
OUT = os.path.join(ROOT, "tests", "out")


def _ensure_out():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)


class ElfReader(unittest.TestCase):
    def test_parse_64(self):
        img = elf_image.ElfImage.from_file(os.path.join(SAMPLES, "uaf_demo64"))
        self.assertTrue(img.is64)
        self.assertEqual(img.bits, 64)
        self.assertGreaterEqual(len(img.loads), 4)
        eh = img.section(".eh_frame")
        self.assertIsNotNone(eh)
        load = img.load_at(eh.addr)
        self.assertFalse(load.flags & elf_image.PF_X)
        self.assertFalse(img.is_executable(eh.addr))

    def test_parse_32(self):
        img = elf_image.ElfImage.from_file(os.path.join(SAMPLES, "uaf_demo32"))
        self.assertFalse(img.is64)
        self.assertEqual(img.bits, 32)
        eh = img.section(".eh_frame")
        self.assertIsNotNone(eh)
        self.assertFalse(img.is_executable(eh.addr))

    def test_vaddr_roundtrip(self):
        img = elf_image.ElfImage.from_file(os.path.join(SAMPLES, "uaf_demo64"))
        eh = img.section(".eh_frame")
        blob = img.read(eh.addr, 16)
        self.assertEqual(len(blob), 16)
        self.assertEqual(blob, bytes(img.data[eh.offset : eh.offset + 16]))

    def test_permission_report(self):
        img = elf_image.ElfImage.from_file(os.path.join(SAMPLES, "uaf_demo64"))
        eh = img.section(".eh_frame")
        text = elf_image.format_permission_report(img, eh.addr)
        self.assertIn("cannot", text)
        self.assertIn("PT_LOAD", text)


class ElfWriter(unittest.TestCase):
    def setUp(self):
        _ensure_out()
        self.src64 = os.path.join(SAMPLES, "uaf_demo64")
        self.src32 = os.path.join(SAMPLES, "uaf_demo32")

    def test_patch_and_exec_flag_64(self):
        dst = os.path.join(OUT, "patched64")
        img = elf_image.ElfImage.from_file(self.src64)
        eh = img.section(".eh_frame")
        blob = b"\x90" * 8
        img2, applied = elf_image.clone_with_patches(
            self.src64, dst, [(eh.addr, blob)], make_exec=eh.addr
        )
        self.assertEqual(applied, [(eh.addr, 8)])
        self.assertEqual(img2.read(eh.addr, 8), blob)
        self.assertTrue(img2.is_executable(eh.addr))
        # Original file untouched
        orig = elf_image.ElfImage.from_file(self.src64)
        self.assertNotEqual(orig.read(eh.addr, 8), blob)
        self.assertFalse(orig.is_executable(eh.addr))

    def test_patch_and_exec_flag_32(self):
        dst = os.path.join(OUT, "patched32")
        img = elf_image.ElfImage.from_file(self.src32)
        eh = img.section(".eh_frame")
        img2, _applied = elf_image.clone_with_patches(
            self.src32, dst, [(eh.addr, b"\xcc" * 4)], make_exec=eh.addr
        )
        self.assertEqual(img2.read(eh.addr, 4), b"\xcc" * 4)
        self.assertTrue(img2.is_executable(eh.addr))

    def test_pf_x_only_touches_that_phdr(self):
        dst = os.path.join(OUT, "pfx_only")
        img = elf_image.ElfImage.from_file(self.src64)
        before = [(s.index, s.flags) for s in img.loads]
        eh = img.section(".eh_frame")
        img.set_exec_flag(eh.addr, True)
        after = [(s.index, s.flags) for s in img.loads]
        changed = [i for i, (b, a) in enumerate(zip(before, after)) if b != a]
        self.assertEqual(len(changed), 1)
        idx = changed[0]
        self.assertEqual(after[idx][1], before[idx][1] | elf_image.PF_X)
        # p_flags really changed in the bytes on disk representation
        seg = img.loads[idx]
        raw = struct.unpack_from("<I", img.data, seg.phoff + 4)[0]
        self.assertTrue(raw & elf_image.PF_X)


def _have_wsl():
    return os.path.exists("/proc/version") or shutil.which("bash") is not None


class RuntimeCheck(unittest.TestCase):
    """End-to-end: patch a real jump into .eh_frame and execute the binary.

    This runs only on a POSIX host (the WSL side of this workspace) because the
    sample binaries are ELF and have to be *executed*.  On Windows the class is
    skipped; the pure-Python checks above still cover the file format, and
    ``tests/runtime_check.sh`` can be run manually inside WSL.
    """

    def setUp(self):
        if os.name != "posix" or not os.path.exists("/proc/version"):
            self.skipTest("ELF samples can only be executed on Linux/WSL")
        _ensure_out()
        self.script = os.path.join(ROOT, "tests", "runtime_check.sh")
        if not os.path.exists(self.script):
            self.skipTest("runtime_check.sh missing")

    def test_run_patched_binary(self):
        proc = subprocess.run(
            ["bash", self.script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
            timeout=180,
        )
        out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn("RUNTIME-OK", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
