"""Tests for ehp.unwind_cave: finding safe overwrite areas in .eh_frame.

The properties that matter for the plugin:

1. A candidate never points past the end of .eh_frame.
2. Level-0 candidates (after the ZERO terminator) are only reported when such
   bytes actually exist.
3. Per-record padding candidates start exactly at the first DW_CFA_nop of the
   trailing run, so the record's real instructions survive.
4. Merged spans reach the requested size (when the section is big enough).
5. pc_begin is decoded as a *signed* pcrel offset; a wrong decode would make
   every FDE look dead, which is the bug this guards against.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _path  # noqa
from ehp import elf_image, unwind_cave

ROOT = _path.ROOT
SAMPLES = os.path.join(ROOT, "samples")


def load(name):
    img = elf_image.ElfImage.from_file(os.path.join(SAMPLES, name))
    sec = img.section(".eh_frame")
    return img, sec, img.read(sec.addr, sec.size)


class TestCandidates(unittest.TestCase):
    def test_candidates_inside_section(self):
        for name in ("main", "uaf_demo64", "uaf_demo32"):
            img, sec, data = load(name)
            cands = unwind_cave.find_candidates(data, sec.addr)
            self.assertTrue(cands, "%s: no candidates at all" % name)
            for c in cands:
                self.assertGreaterEqual(c.ea, sec.addr, name)
                self.assertLessEqual(c.ea + c.size, sec.addr + sec.size,
                                     "%s: candidate runs past section" % name)
                self.assertGreater(c.size, 0, name)

    def test_no_free_tail_when_terminator_is_last(self):
        img, sec, data = load("main")
        cands = unwind_cave.find_candidates(data, sec.addr)
        tails = [c for c in cands if c.level == unwind_cave.Candidate.FREE_TAIL]
        self.assertEqual(tails, [],
                         "main has its terminator at the very end, so no tail")

    def test_padding_starts_at_nop_run(self):
        img, sec, data = load("main")
        cands = unwind_cave.find_candidates(data, sec.addr)
        pads = [c for c in cands if c.level == unwind_cave.Candidate.PADDING]
        self.assertTrue(pads, "expected per-record padding candidates")
        for c in pads:
            off = c.ea - sec.addr
            # everything the candidate covers must be 0x00 (DW_CFA_nop)
            blob = data[off:off + c.size]
            self.assertTrue(all(b == 0 for b in blob),
                            "padding candidate at %#x is not all nops" % c.ea)
            # and the byte before it must NOT be a nop, or the run would be longer
            if off > 0:
                self.assertNotEqual(data[off - 1], 0,
                                    "run at %#x starts too late" % c.ea)

    def test_merged_span_reaches_requested_size(self):
        img, sec, data = load("main")
        spans = unwind_cave.find_merged_padding(data, sec.addr, want=32)
        self.assertTrue(spans, "expected merged spans for 32 bytes")
        biggest = max(s.size for s in spans)
        self.assertGreaterEqual(biggest, 32)
        for s in spans:
            self.assertLessEqual(s.ea + s.size, sec.addr + sec.size)


class TestPcDecoding(unittest.TestCase):
    def test_pc_begin_is_signed_pcrel(self):
        """A wrong (unsigned) decode makes every FDE look dead."""
        img, sec, data = load("main")
        recs = [r for r in unwind_cave._records(data) if r[1] != 0]
        self.assertTrue(recs)
        live = 0
        for (off, header, length, body) in recs:
            rng = unwind_cave._fde_pc(body, sec.addr + off + header)
            if rng is None:
                continue
            pc, size = rng
            self.assertLess(pc, 1 << 32,
                            "pc_begin %#x looks like an unsigned misread" % pc)
            seg = img.load_at(pc)
            if seg is not None and size:
                live += 1
        self.assertGreater(live, 5,
                           "almost no FDE resolved to a mapped address; "
                           "pc_begin decoding is broken")


class TestLiveFilter(unittest.TestCase):
    def test_dead_fde_detected(self):
        """An FDE whose pc points nowhere must be reported as a dead record."""
        img, sec, data = load("main")
        # Patch one FDE's pc_range to 0 via a copy of the data, which makes it
        # "not describing a live function" under our predicate.
        buf = bytearray(data)
        recs = [r for r in unwind_cave._records(bytes(buf)) if r[1] != 0]
        chosen = None
        for (off, header, length, body) in recs:
            if unwind_cave._fde_pc(body, sec.addr + off + header):
                chosen = (off, header)
                break
        self.assertIsNotNone(chosen)
        off, header = chosen
        buf[off + header + 8: off + header + 12] = b"\x00\x00\x00\x00"

        def all_live(pc, rng):
            return True

        cands = unwind_cave.find_candidates(bytes(buf), sec.addr, is_pc_live=all_live)
        self.assertFalse([c for c in cands if c.level == unwind_cave.Candidate.DEAD_RECORD])

        def none_live(pc, rng):
            return False

        cands = unwind_cave.find_candidates(bytes(buf), sec.addr, is_pc_live=none_live)
        dead = [c for c in cands if c.level == unwind_cave.Candidate.DEAD_RECORD]
        self.assertTrue(dead, "is_pc_live=False must yield dead-record candidates")


if __name__ == "__main__":
    unittest.main(verbosity=2)
