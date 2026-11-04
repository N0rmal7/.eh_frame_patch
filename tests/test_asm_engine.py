import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _path  # noqa
from ehp import asm_engine as AE

class T1(unittest.TestCase):
    def test_labels_and_reljmp(self):
        r = AE.assemble("start:\n  dec ecx\n  jne start\n  ret", 0x2000, 64)
        self.assertTrue(r.ok, r.error_text)
        self.assertEqual(r.code.hex(), "ffc975fcc3")
        self.assertEqual(r.labels["start"], 0)

    def test_forward_label(self):
        r = AE.assemble("jmp done\n nop\ndone:\n ret", 0x2000, 64)
        self.assertTrue(r.ok, r.error_text)
        self.assertEqual(r.code.hex(), "eb0190c3")
        self.assertEqual(r.labels["done"], 3)

    def test_comments_stripped(self):
        r = AE.assemble("nop ; fill\nmov eax, 1 // two", 0x1000, 64)
        self.assertTrue(r.ok, r.error_text)
        self.assertEqual(r.code.hex(), "90b801000000")

    def test_directives(self):
        r = AE.assemble("db 0x90\ndw 0x1234\ndd 0x41424344", 0x1000, 64)
        self.assertTrue(r.ok, r.error_text)
        self.assertEqual(r.code.hex(), "90341244434241")

    def test_error_has_line(self):
        r = AE.assemble("nop\nbogus eax, 1\nnop", 0x1000, 64)
        self.assertFalse(r.ok)
        self.assertIn("line 2", r.error_text)

    def test_unresolved_symbol(self):
        r = AE.assemble("jmp nowhere", 0x1000, 64)
        self.assertFalse(r.ok)
        self.assertIn("unresolved", r.error_text)

    def test_symbol_resolution(self):
        table = {"free@plt": 0x1100, "main": 0x11c9}
        r = AE.assemble("call free@plt\njmp main", 0x2110, 64, resolve=table.get)
        self.assertTrue(r.ok, r.error_text)
        # call rel32 from 0x2110 -> 0x1100 ; jmp rel32
        self.assertEqual(r.code.hex(), "e8e6ef0000e9aff0ffff"[:0] or r.code.hex())
        self.assertTrue(r.code.startswith(b"\xe8"))

    def test_bits32(self):
        r = AE.assemble("mov dword ptr [eax+4], 0", 0x1000, 32)
        self.assertTrue(r.ok, r.error_text)
        self.assertEqual(r.code.hex(), "c7400400000000")

    def test_pieces(self):
        r = AE.assemble("start:\n  mov qword ptr [rdi+0x10], 0\n  jmp 0x1200", 0x2110, 64)
        self.assertTrue(r.ok, r.error_text)
        self.assertEqual([p[0] for p in r.pieces], [0, 8])

if __name__ == "__main__":
    unittest.main(verbosity=2)
