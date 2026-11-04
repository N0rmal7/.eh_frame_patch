import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import _path
sys.path.insert(0, str(Path(_path.ROOT)/'examples'))
from awdp_main_fix import build

@unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux/WSL')
class AwdpRuntime(unittest.TestCase):
    def test_normal_and_double_delete(self):
        src = Path(_path.ROOT)/'samples'/'main'
        before = hashlib.sha256(src.read_bytes()).digest()
        with tempfile.TemporaryDirectory() as d:
            dst = Path(d)/'fixed'
            build(str(src),str(dst))
            cases = [b'4   ', b'1   1280 0   4   ', b'1   1280 0   2   0   4   ']
            for payload in cases:
                for file in (src,dst):
                    result=subprocess.run([str(file)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)
                    self.assertEqual(result.returncode,0,result.stdout)
            payload=b'1   1280 0   2   0   2   0   4   '
            original=subprocess.run([str(src)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)
            fixed=subprocess.run([str(dst)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)
            self.assertNotEqual(original.returncode,0,original.stdout)
            self.assertIn(b'double free',original.stdout)
            self.assertEqual(fixed.returncode,0,fixed.stdout)
            self.assertIn(b'Invalid Index',fixed.stdout)
            self.assertNotIn(b'double free',fixed.stdout)
        self.assertEqual(hashlib.sha256(src.read_bytes()).digest(),before)
