"""Integration/regression tests using the upstream demo, never a user's backup.

Usage: python tools/test_recovery.py build/img_to_vhdx.exe
Requires zstandard for constructing the plan.
"""
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

from make_recovery_plan import make_plan, read_at
from discover_rebuild_plan import discover

EXE = pathlib.Path(sys.argv.pop(1)).resolve()
ROOT = pathlib.Path(__file__).resolve().parents[1]


class RecoveryTests(unittest.TestCase):
    def test_rebuild_help_launches_configured_python_without_conversion(self):
        result=subprocess.run([str(EXE),'--rebuild','--python',sys.executable,'--help'],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('--search-only',result.stdout);self.assertIn('--mapping-directory',result.stdout)
        failure=subprocess.run([str(EXE),'--rebuild','--python',sys.executable],capture_output=True,text=True,timeout=30)
        self.assertEqual(failure.returncode,2);self.assertIn('required',failure.stderr)

    def test_discovery_corroborates_intact_and_erased_index_boundaries(self):
        plan,proof=discover(self.source);self.assertEqual(plan,self.plan);self.assertTrue(proof['partitions'][0]['container_verified'])
        damaged=self.root/'erased-index-container.mrimgx';data=bytearray(self.source.read_bytes());header=self.plan['partitions'][0]['header_offset'];data[header:header+32]=bytes(32);damaged.write_bytes(data)
        plan,proof=discover(damaged);self.assertEqual(plan['partitions'][0]['entries_offset'],self.plan['partitions'][0]['entries_offset']);self.assertFalse(plan['partitions'][0]['container_verified']);self.assertGreaterEqual(len(proof['partitions'][0]['decoded_original_hash_corroborations']),8)

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.tmp.name)
        with zipfile.ZipFile(ROOT / 'demo/demo.zip') as z:
            name = next(n for n in z.namelist() if n.endswith('.mrimgx'))
            cls.source = cls.root / 'control.mrimgx'
            cls.source.write_bytes(z.read(name))
        cls.original_hash = hashlib.sha256(cls.source.read_bytes()).hexdigest()
        cls.plan = make_plan(cls.source, {'partitions': [dict(
            entries_offset=1299203, header_offset=1299163, container_verified=True)]})

    def run_plan(self, plan, source=None):
        label = self.id().split('.')[-1]
        p = self.root / (label + '.json')
        p.write_text(json.dumps(plan))
        log = self.root / (label + '.jsonl')
        result = subprocess.run([str(EXE), '--recover-plan', str(source or self.source),
                                 str(p), str(self.root / (label + '.vhdx')), str(log), '--verify-only'],
                                capture_output=True, text=True, timeout=90)
        return result, log

    def test_control_strict(self):
        r = subprocess.run([str(EXE), str(self.source), '-desc'], capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_control_recovery_all_verified(self):
        r, log = self.run_plan(self.plan)
        self.assertEqual(r.returncode, 0, r.stderr)
        summary = json.loads(log.read_text().splitlines()[-1])
        self.assertEqual(summary['status'], 'verified')
        self.assertEqual(summary['verified_blocks'], 1608)
        self.assertEqual(summary['failed_blocks'], 0)

    def test_plan_count_mismatch(self):
        p = json.loads(json.dumps(self.plan))
        p['partitions'][0]['count'] += 1
        r, _ = self.run_plan(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn('bounds/count', r.stderr)

    def test_plan_fingerprint_mismatch(self):
        p = json.loads(json.dumps(self.plan))
        p['partitions'][0]['entries_md5'] = '0' * 32
        r, _ = self.run_plan(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn('fingerprint', r.stderr)

    def test_source_length_mismatch(self):
        p = json.loads(json.dumps(self.plan)); p['source_size'] -= 1
        r, _ = self.run_plan(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn('length', r.stderr)

    def test_metadata_hash_diagnostic(self):
        copy = self.root / 'bad-metadata.mrimgx'; shutil.copyfile(self.source, copy)
        with copy.open('r+b') as f:
            f.seek(1299203); b = f.read(1); f.seek(1299203); f.write(bytes([b[0] ^ 1]))
        r = subprocess.run([str(EXE), str(copy), '-desc'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertIn('payload_offset=1299195', r.stderr)
        self.assertIn('expected=', r.stderr)
        self.assertIn('computed=', r.stderr)

    def test_data_damage_is_manifested(self):
        copy = self.root / 'bad-data.mrimgx'; shutil.copyfile(self.source, copy)
        with copy.open('r+b') as f:
            f.seek(1299203); pos, digest, length, number = struct.unpack('<Q16sIH', f.read(30))
            self.assertGreater(length, 0)
            f.seek(pos); f.write(b'BAD!')
        r, log = self.run_plan(self.plan, copy)
        self.assertEqual(r.returncode, 2, r.stderr)
        summary = json.loads(log.read_text().splitlines()[-1])
        self.assertGreater(summary['failed_blocks'], 0)
        self.assertEqual(summary['status'], 'partial')

    def test_bounded_reader(self):
        with self.source.open('rb') as f:
            with self.assertRaises(ValueError):
                read_at(f, -1, 4, self.source.stat().st_size)
            with self.assertRaises(ValueError):
                read_at(f, self.source.stat().st_size, 1, self.source.stat().st_size)

    @classmethod
    def tearDownClass(cls):
        assert hashlib.sha256(cls.source.read_bytes()).hexdigest() == cls.original_hash
        # Retain the test directory for audit; TemporaryDirectory otherwise removes it.
        cls.tmp._finalizer.detach()
        print('Test artifacts:', cls.root)


if __name__ == '__main__':
    unittest.main()
