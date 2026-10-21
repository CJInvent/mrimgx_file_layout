"""Synthetic regression tests: never use backup contents or private evidence."""
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import shutil
import zlib

import zstandard
from forensic_residuals import merge_ranges,complement,scan
from map_orphan_frames import partial_digest_matches
from appx_anchors import match
from extend_structured_files import file_length
from extend_cab_mappings import checksum
from recover_pdf_xrefs import classic_xrefs,stream_xrefs


class ForensicTests(unittest.TestCase):
    def test_coverage_exact_complement(self):
        covered=merge_ranges([(20,30),(5,10),(8,12),(12,15),(20,21)])
        self.assertEqual(covered,[[5,15],[20,30]])
        self.assertEqual(list(complement(covered,35)),[(0,5),(15,20),(30,35)])
        self.assertEqual(sum(b-a for a,b in covered)+sum(b-a for a,b in complement(covered,35)),35)

    def test_refinement_encoded_export_accounts_for_every_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);source=root/'source.bin';data=bytes(range(64));source.write_bytes(data)
            evidence=root/'evidence';evidence.mkdir()
            (evidence/'coverage-summary.json').write_text(json.dumps(dict(source_size=64,data_region_end=60,metadata_bytes=4,incorporated_encoded_bytes=20)))
            (evidence/'source-coverage.jsonl').write_text(''.join(json.dumps(dict(status='incorporated-encoded-data',source_offset=lo,length=10))+'\n' for lo in (0,20)))
            mappings=root/'mappings.json';mappings.write_text(json.dumps([dict(source_offset=10,stored_length=5)]));out=root/'out'
            command=[sys.executable,str(pathlib.Path(__file__).with_name('refinement_coverage.py')),str(source),str(evidence),str(mappings),str(out)]
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((out/'encoded-location-unresolved.bin').read_bytes(),data[15:20]+data[30:60])
            summary=json.loads((out/'summary.json').read_text());self.assertTrue(summary['accounting_exact']);self.assertEqual(summary['newly_incorporated_encoded_bytes'],5)
            self.assertEqual(source.read_bytes(),data)

    def test_partial_hash_requires_surviving_bits(self):
        candidate=bytes(range(1,17))
        self.assertTrue(partial_digest_matches(candidate[:10]+bytes(6),candidate))
        self.assertFalse(partial_digest_matches(candidate[:7]+bytes(9),candidate))
        self.assertFalse(partial_digest_matches(bytes([255])+candidate[1:10]+bytes(6),candidate))

    def test_blockmap_conflicts_and_duplicates(self):
        data=b'first block contents'
        e=dict(base=4096,digest=hashlib.sha256(data).digest(),record=3)
        self.assertEqual(match(data,{(0,len(data)):[e,e]})[0][0],4096)
        self.assertEqual(match(data,{(0,len(data)):[e,dict(e,base=8192)]}),[])
        self.assertEqual(match(data+b'x',{(0,len(data)+1):[e]}),[])
        whole=b'known-prefix'+data+b'known-suffix'
        cross=dict(e,digest=hashlib.sha256(whole).digest(),template=b'known-prefix'+bytes(len(data))+b'known-suffix',template_offset=len(b'known-prefix'))
        self.assertEqual(match(data,{(0,len(data)):[cross]})[0][0],4096)
        self.assertEqual(match(data+b'x',{(0,len(data)+1):[cross]}),[])

    def test_cab_checksum_word_and_tail_byte_orders(self):
        import struct
        for length in range(65):
            data=bytes(range(length));n=length//4*4;expected=0
            for word, in struct.iter_unpack('<I',data[:n]):expected^=word
            expected^=int.from_bytes(data[n:],'big')
            self.assertEqual(checksum(data),expected)

    def test_structured_file_crc_and_bounds(self):
        import gzip
        compressed=gzip.compress(b'small synthetic file')
        self.assertEqual(file_length(compressed+b'following data','gz'),len(compressed))
        with self.assertRaises(ValueError):file_length(compressed[:-1],'gz')
        bad=bytearray(compressed);bad[-8]^=1
        with self.assertRaises(zlib.error):file_length(bytes(bad),'gz')

    def test_pdf_xref_original_offsets_and_bounds(self):
        data=b'%PDF-1.4\n1 0 obj\n<<>>\nendobj\n';offset=len(data)
        data+=b'xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 >>\nstartxref\n'+str(offset).encode()+b'\n%%EOF\n'
        self.assertEqual(classic_xrefs(data),{(1,0):9})
        with self.assertRaises(ValueError):classic_xrefs(data.replace(b'0000000009 00000 n',b'9999999999 00000 n'))
        self.assertEqual(classic_xrefs(data[:-10]),{})

    def test_pdf_original_xref_stream(self):
        data=b'%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\n';offset=len(data)
        raw=bytes([0])+bytes(4)+(65535).to_bytes(2,'big')+bytes([1])+(9).to_bytes(4,'big')+bytes(2)+bytes([1])+offset.to_bytes(4,'big')+bytes(2)
        encoded=zlib.compress(raw)
        data+=b'2 0 obj\n<< /Type /XRef /Size 3 /W [1 4 2] /Root 1 0 R /Length '+str(len(encoded)).encode()+b' /Filter /FlateDecode >>\nstream\n'+encoded+b'\nendstream\nendobj\nstartxref\n'+str(offset).encode()+b'\n%%EOF\n'
        self.assertEqual(stream_xrefs(data),{(1,0):9,(2,0):offset})
        self.assertEqual(stream_xrefs(data.replace(b'startxref\n'+str(offset).encode(),b'startxref\n0')), {})

    def test_cross_window_frames_and_decode_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); source=root/'source.bin'; out=root/'out';out.mkdir()
            data=bytearray(os.urandom(100000));data[300:304]=bytes.fromhex('28b52ffd')
            frame=zstandard.ZstdCompressor().compress(bytes(data))
            start=8*1024**2-64
            source.write_bytes(bytes(start)+frame+bytes.fromhex('28b52ffd')+bytes(12)+b'TAIL')
            before=hashlib.sha256(source.read_bytes()).digest()
            db=sqlite3.connect(':memory:')
            db.execute('CREATE TABLE entries(partition,reserved,block,disk_offset,decoded_length,incorporated,digest BLOB)')
            digest=hashlib.md5(data).digest()
            db.executemany('INSERT INTO entries VALUES(0,0,0,0,100000,1,?)',[(digest,)]*40)
            metadata=source.stat().st_size-4
            scan(source,out,db,[(0,metadata)],metadata)
            self.assertEqual(db.execute('SELECT count(*) FROM frames').fetchone()[0],1)
            j=json.loads((out/'frames.jsonl').read_text())
            self.assertEqual(j['digest_match_count'],40)
            self.assertEqual(j['digest_matches'],[])
            self.assertTrue(j['matches_via_sql'])
            self.assertEqual(j['source_offset'],start)
            self.assertEqual((out/'orphan-decoded.bin').read_bytes(),bytes(data))
            self.assertEqual((out/'source-residual.bin').read_bytes(),source.read_bytes()[:metadata])
            self.assertTrue((out/'decode-failures.jsonl').stat().st_size or json.loads((out/'scan-summary.json').read_text()).get('unsupported_declared_size'))
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(),before)


@unittest.skipUnless(os.name=='nt' and os.environ.get('QEMU_IMG'),'Windows QEMU integration test')
class RefinementTests(unittest.TestCase):
    def test_clone_refine_cross_block_and_preserve_every_other_byte(self):
        from clone_sparse_file import clone
        from safe_vhdx import VHDX
        from dissect.util.hash.crc32c import crc32c
        import struct
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);raw=root/'baseline.raw';baseline=root/'baseline.vhdx'
            original=bytearray(8*1024**2);original[:4096]=b'A'*4096;original[6*1024**2:6*1024**2+4096]=b'B'*4096;original[-4096:]=b'Z'*4096;raw.write_bytes(original)
            subprocess.run([os.environ['QEMU_IMG'],'convert','-f','raw','-O','vhdx','-o','block_size=2097152',str(raw),str(baseline)],check=True,capture_output=True)
            baseline_hash=hashlib.sha256(baseline.read_bytes()).digest()
            # Cross from the end of a present block into a BAT ZERO block.
            # The following *physical* payload contains nonzero bytes, so a
            # reader that forgets to stop at the boundary returns wrong data.
            check_reader=VHDX(baseline);check_reader.seek(2*1024**2-4096)
            self.assertEqual(check_reader.read(143360),bytes(143360));check_reader.fh.close()
            target=root/'refined.vhdx';clone_log=root/'clone.jsonl';clone(baseline,target,clone_log)
            data=os.urandom(143360);source=root/'frames.bin';encoded=zstandard.ZstdCompressor().compress(data);source.write_bytes(encoded)
            start=2*1024**2-4096
            mapping=dict(partition=0,reserved=False,block=0,disk_offset=start,length=len(data),source_offset=0,stored_length=len(encoded),decoded_md5=hashlib.md5(data).hexdigest(),sha256=hashlib.sha256(data).hexdigest())
            mappings=root/'mappings.json';mappings.write_text(json.dumps([mapping]));manifest=root/'baseline.jsonl'
            manifest.write_text(json.dumps(dict(operation='range',status='unknown-zero-index',partition=0,disk_offset=1024**2,length=6*1024**2))+'\n')
            command=[sys.executable,str(pathlib.Path(__file__).with_name('refine_vhdx.py')),str(source),str(baseline),str(target),str(clone_log),str(manifest),str(mappings),str(root/'refinement.jsonl')]
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            expected=original[:];expected[start:start+len(data)]=data
            v=VHDX(target);self.assertEqual(v.read(len(expected)),bytes(expected));v.fh.close()
            self.assertEqual(hashlib.sha256(baseline.read_bytes()).digest(),baseline_hash)
            self.assertEqual(source.read_bytes(),encoded)
            with target.open('rb') as f:
                for offset in (65536,131072):
                    f.seek(offset);h=bytearray(f.read(4096));crc=struct.unpack_from('<I',h,4)[0];h[4:8]=bytes(4)
                    self.assertEqual(crc32c(bytes(h)),crc)
            check=subprocess.run([os.environ['QEMU_IMG'],'check',str(target)],capture_output=True,text=True)
            self.assertEqual(check.returncode,0,check.stdout+check.stderr)
            verifier=str(pathlib.Path(__file__).with_name('verify_refined_clone.py'))
            verify_command=[sys.executable,verifier,str(baseline),str(target),str(clone_log),str(root/'refinement.jsonl'),str(root/'full-validation.json')]
            checked=subprocess.run(verify_command,capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)
            # Extend an already completed refinement without losing prior
            # placements, then prove the preservation chain incrementally.
            second_data=os.urandom(143360);second_encoded=zstandard.ZstdCompressor().compress(second_data)
            source.write_bytes(encoded+second_encoded)
            second=dict(mapping,block=1,disk_offset=4*1024**2+4096,source_offset=len(encoded),stored_length=len(second_encoded),decoded_md5=hashlib.md5(second_data).hexdigest(),sha256=hashlib.sha256(second_data).hexdigest())
            mappings.write_text(json.dumps([mapping,second]));continued=command[:];continued[-1]=str(root/'refinement2.jsonl');continued+=['--previous-refinement',str(root/'refinement.jsonl')]
            result=subprocess.run(continued,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            expected[second['disk_offset']:second['disk_offset']+len(second_data)]=second_data
            v=VHDX(target);self.assertEqual(v.read(len(expected)),bytes(expected));v.fh.close()
            delta=verify_command[:];delta[-2]=str(root/'refinement2.jsonl');delta[-1]=str(root/'delta-validation.json');delta+=['--previous-refinement',str(root/'refinement.jsonl'),'--previous-validation',str(root/'full-validation.json')]
            checked=subprocess.run(delta,capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)
            full=json.loads((root/'full-validation.json').read_text());incremental=json.loads((root/'delta-validation.json').read_text())
            self.assertEqual(full['verified_allocated_clone_bytes'],incremental['verified_allocated_clone_bytes'])
            # Guard against replacing known data: rejection happens before writes.
            bad=dict(mapping,disk_offset=0);mappings.write_text(json.dumps([bad]));before=hashlib.sha256(target.read_bytes()).digest()
            command[-1]=str(root/'rejected.jsonl');reject=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(reject.returncode,0)
            self.assertEqual(hashlib.sha256(target.read_bytes()).digest(),before)


@unittest.skipUnless(os.environ.get('FRAME_REPAIR_EXE'),'Native frame repair executable')
class BitRepairTests(unittest.TestCase):
    def test_exact_md5_bit_repair_and_source_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);data=os.urandom(1024);encoded=zstandard.ZstdCompressor().compress(data)
            corrupt=bytearray(encoded);corrupt[-40]^=4;source=root/'corrupt.bin';source.write_bytes(corrupt);output=root/'repaired.bin'
            command=[os.environ['FRAME_REPAIR_EXE'],str(source),str(output),hashlib.md5(data).hexdigest(),str(len(data))]
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(zstandard.ZstdDecompressor().decompress(output.read_bytes()),data)
            self.assertEqual(source.read_bytes(),corrupt)
            self.assertEqual(json.loads(result.stdout)['status'],'unique-original-md5-repair')
            source2=root/'two-bits.bin';corrupt[-80]^=16;source2.write_bytes(corrupt);command[1]=str(source2);command[2]=str(root/'no-output.bin')
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertFalse((root/'no-output.bin').exists())


if __name__=='__main__':unittest.main()
