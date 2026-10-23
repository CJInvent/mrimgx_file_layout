import hashlib,json,os,pathlib,sqlite3,subprocess,tempfile,unittest
import zstandard
from recover_orphan_bit_frames import encoded_frame_length,near_magic_candidates


class OrphanBitFrameTests(unittest.TestCase):
    def test_damaged_magic_scan_excludes_known_compressed_intervals(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);magic=bytearray(bytes.fromhex('28b52ffd'));magic[2]^=8;raw=bytes(magic)+b'padding'+bytes(magic)
            (root/'source-residual.bin').write_bytes(raw);(root/'source-residual-map.jsonl').write_text(json.dumps(dict(export_offset=0,source_offset=1000,length=len(raw)))+'\n');db=sqlite3.connect(':memory:');db.execute('CREATE TABLE frames(source_offset,stored_length)');db.execute('INSERT INTO frames VALUES(1000,8)')
            results=list(near_magic_candidates(root,db));db.close();self.assertEqual(len(results),1);self.assertEqual(results[0]['source_offset'],1011);self.assertEqual(results[0]['magic_bit_repair'],dict(byte_offset=2,bit=3))

    def test_original_zstd_boundaries_exclude_trailing_data(self):
        data=bytes(range(256))*1000
        for checksum in (False,True):
            raw=zstandard.ZstdCompressor(write_checksum=checksum).compress(data)
            self.assertEqual(encoded_frame_length(raw+b'extra'),(len(raw),len(data)))
            with self.assertRaises(ValueError):encoded_frame_length(raw[:-1])

    def test_reserved_block_type_rejected(self):
        raw=bytearray(zstandard.ZstdCompressor().compress(b'a'*100));pos=zstandard.frame_header_size(raw);raw[pos]=(raw[pos]&~6)|6
        with self.assertRaises(ValueError):encoded_frame_length(raw)

    def test_native_hash_set_finds_second_original_digest(self):
        helper=os.environ.get('FRAME_REPAIR_EXE')
        if not helper:self.skipTest('FRAME_REPAIR_EXE unavailable')
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);data=bytes(range(256))*32;raw=zstandard.ZstdCompressor().compress(data);bad=bytearray(raw);bad[0]^=1;source=root/'source';source.write_bytes(bad);targets=root/'targets';targets.write_text('ff'*16+'\n'+hashlib.md5(data).hexdigest()+'\n');output=root/'output'
            result=subprocess.run([helper,str(source),str(output),'@'+str(targets),str(len(data))],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertEqual(output.read_bytes(),raw);self.assertEqual(source.read_bytes(),bad);self.assertEqual(json.loads(result.stdout)['tested_bytes'],len(raw))

    def test_native_hash_set_reports_exhaustive_negative_without_output(self):
        helper=os.environ.get('FRAME_REPAIR_EXE')
        if not helper:self.skipTest('FRAME_REPAIR_EXE unavailable')
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);data=os.urandom(1024);raw=bytearray(zstandard.ZstdCompressor().compress(data));raw[-100]^=1;raw[-200]^=2;source=root/'source';source.write_bytes(raw);targets=root/'targets';targets.write_text(hashlib.md5(data).hexdigest()+'\n'+'ff'*16+'\n');output=root/'output'
            result=subprocess.run([helper,str(source),str(output),'@'+str(targets),str(len(data))],capture_output=True,text=True)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr);self.assertFalse(output.exists());self.assertEqual(json.loads(result.stdout)['tested_bytes'],len(raw));self.assertEqual(json.loads(result.stdout)['matches'],0)
