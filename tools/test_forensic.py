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
from recover_chakra_offsets import pointer_arrays,read_variable
from recover_duplicate_files import distinctive,FileView,frame_pieces,exclude_holes
from discover_duplicate_pairs import candidate_records
from recover_sqlite_wal import checksum as wal_checksum,transitions
from ese_checksums import xe_checksum
from mapped_volume import MappedVolume
from recover_fat_signed_pe import name_variants
from recover_fat_multiframe_pe import assignment_digest,digest,patch
from merge_mapping_sets import combine
from recover_png_crc_grid import validate_png,first_idat
from recover_file_hashes import reconstruct,distinctive_hash_bound
from rescue_unplaced_files import carved_files,export as rescue_export
from recover_catalog_files import projected_hash
from recover_chromium_streams import layout as cache_layout,validate as cache_validate,extra_validation as cache_extra,INITIAL,FINAL
from placement_payload import payload as placement_payload
from recover_catalog_sequences import projected_multi_hash


class ForensicTests(unittest.TestCase):
    def test_multiframe_catalog_hash_projection_and_exclusions(self):
        template=os.urandom(4096);contents={'first':os.urandom(2048),'second':os.urandom(2048)};bases=[1000,2000];pieces={1000:[(55,300,500),(900,2100,200)],2000:[(100,1100,700)]};assignment=('first','second')
        data=reconstruct(template,bases,pieces,assignment,contents)
        for regions in ([(0,4096)],[(0,400),(408,1200),(1232,3500)]):
            for algorithm in ('sha1','sha256'):
                h=hashlib.new(algorithm)
                for lo,hi in regions:h.update(data[lo:hi])
                self.assertEqual(projected_multi_hash(template,regions,bases,pieces,algorithm)(assignment,contents),h.hexdigest())

    def test_original_index_repair_validation_without_readable_filesystem(self):
        # A boot/MFT repair must be checked before filesystem construction;
        # also reject a repair whose digest is absent from the original index.
        data=os.urandom(4096);encoded=zstandard.ZstdCompressor().compress(data);corrupt=bytearray(encoded);corrupt[-80]^=2
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);source=root/'source.bin';source.write_bytes(corrupt);fixed=root/'fixed.bin';fixed.write_bytes(encoded);evidence=root/'evidence';evidence.mkdir()
            db=sqlite3.connect(evidence/'catalog.sqlite');db.execute('CREATE TABLE entries(source_offset,stored_length,digest,decoded_length,partition,block,disk_offset)');md5=hashlib.md5(data).hexdigest();db.execute('INSERT INTO entries VALUES(?,?,?,?,?,?,?)',(0,len(encoded),bytes.fromhex(md5),len(data),2,7,4096));db.commit();db.close()
            request=dict(partition=2,disk_offset=4096,length=len(data),source_offset=0,stored_length=len(encoded),decoded_md5=md5,sha256=hashlib.sha256(data).hexdigest(),encoded_bit_repair=dict(encoded_path=str(fixed),original_encoded_sha256=hashlib.sha256(corrupt).hexdigest(),repaired_encoded_sha256=hashlib.sha256(encoded).hexdigest()),evidence=[dict(method='unique-original-index-md5-bit-repair',original_md5=md5,block=7)])
            requests=root/'requests.json';requests.write_text(json.dumps([request]));command=[sys.executable,str(pathlib.Path(__file__).with_name('validate_supplemental_files.py')),str(source),'-','-','-',str(evidence),'-',str(requests),str(root/'valid')]
            result=subprocess.run(command,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            db=sqlite3.connect(evidence/'catalog.sqlite');db.execute('UPDATE entries SET digest=?',(bytes(16),));db.commit();db.close();command[-1]=str(root/'invalid');result=subprocess.run(command,capture_output=True,text=True);self.assertNotEqual(result.returncode,0);self.assertEqual(source.read_bytes(),corrupt)

    def test_verified_slice_and_one_bit_view_never_edit_encoded_source(self):
        data=os.urandom(4096);encoded=zstandard.ZstdCompressor().compress(data);corrupt=bytearray(encoded);corrupt[-100]^=4
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);source=root/'original.bin';source.write_bytes(corrupt);fixed=root/'derivative.bin';fixed.write_bytes(encoded);part=data[300:900]
            m=dict(source_offset=0,stored_length=len(encoded),length=len(part),decoded_slice_offset=300,source_decoded_length=len(data),source_decoded_md5=hashlib.md5(data).hexdigest(),source_decoded_sha256=hashlib.sha256(data).hexdigest(),decoded_md5=hashlib.md5(part).hexdigest(),sha256=hashlib.sha256(part).hexdigest(),encoded_bit_repair=dict(encoded_path=str(fixed),original_encoded_sha256=hashlib.sha256(corrupt).hexdigest(),repaired_encoded_sha256=hashlib.sha256(encoded).hexdigest()))
            with source.open('rb') as reader:self.assertEqual(placement_payload(reader,m),part)
            self.assertEqual(source.read_bytes(),corrupt)
            bad=bytearray(encoded);bad[-101]^=8;fixed.write_bytes(bad);m['encoded_bit_repair']['repaired_encoded_sha256']=hashlib.sha256(bad).hexdigest()
            with source.open('rb') as reader,self.assertRaises(ValueError):placement_payload(reader,m)
    def test_chromium_original_key_bounds_crcs_and_nested_gzip(self):
        import struct
        key=b'https://example.test/asset';name=f'{int.from_bytes(hashlib.sha1(key).digest()[:8],"little"):016x}_0';compress=zlib.compressobj(wbits=31);body=compress.compress(os.urandom(65536))+compress.flush();metadata=b'HTTP/1.1 200 OK\0Content-Encoding: gzip\0'
        header=struct.pack('<Q4I',INITIAL,5,len(key),0,0)+key
        footer1=struct.pack('<Q4I',FINAL,1,zlib.crc32(body),0,0);footer0=struct.pack('<Q4I',FINAL,3,zlib.crc32(metadata),len(metadata),0)
        data=header+body+footer1+metadata+hashlib.sha256(key).digest()+footer0;info=cache_layout(data,name);cache_validate(data,info)
        lo=len(header)+100;hi=len(header)+len(body)-100;known=lambda start,stop:not(start<hi and stop>lo);self.assertEqual(cache_layout(data,name,known),info);self.assertTrue(cache_extra(data,info,data,known))
        wrong=bytearray(data);wrong[len(header)+200]^=1
        with self.assertRaises(ValueError):cache_validate(wrong,info)
        with self.assertRaises(ValueError):cache_layout(data,'0'*16+'_0')
        with self.assertRaises(ValueError):cache_layout(data[:-10],name)
    def test_jpeg_rescue_decodes_without_authorizing_placement(self):
        import io
        from PIL import Image
        stream=io.BytesIO();Image.new('RGB',(8,8),(21,55,89)).save(stream,format='JPEG');data=stream.getvalue();files=list(carved_files(b'prefix'+data+b'suffix'));jpeg=[x for x in files if x[2]=='jpg'];self.assertEqual(len(jpeg),1);self.assertEqual(jpeg[0][1],data);self.assertTrue(jpeg[0][3]['structural_validation_only']);self.assertEqual(list(carved_files(data[:-2])),[])
    def test_catalog_projection_hashes_all_known_and_candidate_ranges(self):
        template=os.urandom(65536);candidate=os.urandom(16384);patches=[(32,8000,9000),(10000,30000,5000)];regions=[(0,16),(20,48),(56,62000)];data=bytearray(template)
        for off,logical,n in patches:data[logical:logical+n]=candidate[off:off+n]
        for algorithm in ('sha1','sha256'):
            expected=hashlib.new(algorithm)
            for lo,hi in regions:expected.update(data[lo:hi])
            self.assertEqual(projected_hash(template,regions,patches,algorithm)(candidate),expected.hexdigest())
    def test_hash_reassembly_uses_physical_pieces_and_preserves_known_bytes(self):
        template=b'0123456789abcdefghij';contents={'x':b'ABCDE','y':b'FGHIJ'};pieces={100:[(1,2,3),(0,14,2)],200:[(2,8,2)]}
        result=reconstruct(template,[100,200],pieces,['x','y'],contents)
        self.assertEqual(result,b'01BCD567HIabcdABghij');self.assertEqual(template,b'0123456789abcdefghij')
        self.assertFalse(distinctive_hash_bound(bytes(32768)));self.assertTrue(distinctive_hash_bound(os.urandom(20000)))

    def test_unplaced_rescue_stays_outside_image_and_keeps_sidecars(self):
        import struct
        def block(kind,payload):return struct.pack('>I',len(payload))+kind+payload+struct.pack('>I',zlib.crc32(kind+payload)&0xffffffff)
        png=b'\x89PNG\r\n\x1a\n'+block(b'IHDR',struct.pack('>IIBBBBB',2,2,8,0,0,0,0))+block(b'IDAT',zlib.compress(b'\0\x01\x02\0\x03\x04'))+block(b'IEND',b'')
        original=b'prefix'+png+bytes(128);sha=hashlib.sha256(original).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);evidence=root/'evidence';evidence.mkdir();(evidence/'orphan-decoded.bin').write_bytes(original)
            db=sqlite3.connect(evidence/'catalog.sqlite');db.execute('CREATE TABLE frames(id,export_offset,decoded_length,source_offset,stored_length,sha256)');db.execute('INSERT INTO frames VALUES(1,0,?,4096,73,?)',(len(original),sha));db.execute('CREATE TABLE records(frame,decoded_offset,signature,length,fixup_valid,record_number,details)');db.commit();db.close();mapping=root/'mapping.json';mapping.write_text('[]');image=root/'baseline.vhdx';image.write_bytes(b'unchanged baseline')
            result=rescue_export(evidence,mapping,root/'recovered_files');self.assertEqual(result['counts']['carved_files'],1);self.assertEqual(image.read_bytes(),b'unchanged baseline');self.assertEqual((evidence/'orphan-decoded.bin').read_bytes(),original)
            files=list((root/'recovered_files/files').glob('*.png'));self.assertEqual(len(files),1);self.assertEqual(files[0].read_bytes(),png);side=json.loads(files[0].with_suffix('.png.json').read_text());self.assertFalse(side['vhdx_insertion_authorized']);self.assertEqual(side['placement_status'],'unresolved');self.assertEqual(side['provenance'][0]['frame_offset'],6)
            damaged=bytearray(png);damaged[-5]^=1;self.assertEqual(list(carved_files(bytes(damaged))),[])

    def test_png_complete_crc_zlib_and_scanline_validation(self):
        import struct
        def block(kind,payload):return struct.pack('>I',len(payload))+kind+payload+struct.pack('>I',zlib.crc32(kind+payload)&0xffffffff)
        header=block(b'IHDR',struct.pack('>IIBBBBB',2,2,8,0,0,0,0));payload=zlib.compress(b'\0\x01\x02\0\x03\x04')
        def assemble(body):return b'\x89PNG\r\n\x1a\n'+header+block(b'IDAT',body)+block(b'IEND',b'')
        png=assemble(payload);self.assertEqual(first_idat(png),(33,len(payload)));self.assertEqual(validate_png(png)['decoded_scanline_bytes'],6)
        corrupt=bytearray(payload);corrupt[-1]^=1
        with self.assertRaises(zlib.error):validate_png(assemble(bytes(corrupt)))
        with self.assertRaises(ValueError):validate_png(png+b'overlay')
        with self.assertRaises(ValueError):validate_png(assemble(zlib.compress(b'\x05\x01\x02\0\x03\x04')))
    def test_additive_branch_merge_rejects_conflicts_and_baseline_changes(self):
        original=dict(disk_offset=0,length=8,partition=0,reserved=False,block=0,sha256='a')
        extra=dict(original,disk_offset=8,block=1,sha256='b')
        self.assertEqual(combine([original],[[original,extra],[original,extra]]),[original,extra])
        with self.assertRaises(ValueError):combine([original],[[dict(original,sha256='c')]])
        with self.assertRaises(ValueError):combine([original],[[original,extra],[original,dict(extra,sha256='c')]])
        with self.assertRaises(ValueError):combine([original],[[original,dict(extra,disk_offset=4)]])
    def test_mapped_volume_reads_crossing_patch_and_baseline(self):
        import io
        mappings={10:dict(length=4,source_offset=7,stored_length=8)}
        volume=MappedVolume(io.BytesIO(b'prefix'+bytes(range(32))),6,32,mappings,lambda offset,length:b'ABCD')
        volume.seek(8);self.assertEqual(volume.read(8),bytes([8,9])+b'ABCD'+bytes([14,15]))
        volume.seek(-2,2);self.assertEqual(volume.read(8),bytes([30,31]))
        with self.assertRaises(ValueError):volume.read()

    def test_fat_boot_mui_shared_original_name_is_explicit(self):
        self.assertIn('bootmgr.exe',name_variants('bootmgfw.efi.mui'))
        self.assertIn('memtest.exe',name_variants('memtest.efi.mui'))
        self.assertNotIn('bootmgr.exe',name_variants('unrelated.efi.mui'))

    def test_multiframe_hash_prefixes_match_full_digest(self):
        data=bytearray(os.urandom(256));info=dict(algorithm='sha256',checksum_offset=16,security_offset=32,certificate_offset=240)
        patches={0:[(64,96,12)],1:[(144,192,6)]};contents={'a':os.urandom(80),'b':os.urandom(80)};states={}
        for assignment in (('a','b'),('b','a'),('a','a')):
            full=data[:]
            for base,sha in zip((0,1),assignment):patch(full,contents[sha],patches[base])
            self.assertEqual(assignment_digest(data,info,[0,1],patches,assignment,contents,states),digest(full,info))
    def test_ese_checksum_microsoft_reference_vector(self):
        import struct
        data=bytearray((i+i//13)&255 for i in range(32768));pgno=0x98765431
        # Microsoft's checksum_test.cxx TestSetPageChecksumLargePage vector.
        flags=struct.unpack_from('<I',data,36)[0]|0x2000;struct.pack_into('<I',data,36,flags)
        expected=(0xf9ce063147b6b865,0x69af69afcdd590e4,0x770988f62ea1a9e2,0x7cb77cb77b839a0e)
        for i in range(1,4):
            calculated=xe_checksum(data[i*8192:(i+1)*8192],pgno,False)
            self.assertEqual(calculated,expected[i]);struct.pack_into('<Q',data,40+(i-1)*8,calculated)
        self.assertEqual(xe_checksum(data[:8192],pgno),expected[0])

    def test_duplicate_stream_overlay_reads_crossing_boundaries(self):
        import io
        original=bytes(range(256))*40;patch=b'changed content'
        mapping=dict(length=len(patch),source_offset=7,stored_length=9)
        view=FileView(io.BytesIO(original),4096,len(original),{4096+512:mapping},lambda offset,length:patch)
        expected=original[:512]+patch+original[512+len(patch):]
        self.assertEqual(view[:],expected)
        self.assertEqual(view[500:550],expected[500:550])
        self.assertEqual(view[520:522],expected[520:522])

    def test_fragmented_duplicate_keeps_physical_and_logical_order_distinct(self):
        import io
        logical=b'A'*4096+b'B'*4096
        extents=[(0,8192,4096),(4096,0,4096)]
        mapping=dict(length=4096,source_offset=1,stored_length=2)
        view=FileView(io.BytesIO(logical),extents,len(logical),{0:mapping},lambda offset,length:b'C'*4096)
        self.assertEqual(view[4000:4200],b'A'*96+b'C'*104)
        self.assertEqual(frame_pieces(extents,0,12288),[(0,4096,4096),(8192,0,4096)])
        self.assertEqual(frame_pieces(extents,0,4096),[(0,4096,4096)])
        self.assertEqual(exclude_holes([(0,4096,4096)],[(5000,6000)]),[(0,4096,904),(1904,6000,2192)])
        self.assertEqual(exclude_holes([(0,4096,4096)],[(0,10000)]),[])

    def test_sqlite_wal_checksums_against_real_sqlite_writer(self):
        import struct
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'test.db';db=sqlite3.connect(path)
            try:
                db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE data (value BLOB)')
                db.executemany('INSERT INTO data VALUES (?)',[(os.urandom(3000),) for _ in range(8)]);db.commit()
                data=path.with_name('test.db-wal').read_bytes();big=bool(struct.unpack_from('>I',data)[0]&1);page=struct.unpack_from('>I',data,8)[0]
                self.assertEqual(wal_checksum(data[:24],big=big),struct.unpack_from('>II',data,24))
                good=transitions(data,32,page,data[16:24],big);self.assertGreaterEqual(len(good),2)
                corrupt=bytearray(data);corrupt[32+(page+24)+100]^=1
                self.assertLess(len(transitions(corrupt,32,page,data[16:24],big)),len(good))
                self.assertEqual(transitions(data,32,page,b'bad salt',big),[])
            finally:db.close()

    def test_duplicate_boundary_rejects_padding_and_small_headers(self):
        self.assertFalse(distinctive(bytes(143360)))
        self.assertFalse(distinctive(bytes(range(256))*560))
        self.assertFalse(distinctive(os.urandom(8192)))
        self.assertTrue(distinctive(os.urandom(32768)))

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

    def test_chakra_absolute_child_offsets_and_variable_fields(self):
        import struct
        data=bytearray(512)
        for start in (64,200):
            end=start+8*4;first_body=1000+end
            pointers=[first_body+40*i for i in reversed(range(8))]
            struct.pack_into('<8I',data,start,*pointers);data[end:end+4]=bytes.fromhex('b11c08c0')
        arrays=list(pointer_arrays(data,500,5000))
        hits=[e for e in arrays if e['origin']==1000]
        self.assertEqual({e['pointer_end'] for e in hits},{96,232})
        self.assertTrue(all(e['pointer_count']==8 for e in hits))
        data[64:96]=bytes(32)
        self.assertEqual(len([e for e in pointer_arrays(data,500,5000) if e['origin']==1000]),1)
        self.assertEqual(read_variable(bytes([13]),0),(13,1))
        self.assertEqual(read_variable(bytes([254,168,1]),0),(424,3))
        self.assertEqual(read_variable(bytes([255,1,2,3,0]),0),(197121,5))

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
            # Preserve a hash-validated subset without copying other bytes
            # from its enclosing source frame, then upgrade with agreeing data.
            slice_offset=1000;slice_data=second_data[slice_offset:slice_offset+4096];slice_at=5*1024**2+8192
            supplement=dict(partition=0,disk_offset=slice_at,length=len(slice_data),source_offset=len(encoded),stored_length=len(second_encoded),source_decoded_length=len(second_data),source_decoded_md5=second['decoded_md5'],source_decoded_sha256=second['sha256'],decoded_slice_offset=slice_offset,decoded_md5=hashlib.md5(slice_data).hexdigest(),sha256=hashlib.sha256(slice_data).hexdigest())
            slices=root/'slices.json';slices.write_text(json.dumps([supplement]));third=command[:];third[-1]=str(root/'refinement3.jsonl');third+=['--previous-refinement',str(root/'refinement2.jsonl'),'--supplemental',str(slices)]
            result=subprocess.run(third,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stdout+result.stderr);expected[slice_at:slice_at+len(slice_data)]=slice_data
            v=VHDX(target);self.assertEqual(v.read(len(expected)),bytes(expected));v.fh.close()
            upgrade=dict(second,block=2,disk_offset=slice_at-slice_offset);mappings.write_text(json.dumps([mapping,second,dict(mapping,block=2,disk_offset=upgrade['disk_offset'])]));fourth=command[:];fourth[-1]=str(root/'conflicting-upgrade.jsonl');fourth+=['--previous-refinement',str(root/'refinement3.jsonl')];before=hashlib.sha256(target.read_bytes()).digest();rejected=subprocess.run(fourth,capture_output=True,text=True);self.assertNotEqual(rejected.returncode,0);self.assertEqual(hashlib.sha256(target.read_bytes()).digest(),before)
            mappings.write_text(json.dumps([mapping,second,upgrade]));fourth[-3]=str(root/'refinement4.jsonl');result=subprocess.run(fourth,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stdout+result.stderr);expected[upgrade['disk_offset']:upgrade['disk_offset']+len(second_data)]=second_data
            v=VHDX(target);self.assertEqual(v.read(len(expected)),bytes(expected));v.fh.close()
            final_check=verify_command[:];final_check[-2]=str(root/'refinement4.jsonl');final_check[-1]=str(root/'final-preservation.json');checked=subprocess.run(final_check,capture_output=True,text=True);self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)
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
