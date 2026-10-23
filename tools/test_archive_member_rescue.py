import io,unittest,zlib,struct,zipfile
from rescue_archive_members import decode_member


def zip64_fixture(payload=b'original contents'*200):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('payload.bin',payload)
    return as_zip64(stream.getvalue())


def as_zip64(raw):
    end=raw.rfind(b'PK\x05\x06');fields=struct.unpack_from('<4s4H2IH',raw,end);count,size,offset=fields[4:7]
    record=struct.pack('<4sQ2H2I4Q',b'PK\x06\x06',44,45,45,0,0,count,count,size,offset)
    locator=struct.pack('<4sIQI',b'PK\x06\x07',0,end,1)
    terminal=struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,65535,65535,0xffffffff,0xffffffff,0)
    return raw[:end]+record+locator+terminal


def local_fixture(entries):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_STORED) as archive:
        for name,data in entries:archive.writestr(name,data)
    data=stream.getvalue();end=data.rfind(b'PK\x05\x06');directory=struct.unpack_from('<I',data,end+16)[0]
    return data[:directory]+bytes(len(data)-directory),directory


class ArchiveMemberRescueTests(unittest.TestCase):
    def test_surviving_zip64_directory_nominates_original_members(self):
        from types import SimpleNamespace
        from recover_indexed_donor_frames import archive_members
        data=zip64_fixture();record=SimpleNamespace(size=lambda:len(data),open=lambda:io.BytesIO(data),segment=7)
        rows=archive_members(SimpleNamespace(holes=lambda record:[]),record)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['key'][0],'payload.bin');self.assertEqual(rows[0]['record'],7)
        row=rows[0];result,decoded=self.decode(b'original contents'*200,encoded=data[row['start']:row['stop']])
        self.assertTrue(result['valid']);self.assertEqual(decoded,b'original contents'*200)

    def test_zip64_end_bounds_reject_conflicts_splits_and_unknown_bytes(self):
        from zip_directory import directory_bounds
        data=zip64_fixture();self.assertEqual(directory_bounds(io.BytesIO(data),len(data))['directory_format'],'zip64')
        locator=len(data)-42;end=len(data)-22;record=len(data)-98
        for offset,fmt,value in [(locator+16,'<I',2),(locator+8,'<Q',5),(record+4,'<Q',10000),(end+12,'<I',1)]:
            bad=bytearray(data);struct.pack_into(fmt,bad,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):directory_bounds(io.BytesIO(bad),len(bad))
        with self.assertRaises(ValueError):directory_bounds(io.BytesIO(data),len(data),[(record,record+1,0)])

    def test_zip64_original_directory_crcs_remain_required_for_placement(self):
        import os
        from recover_zip_files import validate_archive,original_crossing_crcs,independently_crossing
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_STORED) as archive:
            archive.writestr('first',os.urandom(5000));archive.writestr('second',os.urandom(5000))
        data=as_zip64(stream.getvalue());members=validate_archive(data);self.assertEqual(len(members),2)
        start=members[0]['compressed_start']+1000;stop=members[1]['compressed_start']+1000;mask=bytearray(b'\1'*len(data));mask[start:stop]=bytes(stop-start);template=bytearray(data);template[start:stop]=bytes(stop-start);pieces=[(0,start,stop-start)]
        proof=original_crossing_crcs(template,mask,members,pieces);self.assertTrue(independently_crossing(proof))
        mask[-30]=0;self.assertFalse(independently_crossing(original_crossing_crcs(template,mask,members,pieces)))

    def test_classic_directory_comment_may_contain_end_signature(self):
        from zip_directory import directory_bounds
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:archive.writestr('a',b'a');archive.comment=b'comment PK\x05\x06'
        raw=stream.getvalue();self.assertEqual(directory_bounds(io.BytesIO(raw),len(raw))['entries'],1)

    def test_local_header_sizes_crc_and_source_header_fingerprint(self):
        import hashlib
        from zip_local_members import local_members
        payload=b'recovered XML body';raw,directory=local_fixture([('word/document.xml',payload)])
        rows,scan=local_members(io.BytesIO(raw),len(raw),[(directory,len(raw),0)])
        self.assertEqual(len(rows),1);self.assertFalse(rows[0]['directory_membership_proven'])
        member=rows[0];self.assertEqual(member['local_header_sha256'],hashlib.sha256(raw[:member['start']]).hexdigest())
        output=io.BytesIO();result=decode_member(io.BytesIO(raw),member['start'],member['key'][3],member['key'][4],member['key'][2],member['key'][1],[],output,1000)
        self.assertTrue(result['valid']);self.assertEqual(output.getvalue(),payload)

    def test_local_header_encryption_descriptor_and_unknown_header_are_skipped(self):
        from zip_local_members import local_members
        raw,directory=local_fixture([('a',b'contents')])
        for flag,reason in [(1,'encrypted'),(8,'data-descriptor-without-directory')]:
            data=bytearray(raw);struct.pack_into('<H',data,6,flag);rows,scan=local_members(io.BytesIO(data),len(data))
            self.assertEqual(rows,[]);self.assertEqual(scan['skipped'][reason],1)
        rows,scan=local_members(io.BytesIO(raw),len(raw),[(0,4,0)]);self.assertEqual(rows,[])

    def test_local_zip64_sizes_and_scan_bound(self):
        from zip_local_members import local_members
        data=b'local ZIP64 member';name=b'payload';extra=struct.pack('<HHQQ',1,16,len(data),len(data));header=struct.pack('<4s5H3I2H',b'PK\x03\x04',45,0,0,0,0,zlib.crc32(data),0xffffffff,0xffffffff,len(name),len(extra));raw=header+name+extra+data
        rows,scan=local_members(io.BytesIO(raw),len(raw));self.assertEqual(rows[0]['key'][2:4],(len(data),len(data)))
        rows,scan=local_members(io.BytesIO(raw),len(raw),maximum_scan_bytes=10);self.assertEqual(rows,[]);self.assertTrue(scan['scan_bound_reached'])
        with self.assertRaises(ValueError):local_members(io.BytesIO(raw),len(raw),maximum_scan_bytes=0)

    def fallback_export(self,entries,extra_holes=()):
        import tempfile,pathlib,json,hashlib
        from types import SimpleNamespace
        from unittest.mock import patch
        from rescue_archive_members import main
        raw,directory=local_fixture(entries)
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary);source=root/'source';source.write_bytes(b'SOURCE');baseline=root/'baseline';baseline.write_bytes(b'BASELINE');inventory=root/'inventory';inventory.write_text(json.dumps(dict(record=99,path='original\\damaged.docx'))+'\n');output=root/'output'
            record=SimpleNamespace(size=lambda:len(raw),open=lambda:io.BytesIO(raw),segment=99,header=SimpleNamespace(SequenceNumber=3))
            ctx=SimpleNamespace(fs=SimpleNamespace(mft=SimpleNamespace(get=lambda n:record)),holes=lambda r:[(directory,len(raw),0)]+list(extra_holes),close=lambda:None)
            argv=['rescue_archive_members.py']+list(map(str,[source,baseline,root/'mft',inventory,root/'manifest',root/'evidence',root/'mapping',output]))
            with patch('rescue_archive_members.Context',return_value=ctx),patch('sys.argv',argv):main()
            artifacts=[]
            for side in output.rglob('*.bin.json'):
                meta=json.loads(side.read_text());data=side.with_suffix('').read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),meta['sha256']);self.assertFalse(meta['vhdx_insertion_authorized']);self.assertFalse(meta['original_member_directory_binding_proven']);self.assertEqual(meta['archive_sequence'],3);artifacts.append((meta,data))
            self.assertEqual(source.read_bytes(),b'SOURCE');self.assertEqual(baseline.read_bytes(),b'BASELINE');self.assertFalse((root/'outside').exists())
            return artifacts,json.loads((output/'summary.json').read_text())

    def test_missing_directory_exports_crc_valid_members_using_generated_names(self):
        entries=[('../../outside',b'safe bytes'),('word/document.xml',b'<document/>')];artifacts,summary=self.fallback_export(entries)
        self.assertEqual({meta['member_name']:data for meta,data in artifacts},dict(entries));self.assertTrue(all(meta['valid'] for meta,data in artifacts));self.assertEqual(summary['counts']['local_header_valid_members'],2)

    def test_local_payload_hole_retains_only_known_prefix(self):
        name='payload.bin';data=bytes(range(256))*4;start=30+len(name);artifacts,summary=self.fallback_export([(name,data)],[(start+100,start+200,0)])
        self.assertEqual(len(artifacts),1);meta,body=artifacts[0];self.assertFalse(meta['valid']);self.assertEqual(body,data[:100]);self.assertEqual(summary['counts']['local_header_uncertain_members'],1)

    def decode(self,data,encoded=None,holes=(),limit=100000,crc=None,method=8):
        if encoded is None:
            obj=zlib.compressobj(wbits=-15);encoded=obj.compress(data)+obj.flush()
        output=io.BytesIO();result=decode_member(io.BytesIO(b'HEAD'+encoded),4,len(encoded),method,len(data),zlib.crc32(data) if crc is None else crc,holes,output,limit)
        return result,output.getvalue()

    def test_complete_deflate_and_stored_members(self):
        data=bytes(range(256))*200
        for encoded,method in [(None,8),(data,0)]:
            result,output=self.decode(data,encoded,method=method);self.assertTrue(result['valid']);self.assertEqual(output,data)

    def test_crc_error_preserves_all_decoded_bytes_outside_image(self):
        data=b'original bytes'*1000;result,output=self.decode(data,crc=123)
        self.assertFalse(result['valid']);self.assertIn('CRC32',result['error']);self.assertEqual(output,data)

    def test_unknown_compressed_bytes_never_feed_decoder(self):
        data=bytes(range(256))*4;result,output=self.decode(data,data,holes=[(104,204,0)],method=0)
        self.assertFalse(result['valid']);self.assertEqual(output,data[:100]);self.assertEqual(result['compressed_bytes_read'],100)

    def test_bounds_truncation_and_trailing_bytes_are_reported(self):
        data=b'a'*1000
        result,output=self.decode(data,limit=999);self.assertFalse(result['valid']);self.assertEqual(output,b'')
        obj=zlib.compressobj(wbits=-15);encoded=obj.compress(data)+obj.flush()
        for bad in [encoded[:-1],encoded+b'extra']:
            result,output=self.decode(data,bad);self.assertFalse(result['valid'])
        result,output=self.decode(data,method=99);self.assertFalse(result['valid']);self.assertEqual(output,b'')

    def test_lying_declared_size_cannot_expand_past_limit(self):
        obj=zlib.compressobj(wbits=-15);encoded=obj.compress(b'x'*100000)+obj.flush();output=io.BytesIO()
        result=decode_member(io.BytesIO(encoded),0,len(encoded),8,10,0,[],output,100)
        self.assertFalse(result['valid']);self.assertLessEqual(len(output.getvalue()),100)
