import io,struct,unittest
from cfb_member_rescue import Compound,chain,known_parts,END,FREE


def fixture():
    def entry(name,kind,start,size,right=FREE,child=FREE):
        raw=bytearray(128);encoded=(name+'\0').encode('utf-16-le');raw[:len(encoded)]=encoded;struct.pack_into('<HBBIII',raw,64,len(encoded),kind,1,FREE,right,child);struct.pack_into('<IQ',raw,116,start,size);return bytes(raw)
    header=bytearray(512);header[:8]=bytes.fromhex('d0cf11e0a1b11ae1');struct.pack_into('<5H',header,24,0x3e,3,0xfffe,9,6);struct.pack_into('<9I',header,40,0,1,1,0,4096,3,1,END,0);struct.pack_into('<109I',header,76,0,*([FREE]*108))
    fat=[FREE]*128;fat[0]=0xfffffffd;fat[1]=fat[2]=fat[3]=END
    for i in range(4,12):fat[i]=i+1 if i<11 else END
    directory=entry('Root Entry',5,2,64,child=1)+entry('Alpha',2,0,9,right=2)+entry('Zulu',2,4,4096)+bytes(128)
    mini=b'mini body'+bytes(512-9);minifat=struct.pack('<128I',END,*([FREE]*127));body=bytes(range(256))*16
    return bytes(header)+struct.pack('<128I',*fat)+directory+mini+minifat+body,body


class CfbMemberRescueTests(unittest.TestCase):
    def test_false_mz_signatures_do_not_invoke_expensive_pe_parser(self):
        from unittest.mock import patch
        from rescue_unplaced_files import carved_files
        raw=(b'MZ'+bytes(98))*100
        with patch('pefile.PE',side_effect=ValueError('invalid PE')) as parse:
            self.assertEqual(list(carved_files(raw)),[]);parse.assert_not_called()
        raw=bytearray(256);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,128);raw[128:132]=b'PE\0\0'
        with patch('pefile.PE',side_effect=ValueError('invalid PE')) as parse:
            self.assertEqual(list(carved_files(raw)),[]);parse.assert_called_once()

    def test_contiguous_source_ranges_join_but_unknown_logical_gaps_do_not(self):
        from rescue_cfb_members import groups
        parts=[dict(logical_offset=0,file_offset=100,bytes=4),dict(logical_offset=4,file_offset=200,bytes=4),dict(logical_offset=10,file_offset=300,bytes=4)]
        self.assertEqual([(p['logical_offset'],p['bytes']) for p in groups(parts)],[(0,8),(10,4)])

    def test_false_pe_hits_do_not_allocate_large_carving_slices(self):
        import tracemalloc
        from rescue_unplaced_files import carved_files
        raw=(b'MZ'+bytes(2*1024**2-2))*4
        tracemalloc.start()
        try:
            self.assertEqual(list(carved_files(raw,maximum=2*1024**2)),[])
            self.assertLess(tracemalloc.get_traced_memory()[1],512*1024)
        finally:tracemalloc.stop()

    def test_nested_stream_reads_known_ranges_and_refuses_unknown_gaps(self):
        from cfb_member_rescue import KnownStream
        source=io.BytesIO(b'ABCDxxxxEFGHzzIJ');parts=[dict(logical_offset=0,file_offset=0,bytes=4),dict(logical_offset=4,file_offset=8,bytes=4),dict(logical_offset=10,file_offset=14,bytes=2)];view=KnownStream(source,16,12,parts)
        self.assertEqual(view.read(8),b'ABCDEFGH');self.assertEqual(view.holes,[(8,10,0)])
        with self.assertRaises(ValueError):view.read(1)
        view.seek(-2,2);self.assertEqual(view.read(),b'IJ')
        with self.assertRaises(ValueError):view.seek(13)

    def test_original_metadata_binds_regular_and_mini_stream_bytes(self):
        raw,body=fixture();stream=io.BytesIO(raw);cfb=Compound(stream,len(raw))
        try:
            members={m['stream_path'][0]:m for m in cfb.streams()}
            for name,expected in [('Alpha',b'mini body'),('Zulu',body)]:
                pieces=known_parts(members[name],[]);actual=b''.join(raw[p['file_offset']:p['file_offset']+p['bytes']] for p in pieces)
                self.assertEqual(actual,expected);self.assertEqual(cfb.ole.openstream(name).read(),expected)
            self.assertTrue(members['Alpha']['mini_stream']);self.assertFalse(members['Zulu']['mini_stream'])
        finally:cfb.close()

    def test_unknown_allocation_metadata_cannot_nominate_members(self):
        raw,body=fixture()
        for holes in [[(0,1,0)],[(512,513,0)],[(1024,1025,0)],[(2048,2049,0)]]:
            with self.subTest(holes=holes),self.assertRaises(ValueError):Compound(io.BytesIO(raw),len(raw),holes)

    def test_allocation_cycles_and_declared_length_mismatch_fail_closed(self):
        with self.assertRaises(ValueError):chain([1,0],0)
        with self.assertRaises(ValueError):chain([END],0,count=2)
        with self.assertRaises(ValueError):chain([END],3)
        with self.assertRaises(ValueError):chain([END],0,maximum=0)

    def test_unavailable_payload_is_split_and_later_known_bytes_retained(self):
        raw,body=fixture();cfb=Compound(io.BytesIO(raw),len(raw))
        try:
            member=next(m for m in cfb.streams() if m['stream_path']==['Zulu']);start=member['source_ranges'][0]['file_offset'];parts=known_parts(member,[(start+100,start+300,0)])
            self.assertEqual([(p['logical_offset'],p['bytes']) for p in parts],[(0,100),(300,3796)])
            self.assertEqual(sum(p['bytes'] for p in parts),len(body)-200)
        finally:cfb.close()

    def test_mini_stream_unknown_bytes_do_not_become_source_content(self):
        raw,body=fixture();cfb=Compound(io.BytesIO(raw),len(raw))
        try:
            member=next(m for m in cfb.streams() if m['stream_path']==['Alpha']);start=member['source_ranges'][0]['file_offset'];parts=known_parts(member,[(start+2,start+5,0)])
            self.assertEqual([(p['logical_offset'],p['bytes']) for p in parts],[(0,2),(5,4)])
        finally:cfb.close()
