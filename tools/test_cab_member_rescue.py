import io,struct,unittest,zlib
from cab_member_rescue import metadata,folder_prefix,prefix_members,write_prefix_cabinet
from extend_cab_mappings import checksum


def fixture(parts=(b'first contents',b'second contents'),compression=0,reserve=False):
    entries=[];offset=0
    for index,part in enumerate(parts):
        entries.append(struct.pack('<II4H',len(part),offset,0,0,0,0)+f'original-{index}'.encode()+b'\0');offset+=len(part)
    blocks=[]
    for part in parts:
        body=part
        if compression==1:
            encoder=zlib.compressobj(wbits=-15);body=b'CK'+encoder.compress(part)+encoder.flush()
        header=struct.pack('<HH',len(body),len(part));blocks.append(struct.pack('<I',checksum(header+body))+header+body)
    optional=struct.pack('<HBB',5,2,0)+b'abcde' if reserve else b''
    table=36+len(optional)+8+(2 if reserve else 0);start=table+sum(map(len,entries));total=start+sum(map(len,blocks))
    header=struct.pack('<4s5I2B5H',b'MSCF',0,total,0,table,0,3,1,1,len(parts),4 if reserve else 0,0,0)
    raw=header+optional+struct.pack('<IHH',start,len(blocks),compression)+(b'zz' if reserve else b'')+b''.join(entries)+b''.join(blocks)
    return raw,start,blocks


class CabMemberRescueTests(unittest.TestCase):
    def test_classified_batch_errors_do_not_retry_or_authorize_failed_members(self):
        from rescue_cab_members import batch_status
        from subprocess import CompletedProcess
        members=[dict(generated_name='member-00000.bin'),dict(generated_name='member-00001.bin')]
        result=CompletedProcess([],2,'Sub items Errors: 1\n','ERROR: Data Error : member-00001.bin\n')
        self.assertEqual(batch_status(result,members),{'member-00000.bin':(0,''),'member-00001.bin':(2,'Data Error')})
        for output in ('','Sub items Errors: 2\n','Sub items Errors: 1\nERROR: Unknown failure\n'):
            result.stdout=output;self.assertTrue(all(code for code,error in batch_status(result,members).values()))

    def test_decoder_names_cannot_be_original_paths(self):
        from rescue_cab_members import extract_batch
        import pathlib
        raw,start,blocks=fixture();info=metadata(io.BytesIO(raw),len(raw));prefix=folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0]);members=prefix_members(info,prefix);members[0]['generated_name']='../outside'
        with self.assertRaises(ValueError):write_prefix_cabinet(io.BytesIO(raw),len(raw),[],prefix,members,io.BytesIO())
        with self.assertRaises(ValueError):extract_batch(pathlib.Path('unused'),pathlib.Path('unused'),members,pathlib.Path('unused'))

    def test_known_reserved_metadata_and_compressed_prefix(self):
        for compression in (0,1):
            raw,start,blocks=fixture(compression=compression,reserve=True);info=metadata(io.BytesIO(raw),len(raw));prefix=folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0]);members=prefix_members(info,prefix)
            self.assertEqual(len(members),2);self.assertTrue(all(m['complete_original_member'] for m in members));self.assertTrue(prefix['all_original_folder_blocks_known'])
            output=io.BytesIO();write_prefix_cabinet(io.BytesIO(raw),len(raw),[],prefix,members,output)
            generated=output.getvalue();new=metadata(io.BytesIO(generated),len(generated));self.assertEqual([m['name'] for m in new['members']],['member-00000.bin','member-00001.bin']);self.assertEqual(generated[new['folders'][0]['data_offset']:],b''.join(blocks))

    def test_unknown_block_stops_before_placeholder_bytes(self):
        raw,start,blocks=fixture();info=metadata(io.BytesIO(raw),len(raw));holes=[(start+len(blocks[0])+8,len(raw),0)];prefix=folder_prefix(io.BytesIO(raw),len(raw),holes,info['folders'][0]);members=prefix_members(info,prefix)
        self.assertEqual(len(prefix['blocks']),1);self.assertEqual(len(members),1);self.assertIn('unknown source',prefix['stopped_reason'])

    def test_member_crossing_prefix_retains_explicit_partial_status(self):
        raw,start,blocks=fixture();info=metadata(io.BytesIO(raw),len(raw));info['members'][0]['size']+=100;prefix=folder_prefix(io.BytesIO(raw),len(raw),[(start+len(blocks[0]),len(raw),0)],info['folders'][0]);members=prefix_members(info,prefix)
        self.assertFalse(members[0]['complete_original_member']);self.assertEqual(members[0]['available_bytes'],len(b'first contents'))

    def test_unknown_metadata_and_split_cabinets_are_rejected(self):
        raw,start,blocks=fixture()
        for holes in [[(0,1,0)],[(44,45,0)]]:
            with self.assertRaises(ValueError):metadata(io.BytesIO(raw),len(raw),holes)
        bad=bytearray(raw);struct.pack_into('<H',bad,30,1)
        with self.assertRaises(ValueError):metadata(io.BytesIO(bad),len(bad))

    def test_bad_original_checksum_and_explicit_bounds(self):
        raw,start,blocks=fixture();info=metadata(io.BytesIO(raw),len(raw));bad=bytearray(raw);bad[start+8]^=1
        prefix=folder_prefix(io.BytesIO(bad),len(bad),[],info['folders'][0]);self.assertFalse(prefix['blocks']);self.assertIn('checksum',prefix['stopped_reason'])
        prefix=folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0],maximum_encoded=1);self.assertFalse(prefix['blocks']);self.assertIn('bound',prefix['stopped_reason'])
        with self.assertRaises(ValueError):folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0],maximum_encoded=0)

    def test_changed_source_is_rechecked_before_decoder_input(self):
        raw,start,blocks=fixture();info=metadata(io.BytesIO(raw),len(raw));prefix=folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0]);members=prefix_members(info,prefix);bad=bytearray(raw);bad[start+8]^=1
        with self.assertRaises(ValueError):write_prefix_cabinet(io.BytesIO(bad),len(bad),[],prefix,members,io.BytesIO())

    def test_optional_zero_checksum_retains_known_source_without_claiming_crc(self):
        raw,start,blocks=fixture();raw=bytearray(raw);struct.pack_into('<I',raw,start,0);info=metadata(io.BytesIO(raw),len(raw));prefix=folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0])
        self.assertEqual(len(prefix['blocks']),2);self.assertFalse(prefix['blocks'][0]['original_checksum_present']);self.assertTrue(prefix['blocks'][1]['original_checksum_present'])

    def test_bad_checksum_decoder_input_preserves_explicit_uncertainty(self):
        raw,start,blocks=fixture();raw=bytearray(raw);raw[start+len(blocks[0])+8]^=1;info=metadata(io.BytesIO(raw),len(raw));prefix=folder_prefix(io.BytesIO(raw),len(raw),[],info['folders'][0],allow_bad_checksums=True);members=prefix_members(info,prefix)
        self.assertTrue(members[0]['original_block_checksums_agree']);self.assertFalse(members[1]['original_block_checksums_agree'])
        output=io.BytesIO();write_prefix_cabinet(io.BytesIO(raw),len(raw),[],prefix,members,output);generated=output.getvalue();new=metadata(io.BytesIO(generated),len(generated));position=new['folders'][0]['data_offset']+len(blocks[0])
        self.assertEqual(generated[position:position+4],bytes(4));self.assertEqual(generated[position+4:],raw[start+len(blocks[0])+4:])
