import copy,hashlib,io,json,pathlib,struct,tempfile,unittest
from types import SimpleNamespace as NS
import zstandard
from indexed_donor_reconstruction import OriginalIndex,SourceParts,analysis_manifest
from placement_payload import payload,assemble_source_parts
from verify_index_catalog import compare as compare_index_catalog,expected_rows


def fixture():
    bodies=[bytes(range(64)),bytes(reversed(range(64)))];encoded=[zstandard.ZstdCompressor().compress(b) for b in bodies];raw=bytearray(2048);parts=[]
    for i,(body,data) in enumerate(zip(bodies,encoded)):
        position=512*(i+1);raw[position:position+len(data)]=data;parts.append(dict(source_offset=position,stored_length=len(data),decoded_length=len(body),decoded_md5=hashlib.md5(body).hexdigest(),decoded_sha256=hashlib.sha256(body).hexdigest(),target_offset=i*8,decoded_offset=3 if i==0 else 5,length=8))
    expected=bodies[0][3:11]+bodies[1][5:13];struct.pack_into('<Q16sIH',raw,60,100000,hashlib.md5(expected).digest(),123,0)
    index=OriginalIndex.__new__(OriginalIndex);index.stream=io.BytesIO(raw);index.plan={'partitions':[{}, {},dict(count=8,entries_offset=0,entries_md5=hashlib.md5(raw[:240]).hexdigest())]};index.layout={'disks':[{'partitions':[{}, {},dict(_header=dict(block_size=16),_geometry=dict(start=4096,length=128))]}]}
    mapping=dict(partition=2,reserved=False,block=2,disk_offset=4128,length=16,source_offset=512,stored_length=len(encoded[0]),source_encoding='original-index-md5-source-parts',decoded_md5=hashlib.md5(expected).hexdigest(),sha256=hashlib.sha256(expected).hexdigest(),source_parts=parts,evidence=[dict(method='original-index-md5-source-parts-reconstruction',original_index=index.entry(2),nomination=dict(kind='test-metadata-only'))])
    return bytes(raw),expected,index,mapping


class IndexedReconstructionTests(unittest.TestCase):
    def test_original_catalog_handles_empty_reserved_arrays_and_overrides(self):
        raw=bytes(30)+struct.pack('<q16sIH',100,b'x'*16,50,0);part=dict(_header=dict(block_size=16),_geometry=dict(start=4096,length=32),_file_system={});spec=dict(count=2,entries_offset=0,reserved_count=0,reserved_offset=0)
        rows=list(expected_rows(io.BytesIO(raw),len(raw),dict(partitions=[spec]),dict(disks=[dict(partitions=[part])]),set()))
        self.assertEqual(rows,[(0,0,1,4112,16,100,50,b'x'*16,1)])
        spec['overrides']={'1':{'source_offset':2}}
        self.assertEqual(list(expected_rows(io.BytesIO(raw),len(raw),dict(partitions=[spec]),dict(disks=[dict(partitions=[part])]),set()))[0][-1],0)

    def test_cached_catalog_omitted_or_changed_entries_rejected(self):
        rows=[(0,0,1,2,3,4,5,b'a',1),(0,0,2,3,4,5,6,b'b',0)]
        self.assertEqual(compare_index_catalog(iter(rows),iter(rows))['verified_entries'],2)
        for changed in [rows[:1],rows+[rows[-1]],[rows[-1],rows[0]]]:
            with self.assertRaises(ValueError):compare_index_catalog(iter(rows),iter(changed))

    def test_original_target_digest_authorizes_only_exact_source_part_bytes(self):
        raw,expected,index,mapping=fixture();self.assertEqual(index.validate(mapping),expected);self.assertEqual(payload(io.BytesIO(raw),mapping),expected)
        changed=copy.deepcopy(mapping);changed['source_parts'][0]['decoded_offset']+=1
        with self.assertRaises(ValueError):index.validate(changed)
        self.assertEqual(index.stream.getvalue(),raw)

    def test_target_address_and_original_index_bytes_are_independently_checked(self):
        raw,expected,index,mapping=fixture();changed=copy.deepcopy(mapping);changed['disk_offset']+=16
        with self.assertRaises(ValueError):index.validate(changed)
        corrupted=bytearray(raw);corrupted[68]^=1;index.stream=io.BytesIO(corrupted)
        with self.assertRaises(ValueError):index.validate(mapping)

    def test_source_parts_reject_changed_sources_gaps_and_overlaps(self):
        raw,expected,index,mapping=fixture();parts=copy.deepcopy(mapping['source_parts']);parts[1]['target_offset']=9
        with self.assertRaises(ValueError):assemble_source_parts(io.BytesIO(raw),parts,16)
        parts[1]['target_offset']=7
        with self.assertRaises(ValueError):assemble_source_parts(io.BytesIO(raw),parts,16)
        parts=copy.deepcopy(mapping['source_parts']);parts[0]['decoded_sha256']='00'*32
        with self.assertRaises(ValueError):assemble_source_parts(io.BytesIO(raw),parts,16)

    def test_known_reconstruction_parts_flatten_without_cached_donor_bytes(self):
        raw,expected,index,mapping=fixture();ctx=NS(origin=4096,stride=16);resolver=SourceParts(ctx,index,[mapping]);parts=resolver.physical(36,8,0)
        self.assertEqual(assemble_source_parts(io.BytesIO(raw),parts,8),expected[4:12]);self.assertEqual(mapping['source_parts'][0]['target_offset'],0);self.assertEqual(mapping['source_parts'][1]['target_offset'],8)

    def test_analysis_manifest_marks_only_exact_materialized_slices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary);original=root/'original';output=root/'analysis';rows=[dict(operation='range',partition=2,disk_offset=100,length=100,status='unknown-zero-index'),dict(operation='complete')];content=''.join(json.dumps(r)+'\n' for r in rows);original.write_text(content)
            analysis_manifest(original,[dict(partition=2,disk_offset=120,length=20)],output);result=list(map(json.loads,output.read_text().splitlines()))
            self.assertEqual([(r['disk_offset'],r['length']) for r in result[:-1]],[(100,20),(120,20),(140,60)]);self.assertEqual(result[0]['status'],'unknown-zero-index');self.assertEqual(result[1]['status'],'recovered-original-index-md5-source-parts');self.assertEqual(result[2]['status'],'unknown-zero-index');self.assertEqual(original.read_text(),content)

    def test_cached_reconstruction_files_do_not_supply_payload_authority(self):
        raw,expected,index,mapping=fixture();mapping['cached_decoded_path']='this-file-does-not-exist';self.assertEqual(index.validate(mapping),expected)
