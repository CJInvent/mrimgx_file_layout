import os,struct,unittest
import datetime
import gzip,hashlib,io,json,pathlib,tempfile
from types import SimpleNamespace
from unittest import mock
from enrich_recovered_metadata import enrich
from ntfs_compressed_fragments import decode_unit,compressed_units
from nominate_log_locations import filename_time,log_time,matching_names


class MetadataEnrichmentTests(unittest.TestCase):
    def test_final_enrichment_preserves_prior_typed_hints_and_uncertainty(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary);files=root/'recovered/files';files.mkdir(parents=True);body=gzip.compress(b'synthetic log data');target=files/'test.gz';target.write_bytes(body);hint=dict(record=77,sequence=4,evidence_kind='file-size-and-embedded-log-start-time-nomination',placement_confirmed=False,historical_path_binding_proven=False);side=files/'test.gz.json';side.write_text(json.dumps(dict(file_type='gz',bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),possible_locations=[hint],vhdx_insertion_authorized=False)));mft=root/'mft';mft.write_bytes(b'\0');inventory=root/'inventory';inventory.write_text('');layout=dict(disks=[dict(partitions=[{},{},dict(_geometry=dict(start=0,length=4096))])])
            def volume(*args):
                result=io.BytesIO(bytes(4096));result.fh=result;return result
            with mock.patch('enrich_recovered_metadata.VHDX',side_effect=volume),mock.patch('enrich_recovered_metadata.NTFS',side_effect=lambda *args:SimpleNamespace(mft=SimpleNamespace(),cluster_size=4096)),mock.patch('enrich_recovered_metadata.candidate_records',return_value=[]):
                enrich(root/'recovered',root/'baseline',mft,inventory,layout);enrich(root/'recovered',root/'baseline',mft,inventory,layout)
            result=json.loads(side.read_text());self.assertEqual(result['possible_locations'],[hint]);self.assertFalse(result['vhdx_insertion_authorized']);self.assertEqual(target.read_bytes(),body)


@unittest.skipUnless(os.name=='nt','Native bounded LZNT1 decoder requires Windows')
class NtfsCompressedFragmentTests(unittest.TestCase):
    def test_log_names_require_exact_size_and_embedded_start_second(self):
        name='StandaloneUpdate_2024-12-06_052959_123-456.loggz';start=datetime.datetime(2024,12,6,5,29,59)
        self.assertEqual(log_time('12/06/2024 05:29:59.468 Logger: test'.encode('utf-16-le')),start);self.assertEqual(filename_time(name),start)
        self.assertEqual(matching_names([name],1699,1699,start),[name]);self.assertEqual(matching_names([name],1698,1699,start),[]);self.assertEqual(matching_names([name],1699,1699,start+datetime.timedelta(seconds=1)),[])

    def test_invalid_log_metadata_cannot_nominate_a_location(self):
        self.assertIsNone(filename_time('StandaloneUpdate_2024-99-99_999999_1-2.loggz'));self.assertIsNone(log_time(b'not a timestamp'));self.assertEqual(matching_names(['unrelated.loggz'],1,1,None),[])

    def fixture(self):
        blocks=[bytes([i])*4096 for i in range(16)];encoded=b''.join(struct.pack('<H',0x3fff)+b for b in blocks)
        return encoded,b''.join(blocks)

    def test_sixteen_complete_chunks_decode_with_exact_encoded_boundary(self):
        encoded,expected=self.fixture();consumed,decoded=decode_unit(encoded+b'extra')
        self.assertEqual(consumed,len(encoded));self.assertEqual(decoded,expected)

    def test_truncated_invalid_and_incomplete_units_rejected(self):
        encoded,expected=self.fixture()
        for value in (encoded[:-1],encoded[:15*4098],b'\0\0'+encoded[2:]):
            with self.assertRaises(ValueError):decode_unit(value)

    def test_frame_scanning_retains_only_cluster_aligned_complete_sequences(self):
        encoded,expected=self.fixture();results=list(compressed_units(bytes(4096)+encoded+bytes(4096)))
        self.assertEqual(len(results),1);self.assertEqual(results[0],(4096,len(encoded),expected));self.assertEqual(list(compressed_units(b'x'+encoded)),[])
