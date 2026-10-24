import collections,io,json,pathlib,tempfile,unittest,zlib
import py7zr
from sevenzip_copy import copy_members
from rescue_sevenzip_members import export_members,member_parts


class SevenZipCopyTests(unittest.TestCase):
    def test_boundary_candidate_cache_preserves_gaps_and_rejects_overlap(self):
        from indexed_boundary_donors import candidate_bytes
        self.assertEqual(candidate_bytes([(7,b'XY'),(2,b'abc')],12),b'\0\0abc\0\0XY\0\0\0')
        for chunks in ([(2,b'abc'),(4,b'zz')],[(11,b'xx')],[(-1,b'x')]):
            with self.assertRaises(ValueError):candidate_bytes(chunks,12)

    def test_joint_file_tail_parts_keep_offsets_and_explicit_source_padding(self):
        from indexed_boundary_donors import padded_parts
        zero=dict(source_offset=100,decoded_offset=0,decoded_length=100,length=100,target_offset=0)
        parts=[dict(zero,source_offset=200,target_offset=20,decoded_offset=5,length=10),dict(zero,source_offset=300,target_offset=60,decoded_offset=7,length=15)]
        result=padded_parts(parts,zero,100);self.assertEqual([(p['target_offset'],p['length']) for p in result],[(0,20),(20,10),(30,30),(60,15),(75,25)])
        self.assertEqual(result[1]['decoded_offset'],5)
        with self.assertRaises(ValueError):padded_parts(parts+[dict(zero,target_offset=25,length=20)],zero,100)

    def test_record_without_default_stream_is_expected_discovery(self):
        from unittest import mock
        from rescue_sevenzip_members import main
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);inventory=root/'inventory.jsonl';inventory.write_text('{"record":9}\n');record=mock.Mock();record.header.Flags=1;record.size.side_effect=FileNotFoundError('No default DATA stream');context=mock.Mock();context.fs.mft.get.return_value=record
            arguments=SimpleNamespace(source=root/'source',baseline=root/'baseline',mft=root/'mft',inventory=inventory,manifest=root/'manifest',evidence=root/'evidence',mapping_directory=root/'mapping',output=root/'output',maximum_total_bytes=1000)
            with mock.patch('rescue_sevenzip_members.argparse.ArgumentParser.parse_args',return_value=arguments),mock.patch('rescue_sevenzip_members.Context',return_value=context):main()
            self.assertTrue((arguments.output/'summary.json').is_file());context.close.assert_called_once()

    def fixture(self,method=py7zr.FILTER_COPY):
        output=io.BytesIO()
        with py7zr.SevenZipFile(output,'w',filters=[dict(id=method)]) as archive:
            archive.writestr(b'first contents'*40,'sub/original-name.bin');archive.writestr(b'second contents'*40,'sub/second.bin')
        return output.getvalue()

    def test_exact_copy_offsets_and_safe_export(self):
        data=self.fixture();members,proof=copy_members(io.BytesIO(data),len(data));self.assertEqual(len(members),2);self.assertTrue(proof['metadata_reads'])
        for member in members:self.assertEqual(zlib.crc32(data[member['start']:member['stop']]),member['key'][1])
        with tempfile.TemporaryDirectory() as directory:
            folder=pathlib.Path(directory)/'exports';counts=collections.Counter();self.assertFalse(export_members(io.BytesIO(data),len(data),[],dict(archive_record=1),folder,counts,10000));self.assertEqual(counts['valid_members'],2);self.assertFalse((pathlib.Path(directory)/'original-name.bin').exists())

    def test_unknown_body_split_never_joined_or_validated(self):
        data=self.fixture();members,_=copy_members(io.BytesIO(data),len(data));hole=(members[0]['start']+10,members[0]['start']+20,0)
        with tempfile.TemporaryDirectory() as directory:
            folder=pathlib.Path(directory)/'exports';counts=collections.Counter();export_members(io.BytesIO(data),len(data),[hole],dict(archive_record=1),folder,counts,10000)
            parts=[json.loads(p.read_text()) for p in folder.glob('0-*.bin.json')];self.assertEqual(len(parts),2);self.assertTrue(all(not p['valid'] and not p['complete_original_member'] for p in parts));self.assertEqual(sorted(p['logical_member_offset'] for p in parts),[0,20])

    def test_unknown_or_corrupt_header_rejected(self):
        data=self.fixture()
        with self.assertRaises(ValueError):copy_members(io.BytesIO(data),len(data),[(12,14,0)])
        corrupt=bytearray(data);corrupt[12]^=1
        with self.assertRaises(Exception):copy_members(io.BytesIO(corrupt),len(data))

    def test_compressed_folder_never_treated_as_copy(self):
        data=self.fixture(py7zr.FILTER_LZMA2);members,proof=copy_members(io.BytesIO(data),len(data));self.assertEqual(members,[]);self.assertTrue(proof['unsupported_folders'])

    def test_interval_subtraction_and_budget(self):
        self.assertEqual(list(member_parts(10,30,[(0,11,0),(14,20,0),(18,25,0)])),[(11,14),(25,30)])
        data=self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            counts=collections.Counter();self.assertTrue(export_members(io.BytesIO(data),len(data),[],dict(archive_record=1),pathlib.Path(directory)/'exports',counts,1));self.assertEqual(counts['exported_bytes'],0)
