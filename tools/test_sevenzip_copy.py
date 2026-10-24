import collections,io,json,pathlib,tempfile,unittest,zlib
import py7zr
from sevenzip_copy import copy_members
from rescue_sevenzip_members import export_members,member_parts


class SevenZipCopyTests(unittest.TestCase):
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
