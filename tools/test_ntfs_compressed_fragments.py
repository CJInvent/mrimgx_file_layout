import os,struct,unittest
from ntfs_compressed_fragments import decode_unit,compressed_units


@unittest.skipUnless(os.name=='nt','Native bounded LZNT1 decoder requires Windows')
class NtfsCompressedFragmentTests(unittest.TestCase):
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
