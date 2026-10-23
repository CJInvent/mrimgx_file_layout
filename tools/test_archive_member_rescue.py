import io,unittest,zlib
from rescue_archive_members import decode_member


class ArchiveMemberRescueTests(unittest.TestCase):
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
