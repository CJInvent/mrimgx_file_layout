"""Validate source frames, optional one-bit repairs and bounded file slices."""
import hashlib,pathlib
import zstandard


def payload(source,mapping):
    source.seek(mapping['source_offset']);original=source.read(mapping['stored_length'])
    if len(original)!=mapping['stored_length']:raise ValueError('short encoded source frame')
    encoded=original;repair=mapping.get('encoded_bit_repair')
    if repair:
        encoded=pathlib.Path(repair['encoded_path']).read_bytes()
        if hashlib.sha256(original).hexdigest()!=repair['original_encoded_sha256'] or hashlib.sha256(encoded).hexdigest()!=repair['repaired_encoded_sha256'] or len(original)!=len(encoded):raise ValueError('encoded repair provenance differs')
        if sum((a^b).bit_count() for a,b in zip(original,encoded))!=1:raise ValueError('repair is not exactly one original encoded-bit change')
    decoder=zstandard.ZstdDecompressor().decompressobj();data=decoder.decompress(encoded);full_length=mapping.get('source_decoded_length',mapping['length']);full_md5=mapping.get('source_decoded_md5',mapping['decoded_md5']);full_sha=mapping.get('source_decoded_sha256',mapping['sha256'])
    if not decoder.eof or decoder.unused_data or len(data)!=full_length or hashlib.md5(data).hexdigest()!=full_md5 or hashlib.sha256(data).hexdigest()!=full_sha:raise ValueError('source frame payload hashes/length differ')
    start=mapping.get('decoded_slice_offset',0);stop=start+mapping['length']
    if not 0<=start<stop<=len(data):raise ValueError('source slice outside decoded frame')
    result=data[start:stop]
    if hashlib.md5(result).hexdigest()!=mapping['decoded_md5'] or hashlib.sha256(result).hexdigest()!=mapping['sha256']:raise ValueError('source slice hashes differ')
    return result
