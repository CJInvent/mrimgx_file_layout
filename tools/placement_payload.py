"""Validate source frames, optional one-bit repairs and bounded file slices."""
import hashlib,pathlib
import zstandard


def assemble_source_parts(source,parts,size):
    if not 0<size<=4*1024**2 or not 0<len(parts)<=256:raise ValueError('reconstructed source-parts bounds')
    out=bytearray(size);cursor=0
    for p in sorted(parts,key=lambda p:p['target_offset']):
        start=p['target_offset'];off=p['decoded_offset'];n=p['length'];decoded_length=p['decoded_length']
        if start!=cursor or n<=0 or off<0 or off+n>decoded_length or start+n>size or not 0<decoded_length<=4*1024**2:raise ValueError('reconstructed source parts overlap, leave gaps or exceed bounds')
        frame=dict(source_offset=p['source_offset'],stored_length=p['stored_length'],length=decoded_length,decoded_md5=p['decoded_md5'],sha256=p['decoded_sha256'])
        if p.get('encoded_bit_repair'):frame['encoded_bit_repair']=p['encoded_bit_repair']
        decoded=payload(source,frame);out[start:start+n]=decoded[off:off+n];cursor=start+n
    if cursor!=size:raise ValueError('reconstructed source-parts incomplete coverage')
    return bytes(out)


def payload(source,mapping):
    if mapping.get('source_encoding')=='original-index-md5-source-parts':
        out=assemble_source_parts(source,mapping['source_parts'],mapping['length'])
        if hashlib.md5(out).hexdigest()!=mapping['decoded_md5'] or hashlib.sha256(out).hexdigest()!=mapping['sha256']:raise ValueError('reconstructed original-index frame digest/coverage differs')
        return out
    if mapping.get('source_encoding') not in (None,'zstd'):raise ValueError('unsupported source payload encoding')
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
