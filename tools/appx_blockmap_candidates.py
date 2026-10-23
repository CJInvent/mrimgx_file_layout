"""Revalidate source-backed, signature-bound block maps before using their hashes."""
import hashlib,json,pathlib
from appx_signature_hashes import verify_binding


def validated_candidate(path,reader,fs,decode):
    meta=json.loads(path.with_suffix(path.suffix+'.json').read_text())
    if meta.get('kind')!='whole-file-hash-candidate':raise ValueError('not a reconstructed whole-file candidate')
    evidence=[e for e in meta.get('hash_evidence',[]) if isinstance(e.get('hash_source'),dict) and e['hash_source'].get('kind')=='original-appx-signature-file-hash' and e['hash_source'].get('part')=='AXBM']
    if not evidence:raise ValueError('candidate lacks original Appx block map binding')
    if path.stat().st_size>4*1024**2:raise ValueError('candidate block map exceeds bound')
    data=path.read_bytes();sha=hashlib.sha256(data).hexdigest()
    if sha!=meta['sha256']:raise ValueError('candidate block map content changed')
    for e in evidence:
        binding=e['hash_source'];record=fs.mft.get(binding['target_record'])
        if e['algorithm']!='sha256' or e['expected_digest']!=sha or len(data)!=record.size():raise ValueError('candidate block map size/digest differs')
        verify_binding(reader,record,binding,'sha256',sha,fs)
        reconstructed=bytearray(record.open().read())
        if len(reconstructed)!=len(data):raise ValueError('short original block map template')
        for piece in meta.get('provenance',[]):
            off=piece['frame_offset'];logical=piece['file_offset'];n=piece['length']
            if off<0 or logical<0 or n<=0 or logical+n>len(data) or not 0<piece['encoded_bytes']<=4*1024**2:raise ValueError('candidate source piece bounds')
            decoded=decode(piece['source_offset'],piece['encoded_bytes'])
            if len(decoded)>4*1024**2 or off+n>len(decoded) or hashlib.sha256(decoded).hexdigest()!=piece['frame_sha256'] or hashlib.md5(decoded).hexdigest()!=piece['decoded_md5']:raise ValueError('candidate original source piece differs')
            reconstructed[logical:logical+n]=decoded[off:off+n]
        if bytes(reconstructed)!=data:raise ValueError('block map candidate does not reconstruct from original source and filesystem bytes')
    binding=evidence[0]['hash_source']
    return binding['target_path'].casefold(),dict(data=data,candidate_path=str(path.resolve()),binding=binding)


def validate_anchor(raw,anchor,record,base,stride):
    import base64,xml.etree.ElementTree as ET
    from recover_duplicate_files import file_extents
    if b'<!DOCTYPE' in raw.upper():raise ValueError('unsupported block map DTD')
    root=ET.fromstring(raw)
    if not root.attrib.get('HashMethod','').endswith('sha256'):raise ValueError('unexpected block map hash method')
    name=anchor['filename'].replace('/','\\');path=anchor['package']+'\\'+name
    if path.casefold() not in {p.casefold() for p in record.full_paths(ignore_dos=True)}:raise ValueError('Appx anchor original file path differs')
    nodes=[node for node in root if node.tag.endswith('File') and node.attrib.get('Name','').replace('/','\\').casefold()==name.casefold()]
    if len(nodes)!=1 or int(nodes[0].attrib['Size'])!=record.size():raise ValueError('Appx block map original file size/name differs')
    logical=anchor['logical_offset'];blocks=[node for node in nodes[0] if node.tag.endswith('Block')]
    if logical<0 or logical%65536 or logical//65536>=len(blocks):raise ValueError('Appx anchor logical block bounds')
    digest=base64.b64decode(blocks[logical//65536].attrib['Hash'],validate=True)
    if len(digest)!=32 or digest.hex()!=anchor['digest']:raise ValueError('Appx anchor digest absent from verified block map')
    length=min(65536,record.size()-logical);projections=[physical+logical-start for start,physical,n in file_extents(record,record.size()) if start<=logical and logical+length<=start+n]
    if len(projections)!=1:raise ValueError('Appx block map original runlist projection differs')
    address=projections[0];lo=max(address,base);hi=min(address+length,base+stride)
    if hi<=lo or anchor['frame_offset']!=lo-base or anchor['length']!=hi-lo:raise ValueError('Appx anchored piece lies outside original runlist')
    return logical,length,digest.hex()
