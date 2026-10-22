"""PE content identifiers corroborated by MFT runlists and embedded image digests.

Does not execute recovered code or claim certificate trust. The Authenticode
digest checks image content against the digest embedded in its signed message.
"""
from rebuild_audit import caught as _audit_caught
import collections
import hashlib
import struct


def image_digest(data, verify=True):
    import pefile
    from asn1crypto import algos, cms, core
    class Indirect(core.Sequence):
        _fields=[('data',core.Any),('message_digest',algos.DigestInfo)]
    pe=pefile.PE(data=data,fast_load=True)
    cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    offset,size=cert.VirtualAddress,cert.Size
    if not size or offset+size!=len(data):raise ValueError('missing certificate or unsupported overlay')
    n,revision,typ=struct.unpack_from('<IHH',data,offset)
    if typ!=2 or n>size or n<8:raise ValueError('certificate bounds/type')
    ci=cms.ContentInfo.load(data[offset+8:offset+n])
    encap=ci['content']['encap_content_info']
    if encap['content_type'].dotted!='1.3.6.1.4.1.311.2.1.4':raise ValueError('not SPC indirect content')
    # Older PKCS#7 uses an explicitly tagged ANY sequence; retain its contents
    # and restore only the universal outer SEQUENCE tag/length.
    raw=encap['content'].contents
    if len(raw)<128: encoded=bytes([48,len(raw)])+raw
    else:
        length=len(raw).to_bytes((len(raw).bit_length()+7)//8,'big')
        encoded=bytes([48,128+len(length)])+length+raw
    digest=Indirect.load(encoded)['message_digest']
    algorithm=digest['digest_algorithm']['algorithm'].native
    expected=digest['digest'].native
    checksum=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    security=cert.get_file_offset()
    # Restrict to conventional contiguous raw sections. For unusual layouts
    # do not substitute a naive byte-exclusion algorithm for Authenticode.
    end=pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in sorted(pe.sections,key=lambda s:s.PointerToRawData):
        if not section.SizeOfRawData:continue
        if section.PointerToRawData!=end:raise ValueError('noncontiguous PE sections')
        end+=section.SizeOfRawData
    if end>offset or not checksum+4<=security or security+8>end:raise ValueError('PE hash bounds')
    h=hashlib.new(algorithm)
    for chunk in (data[:checksum],data[checksum+4:security],data[security+8:offset]):h.update(chunk)
    if verify and h.digest()!=expected:raise ValueError('embedded Authenticode image digest mismatch')
    return dict(algorithm=algorithm,digest=expected.hex(),matches=h.digest()==expected,checksum_offset=checksum,security_offset=security,certificate_offset=offset)


def candidates(data, fs, names, stride, base_allowed):
    import pefile
    pages=[]; errors=[]
    for off in range(0,len(data)-256,4096):
        if data[off:off+2]!=b'MZ':continue
        try:
            pe=pefile.PE(data=data[off:],fast_load=True)
            pe.parse_data_directories(directories=[2])
            original=set()
            for group in getattr(pe,'FileInfo',[]):
                for info in group:
                    for table in getattr(info,'StringTable',[]):
                        value=table.entries.get(b'OriginalFilename')
                        if value:original.add(value.decode('utf-8',errors='strict').rstrip('\0').lower())
            cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            extent=max([pe.OPTIONAL_HEADER.SizeOfHeaders]+[s.PointerToRawData+s.SizeOfRawData for s in pe.sections]+[cert.VirtualAddress+cert.Size])
            matches=[]
            for name in original:
                for number in names.get(name,[]):
                    try:
                        r=fs.mft.get(number); runs=r.dataruns()
                        if not r.header.Flags&1 or r.is_dir() or not runs or runs[0][0] is None or r.size()!=extent:continue
                        if any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):continue
                        address=runs[0][0]*4096; base=address-off
                        if base<0 or base%stride or not base_allowed(base):continue
                        evidence=dict(record=number,sequence=r.header.SequenceNumber,filename=name,page_offset=off,size=extent)
                        # Reassemble the candidate file through all its extents,
                        # overlaying only bytes from this actual source frame.
                        if cert.Size:
                            stream=r.open(); filedata=bytearray(stream.read())
                            logical=0; outside=0
                            for lcn,count in runs:
                                nbytes=min(count*4096,max(0,extent-logical))
                                if lcn is not None:
                                    a=lcn*4096; lo=max(a,base); hi=min(a+nbytes,base+len(data))
                                    if hi>lo:filedata[logical+lo-a:logical+hi-a]=data[lo-base:hi-base]
                                logical+=count*4096
                            evidence['image_digest']=image_digest(bytes(filedata))
                        matches.append((base,evidence))
                    except Exception as ex:
                        _audit_caught(ex, None, expected=True, site='pe_anchors.py:90')
                        errors.append(dict(page_offset=off,record=number,error=str(ex)))
            if matches:pages.append(matches)
        except Exception as ex:
            _audit_caught(ex, None, expected=True, site='pe_anchors.py:92')
            errors.append(dict(page_offset=off,error=str(ex)))
    if not pages:return [],errors
    bases=set(b for b,_ in pages[0])
    for matches in pages[1:]:bases.intersection_update(b for b,_ in matches)
    if len(bases)!=1:return [],errors+[dict(error='PE anchors do not establish a unique common base')]
    base=bases.pop(); evidence=[e for matches in pages for b,e in matches if b==base]
    # One digest-bound file identity, or two separate PE file headers with
    # matching OriginalFilename and exact MFT lengths, at the same frame base.
    if not any('image_digest' in e for e in evidence) and len({e['page_offset'] for e in evidence})<2:
        return [],errors+[dict(error='single unsigned PE anchor insufficient')]
    return [(base,evidence)],errors
