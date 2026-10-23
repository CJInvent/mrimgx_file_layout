"""Bounded local ZIP member nominations when original directory bytes are lost.

Headers nominate only. Callers must independently decode/CRC-check payloads and
retain the uncertainty of historical directory membership; never authorize a
filesystem write from a local header.
"""
import collections
import hashlib
import struct
from zip_directory import known


def local_members(stream,size,holes=(),maximum_scan_bytes=256*1024**2):
    if maximum_scan_bytes<1:raise ValueError('local-header scan bound must be positive')
    amount=min(size,maximum_scan_bytes);stream.seek(0);raw=stream.read(amount)
    if len(raw)!=amount:raise ValueError('short archive local-header scan')
    result=[];skips=collections.Counter();pos=0;candidates=0
    while True:
        pos=raw.find(b'PK\x03\x04',pos)
        if pos<0:break
        offset=pos;pos+=4
        if offset+30>len(raw) or not known(holes,offset,offset+30):skips['unknown-or-truncated-fixed-header']+=1;continue
        _,needed,flags,method,tm,dt,crc,compressed,length,names,extra=struct.unpack_from('<4s5H3I2H',raw,offset);candidates+=1
        if flags&1:skips['encrypted']+=1;continue
        if flags&8:skips['data-descriptor-without-directory']+=1;continue
        if method not in (0,8):skips['unsupported-compression-method']+=1;continue
        body=offset+30+names+extra
        if not names or body>size or not known(holes,offset,body):skips['unknown-or-invalid-variable-header']+=1;continue
        stream.seek(offset);header=stream.read(body-offset)
        if len(header)!=body-offset:skips['short-variable-header']+=1;continue
        name_raw=header[30:30+names]
        try:
            if b'\0' in name_raw:raise ValueError('NUL in local member name')
            name=name_raw.decode('utf-8' if flags&0x800 else 'cp437')
            if length==0xffffffff or compressed==0xffffffff:
                fields=header[30+names:];cursor=0;zip64=None
                while cursor+4<=len(fields):
                    kind,n=struct.unpack_from('<HH',fields,cursor);cursor+=4
                    if cursor+n>len(fields):raise ValueError('invalid local extra bounds')
                    if kind==1:
                        if zip64 is not None:raise ValueError('duplicate local ZIP64 size field')
                        zip64=fields[cursor:cursor+n]
                    cursor+=n
                if zip64 is None:raise ValueError('local ZIP64 sizes unavailable')
                cursor=0
                if length==0xffffffff:length=struct.unpack_from('<Q',zip64,cursor)[0];cursor+=8
                if compressed==0xffffffff:compressed=struct.unpack_from('<Q',zip64,cursor)[0]
        except (ValueError,UnicodeError,struct.error):skips['invalid-name-or-zip64-sizes']+=1;continue
        if body+compressed>size:skips['member-exceeds-original-file']+=1;continue
        if name.endswith('/'):continue
        result.append(dict(key=(name,crc,length,compressed,method),start=body,stop=body+compressed,local_header_offset=offset,local_header_bytes=len(header),local_header_sha256=hashlib.sha256(header).hexdigest(),directory_membership_proven=False))
    return result,dict(scan_bytes=amount,scan_bound_reached=amount<size,candidate_headers=candidates,nominated_members=len(result),skipped=dict(skips))
