"""Strict single-disk ZIP/ZIP64 directory bounds from known original bytes."""
import struct
import pathlib

ARCHIVES={'.zip','.docx','.xlsx','.xlsb','.pptx','.docm','.xlsm','.pptm','.jar','.vsix','.nupkg','.appx','.msix','.odt','.ods','.odp','.epub','.whl','.apk','.xpi'}


def known(holes, start, end):
    return not any(lo < end and hi > start for lo, hi, *_ in holes)


def archive_nomination(ctx, record, path=''):
    """Bounded content nomination only; unknown placeholders never count."""
    if pathlib.PureWindowsPath(path).suffix.casefold() in ARCHIVES:return 'filename-suffix'
    if getattr(record.header,'Flags',1)&2:return None
    size=record.size()
    if size<4:return None
    holes=[] if getattr(record,'resident',False) else ctx.holes(record)
    stream=record.open();head=stream.read(4)
    if known(holes,0,4) and head==b'PK\x03\x04':return 'known-local-header'
    start=max(0,size-65557);stream.seek(start);tail=stream.read(size-start);end=tail.rfind(b'PK\x05\x06')
    while end>=0:
        if end+22<=len(tail) and start+end+22+struct.unpack_from('<H',tail,end+20)[0]<=size and known(holes,start+end,size):return 'known-end-record'
        end=tail.rfind(b'PK\x05\x06',0,end)
    return None


def directory_bounds(stream, size, holes=(), maximum_directory_bytes=128*1024**2, *, allow_prefix=False):
    start=max(0,size-65557);stream.seek(start);tail=stream.read(size-start);end=tail.rfind(b'PK\x05\x06')
    fallback=None
    while end>=0:
        if end+22<=len(tail):
            fields=struct.unpack_from('<4s4H2IH',tail,end)
            if start+end+22+fields[-1]==size:break
            if allow_prefix and fallback is None and start+end+22+fields[-1]<size:fallback=end
        end=tail.rfind(b'PK\x05\x06',0,end)
    if end<0 and fallback is not None:end=fallback;fields=struct.unpack_from('<4s4H2IH',tail,end)
    if end<0:raise ValueError('archive end record unavailable')
    _,disk,cd_disk,nd,n,cd_size,cd_off,comment=fields;eof=start+end
    if disk or cd_disk or not known(holes,eof,size):raise ValueError('unsupported split archive or unknown end record')
    directory_end=eof;kind='zip';prefix=0
    stream.seek(max(0,eof-20));has_locator=eof>=20 and stream.read(4)==b'PK\x06\x07'
    if nd!=n or n==65535 or cd_size==0xffffffff or cd_off==0xffffffff or has_locator:
        locator_start=eof-20
        if locator_start<0 or not known(holes,locator_start,eof):raise ValueError('ZIP64 locator unavailable')
        stream.seek(locator_start);locator=stream.read(20)
        if len(locator)!=20 or locator[:4]!=b'PK\x06\x07':raise ValueError('ZIP64 locator unavailable')
        _,locator_disk,record_start,disks=struct.unpack('<4sIQI',locator)
        if locator_disk or disks!=1 or record_start+56>locator_start or not known(holes,record_start,locator_start):raise ValueError('unsupported/unknown ZIP64 end bounds')
        stream.seek(record_start);raw=stream.read(56)
        if len(raw)!=56:raise ValueError('short ZIP64 end record')
        sig,length,made,needed,disk64,cd_disk64,nd64,n64,size64,off64=struct.unpack('<4sQ2H2I4Q',raw)
        if sig!=b'PK\x06\x06' or length<44 or record_start+12+length!=locator_start or disk64 or cd_disk64 or nd64!=n64:raise ValueError('invalid/split ZIP64 end record')
        if any(old!=marker and old!=new for old,marker,new in ((nd,65535,nd64),(n,65535,n64),(cd_size,0xffffffff,size64),(cd_off,0xffffffff,off64))):raise ValueError('ZIP64 and legacy end fields disagree')
        n,cd_size,cd_off=n64,size64,off64;directory_end=record_start;kind='zip64'
    elif allow_prefix and cd_off+cd_size<directory_end:
        prefix=directory_end-cd_size-cd_off;cd_off+=prefix
        stream.seek(cd_off)
        if stream.read(4)!=b'PK\x01\x02':raise ValueError('prefixed archive directory unavailable')
    if cd_size>maximum_directory_bytes or cd_off+cd_size!=directory_end or n>cd_size//46:raise ValueError('unsupported/invalid archive directory bounds')
    if not known(holes,cd_off,size):raise ValueError('original archive directory intersects missing bytes')
    return dict(entries=n,directory_offset=cd_off,directory_bytes=cd_size,end_record_offset=eof,directory_format=kind,prefix_bytes=prefix,trailing_bytes=size-eof-22-comment)
