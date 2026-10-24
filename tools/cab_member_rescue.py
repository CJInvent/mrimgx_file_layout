"""Source-known CAB folder prefixes for external member rescue.

Original metadata and every compressed block must be known. A generated cabinet
contains only those blocks, with generated member names. It is a decoder input,
never a replacement for the original cabinet or authority for VHDX placement.
"""
import hashlib
import re
import struct
from extend_cab_mappings import checksum
from zip_directory import known


def read_known(stream,size,holes,offset,length):
    if offset<0 or length<0 or offset+length>size or not known(holes,offset,offset+length):
        raise ValueError('CAB metadata or compressed bytes intersect unknown source')
    stream.seek(offset);data=stream.read(length)
    if len(data)!=length:raise ValueError('short CAB source read')
    return data


def metadata(stream,size,holes=()):
    header=read_known(stream,size,holes,0,36)
    if header[:4]!=b'MSCF':raise ValueError('CAB signature unavailable')
    cabinet_bytes=struct.unpack_from('<I',header,8)[0];table=struct.unpack_from('<I',header,16)[0]
    folders,files,flags=struct.unpack_from('<HHH',header,26)
    if not 36<=cabinet_bytes<=size or header[24:26]!=b'\x03\x01' or not folders or flags&~4:
        raise ValueError('unsupported CAB version, split cabinet or bounds')
    cursor=36;folder_reserve=data_reserve=0
    if flags&4:
        reserve,folder_reserve,data_reserve=struct.unpack('<HBB',read_known(stream,size,holes,cursor,4));cursor+=4+reserve
    if data_reserve:raise ValueError('per-CFDATA reserve area is not supported for rescue')
    rows=[]
    for number in range(folders):
        raw=read_known(stream,size,holes,cursor,8+folder_reserve);start,count,compression=struct.unpack_from('<IHH',raw)
        if start>=cabinet_bytes or not count or compression&15 not in (0,1,3):raise ValueError('unsupported CAB compression or folder bounds')
        rows.append(dict(index=number,data_offset=start,blocks=count,compression=compression));cursor+=len(raw)
    if not cursor<=table<min(r['data_offset'] for r in rows):raise ValueError('CAB file table overlaps folder data')
    entries=[];cursor=table
    for number in range(files):
        start=cursor;raw=read_known(stream,size,holes,cursor,16);cursor+=16;name=bytearray()
        for _ in range(4096):
            char=read_known(stream,size,holes,cursor,1);cursor+=1
            if char==b'\0':break
            name.extend(char)
        else:raise ValueError('CAB filename exceeds rescue bound')
        length,offset,folder,date,time,attributes=struct.unpack('<II4H',raw)
        if folder>=folders:raise ValueError('continued CAB member requires another cabinet')
        if cursor>min(r['data_offset'] for r in rows):raise ValueError('CAB filename overlaps folder data')
        entries.append(dict(index=number,name=name.decode('utf-8' if attributes&128 else 'cp1252',errors='replace'),name_bytes=name.hex(),size=length,folder=folder,folder_offset=offset,date=date,time=time,attributes=attributes,source_entry_offset=start,source_entry_bytes=cursor-start,source_entry_sha256=hashlib.sha256(raw+name+b'\0').hexdigest()))
    original=read_known(stream,size,holes,0,cursor)
    return dict(cabinet_bytes=cabinet_bytes,folders=rows,members=entries,original_metadata_bytes=cursor,original_metadata_sha256=hashlib.sha256(original).hexdigest())


def folder_prefix(stream,size,holes,folder,maximum_encoded=1024**3,maximum_decoded=2*1024**3,*,allow_bad_checksums=False):
    if min(maximum_encoded,maximum_decoded)<1:raise ValueError('CAB prefix bounds must be positive')
    position=folder['data_offset'];blocks=[];decoded=0;digest=hashlib.sha256();reason=None;untrusted=None
    for index in range(folder['blocks']):
        try:
            raw=read_known(stream,size,holes,position,8);expected,stored,expanded=struct.unpack('<IHH',raw)
            if not stored or not 0<expanded<=32768:raise ValueError('CAB split or invalid data block')
            if position+8+stored-folder['data_offset']>maximum_encoded or decoded+expanded>maximum_decoded:
                reason='CAB folder prefix search/output bound reached';break
            raw+=read_known(stream,size,holes,position+8,stored)
            actual=checksum(raw[4:]);valid=not expected or actual==expected
            if not valid and not allow_bad_checksums:raise ValueError('CAB original block checksum mismatched')
        except ValueError as error:reason=str(error);break
        if not valid and untrusted is None:untrusted=decoded
        digest.update(raw);blocks.append(dict(index=index,source_offset=position,bytes=len(raw),decoded_bytes=expanded,original_checksum=expected,actual_checksum=actual,original_checksum_present=bool(expected),original_checksum_valid=valid));position+=len(raw);decoded+=expanded
    return dict(folder_index=folder['index'],compression=folder['compression'],blocks=blocks,source_start=folder['data_offset'],source_end=position,source_bytes=position-folder['data_offset'],source_sha256=digest.hexdigest(),decoded_prefix_bytes=decoded,checksum_trusted_decoded_end=decoded if untrusted is None else untrusted,all_original_folder_blocks_known=len(blocks)==folder['blocks'],stopped_reason=reason)


def prefix_members(info,prefix):
    result=[]
    for member in info['members']:
        if member['folder']!=prefix['folder_index']:continue
        available=max(0,min(member['size'],prefix['decoded_prefix_bytes']-member['folder_offset']))
        if not available and member['size']:continue
        result.append(dict(member,available_bytes=available,complete_original_member=available==member['size'],original_block_checksums_agree=member['folder_offset']+available<=prefix['checksum_trusted_decoded_end'],generated_name=f"member-{member['index']:05d}.bin"))
    return result


def write_prefix_cabinet(stream,size,holes,prefix,members,output):
    """Keep source compressed blocks unchanged; rewrite only decoder metadata."""
    if not prefix['blocks'] or not members:raise ValueError('CAB prefix has no recoverable members')
    entries=[]
    for member in members:
        if not re.fullmatch(r'member-\d{5}\.bin',member['generated_name']) or not 0<=member['available_bytes']<=member['size']:raise ValueError('generated CAB member name or size is not bounded')
        if member['folder_offset']+member['available_bytes']>prefix['decoded_prefix_bytes']:raise ValueError('member exceeds known decoded prefix')
        entries.append(struct.pack('<II4H',member['available_bytes'],member['folder_offset'],0,member['date'],member['time'],0x20)+member['generated_name'].encode('ascii')+b'\0')
    table=b''.join(entries);data_offset=44+len(table);total=data_offset+prefix['source_bytes']
    if total>0xffffffff or len(members)>65535 or len(prefix['blocks'])>65535:raise ValueError('generated CAB field bounds exceeded')
    header=struct.pack('<4s5I2B5H',b'MSCF',0,total,0,44,0,3,1,1,len(members),0,0,0)
    output.write(header+struct.pack('<IHH',data_offset,len(prefix['blocks']),prefix['compression'])+table)
    digest=hashlib.sha256()
    for block in prefix['blocks']:
        raw=read_known(stream,size,holes,block['source_offset'],block['bytes'])
        expected,stored,expanded=struct.unpack_from('<IHH',raw)
        if expected!=block['original_checksum'] or len(raw)!=8+stored or expanded!=block['decoded_bytes'] or checksum(raw[4:])!=block['actual_checksum']:raise ValueError('CAB source block changed before export')
        digest.update(raw)
        # A separate decoder input may bypass an already recorded bad checksum
        # to preserve uncertain output. Original compressed bytes stay exact;
        # source and original cabinet are never rewritten.
        output.write(raw if block['original_checksum_valid'] else bytes(4)+raw[4:])
    if digest.hexdigest()!=prefix['source_sha256']:raise ValueError('CAB source prefix changed before export')
