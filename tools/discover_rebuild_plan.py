"""Discover index arrays from verified root geometry and corroborated boundaries.

Unverified/erased containers stay unverified. Sampled original decoded hashes
corroborate array alignment; the native converter must still check every entry.
No offsets or partition sizes are supplied by an operator.
"""
import argparse,hashlib,json,math,pathlib,struct
import zstandard
from forensic_residuals import root_layout,merge_ranges,complement
from make_recovery_plan import make_plan,read_at


def discover(source):
    layout=root_layout(source)
    if len(layout['disks'])!=1 or layout['_header']['backup_type']!='full' or layout['_encryption'].get('enable') or layout['_header'].get('split_file'):raise ValueError('discovery requires one unencrypted unsplit full image')
    size=source.stat().st_size;metadata=layout['_header']['index_file_position'];reports=[];specs=[]
    with source.open('rb') as f:
        def header(pos):return struct.unpack('<8sI16sB3x',read_at(f,pos,32,size))
        cursor=metadata
        # Strictly verify the disk metadata chain before using its boundary.
        for i in range(128):
            name,n,digest,flags=header(cursor)
            if (i==0 and name!=b'$TRACK0 ') or flags&4 or hashlib.md5(read_at(f,cursor+32,n,size)).digest()!=digest:raise ValueError('disk metadata boundary/hash')
            cursor+=32+n
            if flags&1:break
        else:raise ValueError('unterminated disk metadata')
        for pi,p in enumerate(layout['disks'][0]['partitions']):
            bitmap=cursor;name,n,digest,flags=header(bitmap)
            if name==b'$BITMAP ':
                if flags&4 or (n and hashlib.md5(read_at(f,bitmap+32,n,size)).digest()!=digest):raise ValueError('bitmap metadata hash/encryption')
                index=bitmap+32+n
            elif read_at(f,bitmap,32,size)==bytes(32):index=bitmap+32
            else:raise ValueError(f'partition {pi}: ambiguous bitmap boundary')
            name,n,digest,flags=header(index);count=p['_header']['block_count'];reserved=math.ceil(p['_file_system'].get('reserved_sectors_byte_length',0)/(4*1024**2));expected=8+30*(count+reserved)
            erased=read_at(f,index,32,size)==bytes(32)
            if not erased and (name!=b'$INDEX  ' or flags&6 or n!=expected):raise ValueError(f'partition {pi}: unsupported index header/length')
            payload=read_at(f,index+32,expected,size);verified=not erased and hashlib.md5(payload).digest()==digest
            rc=struct.unpack_from('<I',payload)[0];normal=4+reserved*30;nc=struct.unpack_from('<I',payload,normal)[0]
            if rc not in (0,reserved) or nc not in (0,count) or (verified and (rc!=reserved or nc!=count)):raise ValueError('index counters contradict verified root')
            entries=index+32+normal+4;raw=payload[normal+4:];available=[]
            for bi,(pos,md5,nbytes,fn) in enumerate(struct.iter_unpack('<q16sIH',raw)):
                if nbytes and not fn and 0<=pos<pos+nbytes<=metadata and md5!=bytes(16):available.append((bi,pos,md5,nbytes))
            # Spread checks over the array, including both independent ends.
            sample=[available[k] for k in sorted({i*(len(available)-1)//min(31,len(available)-1) for i in range(min(32,len(available)))})] if len(available)>1 else available
            valid=[]
            for bi,pos,md5,nbytes in sample:
                try:
                    decoder=zstandard.ZstdDecompressor().decompressobj();encoded=read_at(f,pos,nbytes,size);data=decoder.decompress(encoded)
                    if decoder.eof and not decoder.unused_data and 0<len(data)<=p['_header']['block_size'] and hashlib.md5(data).digest()==md5:valid.append(dict(block=bi,source_offset=pos,decoded_bytes=len(data),original_md5=md5.hex()))
                except Exception:continue
            end=index+32+expected
            if pi+1<len(layout['disks'][0]['partitions']):
                nextname=header(end)[0]
                if nextname!=b'$BITMAP ' and read_at(f,end,32,size)!=bytes(32):raise ValueError('next partition boundary does not corroborate array length')
            if erased and len(valid)<8:raise ValueError('erased index header lacks eight independent decoded original-hash corroborations')
            if not verified and available and len(valid)<min(8,len(sample)):raise ValueError('damaged index alignment lacks sufficient decoded original hashes')
            spec=dict(entries_offset=entries,reserved_count=reserved,reserved_offset=index+36 if reserved else 0,container_verified=verified)
            if verified:spec['header_offset']=index
            specs.append(spec);reports.append(dict(partition=pi,index_header_offset=index,index_header_erased=erased,container_verified=verified,decoded_original_hash_corroborations=valid,available_entries=len(available),next_boundary=end));cursor=end
    return make_plan(source,dict(partitions=specs)),dict(root_geometry_verified=True,partitions=reports,scope='Offsets inferred from metadata chains, declared counts, neighboring boundaries and sampled original content digests. Every entry is independently checked during native conversion; missing original digests remain missing.')


def bootstrap_boot(source,plan):
    """Locate absent NTFS boot frames in unindexed source gaps using root BPB data."""
    layout=root_layout(source);parts=layout['disks'][0]['partitions'];wanted=[];covered=[];size=source.stat().st_size;metadata=layout['_header']['index_file_position']
    with source.open('rb') as f:
        for pi,(p,spec) in enumerate(zip(parts,plan['partitions'])):
            raw=read_at(f,spec['entries_offset'],spec['count']*30,size)
            for pos,md5,n,fn in struct.iter_unpack('<q16sIH',raw):
                if n and not fn and 0<=pos<pos+n<=metadata:covered.append((pos,pos+n))
            for pos,md5,n,fn in struct.iter_unpack('<q16sIH',read_at(f,spec['reserved_offset'],spec['reserved_count']*30,size)):
                if n and not fn and 0<=pos<pos+n<=metadata:covered.append((pos,pos+n))
            pos,md5,n,fn=struct.unpack_from('<q16sIH',raw)
            if p['_file_system']['type']=='NTFS' and not n and not spec.get('container_verified') and '0' not in spec.get('overrides',{}):wanted.append(pi)
        if not wanted:return plan,[]
        found={pi:{} for pi in wanted};maxstride=max(parts[pi]['_header']['block_size'] for pi in wanted);gaps=list(complement(merge_ranges(covered),metadata))
        for lo,hi in gaps:
            for start in range(lo,hi,8*1024**2):
                f.seek(start);buf=f.read(min(8*1024**2+maxstride+1024**2,hi-start));offset=0;window=min(8*1024**2,hi-start)
                while True:
                    offset=buf.find(b'\x28\xb5\x2f\xfd',offset)
                    if offset<0 or offset>=window:break
                    pos=start+offset;raw=buf[offset:];offset+=4
                    try:
                        expected=zstandard.frame_content_size(raw)
                        if expected not in {parts[pi]['_header']['block_size'] for pi in wanted}:continue
                        d=zstandard.ZstdDecompressor().decompressobj();data=d.decompress(raw);stored=len(raw)-len(d.unused_data)
                        if not d.eof or pos+stored>hi or data[3:11]!=b'NTFS    ' or data[510:512]!=b'\x55\xaa':continue
                        sector=struct.unpack_from('<H',data,11)[0];spc=data[13];total=struct.unpack_from('<Q',data,40)[0];mft=struct.unpack_from('<Q',data,48)[0]
                        for pi in wanted:
                            p=parts[pi];fs=p['_file_system'];geo=p['_geometry']
                            if len(data)!=p['_header']['block_size'] or sector!=512 or spc!=fs['sectors_per_cluster'] or abs((total+1)*sector-geo['length'])>sector or geo['start']+mft*sector*spc!=fs['mft_offset']:continue
                            sha=hashlib.sha256(data).hexdigest();found[pi][sha]=dict(source_offset=pos,stored_length=stored,decoded_md5=hashlib.md5(data).hexdigest(),reason='Unique carved NTFS boot frame: OEM/BPB, root geometry, total sectors and MFT address agree. Original index digest unavailable; corroborate through readable MFT before use.')
                    except Exception:continue
                print(json.dumps(dict(boot_scan_source_end=start+window,candidates={str(pi):len(x) for pi,x in found.items()})),flush=True)
    reports=[]
    for pi,candidates in found.items():
        if len(candidates)!=1:raise ValueError(f'partition {pi}: absent boot frame has {len(candidates)} distinct candidates')
        plan['partitions'][pi].setdefault('overrides',{})['0']=next(iter(candidates.values()))
        from recover_ntfs_indexes import IndexedVolume
        from dissect.ntfs import NTFS
        volume=IndexedVolume(source,plan,pi);fs=NTFS(volume);record=fs.mft.get(0)
        if record.filename!='$MFT' or record.size()<1024 or not record.dataruns():raise ValueError('boot candidate does not lead to a readable original MFT')
        reports.append(dict(partition=pi,boot_override=plan['partitions'][pi]['overrides']['0'],mft_record_zero_valid=True))
    return plan,reports


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=pathlib.Path);ap.add_argument('output',type=pathlib.Path);ap.add_argument('--bootstrap-boot',action='store_true');a=ap.parse_args();a.output.mkdir(exist_ok=False);plan,proof=discover(a.source)
    if a.bootstrap_boot:plan,proof['boot_recovery']=bootstrap_boot(a.source,plan)
    (a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'discovery-evidence.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof),flush=True)
