"""Reconstruct one-hole ZIP/Office archives with original CRC evidence.

Every member is decompressed and CRC-checked within explicit bounds. This stage
requires two independent original crossing CRCs and a distinctive unique frame
before proposing placement. Other internally valid archives remain external.
"""
import argparse,collections,hashlib,io,json,pathlib,sqlite3,struct,zipfile,zlib,lzma
from rebuild_context import Context
from recover_duplicate_files import file_extents,frame_pieces
from recover_file_hashes import reconstruct
from recover_file_hashes import distinctive_hash_bound


def validate_archive(data,maximum=64*1024**2):
    if data[:4]!=b'PK\x03\x04':raise ValueError('archive must begin at its original file boundary')
    end=data.rfind(b'PK\x05\x06',max(0,len(data)-65557))
    if end<0 or end+22>len(data):raise ValueError('ZIP end record missing')
    signature,disk,cd_disk,disk_count,count,cd_size,cd_offset,comment=struct.unpack_from('<4s4H2IH',data,end)
    if disk or cd_disk or count!=disk_count or count==65535 or end+22+comment!=len(data) or cd_offset+cd_size!=end:raise ValueError('archive boundary, disk or ZIP64 layout unsupported')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos=archive.infolist()
        if not infos or len(infos)!=count or min(i.header_offset for i in infos)!=0 or archive.start_dir!=cd_offset or len(infos)>10000 or sum(i.file_size for i in infos)>maximum:raise ValueError('archive expansion/boundary bounds')
        if any(i.flag_bits&1 or i.file_size>maximum for i in infos):raise ValueError('encrypted or excessive member')
        for item in infos:
            with archive.open(item) as stream:
                while stream.read(65536):pass
        result=[]
        for i in infos:
            names,extra=struct.unpack_from('<HH',data,i.header_offset+26);start=i.header_offset+30+names+extra
            if not 0<=start<=start+i.compress_size<=cd_offset:raise ValueError('member payload bounds')
            result.append(dict(name=i.filename,crc32=i.CRC,decoded_bytes=i.file_size,encoded_bytes=i.compress_size,header_offset=i.header_offset,compressed_start=start,compressed_end=start+i.compress_size))
        return result


def original_crossing_crcs(template,mask,members,pieces):
    result=[]
    for item in members:
        off=item['header_offset']
        if off<0 or off+30>len(template) or not all(mask[off:off+30]) or template[off:off+4]!=b'PK\x03\x04':continue
        flags,method,mtime,mdate,crc,stored,decoded,names,extra=struct.unpack_from('<HHHHIIIHH',template,off+6)
        start=off+30+names+extra;stop=start+item['encoded_bytes']
        if flags&8 or crc!=item['crc32'] or stored!=item['encoded_bytes'] or decoded!=item['decoded_bytes'] or not 0<=start<=stop<=len(template):continue
        missing=sum(max(0,min(stop,logical+n)-max(start,logical)) for offset,logical,n in pieces)
        if missing:result.append(dict(name=item['name'],crc32=crc,missing_compressed_bytes=missing,compressed_start=start,compressed_end=stop,source='surviving-original-local-header'))
    # The original central directory may survive even when every local header
    # is missing. Its original names, offsets, lengths and CRCs are independent
    # constraints, unlike a directory supplied by the candidate itself.
    try:
        end=template.rfind(b'PK\x05\x06',max(0,len(template)-65557))
        if end<0 or end+22>len(template) or not all(mask[end:]):return result
        signature,disk,cd_disk,disk_count,count,cd_size,cd_offset,comment=struct.unpack_from('<4s4H2IH',template,end)
        if disk or cd_disk or count!=disk_count or end+22+comment!=len(template) or cd_offset+cd_size!=end or not all(mask[cd_offset:end]):return result
        with zipfile.ZipFile(io.BytesIO(template)) as archive:original={i.filename:i for i in archive.infolist()}
        if len(original)!=count or len(members)!=count:return result
        for item in members:
            orig=original.get(item['name'])
            if orig is None or (orig.CRC,orig.file_size,orig.compress_size,orig.header_offset)!=(item['crc32'],item['decoded_bytes'],item['encoded_bytes'],item['header_offset']):return result
        for item in members:
            directory=dict(start=cd_offset,end=end,sha256=hashlib.sha256(template[cd_offset:end]).hexdigest(),end_record_sha256=hashlib.sha256(template[end:]).hexdigest())
            existing=next((r for r in result if r['name']==item['name']),None)
            if existing is not None:existing['original_directory']=directory;continue
            start=item['compressed_start'];stop=item['compressed_end'];missing=sum(max(0,min(stop,logical+n)-max(start,logical)) for offset,logical,n in pieces)
            if missing:result.append(dict(name=item['name'],crc32=item['crc32'],missing_compressed_bytes=missing,compressed_start=start,compressed_end=stop,source='surviving-original-central-directory',original_directory=directory))
    except (ValueError,OSError,zipfile.BadZipFile,struct.error):pass
    return result


def independently_crossing(crcs):
    for i,left in enumerate(crcs):
        for right in crcs[i+1:]:
            if left.get('original_directory') and left['original_directory']==right.get('original_directory') and left['missing_compressed_bytes']>=256 and right['missing_compressed_bytes']>=256 and left['crc32']!=right['crc32'] and (left['compressed_end']<=right['compressed_start'] or right['compressed_end']<=left['compressed_start']):return True
    return False


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--only-record',type=int);ap.add_argument('--maximum-file-size',type=int,default=4*1024**2);ap.add_argument('--maximum-expanded',type=int,default=64*1024**2);a=ap.parse_args();a.output.mkdir(exist_ok=False);external=a.output/'recovered_files';external.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames={};contents={}
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(ctx.stride,)):
            if f[6] in contents:continue
            corpus.seek(f[3]);data=corpus.read(ctx.stride)
            if hashlib.sha256(data).hexdigest()!=f[6]:raise ValueError('corpus differs')
            frames[f[6]]=f;contents[f[6]]=data
    reports=[];count=0;total=0;accepted=ctx.maps[:];plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());pending=collections.defaultdict(list)
    with (a.output/'archive-evidence.jsonl').open('x') as log:
        for row in map(json.loads,a.inventory.open()):
            if a.only_record is not None and row['record']!=a.only_record:continue
            path=row.get('path') or '';suffix=pathlib.PureWindowsPath(path).suffix.casefold()
            if suffix not in ('.zip','.docx','.xlsx','.pptx','.docm','.xlsm','.pptm','.jar','.vsix','.nupkg','.appx','.msix'):continue
            try:
                rec=ctx.fs.mft.get(row['record']);size=rec.size()
                if not 32768<size<=a.maximum_file_size:continue
                bases=sorted({base for lo,hi,base in ctx.holes(rec)})
                if len(bases)!=1:continue
                base=bases[0];extents=file_extents(rec,size);pieces={base:frame_pieces(extents,base,ctx.stride)};template=rec.open().read();mask=bytearray(b'\1'*size)
                if len(template)!=size:raise ValueError('short archive')
                for off,logical,n in pieces[base]:mask[logical:logical+n]=bytes(n)
                known=bytes(b for b,m in zip(template,mask) if m)
                if len(known)<4096 or len(set(known))<32:continue
                report=dict(record=row['record'],path=path,file_bytes=size,known_file_bytes=len(known),checked=0,candidates=0);seen=set();qualified=[]
                for sha,content in contents.items():
                    report['checked']+=1;data=reconstruct(template,bases,pieces,[sha],contents)
                    try:members=validate_archive(data,a.maximum_expanded)
                    except (ValueError,OSError,RuntimeError,EOFError,NotImplementedError,zipfile.BadZipFile,zlib.error,lzma.LZMAError):continue
                    digest=hashlib.sha256(data).hexdigest()
                    if digest in seen:continue
                    f=frames[sha]
                    if ctx.decode(f[1],f[2])!=content or hashlib.md5(content).digest()!=f[5]:raise ValueError('original source differs')
                    target=external/f"record-{row['record']}-{digest}.candidate{suffix}"
                    with target.open('xb') as out:out.write(data)
                    crcs=original_crossing_crcs(template,mask,members,pieces[base]);metadata=dict(schema_version=1,kind='zip-reconstruction-candidate',placement_status='original-location-candidate',vhdx_insertion_authorized=False,bytes=len(data),sha256=digest,possible_locations=[dict(record=row['record'],path=path,file_extents=extents)],known_original_file_bytes=len(known),validation=dict(all_members_decompressed_and_crc_checked=True,members=members,original_crossing_crcs=crcs),provenance=[dict(frame=f[0],source_offset=f[1],stored_length=f[2],decoded_sha256=sha,candidate_disk_offset=ctx.origin+base,file_pieces=pieces[base])],note='Internal candidate CRCs do not prove original placement. Original surviving CRC coverage and final mapping authorization are recorded separately.')
                    target.with_suffix(target.suffix+'.json').write_text(json.dumps(metadata,indent=2));seen.add(digest);count+=1;total+=len(data);report['candidates']+=1
                    if independently_crossing(crcs):qualified.append((sha,digest,crcs,target))
                if len(seen)==1 and len(qualified)==1:
                    sha,digest,crcs,target=qualified[0];content=contents[sha];parts=b''.join(content[off:off+n] for off,logical,n in pieces[base]);alternatives=[s for s,d in contents.items() if all(d[off:off+n]==content[off:off+n] for off,logical,n in pieces[base])]
                    if len(alternatives)==1 and distinctive_hash_bound(parts):
                        pending[base].append((sha,dict(method='zip-original-member-crcs-and-directory',record=row['record'],file_size=size,file_sha256_observed=digest,original_crossing_crcs=crcs,original_missing_pieces=pieces[base],known_file_bytes=len(known))))
                        side=target.with_suffix(target.suffix+'.json');meta=json.loads(side.read_text());meta.update(placement_status='original-independent-crcs-and-runlist-validated',vhdx_insertion_authorized=True,vhdx_written_by_this_stage=False);side.write_text(json.dumps(meta,indent=2));report['qualified_full_frame']=True
                reports.append(report);log.write(json.dumps(report)+'\n');log.flush();print(json.dumps(report),flush=True)
            except Exception as e:log.write(json.dumps(dict(record=row['record'],error=str(e)))+'\n');log.flush()
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({sha for sha,e in items})!=1:conflicts.append(base);continue
        sha=items[0][0];f=frames[sha];accepted.append(dict(partition=2,reserved=False,block=base//ctx.stride,disk_offset=ctx.origin+base,length=ctx.stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=sha,frames=[r[0] for r in db.execute('SELECT id FROM frames WHERE sha256=?',(sha,))],evidence=[e for s,e in items]));plan['partitions'][2].setdefault('overrides',{})[str(base//ctx.stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Unique complete ZIP archive with multiple independent original crossing member CRCs, original metadata/runlist and distinctive unique full-frame boundary; structural reconstruction, original frame digest absent.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),new_placements=len(accepted)-len(ctx.maps),conflicts=conflicts,targets=len(reports),external_candidates=count,external_candidate_bytes=total,maximum_file_size=a.maximum_file_size,maximum_expanded=a.maximum_expanded);(a.output/'summary.json').write_text(json.dumps(result,indent=2));ctx.close();db.close();print(json.dumps(result),flush=True)


if __name__=='__main__':main()
