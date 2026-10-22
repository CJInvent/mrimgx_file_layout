"""Recover Chromium cache fragments using original stream CRCs and key identity.

A single CRC32 is insufficient: require two independently crossing stream CRCs,
or a complete nested CRC/hash validation or a surviving labeled payload digest.
All header/key/EOF addresses come from the original file and its MFT runlist.
"""
from rebuild_audit import caught as _audit_caught
import argparse,base64,collections,hashlib,json,pathlib,re,sqlite3,struct,zlib
from rescue_unplaced_files import exclusive_write
from rebuild_context import Context
from recover_duplicate_files import file_extents,frame_pieces
from recover_file_hashes import reconstruct,distinctive_hash_bound
from rescue_unplaced_files import carved_files
INITIAL=0xfcfb6d1ba7725c30
FINAL=0xf4fa6f45970d41d8


def layout(data,name,known=lambda lo,hi:True):
    if len(data)<48 or not known(0,24) or not known(len(data)-24,len(data)):raise ValueError('unknown header/footer')
    magic,version,n,key_hash,padding=struct.unpack_from('<Q4I',data)
    if magic!=INITIAL or version!=5 or not 0<n<8192 or 24+n>len(data) or not known(24,24+n):raise ValueError('header/key')
    key=data[24:24+n];stem=f'{int.from_bytes(hashlib.sha1(key).digest()[:8],"little"):016x}'
    if name not in (stem+'_0',stem+'_1'):raise ValueError('original filename/key SHA1 mismatch')
    def eof(at):
        if not 0<=at<=len(data)-24 or not known(at,at+24):raise ValueError('unknown original EOF')
        magic,flags,crc,size,pad=struct.unpack_from('<Q4I',data,at)
        if magic!=FINAL or flags&~3 or size>=2**31:raise ValueError('EOF format')
        return flags,crc,size
    at=len(data)-24;flags,crc,size=eof(at)
    if name.endswith('_1'):
        if flags&2:raise ValueError('unexpected stream2 key SHA')
        return dict(key_sha256=hashlib.sha256(key).hexdigest(),key_utf8=key.decode('utf-8',errors='backslashreplace'),streams=[dict(index=2,start=24+n,end=at,expected_crc32=crc,has_crc32=bool(flags&1))])
    if flags&2:
        if not known(at-32,at) or data[at-32:at]!=hashlib.sha256(key).digest():raise ValueError('unknown/mismatched original key SHA256')
        at-=32
    start0=at-size;footer1=start0-24;flags1,crc1,unused=eof(footer1)
    if flags1&2 or not 24+n<=footer1 or not start0<=at:raise ValueError('stream bounds/flags')
    return dict(key_sha256=hashlib.sha256(key).hexdigest(),key_utf8=key.decode('utf-8',errors='backslashreplace'),streams=[dict(index=1,start=24+n,end=footer1,expected_crc32=crc1,has_crc32=bool(flags1&1)),dict(index=0,start=start0,end=at,expected_crc32=crc,has_crc32=bool(flags&1))])


def validate(data,info):
    for stream in info['streams']:
        if stream['has_crc32'] and zlib.crc32(data[stream['start']:stream['end']])!=stream['expected_crc32']:raise ValueError('original stream CRC mismatch')


def extra_validation(data,info,original,known):
    results=[];stream0=next((s for s in info['streams'] if s['index']==0),None)
    metadata=original[stream0['start']:stream0['end']] if stream0 and known(stream0['start'],stream0['end']) else b''
    digests=[]
    for match in re.finditer(rb'(?i)(?:etag|content-md5|x-amz-content-sha256)\s*:\s*(?:W/)?["\s]*([A-Za-z0-9+/=]{16,128})',metadata):
        value=match[1]
        if re.fullmatch(rb'[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}',value):digests.append(({32:'md5',40:'sha1',64:'sha256'}[len(value)],value.decode().lower()))
        else:
            try:
                raw=base64.b64decode(value,validate=True)
                if len(raw) in (16,20,32):digests.append(({16:'md5',20:'sha1',32:'sha256'}[len(raw)],raw.hex()))
            except Exception as _audit_error:
                _audit_caught(_audit_error, None, expected=True, site='recover_chromium_streams.py:56')
                pass
    for stream in info['streams']:
        lo,hi=stream['start'],stream['end']
        if known(lo,hi):continue
        content=data[lo:hi]
        for algorithm,expected in digests:
            if hashlib.new(algorithm,content).hexdigest()==expected:results.append(dict(method='original-labeled-payload-digest',stream=stream['index'],algorithm=algorithm,digest=expected))
        # Only checksum/hash-bound nested files qualify. JPEG/RIFF structural
        # validity alone is deliberately insufficient for VHDX placement.
        for offset,body,kind,proof in carved_files(content):
            if offset==0 and len(body)==len(content) and kind in ('gz','png','zip','exe'):results.append(dict(method='complete-nested-file-validation',stream=stream['index'],kind=kind,validation=proof))
    return results


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-file-size',type=int,default=4*1024**2);ap.add_argument('--only-record',type=int);a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);accepted=ctx.maps[:];previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);contents={}
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(ctx.stride,)):
            frames[f[6]].append(f)
            if f[6] not in contents:
                corpus.seek(f[3]);data=corpus.read(ctx.stride)
                if hashlib.sha256(data).hexdigest()!=f[6]:raise ValueError('corpus mismatch')
                contents[f[6]]=data
    pending=collections.defaultdict(list);reports=[]
    for row in map(json.loads,a.inventory.open()):
        if a.only_record is not None and row['record']!=a.only_record:continue
        name=pathlib.PureWindowsPath(row.get('path') or '').name.lower()
        if not re.fullmatch('[0-9a-f]{16}_[01]',name):continue
        try:
            rec=ctx.fs.mft.get(row['record']);size=rec.size()
            if not 32768<size<=a.maximum_file_size:continue
            holes=ctx.holes(rec);bases=sorted({base for lo,hi,base in holes})
            if len(bases)!=1:continue
            known=lambda lo,hi:not any(start<hi and stop>lo for start,stop,base in holes)
            template=rec.open().read();info=layout(template,name,known);base=bases[0];pieces={base:frame_pieces(file_extents(rec,size),base,ctx.stride)};crossings=0
            for stream in info['streams']:
                lo,hi=stream['start'],stream['end'];missing=sum(max(0,min(hi,stop)-max(lo,start)) for start,stop,b in holes)
                if stream['has_crc32'] and missing and hi-lo-missing>=256:crossings+=1
            if not crossings:continue
            solutions=[];crc_matches=0;crc_candidates=[];candidate_files=[]
            for sha in contents:
                data=reconstruct(template,[base],pieces,[sha],contents)
                try:validate(data,info)
                except ValueError as _audit_error:
                    _audit_caught(_audit_error, None, expected=True, site='recover_chromium_streams.py:101')
                    continue
                crc_matches+=1;crc_candidates.append(dict(sha256=sha,frames=[f[0] for f in frames[sha]],stream_prefixes={str(s['index']):data[s['start']:min(s['end'],s['start']+96)].hex() for s in info['streams']}));extra=extra_validation(data,info,template,known)
                if crossings>=2 or extra:solutions.append((sha,extra,hashlib.sha256(data).hexdigest()))
                else:candidate_files.append((sha,bytes(data)))
            report=dict(record=row['record'],path=row.get('path'),size=size,base=base,crossing_original_crcs=crossings,crc_candidates=crc_matches,candidate_details=crc_candidates,qualified_solutions=len(solutions));reports.append(report)
            if len({s for s,e,h in solutions})==1 and solutions:
                sha,extra,observed=solutions[0];parts=b''.join(contents[sha][off:off+n] for off,logical,n in pieces[base]);alternatives=[s for s,data in contents.items() if all(data[off:off+n]==contents[sha][off:off+n] for off,logical,n in pieces[base])]
                if distinctive_hash_bound(parts) and len(alternatives)==1:pending[base].append((sha,dict(method='chromium-original-stream-crcs-and-key-identity',record=row['record'],filename=name,file_size=size,stream_layout=info,crossing_original_crcs=crossings,extra_validation=extra,file_sha256_observed=observed)))
                else:report['rejected']='ambiguous frame or insufficient distinctive file bytes'
            elif not solutions:
                # A useful, fully assembled candidate can be rescued without
                # overstating one CRC32 as adequate placement authority.
                directory=a.output/'recovered_files';directory.mkdir(exist_ok=True)
                for sha,data in candidate_files:
                    parts=b''.join(contents[sha][off:off+n] for off,logical,n in pieces[base])
                    if not distinctive_hash_bound(parts):continue
                    digest=hashlib.sha256(data).hexdigest();target=directory/(f'{row["record"]}-{digest}.cache.bin')
                    if target.exists():continue
                    exclusive_write(target,data);proof=dict(schema_version=1,kind='reconstructed-file-candidate',file_type='chromium-cache',placement_status='candidate-only',vhdx_insertion_authorized=False,original_digest_available=False,sha256=digest,bytes=len(data),original_filename=name,possible_locations=[dict(record=row['record'],path=row.get('path'),partition=2,partition_disk_offset=ctx.origin,cluster_bytes=4096,physical_cluster_runs=list(rec.dataruns()),placement_confirmed=False)],validation=dict(original_stream_crcs=True,key_filename_sha1=True,stream_layout=info,crossing_original_crcs=crossings,independent_extra_validation=False),provenance=[dict(frame=f[0],source_offset=f[1],encoded_bytes=f[2],decoded_frame_sha256=sha) for f in frames[sha]],alternative_crc_candidates=crc_matches,note='A single original CRC32 nominates this complete file. Additional independent validation is still needed before inserting its frame into VHDX.')
                    exclusive_write(target.with_suffix(target.suffix+'.json'),json.dumps(proof,indent=2))
            print(json.dumps(report),flush=True)
        except Exception as _audit_error:
            _audit_caught(_audit_error, locals(), expected=False, site='recover_chromium_streams.py:122')
            continue
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({sha for sha,e in items})!=1:conflicts.append(base);continue
        sha=items[0][0];f=frames[sha][0];data=ctx.decode(f[1],f[2])
        if len(data)!=ctx.stride or hashlib.sha256(data).hexdigest()!=sha or hashlib.md5(data).digest()!=f[5]:raise ValueError('source mismatch')
        accepted.append(dict(partition=2,reserved=False,block=base//ctx.stride,disk_offset=ctx.origin+base,length=ctx.stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=sha,frames=[x[0] for x in frames[sha]],evidence=[e for s,e in items]));plan['partitions'][2].setdefault('overrides',{})[str(base//ctx.stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Original Chromium stream CRCs, original key/filename, MFT runlist and additional nested checksums/hash or two crossing CRCs validate a unique frame.')
    for name,value in (('accepted-mappings.json',accepted),('recovery-plan.json',plan),('chromium-stream-evidence.json',reports)):(a.output/name).write_text(json.dumps(value,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),new_placements=len(accepted)-previous,targets=len(reports),conflicts=conflicts);(a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
