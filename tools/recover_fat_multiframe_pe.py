"""Complete FAT PE files with multiple missing frames and an embedded digest.

Source proximity nominates bounded candidate combinations only. Acceptance
requires the complete embedded cryptographic image digest plus PE name/language
identity. Conflicting frame contents at one address remain unresolved.
"""
import argparse,bisect,collections,functools,hashlib,itertools,json,math,pathlib,sqlite3,struct
import pefile,zstandard
from dissect.fat import FATFS
from safe_vhdx import VHDX
from mapped_volume import MappedVolume
from recover_fat_duplicates import fat_extents
from recover_fat_signed_pe import pe_identity
from pe_anchors import image_digest
from dissect.ntfs import NTFS
from recover_duplicate_files import file_extents
from dissect.util.stream import RangeStream


def patch(data,frame,patches):
    for lo,hi,offset in patches:data[lo:hi]=frame[offset:offset+hi-lo]


def digest(data,info):
    h=hashlib.new(info['algorithm']);cs=info['checksum_offset'];sec=info['security_offset'];end=info['certificate_offset']
    for piece in (data[:cs],data[cs+4:sec],data[sec+8:end]):h.update(piece)
    return h.hexdigest()


def assignment_digest(data,info,bases,patches,assignment,contents,states):
    """Cache exact hash-prefix states for contiguous file patches."""
    regions=[patches[base][0] for base in bases]
    if not regions:return digest(data,info)
    if () not in states:
        cs=info['checksum_offset'];sec=info['security_offset'];h=hashlib.new(info['algorithm'])
        for piece in (data[:cs],data[cs+4:sec],data[sec+8:regions[0][0]]):h.update(piece)
        states[()]=h
    for i,(sha,(lo,hi,offset)) in enumerate(zip(assignment,regions)):
        key=assignment[:i+1]
        if key in states:h=states[key];continue
        h=states[assignment[:i]].copy();h.update(contents[sha][offset:offset+hi-lo]);stop=regions[i+1][0] if i+1<len(regions) else info['certificate_offset'];h.update(data[hi:stop])
        if i+1<len(regions):states[key]=h
    return h.hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-missing',type=int,default=8);ap.add_argument('--per-file-budget',type=int,default=300000)
    ap.add_argument('--only-path',help='restrict analysis to one FAT file path')
    ap.add_argument('--minimum-missing',type=int,default=2);ap.add_argument('--partition',type=int,default=0)
    ap.add_argument('--mft',type=pathlib.Path);ap.add_argument('--inventory',type=pathlib.Path)
    ap.add_argument('--minimum-file-size',type=int,default=8192);ap.add_argument('--maximum-file-size',type=int,default=4*1024**2)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);pi=a.partition
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][pi];origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==pi};ranges=[]
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('partition')==pi and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    source=a.source.open('rb')
    @functools.lru_cache(maxsize=128)
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    v=VHDX(a.baseline);view=MappedVolume(v,origin,p['_geometry']['length'],mapped,decode)
    if pi==0:fat=FATFS(view);data_start=fat.first_data_sector*fat.sector_size;root=fat.root
    elif pi==2:
        if not a.mft or not a.inventory:raise ValueError('NTFS mode requires cached MFT and inventory')
        ntfs=NTFS(view);ntfs.mft.fh=a.mft.open('rb');data_start=0;fat=None
        class NtfsEntry:
            def __init__(self,record,path):self.record=record;self.name=path.replace('\\','/');self.size=record.size()
            def is_directory(self):return False
            def open(self):return self.record.open()
        class Root:
            def iterdir(self):
                for row in map(json.loads,a.inventory.open()):
                    path=row.get('path') or ''
                    if pathlib.PureWindowsPath(path).suffix.casefold() not in ('.dll','.exe','.sys','.mui','.efi','.ocx','.cpl','.scr','.winmd','.ax'):continue
                    try:
                        record=ntfs.mft.get(row['record']);file_extents(record,record.size());yield NtfsEntry(record,path)
                    except Exception:continue
        root=Root()
    else:raise ValueError('supports FAT partition0 and cached NTFS partition2')
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);contents={}
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(stride,)):
            frames[f[6]].append(f)
            if f[6] not in contents:corpus.seek(f[3]);contents[f[6]]=corpus.read(stride)
    ordered=sorted(contents,key=lambda sha:frames[sha][0][1]);rank={sha:i for i,sha in enumerate(ordered)};source_positions=[frames[sha][0][1] for sha in ordered];pending=collections.defaultdict(list);reports=[]
    index_sources=dict(db.execute('SELECT block,source_offset FROM entries WHERE partition=? AND reserved=0 AND incorporated=1 AND stored_length>0',(pi,)))
    for m in accepted:
        if m['partition']==pi and not m['reserved']:index_sources[m['block']]=m['source_offset']
    index_blocks=sorted(index_sources)
    def walk(entry,path=''):
        for child in entry.iterdir():
            if child.name in ('.','..'):continue
            full=path+'/'+child.name
            if child.is_directory():walk(child,full);continue
            if a.only_path and full.casefold()!=a.only_path.casefold():continue
            if not a.minimum_file_size<=child.size<=a.maximum_file_size:continue
            extents=fat_extents(child,fat) if pi==0 else file_extents(child.record,child.size);bases=sorted({b for l,p,n in extents for b in range((p-data_start)//stride*stride+data_start,p+n,stride) if unknown(b)})
            if not a.minimum_missing<=len(bases)<=a.maximum_missing:continue
            print('Testing',full,'missing frames',len(bases),flush=True)
            template=bytearray(child.open().read());patches={base:[] for base in bases}
            def physical_at(logical):
                for lo,ph,n in extents:
                    if lo<=logical<lo+n:return ph+logical-lo
                raise ValueError('logical offset outside file')
            for base in bases:
                for logical,physical,length in extents:
                    lo=max(base,physical);hi=min(base+stride,physical+length)
                    if hi>lo:patches[base].append((logical+lo-physical,logical+hi-physical,lo-base))
            header_base=(physical_at(0)-data_start)//stride*stride+data_start
            header_options=ordered if header_base in bases else [None];tested=0;solutions=[];seen=set();report=dict(path=full,bases=bases,digest_matches=0,identity_rejections=[],nominations=[]);reports.append(report)
            for header_sha in header_options:
                initial=template[:];fixed={}
                if header_sha is not None:patch(initial,contents[header_sha],patches[header_base]);fixed[header_base]=header_sha
                if initial[:2]!=b'MZ':continue
                try:
                    pe=pefile.PE(data=bytes(initial),fast_load=True);cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                    if not cert.Size or cert.VirtualAddress+cert.Size!=child.size:continue
                    cert_base=(physical_at(cert.VirtualAddress)-data_start)//stride*stride+data_start
                    cert_options=ordered if cert_base in bases and cert_base not in fixed else [fixed.get(cert_base)]
                except Exception:continue
                for cert_sha in cert_options:
                    data=initial[:];fixed2=dict(fixed)
                    if cert_sha is not None:patch(data,contents[cert_sha],patches[cert_base]);fixed2[cert_base]=cert_sha
                    if cert.VirtualAddress+8>len(data):continue
                    n,revision,typ=struct.unpack_from('<IHH',data,cert.VirtualAddress)
                    if typ!=2 or revision!=0x200 or not 8<=n<=cert.Size:continue
                    try:info=image_digest(bytes(data),verify=False)
                    except Exception:continue
                    report['nominations'].append(dict(fixed={str(b):frames[s][0][0] for b,s in fixed2.items()},digest=info['digest']))
                    remaining=[base for base in bases if base not in fixed2];pools=[]
                    remaining.sort(key=lambda b:patches[b][0][0]);regions=[patches[b][0] for b in remaining]
                    fast=bool(remaining and all(len(patches[b])==1 for b in remaining) and regions[0][0]>=info['security_offset']+8 and all(lo<=hi<=info['certificate_offset'] for lo,hi,off in regions) and all(regions[i][1]<=regions[i+1][0] for i in range(len(regions)-1)));states={}
                    if len(remaining)<=1 and child.size<=4*1024**2:pools=[ordered]
                    elif fixed2:
                        indexes=[rank[sha] for sha in fixed2.values()]
                        for anchor in (header_base,cert_base):
                            block=(anchor-data_start)//stride
                            if anchor not in fixed2 and block in index_sources:indexes.append(min(len(ordered)-1,bisect.bisect_left(source_positions,index_sources[block])))
                        for padding in (0,2,4,8,16):pools.append(ordered[max(0,min(indexes)-padding):max(indexes)+padding+1])
                    else:
                        positions=[]
                        for base in bases:
                            block=(base-data_start)//stride;k=bisect.bisect_left(index_blocks,block)
                            positions.extend(index_sources[index_blocks[i]] for i in range(max(0,k-2),min(len(index_blocks),k+2)))
                        if positions:
                            left=bisect.bisect_left(source_positions,min(positions));right=bisect.bisect_right(source_positions,max(positions))
                            for padding in (0,2,4,8,16):pools.append(ordered[max(0,left-padding):min(len(ordered),right+padding)])
                    for pool in pools:
                        pool=[sha for sha in pool if sha not in fixed2.values()]
                        if len(pool)<len(remaining):continue
                        count=math.perm(len(pool),len(remaining))
                        if tested+count>a.per_file_budget:continue
                        for assignment in itertools.permutations(pool,len(remaining)):
                            combination=tuple(sorted(fixed2.items()))+tuple(zip(remaining,assignment))
                            if combination in seen:continue
                            seen.add(combination);tested+=1
                            if fast:
                                actual=assignment_digest(data,info,remaining,patches,assignment,contents,states)
                                if actual!=info['digest']:continue
                            candidate=data[:]
                            for base,sha in zip(remaining,assignment):patch(candidate,contents[sha],patches[base])
                            if digest(candidate,info)!=info['digest']:continue
                            report['digest_matches']+=1
                            try:identity=pe_identity(bytes(candidate),full)
                            except Exception as e:report['identity_rejections'].append(str(e));continue
                            solution=dict(fixed2);solution.update(zip(remaining,assignment));solutions.append(solution)
                            evidence=dict(method=('fat' if pi==0 else 'ntfs')+'-multiframe-complete-embedded-pe-image-digest',file_path=full,image_digest=info,identity=identity,missing_frames=len(bases),source_proximity_only_nominated=True)
                            for base,sha in solution.items():pending[base].append((frames[sha],evidence))
                if tested>=a.per_file_budget:break
            report.update(combinations_checked=tested,solutions=len(solutions));print(full,'checked',tested,'solutions',len(solutions),flush=True)
    walk(root);conflicts=[]
    for base,items in sorted(pending.items()):
        if len({fs[0][6] for fs,e in items})!=1:conflicts.append(base);continue
        f=items[0][0][0];data=decode(f[1],f[2])
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source validation')
        accepted.append(dict(partition=pi,reserved=False,block=(base-data_start)//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=sorted({f[0] for fs,e in items for f in fs}),evidence=[e for fs,e in items]))
        plan['partitions'][pi].setdefault('overrides',{})[str((base-data_start)//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Multiple missing FAT file frames jointly validate complete embedded PE image digest and name/language identity. Source proximity only nominated candidates; original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'multiframe-evidence.json').write_text(json.dumps(reports,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),multiframe_additions=len(accepted)-previous,targets=len(reports),conflicts=conflicts)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
