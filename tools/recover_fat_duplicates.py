"""Map orphan FAT frames through surviving chains and intact NTFS duplicates.

Requires equal FAT copies, a surviving directory entry and complete FAT chain,
same-name/size NTFS donor, mutually known bytes and unique exact orphan content.
No executable is run and no directory/FAT metadata is synthesized.
"""
import argparse
import bisect
import collections
import functools
import hashlib
import json
import mmap
import pathlib
import sqlite3
import zstandard
from safe_vhdx import VHDX
from dissect.fat import FATFS
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream
from discover_duplicate_pairs import candidate_records
from recover_duplicate_files import FileView,file_extents,frame_pieces,exclude_holes,distinctive
from mapped_volume import MappedVolume


def fat_extents(entry,fs):
    logical=0;result=[]
    for cluster,count in entry.dataruns():
        length=min(count*fs.cluster_size,entry.size-logical)
        if length<=0:break
        physical=fs.first_data_sector*fs.sector_size+cluster*fs.cluster_size
        if result and result[-1][0]+result[-1][2]==logical and result[-1][1]+result[-1][2]==physical:
            lo,ph,n=result[-1];result[-1]=(lo,ph,n+length)
        else:result.append((logical,physical,length))
        logical+=length
    if logical!=entry.size:raise ValueError('FAT chain shorter than file size')
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--partition',type=int,default=0)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);pi=a.partition
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());parts=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'];p=parts[pi];origin=p['_geometry']['start'];stride=p['_header']['block_size'];data_origin=p['_file_system']['lcn0_offset']-p['_file_system']['start'];mapped=collections.defaultdict(dict);ranges=collections.defaultdict(list)
    for m in accepted:mapped[m['partition']][m['disk_offset']-parts[m['partition']]['_geometry']['start']]=m
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):
            n=row['partition'];lo=row['disk_offset']-parts[n]['_geometry']['start'];ranges[n].append((lo,lo+row['length']))
    for rs in ranges.values():rs.sort()
    starts={n:[lo for lo,hi in rs] for n,rs in ranges.items()}
    def missing(n,lo,hi):
        rs=ranges[n];k=max(0,bisect.bisect_right(starts.get(n,[]),lo)-1)
        return [(max(lo,l),min(hi,h)) for l,h in rs[k:] if l<hi and h>lo]
    def unknown(base):return base not in mapped[pi] and any(lo<=base and base+stride<=hi for lo,hi in missing(pi,base,base+stride))
    def holes(n,extents):
        result=[];block=parts[n]['_header']['block_size'];offset=parts[n]['_file_system'].get('lcn0_offset',parts[n]['_file_system'].get('start',0))-parts[n]['_file_system'].get('start',0)
        for logical,physical,length in extents:
            for lo,hi in missing(n,physical,physical+length):
                while lo<hi:
                    base=(lo-offset)//block*block+offset;stop=min(hi,base+block)
                    if base not in mapped[n]:result.append((logical+lo-physical,logical+stop-physical))
                    lo=stop
        return sorted(result)
    source=a.source.open('rb')
    @functools.lru_cache(maxsize=64)
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    v=VHDX(a.baseline);fat=FATFS(MappedVolume(v,origin,p['_geometry']['length'],mapped[pi],decode));ntfs=NTFS(RangeStream(v,parts[2]['_geometry']['start'],parts[2]['_geometry']['length']));ntfs.mft.fh=a.mft.open('rb')
    if fat.bpb.BPB_NumFATs!=2:raise ValueError('requires two corroborating FAT copies')
    copies=[]
    for i in range(2):
        v.seek(origin+(fat.bpb.BPB_RsvdSecCnt+i*fat.fat_size)*fat.sector_size);copies.append(v.read(fat.fat_size*fat.sector_size))
    if copies[0]!=copies[1]:raise ValueError('FAT copies differ')
    targets=[]
    def walk(entry,path=''):
        for child in entry.iterdir():
            if child.name in ('.','..'):continue
            full=path+'/'+child.name
            if child.is_directory():walk(child,full);continue
            if not 32768<=child.size<=16*1024**2:continue
            extents=fat_extents(child,fat);bases={base for logical,physical,length in extents for base in range((physical-data_origin)//stride*stride+data_origin,physical+length,stride) if unknown(base)}
            if bases:targets.append(dict(entry=child,path=full,size=child.size,extents=extents,bases=sorted(bases)))
    walk(fat.root);names={(t['entry'].name.casefold(),t['size']) for t in targets};donors=collections.defaultdict(set)
    with a.mft.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        for number,filenames,size in candidate_records(data):
            for name in filenames:
                if (name.casefold(),size) in names:donors[(name.casefold(),size)].add(number)
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);data_by_hash={};corpus=(a.evidence/'orphan-decoded.bin').open('rb')
    for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(stride,)):
        frames[f[6]].append(f)
        if f[6] not in data_by_hash:corpus.seek(f[3]);data_by_hash[f[6]]=corpus.read(stride)
    print('FAT targets',len(targets),'candidate donors',sum(map(len,donors.values())),flush=True);reports=[];pending=collections.defaultdict(list)
    for t in targets:
        entry=t['entry'];extents=t['extents'];targetdata=FileView(entry.open(),extents,t['size'],mapped[pi],decode)[:];targetholes=holes(pi,extents)
        for number in donors.get((entry.name.casefold(),t['size']),[]):
            report=dict(path=t['path'],donor=number);reports.append(report)
            try:
                r=ntfs.mft.get(number)
                if not r.header.Flags&1 or r.size()!=t['size'] or r.filename.casefold()!=entry.name.casefold():continue
                donor_extents=file_extents(r,r.size())
                if holes(2,donor_extents):raise ValueError('donor unresolved')
                donor=FileView(r.open(),donor_extents,r.size(),mapped[2],decode)[:];known=bytearray(b'\1')*t['size']
                for lo,hi in targetholes:known[lo:hi]=b'\0'*(hi-lo)
                compared=known.count(1)
                if compared<4096:raise ValueError('insufficient surviving target bytes')
                if any(x!=y for x,y,k in zip(targetdata,donor,known) if k):raise ValueError('surviving bytes differ')
                report.update(compared_bytes=compared,donor_sha256=hashlib.sha256(donor).hexdigest(),candidates=0)
                for base in t['bases']:
                    pieces=frame_pieces(extents,base,stride);expected=[donor[logical:logical+length] for offset,logical,length in pieces]
                    if not distinctive(b''.join(expected)):continue
                    matches=[sha for sha,data in data_by_hash.items() if all(data[offset:offset+length]==part for (offset,logical,length),part in zip(pieces,expected))]
                    if len(matches)!=1:continue
                    sha=matches[0];pending[base].append((frames[sha],dict(method='fat-chain-ntfs-duplicate-exact-slices',fat_path=t['path'],donor=number,donor_sha256=report['donor_sha256'],compared_surviving_bytes=compared,matched_candidate_bytes=sum(map(len,expected)),pieces=[dict(decoded_offset=o,logical_offset=l,length=n) for o,l,n in pieces],fat_copies_sha256=hashlib.sha256(copies[0]).hexdigest())));report['candidates']+=1
            except Exception as e:report['rejected']=str(e)
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({fs[0][6] for fs,e in items})!=1:conflicts.append(base);continue
        f=items[0][0][0];data=decode(f[1],f[2])
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source revalidation')
        accepted.append(dict(partition=pi,reserved=False,block=(base-data_origin)//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=sorted({f[0] for fs,e in items for f in fs}),evidence=[e for fs,e in items]))
        plan['partitions'][pi].setdefault('overrides',{})[str((base-data_origin)//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Matching FAT copies and original file chain; exact distinctive slices from same-name/size intact NTFS duplicate and agreement of all surviving target bytes. Original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'fat-evidence.json').write_text(json.dumps(reports,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),fat_additions=len(accepted)-previous,targets=len(targets),conflicts=conflicts)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
