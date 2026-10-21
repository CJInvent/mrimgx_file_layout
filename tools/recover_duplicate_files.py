"""Map orphan frames by exact slices of intact duplicate NTFS files.

Requires explicit target/donor record pairs, matching sizes and all surviving
target bytes, an entirely covered donor, and exact orphan SHA256+MD5 matches.
Boundary frames optionally require at least 32 KiB of exact, varied file bytes.
Source frames are revalidated before acceptance; donor bytes are never copied.
"""
import argparse
import bisect
import collections
import hashlib
import functools
import json
import pathlib
import sqlite3
import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def distinctive(data):
    """Reject padding, tiny headers, and low-information repetitive matches."""
    return len(data)>=32768 and len(set(data))>=64 and len({bytes(data[i:i+32]) for i in range(0,len(data)-31,32)})>=512


class FileView:
    def __init__(self,stream,physical,size,mappings,decode):
        self.stream=stream;self.physical=physical;self.size=size;self.mappings=mappings;self.decode=decode

    def __getitem__(self,key):
        lo,hi,step=key.indices(self.size)
        if step!=1:raise ValueError('slice step')
        self.stream.seek(lo);data=bytearray(self.stream.read(hi-lo))
        if len(data)!=hi-lo:raise ValueError('short file read')
        for mb,m in self.mappings.items():
            start=max(self.physical+lo,mb);end=min(self.physical+hi,mb+m['length'])
            if end>start:data[start-self.physical-lo:end-self.physical-lo]=self.decode(m['source_offset'],m['stored_length'])[start-mb:end-mb]
        return data


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--pair',action='append',default=[],help='target:donor MFT record numbers')
    ap.add_argument('--pairs-json',type=pathlib.Path,help='JSON array of target:donor strings')
    ap.add_argument('--allow-boundary',action='store_true')
    ap.add_argument('--maximum-file-size',type=int,default=64*1024**2,help='bound in-memory comparison; larger files require a separate streamed pass')
    ap.add_argument('--stream-large-files',action='store_true',help='compare larger files in bounded chunks')
    ap.add_argument('--allow-metadata-duplicates',action='store_true',help='permit sparse corroboration only with identical filename and original NTFS modification timestamp')
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted)
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][2]
    origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2}
    ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def missing(lo,hi):
        k=max(0,bisect.bisect_right(starts,lo)-1)
        return [(max(lo,l),min(hi,h)) for l,h in ranges[k:] if l<hi and h>lo]
    def unknown(base):
        return base not in mapped and any(l<=base and base+stride<=h for l,h in missing(base,base+stride))
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']));fs.mft.fh=a.mft.open('rb')
    source=a.source.open('rb');db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    @functools.lru_cache(maxsize=64)
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    frames=collections.defaultdict(list)
    for row in db.execute('SELECT id,source_offset,stored_length,decoded_length,md5,sha256 FROM frames'):frames[(row[3],row[5])].append(row)
    reports=[];pending={};conflicts=set();corpus=(a.evidence/'orphan-decoded.bin').open('rb')
    exports=dict(db.execute('SELECT id,export_offset FROM frames'))
    pairs=a.pair+(json.loads(a.pairs_json.read_text()) if a.pairs_json else [])
    if not pairs:raise ValueError('no record pairs')
    for pair in pairs:
        target,donor=map(int,pair.split(':'));report=dict(target=target,donor=donor);reports.append(report)
        try:
            records=[fs.mft.get(n) for n in (target,donor)]
            if records[0].size()!=records[1].size():raise ValueError('different sizes')
            size=records[0].size();contents=[];positions=[];pair_pending={}
            streaming=size>a.maximum_file_size
            if streaming and not a.stream_large_files:raise ValueError('file exceeds in-memory comparison bound')
            target_runs=list(records[0].dataruns())
            if len(target_runs)==1 and target_runs[0][0] is not None:
                tb=target_runs[0][0]*4096
                if not any(unknown(base) for base in range(tb//stride*stride,tb+size,stride)):
                    report['skipped']='no unresolved target backup frames';continue
            for r in records:
                runs=list(r.dataruns())
                if len(runs)!=1 or runs[0][0] is None or any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):raise ValueError('requires contiguous uncompressed files')
                base=runs[0][0]*4096;positions.append(base)
                view=FileView(r.open(),base,size,mapped,decode);data=view if streaming else view[:]
                contents.append(data)
            tb,dbase=positions;tdata,ddata=contents
            for lo,hi in missing(dbase,dbase+size):
                while lo<hi:
                    mb=(lo//stride)*stride
                    if mb not in mapped:raise ValueError('donor has unresolved bytes')
                    lo=min(hi,mb+stride)
            holes=missing(tb,tb+size);compared=0;donor_hash=hashlib.sha256()
            for chunk in range(0,size,8*1024**2):
                stop=min(size,chunk+8*1024**2);known=bytearray(b'\1')*(stop-chunk)
                for lo,hi in holes:
                    lo=max(tb+chunk,lo);hi=min(tb+stop,hi)
                    if hi>lo:known[lo-tb-chunk:hi-tb-chunk]=b'\0'*(hi-lo)
                for mb,m in mapped.items():
                    lo=max(tb+chunk,mb);hi=min(tb+stop,mb+m['length'])
                    if hi>lo:known[lo-tb-chunk:hi-tb-chunk]=b'\1'*(hi-lo)
                target_chunk=tdata[chunk:stop];donor_chunk=ddata[chunk:stop];donor_hash.update(donor_chunk);compared+=sum(known)
                if target_chunk!=donor_chunk and any(x!=y for x,y,k in zip(target_chunk,donor_chunk,known) if k):raise ValueError('surviving target bytes differ')
            metadata_inference=False;mtime=None
            if compared<4096:
                times=[r.attributes.STANDARD_INFORMATION[0].attr.LastModificationTime for r in records]
                metadata_inference=bool(a.allow_metadata_duplicates and records[0].filename.casefold()==records[1].filename.casefold() and times[0] and times[0]==times[1])
                if not metadata_inference:raise ValueError('insufficient surviving target bytes')
                mtime=int(times[0])
            report.update(size=size,compared_bytes=compared,donor_sha256=donor_hash.hexdigest(),candidates=0)
            if metadata_inference:report.update(metadata_inference=True,original_modification_filetime=mtime)
            for base in range(((tb+stride-1)//stride)*stride,tb+size-stride+1,stride):
                if not unknown(base):continue
                data=ddata[base-tb:base-tb+stride];sha=hashlib.sha256(data).hexdigest();rows=frames.get((stride,sha),[])
                if not rows:continue
                if metadata_inference and not distinctive(data):continue
                pair_pending[base]=(rows[0],dict(method='intact-duplicate-file-exact-frame',target=target,donor=donor,compared_bytes=compared,donor_sha256=report['donor_sha256'],logical_offset=base-tb),rows);report['candidates']+=1
            if a.allow_boundary:
                for base in sorted({tb//stride*stride,(tb+size-1)//stride*stride}):
                    if not unknown(base) or base in pair_pending:continue
                    lo=max(tb,base);hi=min(tb+size,base+stride);expected=ddata[lo-tb:hi-tb]
                    if not distinctive(expected):continue
                    matches=[]
                    for (length,sha),rows in frames.items():
                        if length!=stride:continue
                        corpus.seek(exports[rows[0][0]]);candidate=corpus.read(stride)
                        if candidate[lo-base:hi-base]==expected:matches.extend(rows)
                    if len({f[5] for f in matches})!=1:continue
                    pair_pending[base]=(matches[0],dict(method='intact-duplicate-file-exact-boundary-slice',target=target,donor=donor,compared_bytes=compared,donor_sha256=report['donor_sha256'],logical_offset=lo-tb,matched_bytes=hi-lo),matches);report['candidates']+=1
            if metadata_inference:
                for f,e,rows in pair_pending.values():e.update(metadata_inference=True,original_modification_filetime=mtime,identity_evidence='same original filename, size and exact NTFS modification FILETIME; original target bytes insufficient')
            for base,item in pair_pending.items():
                if base in pending and pending[base][0][5]!=item[0][5]:conflicts.add(base);pending.pop(base)
                if base not in conflicts:pending[base]=item
        except Exception as e:report['rejected']=str(e)
    for base,(f,e,rows) in sorted(pending.items()):
        source.seek(f[1]);data=zstandard.ZstdDecompressor().decompress(source.read(f[2]))
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[5] or hashlib.md5(data).digest()!=f[4]:raise ValueError('source digest mismatch')
        m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[4].hex(),sha256=f[5],frames=[r[0] for r in rows],evidence=[e]);accepted.append(m)
        reason='Exact orphan frame matches intact duplicate file slice; all surviving target bytes agree through original NTFS runlist. Original target digest unavailable.'
        if e.get('metadata_inference'):reason+=' Target identity additionally inferred from matching filename, size and exact NTFS modification time; target has fewer than 4096 surviving corroborating bytes.'
        plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[4].hex(),reason=reason)
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),duplicate_additions=len(accepted)-previous,conflicts=sorted(conflicts),pairs=reports)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
