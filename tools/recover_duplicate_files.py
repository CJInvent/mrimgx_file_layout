"""Map orphan frames by exact slices of intact duplicate NTFS files.

Requires explicit target/donor record pairs, matching sizes and all surviving
target bytes, an entirely covered donor, and exact orphan SHA256+MD5 matches.
Boundary frames optionally require at least 32 KiB of exact, varied file bytes.
Source frames are revalidated before acceptance; donor bytes are never copied.
"""
from rebuild_audit import caught as _audit_caught
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
        self.stream=stream;self.extents=[(0,physical,size)] if isinstance(physical,int) else physical;self.size=size;self.mappings=mappings;self.decode=decode

    def __getitem__(self,key):
        lo,hi,step=key.indices(self.size)
        if step!=1:raise ValueError('slice step')
        self.stream.seek(lo);data=bytearray(self.stream.read(hi-lo))
        if len(data)!=hi-lo:raise ValueError('short file read')
        for logical,physical,length in self.extents:
            left=max(lo,logical);right=min(hi,logical+length)
            if right<=left:continue
            for mb,m in self.mappings.items():
                start=max(physical+left-logical,mb);end=min(physical+right-logical,mb+m['length'])
                if end>start:data[logical+start-physical-lo:logical+end-physical-lo]=self.decode(m['source_offset'],m['stored_length'])[start-mb:end-mb]
        return data


def file_extents(record,size):
    if any(attr.header.flags&0x4001 for attr in record.attributes.DATA if attr.name==''):raise ValueError('requires uncompressed non-sparse files')
    result=[];logical=0
    for cluster,count in record.dataruns():
        if cluster is None:raise ValueError('requires allocated file extents')
        length=min(count*4096,size-logical)
        if length<=0:break
        result.append((logical,cluster*4096,length));logical+=length
    if logical!=size:raise ValueError('file runlist does not cover size')
    return result


def frame_pieces(extents,base,stride):
    return sorted((max(physical,base)-base,logical+max(physical,base)-physical,min(physical+length,base+stride)-max(physical,base)) for logical,physical,length in extents if min(physical+length,base+stride)>max(physical,base))


def exclude_holes(pieces,holes):
    result=[]
    for offset,logical,length in pieces:
        parts=[(logical,logical+length)]
        for lo,hi in holes:
            parts=[part for start,stop in parts for part in ((start,min(stop,lo)),(max(start,hi),stop)) if part[1]>part[0]]
        result.extend((offset+start-logical,start,stop-start) for start,stop in parts)
    return sorted(result)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--pair',action='append',default=[],help='target:donor MFT record numbers')
    ap.add_argument('--pairs-json',type=pathlib.Path,help='JSON array of target:donor strings')
    ap.add_argument('--allow-boundary',action='store_true')
    ap.add_argument('--maximum-file-size',type=int,default=64*1024**2,help='bound in-memory comparison; larger files require a separate streamed pass')
    ap.add_argument('--stream-large-files',action='store_true',help='compare larger files in bounded chunks')
    ap.add_argument('--allow-metadata-duplicates',action='store_true',help='permit sparse corroboration only with identical filename and original NTFS modification timestamp')
    ap.add_argument('--allow-partial-donor',action='store_true',help='use only independently known donor slices and compare mutually known target/donor bytes')
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
    def logical_holes(extents):
        holes=[]
        for logical,physical,length in extents:
            for lo,hi in missing(physical,physical+length):
                while lo<hi:
                    base=lo//stride*stride;stop=min(hi,base+stride)
                    if base not in mapped:holes.append((logical+lo-physical,logical+stop-physical))
                    lo=stop
        return sorted(holes)
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
            target_extents=file_extents(records[0],size)
            bases={base for logical,physical,length in target_extents for base in range(physical//stride*stride,physical+length,stride) if unknown(base)}
            if not bases:report['skipped']='no unresolved target backup frames';continue
            for r in records:
                extents=file_extents(r,size);positions.append(extents)
                view=FileView(r.open(),extents,size,mapped,decode);data=view if streaming else view[:]
                contents.append(data)
            target_extents,donor_extents=positions;tdata,ddata=contents
            donor_holes=logical_holes(donor_extents)
            if donor_holes and not a.allow_partial_donor:raise ValueError('donor has unresolved bytes')
            holes=[];restored=[]
            for logical,physical,length in target_extents:
                holes.extend((logical+lo-physical,logical+hi-physical) for lo,hi in missing(physical,physical+length))
                for mb,m in mapped.items():
                    lo=max(physical,mb);hi=min(physical+length,mb+m['length'])
                    if hi>lo:restored.append((logical+lo-physical,logical+hi-physical))
            compared=0;donor_hash=hashlib.sha256()
            for chunk in range(0,size,8*1024**2):
                stop=min(size,chunk+8*1024**2);known=bytearray(b'\1')*(stop-chunk)
                for lo,hi in holes:
                    lo=max(chunk,lo);hi=min(stop,hi)
                    if hi>lo:known[lo-chunk:hi-chunk]=b'\0'*(hi-lo)
                for lo,hi in restored:
                    lo=max(chunk,lo);hi=min(stop,hi)
                    if hi>lo:known[lo-chunk:hi-chunk]=b'\1'*(hi-lo)
                for lo,hi in donor_holes:
                    lo=max(chunk,lo);hi=min(stop,hi)
                    if hi>lo:known[lo-chunk:hi-chunk]=b'\0'*(hi-lo)
                target_chunk=tdata[chunk:stop];donor_chunk=ddata[chunk:stop];donor_hash.update(donor_chunk);compared+=known.count(1)
                if target_chunk!=donor_chunk and any(x!=y for x,y,k in zip(target_chunk,donor_chunk,known) if k):raise ValueError('surviving target bytes differ')
            metadata_inference=False;mtime=None
            if compared<4096:
                times=[r.attributes.STANDARD_INFORMATION[0].attr.LastModificationTime for r in records]
                metadata_inference=bool(a.allow_metadata_duplicates and records[0].filename.casefold()==records[1].filename.casefold() and times[0] and times[0]==times[1])
                if not metadata_inference:raise ValueError('insufficient surviving target bytes')
                mtime=int(times[0])
            report.update(size=size,compared_bytes=compared,donor_sha256=donor_hash.hexdigest(),candidates=0)
            if donor_holes:report.update(donor_complete=False,donor_unresolved_bytes=sum(hi-lo for lo,hi in donor_holes),donor_hash_scope='observed bytes including unresolved zero placeholders; not a complete-file digest')
            if metadata_inference:report.update(metadata_inference=True,original_modification_filetime=mtime)
            for base in sorted(bases):
                pieces=exclude_holes(frame_pieces(target_extents,base,stride),donor_holes);expected=[ddata[logical:logical+length] for offset,logical,length in pieces];matched=sum(len(part) for part in expected)
                full=matched==stride and pieces[0][0]==0 and all(pieces[i][0]+pieces[i][2]==pieces[i+1][0] for i in range(len(pieces)-1))
                if full:
                    data=b''.join(expected);sha=hashlib.sha256(data).hexdigest();matches=frames.get((stride,sha),[])
                    if metadata_inference and not distinctive(data):continue
                elif a.allow_boundary and distinctive(b''.join(expected)):
                    matches=[]
                    for (length,sha),rows in frames.items():
                        if length!=stride:continue
                        corpus.seek(exports[rows[0][0]]);candidate=corpus.read(stride)
                        if all(candidate[offset:offset+n]==part for (offset,logical,n),part in zip(pieces,expected)):matches.extend(rows)
                else:continue
                if len({f[5] for f in matches})!=1:continue
                method='intact-duplicate-file-exact-frame' if full else 'intact-duplicate-file-exact-boundary-slice'
                pair_pending[base]=(matches[0],dict(method=method,target=target,donor=donor,compared_bytes=compared,donor_sha256=report['donor_sha256'],pieces=[dict(decoded_offset=o,logical_offset=l,length=n) for o,l,n in pieces],matched_bytes=matched,target_extent_count=len(target_extents),donor_extent_count=len(donor_extents)),matches);report['candidates']+=1
                if donor_holes:pair_pending[base][1].update(donor_complete=False,donor_hash_scope=report['donor_hash_scope'],donor_unresolved_bytes=report['donor_unresolved_bytes'])
            if metadata_inference:
                for f,e,rows in pair_pending.values():e.update(metadata_inference=True,original_modification_filetime=mtime,identity_evidence='same original filename, size and exact NTFS modification FILETIME; original target bytes insufficient')
            for base,item in pair_pending.items():
                if base in pending and pending[base][0][5]!=item[0][5]:conflicts.add(base);pending.pop(base)
                if base not in conflicts:pending[base]=item
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='recover_duplicate_files.py:184')
            report['rejected']=str(e)
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
