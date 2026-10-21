"""Iterate package hash constraints across frame boundaries using known neighbors."""
import argparse
import bisect
import collections
import functools
import hashlib
import io
import json
import pathlib
import sqlite3

import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream
from appx_anchors import targets,match


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):
        ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text())
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text())
    layout=json.loads((a.evidence/'layout.json').read_text());p=layout['disks'][0]['partitions'][2]
    stride=p['_header']['block_size'];origin=p['_geometry']['start']
    ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):
            ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[x[0] for x in ranges]
    mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2}
    def unknown(base):
        if base in mapped:return False
        k=bisect.bisect_right(starts,base)-1
        return k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']))
    fs.mft.fh=a.mft.open('rb',buffering=8*1024**2)
    corpus=(a.evidence/'orphan-decoded.bin').open('rb')
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    frames=[dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row)) for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames')]
    @functools.lru_cache(maxsize=256)
    def decoded(offset,length):
        corpus.seek(offset);return corpus.read(length)
    source=a.source.open('rb')
    @functools.lru_cache(maxsize=256)
    def source_frame(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    def read_known(address,length):
        v.seek(origin+address);out=bytearray(v.read(length));base=address-address%stride
        while base<address+length:
            if base in mapped:
                m=mapped[base];data=source_frame(m['source_offset'],m['stored_length'])
                lo=max(address,base);hi=min(address+length,base+len(data))
                out[lo-address:hi-address]=data[lo-base:hi-base]
            base+=stride
        return bytes(out)
    class Overlay(io.RawIOBase):
        def __init__(self):self.pos=0
        def readable(self):return True
        def seekable(self):return True
        def tell(self):return self.pos
        def seek(self,offset,whence=0):
            self.pos=offset if whence==0 else self.pos+offset if whence==1 else p['_geometry']['length']+offset
            if not 0<=self.pos<=p['_geometry']['length']:raise ValueError('overlay seek bounds')
            return self.pos
        def read(self,length=-1):
            if length<0:raise ValueError('unbounded overlay read')
            length=min(length,p['_geometry']['length']-self.pos)
            data=read_known(self.pos,length);self.pos+=len(data);return data
    # Newly mapped directory pages and package metadata can unlock additional
    # block maps. Read them through the mapped overlay, while keeping baseline
    # and original cached MFT bytes immutable.
    fs.fh=Overlay()
    previous=len(accepted);stats=[]
    with (a.output/'iteration-evidence.jsonl').open('x') as log:
        for iteration in range(1,9):
            groups,counts,errors=targets(fs,a.inventory,stride,unknown,read_known)
            print('cross-frame iteration',iteration,'groups',len(groups),flush=True)
            used={fid for m in accepted for fid in m['frames']};proposals=collections.defaultdict(list)
            for f in frames:
                if f['id'] in used or f['decoded_length']!=stride:continue
                data=decoded(f['export_offset'],f['decoded_length'])
                for base,evidence in match(data,groups):proposals[base].append((f,evidence))
            additions=[];conflicts=[]
            for base,rows in sorted(proposals.items()):
                if len({f['sha256'] for f,e in rows})!=1:
                    conflicts.append(base);continue
                f=rows[0][0];data=source_frame(f['source_offset'],f['stored_length'])
                if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f['sha256'] or hashlib.md5(data).digest()!=f['md5']:raise ValueError('source frame revalidation')
                m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,
                       source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=sorted({f['id'] for f,e in rows}),
                       evidence=[dict(method='appx-cross-frame-sha256-mft-runlist',iteration=iteration,detail=e) for f,e in rows])
                additions.append(m)
            # Resolve destination evidence before exposing any additions to the
            # next iteration. Reject a frame proposed at multiple new bases.
            frame_counts=collections.Counter(fid for m in additions for fid in m['frames'])
            additions=[m for m in additions if all(frame_counts[fid]==1 for fid in m['frames'])]
            for m in additions:
                mapped[m['disk_offset']-origin]=m;accepted.append(m)
                plan['partitions'][2].setdefault('overrides',{})[str(m['block'])]=dict(source_offset=m['source_offset'],stored_length=m['stored_length'],decoded_md5=m['decoded_md5'],reason='AppxBlockMap SHA-256 block reconstructed across mapped neighboring frames and original MFT runlist; original index hash unavailable.')
                log.write(json.dumps(m)+'\n')
            stat=dict(iteration=iteration,groups=len(groups),added=len(additions),conflicting_destinations=conflicts,blockmap_statistics=counts,blockmap_errors=errors)
            stats.append(stat);log.flush();print('cross-frame added',len(additions),flush=True)
            if not additions:break
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2))
    (a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    summary=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),cross_frame_additions=len(accepted)-previous,iterations=stats)
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps({k:v for k,v in summary.items() if k!='iterations'}),flush=True)


if __name__=='__main__':main()
