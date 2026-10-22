"""Use embedded PE image digests to solve one missing frame in a known file.

Each candidate fills only the missing file extent(s), preserving the original
header, certificate and all known neighbors. No recovered executable is run.
"""
from rebuild_audit import caught as _audit_caught
import argparse
import bisect
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
from pe_anchors import image_digest


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):
        ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted)
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text())
    layout=json.loads((a.evidence/'layout.json').read_text());p=layout['disks'][0]['partitions'][2]
    stride=p['_header']['block_size'];origin=p['_geometry']['start'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2}
    ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):
            ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[r[0] for r in ranges]
    def unknown(base):
        if base in mapped:return False
        k=bisect.bisect_right(starts,base)-1
        return k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']))
    fs.mft.fh=a.mft.open('rb',buffering=8*1024**2);source=a.source.open('rb')
    @functools.lru_cache(maxsize=256)
    def frame_bytes(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    class Overlay(io.RawIOBase):
        def __init__(self):self.pos=0
        def readable(self):return True
        def seekable(self):return True
        def tell(self):return self.pos
        def seek(self,offset,whence=0):
            self.pos=offset if whence==0 else self.pos+offset if whence==1 else p['_geometry']['length']+offset
            return self.pos
        def read(self,length=-1):
            if length<0:raise ValueError('unbounded read')
            address=self.pos;v.seek(origin+address);data=bytearray(v.read(length));base=address-address%stride
            while base<address+length:
                if base in mapped:
                    m=mapped[base];decoded=frame_bytes(m['source_offset'],m['stored_length']);lo=max(base,address);hi=min(base+len(decoded),address+length)
                    data[lo-address:hi-address]=decoded[lo-base:hi-base]
                base+=stride
            self.pos+=len(data);return bytes(data)
    fs.fh=Overlay()
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);corpus=(a.evidence/'orphan-decoded.bin').open('rb')
    used={fid for m in accepted for fid in m['frames']};frames=[]
    for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
        f=dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row))
        if f['id'] in used or f['decoded_length']!=stride:continue
        corpus.seek(f['export_offset']);f['data']=corpus.read(stride);frames.append(f)
    targets=[];stats={};reports=(a.output/'signed-pe-evidence.jsonl').open('x')
    for line in a.inventory.open():
        row=json.loads(line);path=row.get('path') or ''
        if pathlib.PureWindowsPath(path).suffix.lower() not in ('.dll','.exe','.sys','.ocx','.cpl','.mui','.winmd','.scr'):continue
        try:
            r=fs.mft.get(row['record']);size=r.size()
            if not 8192<size<=2*1024**2 or any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):continue
            extents=[];logical=0;unknown_bases=set()
            for lcn,count in r.dataruns():
                length=min(count*4096,max(0,size-logical))
                if lcn is not None and length:
                    physical=lcn*4096;extents.append((logical,logical+length,physical));base=physical-physical%stride
                    while base<physical+length:
                        if unknown(base):unknown_bases.add(base)
                        base+=stride
                logical+=count*4096
            if len(unknown_bases)!=1:continue
            base=unknown_bases.pop();patches=[]
            for lo,hi,physical in extents:
                start=max(physical,base);end=min(physical+hi-lo,base+stride)
                if end>start:patches.append((lo+start-physical,lo+end-physical,start-base))
            if any(lo<512 for lo,hi,off in patches):continue
            data=r.open().read()
            if data[:2]!=b'MZ':continue
            info=image_digest(data,verify=False)
            if info['matches']:continue
            if any(hi>info['certificate_offset'] for lo,hi,off in patches):continue
            # Restrict to a single missing contiguous portion for efficient,
            # exact prefix-state hashing. Fragmented hypotheses stay unresolved.
            if len(patches)!=1:continue
            lo,hi,off=patches[0];cs=info['checksum_offset'];sec=info['security_offset'];cert=info['certificate_offset']
            if lo<sec+8:continue
            prefix=hashlib.new(info['algorithm']);prefix.update(data[:cs]);prefix.update(data[cs+4:sec]);prefix.update(data[sec+8:lo])
            targets.append(dict(record=row['record'],base=base,lo=lo,hi=hi,frame_offset=off,info=info,prefix=prefix,suffix=data[hi:cert]))
        except Exception as _audit_error:
            _audit_caught(_audit_error, locals(), expected=False, site='extend_signed_pe_mappings.py:104')
            continue
    print('signed PE single-frame targets',len(targets),'candidate frames',len(frames),flush=True)
    proposals={}
    for index,t in enumerate(targets):
        matches=[]
        for f in frames:
            if f['id'] in used:continue
            h=t['prefix'].copy();off=t['frame_offset'];n=t['hi']-t['lo'];h.update(f['data'][off:off+n]);h.update(t['suffix'])
            if h.hexdigest()==t['info']['digest']:matches.append(f)
        evidence={k:v for k,v in t.items() if k not in ('prefix','suffix')};evidence['matches']=[f['id'] for f in matches];reports.write(json.dumps(evidence)+'\n')
        if len({f['sha256'] for f in matches})==1:proposals.setdefault(t['base'],[]).append((matches[0],evidence))
        if index%50==0:print('signed PE targets processed',index,flush=True)
    frame_destinations={}
    for base,rows in proposals.items():
        for f,e in rows:frame_destinations.setdefault(f['id'],set()).add(base)
    for base,rows in sorted(proposals.items()):
        if len({f['sha256'] for f,e in rows})!=1 or any(len(frame_destinations[f['id']])!=1 for f,e in rows):continue
        f=rows[0][0];data=frame_bytes(f['source_offset'],f['stored_length'])
        if data!=f['data'] or hashlib.sha256(data).hexdigest()!=f['sha256']:raise ValueError('source frame revalidation')
        m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=sorted({f['id'] for f,e in rows}),evidence=[dict(method='known-pe-embedded-image-digest',detail=e) for f,e in rows])
        accepted.append(m)
        plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),reason='Missing PE fragment identified by complete embedded image digest with original NTFS file runlist and known header/certificate/neighbors; original index digest unavailable.')
    reports.close()
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    summary=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),signed_pe_additions=len(accepted)-previous,targets=len(targets))
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
