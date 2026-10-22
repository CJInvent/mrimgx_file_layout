"""Map orphan data using SQLite WAL salts, rolling checksums and frame grid.

At least two checksum transitions must validate within the orphan. Salt identity
and original file runlist/grid must yield exactly one destination. No WAL replay.
Format: https://www.sqlite.org/fileformat2.html#wal_file_format
"""
from rebuild_audit import caught as _audit_caught
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import sqlite3
import struct
import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def checksum(data,seed=(0,0),big=False):
    if len(data)%8:raise ValueError('checksum input must contain word pairs')
    s0,s1=seed
    for x,y in struct.iter_unpack('>II' if big else '<II',data):
        s0=(s0+x+s1)&0xffffffff;s1=(s1+y+s0)&0xffffffff
    return s0,s1


def transitions(data,position,page,salt,big):
    step=page+24;good=[]
    while position+2*step<=len(data):
        previous=data[position:position+24];pos=position+step;head=data[pos:pos+24]
        if previous[8:16]==salt and head[8:16]==salt and 0<struct.unpack_from('>I',head)[0]<0xffffffff:
            seed=struct.unpack_from('>II',previous,16)
            if checksum(head[:8]+data[pos+24:pos+step],seed,big)==struct.unpack_from('>II',head,16):good.append(pos)
        position+=step
    return good


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted)
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][2]
    origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2};ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']));fs.mft.fh=a.mft.open('rb');source=a.source.open('rb');targets=[];errors=[]
    for row in map(json.loads,a.inventory.open()):
        if not (row.get('path') or '').lower().endswith('-wal'):continue
        try:
            r=fs.mft.get(row['record']);runs=list(r.dataruns());size=r.size()
            if len(runs)!=1 or runs[0][0] is None or any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):continue
            physical=runs[0][0]*4096;header=bytearray(r.open().read(32))
            for mb,m in mapped.items():
                lo=max(physical,mb);hi=min(physical+32,mb+m['length'])
                if hi>lo:
                    source.seek(m['source_offset']);data=zstandard.ZstdDecompressor().decompress(source.read(m['stored_length']));header[lo-physical:hi-physical]=data[lo-mb:hi-mb]
            if len(header)!=32:continue
            magic,version,page=struct.unpack_from('>III',header)
            if magic not in (0x377f0682,0x377f0683) or version!=3007000 or page<512 or page>65536 or page&(page-1):continue
            big=bool(magic&1)
            if checksum(header[:24],big=big)!=struct.unpack_from('>II',header,24):continue
            targets.append(dict(record=row['record'],physical=physical,size=size,page=page,salt=bytes(header[16:24]),big=big))
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='recover_sqlite_wal.py:71')
            errors.append(dict(record=row['record'],error=str(e)))
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);used={f for m in accepted for f in m['frames']};pending=collections.defaultdict(list)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
            if f[0] in used or f[4]!=stride:continue
            corpus.seek(f[3]);data=corpus.read(stride);votes=collections.defaultdict(list)
            for t in targets:
                hit=data.find(t['salt']);step=t['page']+24
                if hit<8:continue
                pos=hit-8;good=transitions(data,pos,t['page'],t['salt'],t['big'])
                if len(good)<2:continue
                for n in range(max(0,(pos-32)//step),max(0,(t['size']-32)//step)):
                    logical=32+n*step-pos;base=t['physical']+logical
                    if logical<0 or logical+stride>t['size'] or base%stride or not unknown(base):continue
                    votes[base].append(dict(method='sqlite-wal-salt-checksum-grid',record=t['record'],logical_offset=logical,salt=t['salt'].hex(),checksum_transitions=len(good),first_frame_offset=pos,page_size=t['page']))
            if len(votes)==1:
                base,ev=next(iter(votes.items()));pending[base].append((f,ev))
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({f[6] for f,e in items})!=1:conflicts.append(base);continue
        f=items[0][0];source.seek(f[1]);data=zstandard.ZstdDecompressor().decompress(source.read(f[2]))
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source revalidation')
        accepted.append(dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=[f[0] for f,e in items],evidence=[e for f,ev in items for e in ev]))
        plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Original SQLite WAL salts, multiple rolling checksum transitions and unique NTFS file/frame grid agree. Original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),wal_additions=len(accepted)-previous,wal_headers=len(targets),conflicts=conflicts,errors=errors)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
