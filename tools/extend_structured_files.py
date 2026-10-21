"""Corroborate frame addresses with multiple complete CRC-checked small files.

Requires at least three distinct file starts, distinct sizes and MFT records
agreeing on one unique frame base. Size alone never accepts a placement.
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import sqlite3
import struct
import zlib

import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def file_length(data,kind):
    if kind=='png':
        if data[:8]!=b'\x89PNG\r\n\x1a\n':raise ValueError('PNG signature')
        offset=8;chunks=0
        while offset+12<=len(data):
            n=struct.unpack_from('>I',data,offset)[0]
            if offset+12+n>len(data):raise ValueError('incomplete PNG')
            typ=data[offset+4:offset+8]
            if not chunks and (typ!=b'IHDR' or n!=13):raise ValueError('PNG IHDR')
            if zlib.crc32(data[offset+4:offset+8+n])!=struct.unpack_from('>I',data,offset+8+n)[0]:raise ValueError('PNG CRC')
            chunks+=1;offset+=12+n
            if typ==b'IEND':
                if n or chunks<3:raise ValueError('PNG end')
                return offset
        raise ValueError('incomplete PNG')
    if kind=='gz':
        decoder=zlib.decompressobj(31);decoder.decompress(data,16*1024**2)
        if not decoder.eof:raise ValueError('incomplete or excessive gzip')
        return len(data)-len(decoder.unused_data)
    raise ValueError('unknown format')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted)
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());layout=json.loads((a.evidence/'layout.json').read_text());p=layout['disks'][0]['partitions'][2]
    origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin for m in accepted if m['partition']==2}
    ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        if base in mapped:return False
        k=bisect.bisect_right(starts,base)-1
        return k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']));fs.mft.fh=a.mft.open('rb',buffering=8*1024**2)
    targets=collections.defaultdict(list)
    for line in a.inventory.open():
        row=json.loads(line);path=row.get('path') or '';ext=pathlib.PureWindowsPath(path).suffix.lower()
        if ext not in ('.png','.gz'):continue
        try:
            r=fs.mft.get(row['record']);size=r.size();runs=r.dataruns()
            if not r.header.Flags&1 or not 32<size<stride or not runs or runs[0][0] is None or any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):continue
            if runs[0][1]*4096<size:continue
            address=runs[0][0]*4096;base=address-address%stride
            if unknown(base):targets[(ext[1:],size)].append(dict(base=base,address=address,record=row['record'],filename=pathlib.PureWindowsPath(path).name))
        except Exception:continue
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);used={fid for m in accepted for fid in m['frames']}
    pending=collections.defaultdict(list)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus,a.source.open('rb') as source,(a.output/'structured-file-evidence.jsonl').open('x') as log:
        for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
            f=dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row))
            if f['id'] in used or f['decoded_length']!=stride:continue
            corpus.seek(f['export_offset']);data=corpus.read(stride);votes=collections.defaultdict(list)
            for off in range(0,len(data)-32,4096):
                kind='png' if data[off:off+8]==b'\x89PNG\r\n\x1a\n' else 'gz' if data[off:off+3]==b'\x1f\x8b\x08' else None
                if kind is None:continue
                try:length=file_length(data[off:],kind)
                except Exception:continue
                for target in targets.get((kind,length),[]):
                    base=target['address']-off
                    if base==target['base'] and base%stride==0:votes[base].append(dict(target,frame_offset=off,length=length,format=kind,crc_valid=True))
            qualified={base:rows for base,rows in votes.items() if len({e['record'] for e in rows})>=3 and len({e['frame_offset'] for e in rows})>=3 and len({e['length'] for e in rows})>=3 and sum({e['frame_offset']:e['length'] for e in rows}.values())>=8192}
            if votes:log.write(json.dumps(dict(frame=f['id'],candidate_bases={str(base):rows for base,rows in votes.items()},qualified_bases=list(qualified)))+'\n')
            if len(qualified)!=1:continue
            base,evidence=next(iter(qualified.items()))
            source.seek(f['source_offset']);decoded=zstandard.ZstdDecompressor().decompress(source.read(f['stored_length']))
            if decoded!=data or hashlib.sha256(data).hexdigest()!=f['sha256']:raise ValueError('source frame revalidation')
            m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=[f['id']],evidence=[dict(method='multiple-crc-files-mft-layout',detail=evidence)])
            pending[base].append(m)
    conflicts=[]
    for base,rows in sorted(pending.items()):
        if len({m['sha256'] for m in rows})!=1:
            conflicts.append(base);continue
        m=rows[0];m['frames']=sorted({fid for row in rows for fid in row['frames']});accepted.append(m)
        plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=m['source_offset'],stored_length=m['stored_length'],decoded_md5=m['decoded_md5'],reason='At least three complete CRC-validated PNG/gzip files with distinct sizes and original MFT runlist starts agree on a unique frame address; structural reconstruction, original digest absent.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    summary=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),structured_file_additions=len(accepted)-previous,conflicting_bases=conflicts)
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
