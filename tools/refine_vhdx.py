"""Apply mapped source frames to a completed exclusive clone of a baseline VHDX.

Only absent baseline manifest ranges can be changed. The baseline, source,
original plan and evidence stay read-only. Uses standalone VHDX payload states
0/2/6 only, rejects parents and active logs, records each physical mutation.
"""
import argparse
import hashlib
import json
import os
import pathlib
import struct
import uuid

import zstandard
from safe_vhdx import VHDX
from dissect.util.hash.crc32c import crc32c
from placement_payload import payload


def checksum_block(raw, signature):
    data=bytearray(raw)
    if data[:4]!=signature:raise ValueError('container signature')
    expected=struct.unpack_from('<I',data,4)[0];data[4:8]=bytes(4)
    if crc32c(bytes(data))!=expected:raise ValueError('container CRC32C')
    return data


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','clone','clone_manifest','baseline_manifest','mappings','output_manifest'):
        ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--previous-refinement',type=pathlib.Path)
    ap.add_argument('--supplemental',type=pathlib.Path,help='independently validated file slices/bit repairs, kept separate from full-frame mappings')
    a=ap.parse_args()
    paths=[a.source.resolve(),a.baseline.resolve(),a.clone.resolve()]
    if len(set(paths))!=3:raise ValueError('source, baseline and clone must differ')
    state={p:(p.stat().st_size,p.stat().st_mtime_ns) for p in (a.source,a.baseline)}
    with a.clone_manifest.open() as cm:
        first=json.loads(next(cm));last=first
        for line in cm:last=json.loads(line)
    previous=[];previous_mutations=[]
    if a.previous_refinement:
        previous=[json.loads(line) for line in a.previous_refinement.open()]
        if previous[-1].get('operation')!='complete' or previous[0].get('baseline')!=str(a.baseline.resolve()) or previous[0].get('clone')!=str(a.clone.resolve()):raise ValueError('previous refinement provenance')
        previous_mutations=previous[-1]['physical_mutations']
    size_ok=first['size']<=a.clone.stat().st_size if previous else first['size']==a.clone.stat().st_size
    if first['source']!=str(a.baseline.resolve()) or last.get('operation')!='complete' or not last.get('source_stat_unchanged') or not size_ok:
        raise ValueError('clone provenance incomplete or mismatched')
    if (first['size'],first['mtime_ns'])!=state[a.baseline]:raise ValueError('baseline changed since clone')
    absent={}
    for line in a.baseline_manifest.open():
        j=json.loads(line)
        if j.get('operation')=='range' and j.get('status') in ('unknown-zero-index','unrecoverable'):
            absent.setdefault(j['partition'],[]).append((j['disk_offset'],j['disk_offset']+j['length']))
    mappings=json.loads(a.mappings.read_text());intervals=[];supplements={}
    for row in previous:
        if row.get('operation')=='placed-supplement':supplements[(row['disk_offset'],row['length'])]={k:v for k,v in row.items() if k!='operation'}
    if a.supplemental:
        for m in json.loads(a.supplemental.read_text()):
            key=(m['disk_offset'],m['length'])
            if key in supplements and supplements[key]['sha256']!=m['sha256']:raise ValueError('supplement contradicts a previous verified slice')
            supplements.setdefault(key,m)
    supplements=list(supplements.values());all_requests=mappings+supplements
    for index,m in enumerate(all_requests):
        start=m['disk_offset'];end=start+m['length']
        if not any(lo<=start and end<=hi for lo,hi in absent.get(m['partition'],[])):raise ValueError('mapping would replace available baseline data')
        if index<len(mappings):intervals.append((start,end))
    intervals.sort()
    if any(end>nstart for (_,end),(nstart,_) in zip(intervals,intervals[1:])):raise ValueError('overlapping mappings')
    baseline=VHDX(a.baseline); clone=VHDX(a.clone)
    if baseline.size!=clone.size or clone.has_parent or clone.block_size!=2*1024**2 or clone.sector_size!=512:
        raise ValueError('unsupported or mismatched VHDX geometry')
    already={row['disk_offset']:row for row in previous if row.get('operation')=='placed'}
    old_supplements={(row['disk_offset'],row['length']):row for row in previous if row.get('operation')=='placed-supplement'}
    requested={m['disk_offset']:m for m in mappings}
    for position,m in already.items():
        if position not in requested or requested[position]['sha256']!=m['sha256'] or requested[position]['length']!=m['length']:raise ValueError('new mappings contradict previous refinement')
        clone.seek(position)
        if hashlib.sha256(clone.read(m['length'])).hexdigest()!=m['sha256']:raise ValueError('previous placement changed')
    for (position,length),m in old_supplements.items():
        clone.seek(position)
        if hashlib.sha256(clone.read(length)).hexdigest()!=m['sha256']:raise ValueError('previous verified file slice changed')
    # Validate every target before the first mutation. Incomplete source or a
    # contradictory baseline must never leave a partially refined output.
    with a.source.open('rb') as preflight:
        for m in all_requests:
            baseline.seek(m['disk_offset'])
            if any(baseline.read(m['length'])):raise ValueError('unresolved baseline range contains unexpected nonzero bytes')
            data=payload(preflight,m)
        # Overlapping requests are permitted only for identical validated
        # bytes. Thus a later full frame can cover an earlier proven slice.
        for i,m in enumerate(supplements):
            for n in mappings+supplements[:i]:
                lo=max(m['disk_offset'],n['disk_offset']);hi=min(m['disk_offset']+m['length'],n['disk_offset']+n['length'])
                if hi>lo and payload(preflight,m)[lo-m['disk_offset']:hi-m['disk_offset']]!=payload(preflight,n)[lo-n['disk_offset']:hi-n['disk_offset']]:raise ValueError('conflicting verified source slices')
    bat_offset=clone.bat.offset;count=clone.bat.entry_count;blocksize=clone.block_size;ratio=clone._chunk_ratio
    # Snapshot metadata before opening the clone for writes; close parser file
    # handles so buffered reads can never hide modified payload data.
    clone.fh.close()
    with a.clone.open('r+b',buffering=0) as dst, a.source.open('rb') as src, a.output_manifest.open('x') as log:
        mutations=list(previous_mutations)
        def write(offset,data):
            dst.seek(offset)
            if dst.write(data)!=len(data):raise OSError('short VHDX write')
            mutations.append((offset,offset+len(data)))
        headers=[]
        for off in (65536,131072):
            dst.seek(off);h=checksum_block(dst.read(4096),b'head')
            if any(h[48:64]):raise ValueError('active VHDX log')
            headers.append((off,h))
        for off in (196608,262144):
            dst.seek(off);checksum_block(dst.read(65536),b'regi')
        dst.seek(bat_offset);bat=list(struct.unpack('<'+'Q'*count,dst.read(count*8)))
        for i in range((clone.size+blocksize-1)//blocksize):
            if bat[i+i//ratio]&7 not in (0,2,6):raise ValueError('unsupported BAT state')
        fileid=uuid.uuid4().bytes_le;dataid=uuid.uuid4().bytes_le
        sequence=max(struct.unpack_from('<Q',h,8)[0] for _,h in headers)+1
        for off,h in headers:
            struct.pack_into('<Q',h,8,sequence);sequence+=1;h[16:32]=fileid;h[32:48]=dataid
            struct.pack_into('<I',h,4,crc32c(bytes(h)));write(off,h)
        begin=dict(operation='begin',baseline=str(a.baseline.resolve()),clone=str(a.clone.resolve()),mappings=len(mappings))
        if a.previous_refinement:begin['previous_refinement_sha256']=hashlib.sha256(a.previous_refinement.read_bytes()).hexdigest()
        log.write(json.dumps(begin)+'\n');log.flush()
        for index,m in enumerate(all_requests):
            supplemental=index>=len(mappings);operation='placed-supplement' if supplemental else 'placed'
            previously_placed=(m['disk_offset'],m['length']) in old_supplements if supplemental else m['disk_offset'] in already
            if previously_placed:
                log.write(json.dumps(dict(operation=operation,**m))+'\n');continue
            data=payload(src,m)
            position=m['disk_offset'];remaining=data
            baseline.seek(position)
            if any(baseline.read(len(data))):raise ValueError('unresolved baseline range contains unexpected nonzero bytes')
            while remaining:
                block,within=divmod(position,blocksize);slot=block+block//ratio;entry=bat[slot]
                if entry&7 in (0,2):
                    # Explicitly write a zero block; this avoids CRT sparse
                    # extension semantics and preserves every other sector.
                    offset=(a.clone.stat().st_size+1048575)&~1048575
                    write(offset,bytes(blocksize));entry=offset|6;bat[slot]=entry;write(bat_offset+slot*8,struct.pack('<Q',entry))
                n=min(len(remaining),blocksize-within)
                write((entry&0xfffffffffff00000)+within,remaining[:n]);position+=n;remaining=remaining[n:]
            log.write(json.dumps(dict(operation=operation,**m))+'\n')
        dst.flush();os.fsync(dst.fileno())
        for p,expected in state.items():
            if (p.stat().st_size,p.stat().st_mtime_ns)!=expected:raise ValueError('protected input changed')
        log.write(json.dumps(dict(operation='complete',placed_bytes=sum(m['length'] for m in mappings),supplemental_bytes=sum(m['length'] for m in supplements),supplemental_destinations=len(supplements),protected_input_stats_unchanged=True,physical_mutations=mutations))+'\n')
    baseline.fh.close()
    # Reopen through an independent reader, checking every new destination.
    result=VHDX(a.clone)
    for m in all_requests:
        result.seek(m['disk_offset']);data=result.read(m['length'])
        if hashlib.sha256(data).hexdigest()!=m['sha256']:raise ValueError('independent VHDX readback failed')
    print(json.dumps(dict(placed_destinations=len(mappings),placed_bytes=sum(m['length'] for m in mappings),supplemental_destinations=len(supplements),supplemental_bytes=sum(m['length'] for m in supplements),independent_readback=True)),flush=True)


if __name__=='__main__':main()
