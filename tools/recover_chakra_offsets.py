"""Map serialized Chakra bytecode through nested-function absolute offsets.

Chakra serializes nested bodies in reverse order: the last descending child
pointer addresses the first body immediately after its pointer array. Two
independent arrays must infer one frame address and match surviving body masks.
Only parses bytes; never loads bytecode into an engine or executes it.
Reference: ChakraCore lib/Runtime/ByteCode/ByteCodeSerializer.cpp, AddFunction.
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import sqlite3
import struct
import numpy as np
import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def pointer_arrays(data,functions_start,file_size,minimum=8):
    for phase in range(4):
        end=len(data)-(len(data)-phase)%4
        if end<=phase:continue
        words=np.frombuffer(data[phase:end],dtype='<u4')
        valid=(words>=functions_start)&(words<file_size)
        steps=valid[:-1]&valid[1:]&(words[:-1]>words[1:])&((words[:-1]-words[1:])>=16)
        edges=np.flatnonzero(np.diff(np.r_[False,steps,False].astype(np.int8)))
        for lo,hi in edges.reshape(-1,2):
            count=int(hi-lo+1)
            if count<minimum:continue
            finish=int(phase+(hi+1)*4);first=int(words[hi]);origin=first-finish
            yield dict(origin=origin,pointer_start=int(phase+lo*4),pointer_end=finish,pointer_count=count,first_body_offset=first,body_prefix=data[finish:finish+4].hex())


def read_variable(data,offset):
    value=data[offset]
    if value<254:return value,offset+1
    if value==254:return struct.unpack_from('<H',data,offset+1)[0],offset+3
    return struct.unpack_from('<i',data,offset+1)[0],offset+5


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--record',type=int,required=True)
    ap.add_argument('--minimum-pointers',type=int,default=8)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    if a.minimum_pointers<3:raise ValueError('requires at least three descending child pointers per array')
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted)
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][2]
    origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2}
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
    record=fs.mft.get(a.record);runs=record.dataruns();size=record.size()
    if len(runs)!=1 or runs[0][0] is None or any(attr.header.flags&0x4001 for attr in record.attributes.DATA if attr.name==''):raise ValueError('requires contiguous uncompressed bytecode file')
    physical=runs[0][0]*4096;known=bytearray(record.open().read());source=a.source.open('rb')
    for base,m in mapped.items():
        start=max(physical,base);end=min(physical+size,base+stride)
        if end>start:
            source.seek(m['source_offset']);data=zstandard.ZstdDecompressor().decompress(source.read(m['stored_length']));known[start-physical:end-physical]=data[start-base:end-base]
    if known[:4]!=b'ChBc' or struct.unpack_from('<I',known,4)[0]!=size or known[25]!=64:raise ValueError('unsupported bytecode header/size/architecture')
    offset=26
    for _ in range(5):value,offset=read_variable(known,offset)
    strings,lines,functions,scopes=struct.unpack_from('<IIII',known,offset)
    if not 0<strings<lines<functions<scopes<size:raise ValueError('bytecode section bounds')
    known_arrays=[e for e in pointer_arrays(known,functions,size) if e['origin']==0]
    body_masks={e['body_prefix'] for e in known_arrays if len(e['body_prefix'])==8}
    if len({e['pointer_end'] for e in known_arrays})<4:raise ValueError('insufficient surviving self-address corroboration')
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);used={fid for m in accepted for fid in m['frames']};pending=collections.defaultdict(list)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus,(a.output/'chakra-evidence.jsonl').open('x') as log:
        for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
            f=dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row))
            if f['id'] in used or f['decoded_length']!=stride:continue
            corpus.seek(f['export_offset']);data=corpus.read(stride);votes=collections.defaultdict(list)
            for e in pointer_arrays(data,functions,size,a.minimum_pointers):
                logical=e['origin'];base=physical+logical
                if functions<=logical<size and base%stride==0 and unknown(base) and e['body_prefix'] in body_masks:
                    votes[base].append(e)
            qualified={}
            for base,entries in votes.items():
                selected=[]
                for e in sorted(entries,key=lambda e:e['pointer_start']):
                    if not selected or e['pointer_start']>=selected[-1]['pointer_end']:selected.append(e)
                if len(selected)>=2:qualified[base]=selected
            if len(qualified)!=1:continue
            base,evidence=next(iter(qualified.items()));log.write(json.dumps(dict(frame=f['id'],record=a.record,base=base,arrays=evidence))+'\n');pending[base].append((f,evidence))
    conflicts=[]
    for base,rows in sorted(pending.items()):
        if len({f['sha256'] for f,e in rows})!=1:conflicts.append(base);continue
        f=rows[0][0];source.seek(f['source_offset']);data=zstandard.ZstdDecompressor().decompress(source.read(f['stored_length']))
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f['sha256'] or hashlib.md5(data).digest()!=f['md5']:raise ValueError('source revalidation')
        m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=sorted({f['id'] for f,e in rows}),evidence=[dict(method='chakra-nested-function-self-offsets',record=a.record,detail=e) for f,e in rows])
        accepted.append(m);plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),reason='Multiple independent Chakra nested-function absolute offset arrays and surviving body masks agree through original NTFS file runlist; structural reconstruction, original digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),chakra_additions=len(accepted)-previous,known_self_address_arrays=len({e['pointer_end'] for e in known_arrays}),known_body_masks=len(body_masks),minimum_child_pointers=a.minimum_pointers,record=a.record,functions_start=functions,conflicts=conflicts)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
