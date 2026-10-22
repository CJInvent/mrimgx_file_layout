"""Find possible duplicate NTFS file records for content-based mapping.

Raw cached MFT fields are used only to nominate records, never to authorize a
placement. recover_duplicate_files.py must validate records, coverage and bytes.
Both filename/size and arbitrary-name exact-size candidates are emitted.
"""
import argparse
import bisect
import collections
import json
import mmap
import pathlib
import struct
from dissect.ntfs.util import apply_fixup
from rebuild_audit import caught


def candidate_records(data):
    for start in range(0,len(data)-1023,1024):
        if data[start:start+4]!=b'FILE' or not struct.unpack_from('<H',data,start+22)[0]&1:continue
        try:record=apply_fixup(data[start:start+1024])
        except Exception as e:caught(e,dict(number=start//1024),site='candidate-record-fixups');continue
        pos=struct.unpack_from('<H',record,20)[0];names=[];size=None
        if not 48<=pos<=1000:continue
        while pos+24<=1024:
            kind,length=struct.unpack_from('<II',record,pos)
            if kind==0xffffffff or length<24 or pos+length>1024:break
            if kind==48 and record[pos+8]==0:
                value=pos+struct.unpack_from('<H',record,pos+20)[0]
                if value+66<=pos+length:
                    n=record[value+64]
                    if value+66+2*n<=pos+length:names.append(record[value+66:value+66+2*n].decode('utf-16-le',errors='replace'))
            elif kind==128 and record[pos+9]==0:
                if record[pos+8] and length>=64:size=struct.unpack_from('<Q',record,pos+48)[0]
                elif not record[pos+8]:size=struct.unpack_from('<I',record,pos+16)[0]
            pos+=length
        if names and size is not None:yield start//1024,names,size


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('mft','inventory','mappings','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--minimum-size',type=int,default=32768)
    ap.add_argument('--maximum-size-donors',type=int,default=100)
    a=ap.parse_args();ranges=sorted((m['disk_offset'],m['disk_offset']+m['length']) for m in json.loads(a.mappings.read_text()));ends=[hi for lo,hi in ranges]
    def remaining(row):
        total=0
        for hit in row['ranges']:
            if hit['status']=='reconstructed-unverified' or hit['type']!=128:continue
            lo=hit['disk_offset'];hi=lo+hit['length'];left=hit['length'];k=bisect.bisect_right(ends,lo)
            while k<len(ranges) and ranges[k][0]<hi:
                l,h=ranges[k];left-=max(0,min(hi,h)-max(lo,l));k+=1
            total+=left
        return total
    targets={r['record'] for r in map(json.loads,a.inventory.open()) if remaining(r)}
    byname=collections.defaultdict(set);bysize=collections.defaultdict(set);wanted={}
    with a.mft.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        for number,names,size in candidate_records(data):
            if size<a.minimum_size:continue
            bysize[size].add(number)
            for name in names:byname[(name.casefold(),size)].add(number)
            if number in targets:wanted[number]=(names,size)
    pairs=set()
    for target,(names,size) in wanted.items():
        donors=set()
        for name in names:donors.update(byname[(name.casefold(),size)])
        if len(bysize[size])<=a.maximum_size_donors:donors.update(bysize[size])
        pairs.update((target,donor) for donor in donors if donor!=target)
    result=[f'{t}:{d}' for t,d in sorted(pairs)];a.output.open('x').write(json.dumps(result,indent=2))
    print(json.dumps(dict(affected_targets=len(targets),eligible_targets=len(wanted),candidate_pairs=len(result))),flush=True)


if __name__=='__main__':main()
