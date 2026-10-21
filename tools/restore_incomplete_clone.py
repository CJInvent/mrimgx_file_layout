"""Restore an interrupted refinement to its original clone bytes, never the baseline.

Only standalone VHDX clones with a copy manifest and placement journal qualify.
All restored payload bytes come from the read-only baseline; extra tail is cut.
"""
import argparse
import json
import pathlib
import struct
from safe_vhdx import VHDX


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','clone','clone_manifest','incomplete_manifest','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args()
    if a.baseline.resolve()==a.clone.resolve():raise ValueError('baseline equals clone')
    with a.clone_manifest.open() as f:first=json.loads(next(f))
    if first['source']!=str(a.baseline.resolve()) or first['size']!=a.baseline.stat().st_size or first['mtime_ns']!=a.baseline.stat().st_mtime_ns:raise ValueError('baseline provenance')
    entries=[json.loads(line) for line in a.incomplete_manifest.open()]
    if entries[-1].get('operation')=='complete':raise ValueError('refinement already complete')
    if entries[0].get('baseline')!=str(a.baseline.resolve()) or entries[0].get('clone')!=str(a.clone.resolve()):raise ValueError('refinement provenance')
    baseline=VHDX(a.baseline);bs=baseline.block_size;bat_offset=baseline.bat.offset;bat_length=baseline.bat.entry_count*8
    if baseline.has_parent:raise ValueError('parent disk unsupported')
    restored=0
    with a.baseline.open('rb') as original,a.clone.open('r+b',buffering=0) as clone:
        for m in entries:
            if m.get('operation')!='placed':continue
            position=m['disk_offset'];remaining=m['length']
            while remaining:
                block,within=divmod(position,bs);n=min(remaining,bs-within);entry=baseline.bat.pb(block)
                if entry.state==6:
                    offset=entry.file_offset_mb*1024**2+within;original.seek(offset);data=original.read(n)
                    if len(data)!=n:raise ValueError('short baseline')
                    clone.seek(offset);clone.write(data);restored+=n
                elif entry.state not in (0,2):raise ValueError('unsupported baseline payload state')
                position+=n;remaining-=n
        for offset,length in ((65536,4096),(131072,4096),(bat_offset,bat_length)):
            original.seek(offset);data=original.read(length);clone.seek(offset);clone.write(data)
        clone.truncate(first['size']) # Shrinking only; never CRT grow.
    result=dict(restored_payload_bytes=restored,restored_original_headers_and_bat=True,clone_length=first['size'],scope='Rollback only of journaled clone mutations; baseline read-only. Full clone extent verification follows final refinement.')
    with a.output.open('x') as out:json.dump(result,out,indent=2)
    print(json.dumps(result),flush=True)


if __name__=='__main__':main()
