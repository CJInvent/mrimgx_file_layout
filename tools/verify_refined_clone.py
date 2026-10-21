"""Verify every cloned allocated byte against pre-refinement copy hashes.

Only logged physical mutations are normalized from the read-only baseline.
Newly placed payloads must also pass refine_vhdx's independent logical readback.
"""
import argparse
import bisect
import hashlib
import json
import pathlib
import time
from forensic_residuals import merge_ranges


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','clone','clone_manifest','refinement_manifest','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--previous-validation',type=pathlib.Path)
    ap.add_argument('--previous-refinement',type=pathlib.Path)
    a=ap.parse_args();last=None
    for line in a.refinement_manifest.open():last=json.loads(line)
    if not last or last.get('operation')!='complete':raise ValueError('incomplete refinement')
    mutations=merge_ranges(last['physical_mutations']);ends=[hi for lo,hi in mutations]
    previous=None;new_mutations=None
    if bool(a.previous_validation)!=bool(a.previous_refinement):raise ValueError('both previous validation and refinement are required')
    if a.previous_validation:
        previous=json.loads(a.previous_validation.read_text());old=None
        for line in a.previous_refinement.open():old=json.loads(line)
        if not previous.get('valid') or old.get('operation')!='complete':raise ValueError('previous validation/refinement incomplete')
        n=len(old['physical_mutations'])
        if last['physical_mutations'][:n]!=old['physical_mutations']:raise ValueError('refinement mutation history differs')
        new_mutations=merge_ranges(last['physical_mutations'][n:])
    new_ends=[hi for lo,hi in new_mutations] if new_mutations is not None else None
    before=a.baseline.stat();total=0;count=0;normalized=0;began=time.monotonic();updated=began
    with a.baseline.open('rb') as baseline,a.clone.open('rb') as clone:
        for line in a.clone_manifest.open():
            item=json.loads(line)
            if 'sha256' not in item:continue
            offset=item['offset'];length=item['length']
            if new_mutations is not None:
                k=bisect.bisect_right(new_ends,offset)
                if k>=len(new_mutations) or new_mutations[k][0]>=offset+length:continue
            clone.seek(offset);data=bytearray(clone.read(length))
            if len(data)!=length:raise ValueError('short clone')
            k=bisect.bisect_right(ends,offset)
            while k<len(mutations) and mutations[k][0]<offset+length:
                lo=max(offset,mutations[k][0]);hi=min(offset+length,mutations[k][1]);baseline.seek(lo)
                original=baseline.read(hi-lo)
                if len(original)!=hi-lo:raise ValueError('short baseline')
                data[lo-offset:hi-offset]=original;normalized+=hi-lo;k+=1
            if hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError(f'unexpected byte changes in cloned extent at {offset}')
            total+=length;count+=1
            if time.monotonic()-updated>15:
                print(json.dumps(dict(verified_bytes=total,chunks=count,elapsed=time.monotonic()-began)),flush=True);updated=time.monotonic()
    after=a.baseline.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('baseline changed')
    result=dict(valid=True,verified_allocated_clone_bytes=previous['verified_allocated_clone_bytes'] if previous else total,verified_chunks=previous['verified_chunks'] if previous else count,checked_in_this_pass_bytes=total,checked_in_this_pass_chunks=count,normalized_documented_mutation_bytes=normalized,baseline_size_and_mtime_unchanged=True,elapsed=time.monotonic()-began,clone_manifest_sha256=hashlib.sha256(a.clone_manifest.read_bytes()).hexdigest(),refinement_manifest_sha256=hashlib.sha256(a.refinement_manifest.read_bytes()).hexdigest(),scope='Every original allocated clone extent matches its baseline copy SHA-256 after normalizing only documented refinement writes. Original sparse holes were created as zeros; source frame and VHDX logical placement hashes are validated separately.')
    if previous:
        result['previous_validation_sha256']=hashlib.sha256(a.previous_validation.read_bytes()).hexdigest()
        result['previous_refinement_sha256']=hashlib.sha256(a.previous_refinement.read_bytes()).hexdigest()
        result['scope']+=' This result combines the prior full verification with rechecking every copied extent intersected by additional mutations.'
    with a.output.open('x') as out:json.dump(result,out,indent=2)
    print(json.dumps(result),flush=True)


if __name__=='__main__':main()
