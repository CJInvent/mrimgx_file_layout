"""Independently re-read every placed VHDX range against its original source."""
import argparse,hashlib,json,pathlib
from safe_vhdx import VHDX
from placement_payload import payload
from rebuild_audit import caught,emit


def verify(source,image,mappings,supplemental,output):
    output.mkdir(exist_ok=False);requests=[('frame',m) for m in json.loads(mappings.read_text())]+[('file-slice-or-index-repair',m) for m in json.loads(supplemental.read_text())];volume=VHDX(image);results=[]
    try:
        with source.open('rb') as stream,(output/'range-checks.jsonl').open('x') as log:
            for kind,m in requests:
                row=dict(kind=kind,partition=m['partition'],disk_offset=m['disk_offset'],bytes=m['length'],expected_sha256=m['sha256'],valid=False)
                try:
                    expected=payload(stream,m);volume.seek(m['disk_offset']);observed=volume.read(m['length']);row.update(source_sha256=hashlib.sha256(expected).hexdigest(),observed_sha256=hashlib.sha256(observed).hexdigest(),valid=observed==expected)
                    if not row['valid']:emit('placed-content-mismatch','Actual VHDX bytes differ from independently redecoded source',severity='error',context=row)
                except Exception as error:caught(error,row,expected=False,site='placed-content-verification');row['error']=str(error)
                results.append(row);log.write(json.dumps(row)+'\n');log.flush()
    finally:volume.fh.close()
    summary=dict(valid=all(r['valid'] for r in results),requests=len(results),checked_bytes=sum(r['bytes'] for r in results),failed_requests=sum(not r['valid'] for r in results),scope='Every declared full-frame and supplemental destination was independently read from the rebuilt VHDX and compared byte-for-byte with a freshly revalidated original-source payload. Filesystem address authorization and baseline preservation are separate checks.');(output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);return summary


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','image','mappings','supplemental','output'):ap.add_argument(name,type=pathlib.Path)
    raise SystemExit(0 if verify(**vars(ap.parse_args()))['valid'] else 1)
