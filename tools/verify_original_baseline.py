"""Read back every incorporated native VHDX block against the original index MD5."""
import argparse,hashlib,json,pathlib,sqlite3,time
import zstandard
from safe_vhdx import VHDX
from make_recovery_plan import make_plan
from rebuild_audit import emit,caught


def verify(source,baseline,evidence,output,reuse=None):
    output.mkdir(exist_ok=False);plan_path=evidence/'input-plan.json';plan=json.loads(plan_path.read_text());layout=json.loads((evidence/'layout.json').read_text())
    if make_plan(source,plan)!=plan:raise ValueError('baseline verification source/plan fingerprint differs')
    identity=dict(source=str(source.resolve()),source_size=source.stat().st_size,source_mtime_ns=source.stat().st_mtime_ns,baseline=str(baseline.resolve()),baseline_size=baseline.stat().st_size,baseline_mtime_ns=baseline.stat().st_mtime_ns,plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),verifier_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())
    if reuse:
        cached=json.loads(reuse.read_text())
        if cached.get('valid') and cached.get('identity')==identity and not cached.get('failed_blocks'):
            result=dict(cached,reused=True,reused_proof=str(reuse.resolve()),reused_proof_sha256=hashlib.sha256(reuse.read_bytes()).hexdigest());(output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True);return result
        emit('baseline-validation-cache-rejected','Cached native readback proof does not match current immutable inputs/program; performing full readback',severity='warning')
    db=sqlite3.connect((evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);volume=VHDX(baseline);checked=0;total=0;failed=0;partial=0;last=time.monotonic();began=last;ledger=hashlib.sha256()
    try:
        with source.open('rb') as stream,(output/'failures.jsonl').open('x') as errors:
            for pi,block,address,n,position,stored,digest in db.execute('SELECT partition,block,disk_offset,decoded_length,source_offset,stored_length,digest FROM entries WHERE incorporated=1 ORDER BY rowid'):
                row=dict(partition=pi,block=block,disk_offset=address,length=n,source_offset=position,stored_length=stored,expected_md5=digest.hex());checked+=1;total+=n
                try:
                    volume.seek(address);observed=volume.read(n);actual=hashlib.md5(observed).digest();valid=len(observed)==n and actual==digest
                    if not valid and n<layout['disks'][0]['partitions'][pi]['_header']['block_size']:
                        stream.seek(position);encoded=stream.read(stored);decoded=encoded if layout['_compression']['compression_level']=='none' else zstandard.ZstdDecompressor().decompress(encoded,max_output_size=4*1024**2)
                        valid=hashlib.md5(decoded).digest()==digest and observed==decoded[:n];partial+=1
                    ledger.update(str(address).encode()+b':'+actual)
                    if not valid:raise ValueError('native baseline logical block MD5/read length differs from original source index')
                except Exception as error:
                    failed+=1;row.update(error=str(error));errors.write(json.dumps(row)+'\n');errors.flush();caught(error,row,expected=False,site='native-baseline-readback')
                if time.monotonic()-last>15:print(json.dumps(dict(verified_blocks=checked,checked_bytes=total,failed_blocks=failed)),flush=True);last=time.monotonic()
    finally:volume.fh.close();db.close()
    if any(identity[key]!=value for key,value in dict(source_size=source.stat().st_size,source_mtime_ns=source.stat().st_mtime_ns,baseline_size=baseline.stat().st_size,baseline_mtime_ns=baseline.stat().st_mtime_ns).items()):raise ValueError('native verification protected input changed')
    result=dict(valid=failed==0,identity=identity,reused=False,verified_blocks=checked,checked_bytes=total,failed_blocks=failed,partial_tail_checks=partial,readback_ledger_sha256=ledger.hexdigest(),elapsed_seconds=time.monotonic()-began,scope='Every incorporated native block was read from the baseline logical VHDX and checked against its original recorded MD5. Unknown/unrecoverable ranges, additional forensic placements and higher-level file integrity are separate checks.');(output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True);return result


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','evidence','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--reuse',type=pathlib.Path);a=ap.parse_args();raise SystemExit(0 if verify(**vars(a))['valid'] else 1)
