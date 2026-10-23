"""Compare an independent rebuild with separately supplied reference results.

References are used only after rebuilding, never as reconstruction inputs.
Checks actual VHDX bytes and external artifact contents, not just mapping counts.
"""
import argparse,collections,hashlib,json,pathlib
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream
from rebuild_audit import Audit,emit,caught


def digest_file(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(8*1024**2):h.update(chunk)
    return h.hexdigest()


def artifacts(root):
    result=[]
    for side in root.rglob('*.json'):
        path=side.with_suffix('')
        if not path.is_file():continue
        meta=json.loads(side.read_text())
        if isinstance(meta,dict) and meta.get('sha256'):result.append((path,meta))
    return result


def compare(rebuild,reference_mappings,reference_supplemental,reference_files,output):
    summary=json.loads((rebuild/'summary.json').read_text())
    if summary.get('fatal_error') or summary.get('search_only') or not summary.get('vhdx'):raise ValueError('reference comparison requires a completed image-producing rebuild')
    mappings=json.loads((pathlib.Path(summary['mapping_directory'])/'accepted-mappings.json').read_text());reference=json.loads(reference_mappings.read_text());supplemental=json.loads(reference_supplemental.read_text());v=VHDX(pathlib.Path(summary['vhdx']));by_sha=collections.defaultdict(list)
    for m in mappings:by_sha[m['sha256']].append(m)
    matches=0;bad=[];mapping_changes=[]
    proposed={m['disk_offset']:m for m in mappings}
    for index,m in enumerate(reference+supplemental):
        v.seek(m['disk_offset']);data=v.read(m['length']);valid=len(data)==m['length'] and hashlib.sha256(data).hexdigest()==m['sha256']
        if valid:matches+=1
        else:bad.append(dict(disk_offset=m['disk_offset'],length=m['length'],expected_sha256=m['sha256'],observed_sha256=hashlib.sha256(data).hexdigest()));emit('replay-content-mismatch','Reference bytes absent or different in rebuilt VHDX',severity='error',context=bad[-1])
        if index<len(reference) and (m['disk_offset'] not in proposed or (proposed[m['disk_offset']]['length'],proposed[m['disk_offset']]['sha256'])!=(m['length'],m['sha256'])):mapping_changes.append(dict(disk_offset=m['disk_offset'],represented_bytes_match=valid))
    rebuilt_files=artifacts(pathlib.Path(summary['recovered_files']));external=collections.defaultdict(list)
    for path,meta in rebuilt_files:external[meta['sha256']].append(path)
    cached={}
    def verified_external(sha):
        for path in external.get(sha,[]):
            if path not in cached:cached[path]=digest_file(path)
            if cached[path]==sha:return str(path)
    layout=json.loads((pathlib.Path(summary.get('evidence_directory',rebuild/'evidence'))/'layout.json').read_text());p=layout['disks'][0]['partitions'][2];fs=NTFS(RangeStream(v,p['_geometry']['start'],p['_geometry']['length']));ref_artifacts=artifacts(reference_files);ref_frames={meta['source_offset']:meta for path,meta in ref_artifacts if meta.get('kind')=='unplaced-frame'};file_results=[];unresolved=[]
    for path,meta in ref_artifacts:
        sha=meta['sha256'];row=dict(reference=str(path),kind=meta.get('kind'),sha256=sha,bytes=path.stat().st_size);represented=None
        if digest_file(path)!=sha:raise ValueError('reference artifact changed: '+str(path))
        external_path=verified_external(sha)
        if external_path:represented=dict(kind='external',path=external_path)
        if represented is None and meta.get('kind')=='unplaced-frame':
            for m in by_sha.get(sha,[]):
                v.seek(m['disk_offset'])
                if hashlib.sha256(v.read(m['length'])).hexdigest()==sha:represented=dict(kind='mapped-frame',disk_offset=m['disk_offset']);break
        if represented is None:
            for location in meta.get('possible_locations',[]):
                name=location.get('path') or location.get('original_path')
                if not name:continue
                try:
                    rec=fs.mft.get(name)
                    if rec.size()!=row['bytes']:continue
                    data=rec.open().read()
                    if hashlib.sha256(data).hexdigest()==sha:represented=dict(kind='ntfs-file',path=name);break
                except Exception as e:caught(e,expected=True,site='compare-reference-namespace');continue
        if represented is None:
            for provenance in meta.get('provenance',[]):
                frame=ref_frames.get(provenance.get('source_offset'));off=provenance.get('frame_offset')
                if frame is None or off is None:continue
                for m in by_sha.get(frame['sha256'],[]):
                    if off+row['bytes']>m['length']:continue
                    v.seek(m['disk_offset']+off)
                    if hashlib.sha256(v.read(row['bytes'])).hexdigest()==sha:represented=dict(kind='carved-content-in-mapped-frame',disk_offset=m['disk_offset']+off);break
                if represented:break
        row['represented']=represented;file_results.append(row)
        if represented is None:unresolved.append(row)
    # A newer native baseline can incorporate a frame that was formerly an
    # orphan. Check those source-addressed manifest destinations as well.
    pending={meta['source_offset']:meta['sha256'] for path,meta in ref_artifacts if meta.get('kind')=='unplaced-frame' and any(r['sha256']==meta['sha256'] and r['represented'] is None for r in file_results)}
    manifest=rebuild/'baseline-manifest.jsonl'
    if pending and manifest.exists():
        for m in map(json.loads,manifest.open()):
            source=m.get('source_offset')
            if m.get('operation')!='range' or m.get('status') not in ('verified','reconstructed-unverified') or source not in pending:continue
            v.seek(m['disk_offset']);data=v.read(m['length']);sha=hashlib.sha256(data).hexdigest()
            if sha==pending[source]:
                for row in file_results:
                    if row['sha256']==sha and row['represented'] is None:row['represented']=dict(kind='native-baseline-frame',disk_offset=m['disk_offset'])
        unresolved=[r for r in file_results if r['represented'] is None]
    for row in unresolved:emit('replay-artifact-missing','Reference recovered artifact is not represented by verified external/image bytes',severity='error',context=row)
    ref_offsets={r['disk_offset'] for r in reference};run_valid=summary.get('all_requested_stages_succeeded') is True and summary.get('operational_error_count')==0 and summary.get('protected_input_stats_unchanged') is True and summary.get('program_sources_unchanged') is True and summary.get('process_exit_code') in (0,2)
    if not run_valid:emit('rebuild-status-validation-failed','Rebuild audit/stage completion requirements did not all pass',severity='error',context=summary)
    result=dict(valid=not bad and not unresolved and run_valid,content_matches_reference=not bad and not unresolved,rebuild_run_checks_passed=run_valid,reference_full_frames=len(reference),reference_supplements=len(supplemental),reference_byte_ranges_matching=matches,content_mismatches=bad,mapping_representation_changes=mapping_changes,new_mapping_count=sum(m['disk_offset'] not in ref_offsets for m in mappings),reference_artifacts=len(file_results),represented_artifacts=len(file_results)-len(unresolved),missing_artifacts=unresolved,rebuild_all_requested_stages_succeeded=summary.get('all_requested_stages_succeeded'),rebuild_operational_error_count=summary.get('operational_error_count'),scope='Independent post-run content comparison. References were not supplied to reconstruction. New placements are not accepted merely because this comparison finds additional bytes.')
    (output/'artifact-comparison.json').write_text(json.dumps(file_results,indent=2));(output/'comparison.json').write_text(json.dumps(result,indent=2));v.fh.close();return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('rebuild','reference_mappings','reference_supplemental','reference_files','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);audit=Audit(a.output,vars(a))
    try:result=compare(a.rebuild,a.reference_mappings,a.reference_supplemental,a.reference_files,a.output)
    except BaseException as e:audit.finish(1,e);raise
    code=0 if result['valid'] else 1;audit.finish(code);print(json.dumps(result,indent=2),flush=True);return code


if __name__=='__main__':raise SystemExit(main())
