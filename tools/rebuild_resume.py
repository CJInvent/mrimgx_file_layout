"""Resume discovery without promoting unvalidated checkpoint maps to trusted base."""
import hashlib
import json
import pathlib


def resume_inputs(run, checkpoint, source, baseline, manifest, evidence, mft, inventory, plan):
    run=run.resolve()
    with (run/'audit-events.jsonl').open(encoding='utf-8') as stream:
        start=json.loads(next(stream))
    if start.get('category')!='run-start':raise ValueError('resume audit lacks run-start')
    args=start['context']['arguments']
    expected=dict(source=args['source'],baseline=args.get('baseline') or run/'baseline.vhdx',
                  manifest=args.get('manifest') or run/'baseline-manifest.jsonl',
                  evidence=args.get('evidence') or run/'evidence',mft=args.get('mft') or run/'filesystem/mft.bin',
                  inventory=args.get('inventory') or run/'filesystem/affected-files.jsonl')
    actual=dict(source=source,baseline=baseline,manifest=manifest,evidence=evidence,mft=mft,inventory=inventory)
    for name,path in actual.items():
        if path is None or pathlib.Path(path).resolve()!=pathlib.Path(expected[name]).resolve():
            raise ValueError('resume requires the same '+name+' input')
    previous_plan=pathlib.Path(args.get('plan') or run/'discovered-plan.json')
    if json.loads(previous_plan.read_text())!=plan:raise ValueError('resume plan mismatch')
    # Only successfully completed stages may contribute checkpoint artifacts.
    directories=set()
    for stage in json.loads((run/'stages.json').read_text()):
        if not stage.get('success'):continue
        for arg in stage.get('command',[]):
            path=pathlib.Path(arg)
            if path.is_absolute() and path.is_dir() and path.parent.resolve()==run:
                directories.add(path.resolve())
    checkpoint=checkpoint.resolve()
    if checkpoint not in directories:raise ValueError('checkpoint is not a completed stage output')
    inherited=run/'resume-inputs.json'
    prior=json.loads(inherited.read_text()) if inherited.exists() else {}
    base=pathlib.Path(prior.get('validation_base') or args.get('mapping_directory') or run/'initial-mapping').resolve()
    if not (base/'accepted-mappings.json').is_file():raise ValueError('resume validation base unavailable')
    supplemental=list(prior.get('supplemental_paths',[]))
    candidates=list(prior.get('candidate_directories',[]))
    for directory in sorted(directories):
        if (directory/'supplemental-placements.json').is_file():supplemental.append(str(directory/'supplemental-placements.json'))
        if (directory/'recovered_files').is_dir():candidates.append(str(directory/'recovered_files'))
    result=dict(previous_run=str(run),checkpoint=str(checkpoint),validation_base=str(base),
                supplemental_paths=sorted(set(supplemental)),candidate_directories=sorted(set(candidates)),
                checkpoint_sha256=hashlib.sha256((checkpoint/'accepted-mappings.json').read_bytes()).hexdigest(),
                validation_base_sha256=hashlib.sha256((base/'accepted-mappings.json').read_bytes()).hexdigest(),
                previous_run_completed=(run/'audit-summary.json').is_file())
    # Checkpoint mappings remain proposals: the normal independent validator
    # rechecks every addition relative to this original base before any write.
    return result
