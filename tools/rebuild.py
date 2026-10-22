"""Opt-in forensic rebuild: discover, iterate, validate, refine and rescue.

Never launches a recovered program or writes to the source/baseline/evidence.
Native strict conversion remains the default. All stages use the same reusable
methods as interactive forensic work, with machine-readable logs and failures.
"""
from rebuild_audit import caught as _audit_caught
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,time,traceback,contextlib
from make_recovery_plan import make_plan
from forensic_residuals import root_layout
from rebuild_audit import Audit,emit,record_exception

TOOLS=pathlib.Path(__file__).resolve().parent
DEFAULT_STAGES='residual-audit,bit-repair,appx,cab,signed-pe,structured,zip-files,pdf,duplicates,chakra,wal,ese,fat-directories,fat-duplicates,fat-signed-pe,fat-joint-pe,ntfs-joint-pe,png,chromium-streams,installer-hashes,manifest-hashes,catalog-hashes,metadata-rescue'
ACTIVE_RUNNER=None


def mark_manifest_restorations(recovered,verified,manifest_records,written):
    """Distinguish external copies of proven restored files from unresolved ones."""
    count=0
    for side in recovered.rglob('*.json'):
        path=side.with_suffix('')
        if not path.is_file():continue
        meta=json.loads(side.read_text())
        if not isinstance(meta,dict) or meta.get('kind') not in ('carved-file','whole-file-hash-candidate','catalog-sequence-candidate','zip-reconstruction-candidate'):continue
        resolved=[r['record'] for r in meta.get('possible_locations',[]) if r.get('record') in manifest_records and verified.get(r['record'],{}).get('sha256')==meta.get('sha256')]
        if not resolved:continue
        if hashlib.sha256(path.read_bytes()).hexdigest()!=meta['sha256']:raise ValueError('rescued candidate file changed before metadata resolution: '+str(path))
        meta.update(placement_status='original-component-manifest-and-runlist-validated',vhdx_insertion_authorized=True,vhdx_written_by_rebuild=written,validated_records=sorted(set(resolved)),historical_component_version_binding=True)
        meta.setdefault('validation',{}).update(original_whole_file_digest_available=True,original_component_manifest_rechecked=True,historical_path_binding_proven=True,excluded_pe_fields_not_bound=False)
        meta['original_component_manifest_bindings']=[binding for number in sorted(set(resolved)) for binding in verified[number].get('original_manifest_bindings',[])]
        for location in meta['possible_locations']:
            if location.get('record') in resolved:location['placement_confirmed']=True
        side.write_text(json.dumps(meta,indent=2));count+=1
    return count


def corrupted(manifest):
    complete=None;hits=0
    for row in map(json.loads,manifest.open()):
        if row.get('status') in ('unknown-zero-index','unrecoverable','reconstructed-unverified'):hits+=1
        complete=row
    if not complete or complete.get('operation')!='complete':raise ValueError('baseline manifest incomplete')
    return bool(hits)


class Runner:
    def __init__(self,output,arguments=None):self.output=output;self.events=[];self.serial=0;self.audit=Audit(output,arguments or {})
    def process(self,label,command,allowed=(0,)):
        self.serial+=1;name=f'{self.serial:04d}-{label}';log=self.output/'logs'/(name+'.log');began=time.monotonic();print(json.dumps(dict(stage=name,event='begin',log=str(log))),flush=True);emit('stage-start',label,context=dict(stage=name,command=command,log=log))
        try:
            with log.open('x') as stream:code=subprocess.run([str(x) for x in command],stdout=stream,stderr=subprocess.STDOUT,env=self.audit.child_environment(name)).returncode
        except BaseException as e:
            record_exception(e,dict(stage=name,command=command,log=log),category='stage-launch-error');event=dict(stage=name,command=[str(x) for x in command],exit_code=None,seconds=time.monotonic()-began,log=str(log.resolve()),success=False,launch_error=str(e));self.events.append(event);(self.output/'stages.json').write_text(json.dumps(self.events,indent=2));raise
        event=dict(stage=name,command=[str(x) for x in command],exit_code=code,seconds=time.monotonic()-began,log=str(log.resolve()),success=code in allowed);self.events.append(event);(self.output/'stages.json').write_text(json.dumps(self.events,indent=2));emit('stage-end',label,severity='info' if code in allowed else 'error',context=event);print(json.dumps(event),flush=True)
        with log.open(encoding='utf-8',errors='replace') as stream:
            for line in stream:
                try:row=json.loads(line)
                except (ValueError,TypeError):continue
                if not isinstance(row,dict):continue
                for key in ('conflicts','conflicting_bases','budget_reached','budget_exhausted','skipped'):
                    if row.get(key):emit('mapping-conflict' if 'conflict' in key else 'search-limit' if 'budget' in key else 'search-skip',key,severity='warning' if key!='skipped' else 'info',context=dict(stage=name,details=row))
        if code not in allowed:raise RuntimeError(f'{name} failed ({code}); see {log}')
        return event
    def action(self,label,function):
        self.serial+=1;name=f'{self.serial:04d}-{label}';log=self.output/'logs'/(name+'.log');began=time.monotonic();print(json.dumps(dict(stage=name,event='begin',log=str(log))),flush=True);emit('stage-start',label,context=dict(stage=name,log=log));code=0
        try:
            with log.open('x') as stream,contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):return function()
        except BaseException as e:code=1;record_exception(e,dict(stage=name,log=log),category='stage-action-error');raise
        finally:
            event=dict(stage=name,exit_code=code,seconds=time.monotonic()-began,log=str(log.resolve()),success=not code);self.events.append(event);(self.output/'stages.json').write_text(json.dumps(self.events,indent=2));emit('stage-end',label,severity='error' if code else 'info',context=event);print(json.dumps(event),flush=True)
    def call(self,tool,args,output=None,allowed=(0,)):
        command=[sys.executable,str(TOOLS/(tool+'.py'))]+[str(x) for x in args];self.process(tool,command,allowed)
        return output


def main():
    global ACTIVE_RUNNER
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=pathlib.Path);ap.add_argument('--plan',type=pathlib.Path,help='optional existing fingerprinted plan; otherwise discover corroborated index arrays and boot frames')
    ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--native',type=pathlib.Path);ap.add_argument('--baseline',type=pathlib.Path);ap.add_argument('--manifest',type=pathlib.Path);ap.add_argument('--evidence',type=pathlib.Path);ap.add_argument('--mft',type=pathlib.Path);ap.add_argument('--inventory',type=pathlib.Path);ap.add_argument('--mapping-directory',type=pathlib.Path)
    ap.add_argument('--qemu-img',type=pathlib.Path,required=True);ap.add_argument('--seven-zip',type=pathlib.Path,required=True)
    ap.add_argument('--bit-repair-exe',type=pathlib.Path,help='defaults to repair_frame_bits.exe next to the native converter')
    ap.add_argument('--reuse-bit-negative-attempts',type=pathlib.Path,help='reuse completed zero-match native tests only with identical encoded input, original MD5, decoded length and full byte coverage')
    ap.add_argument('--stages',default=DEFAULT_STAGES);ap.add_argument('--rounds',type=int,default=0,help='0 repeats until no new placements; a bound is reported as a limit')
    ap.add_argument('--per-file-budget',type=int,default=300000);ap.add_argument('--metadata-identity',action='store_true',help='also permit separately labeled filename/size/exact-time duplicate inferences')
    ap.add_argument('--existing-clone',type=pathlib.Path);ap.add_argument('--clone-manifest',type=pathlib.Path);ap.add_argument('--previous-refinement',type=pathlib.Path);ap.add_argument('--previous-validation',type=pathlib.Path)
    ap.add_argument('--search-only',action='store_true',help='produce mappings and recovered_files; never modify an image')
    a=ap.parse_args()
    if bool(a.baseline)!=bool(a.manifest) or bool(a.mft)!=bool(a.inventory):ap.error('baseline/manifest and mft/inventory must be supplied in pairs')
    continuation=(a.existing_clone,a.clone_manifest,a.previous_refinement,a.previous_validation)
    if any(continuation) and not all(continuation):ap.error('continuation requires all four clone/preservation arguments')
    if a.rounds<0 or a.per_file_budget<1:ap.error('invalid search limits')
    requested=set(a.stages.split(','));unknown=requested-set(DEFAULT_STAGES.split(','))
    if unknown:ap.error('unknown stages: '+','.join(sorted(unknown)))
    a.output.mkdir(exist_ok=False);(a.output/'logs').mkdir();runner=Runner(a.output,vars(a));ACTIVE_RUNNER=runner
    if a.plan is None:
        from discover_rebuild_plan import discover,bootstrap_boot
        plan,discovery=runner.action('discover-index-arrays',lambda:discover(a.source));plan,discovery['boot_recovery']=runner.action('discover-ntfs-boot',lambda:bootstrap_boot(a.source,plan));a.plan=a.output/'discovered-plan.json';a.plan.open('x').write(json.dumps(plan,indent=2));(a.output/'plan-discovery.json').open('x').write(json.dumps(discovery,indent=2))
    else:
        plan=json.loads(a.plan.read_text())
    if make_plan(a.source,plan)!=plan:raise ValueError('source/plan fingerprint mismatch')
    layout=root_layout(a.source);parts=layout['disks'][0]['partitions']
    if len(parts)<3 or parts[2]['_header']['block_size']!=143360:raise ValueError('current mapping suite requires Windows NTFS at partition 2 with 143360-byte frames; unsupported geometry is not guessed')
    protected=[p for p in (a.source,a.plan,a.baseline,a.manifest,a.mft,a.inventory) if p];stats={str(p.resolve()):(p.stat().st_size,p.stat().st_mtime_ns) for p in protected}
    baseline=a.baseline;manifest=a.manifest
    if baseline is None:
        if not a.native:ap.error('--native required to create a baseline')
        baseline=a.output/'baseline.vhdx';manifest=a.output/'baseline-manifest.jsonl'
        command=[str(a.native), '--recover-plan',str(a.source),str(a.plan),str(baseline),str(manifest),'--direct-vhdx',str(a.qemu_img)]
        runner.process('baseline-conversion',command,allowed=(0,2))
    for row in map(json.loads,manifest.open()):
        if row.get('operation')=='range' and row.get('status') in ('unrecoverable','unknown-zero-index','reconstructed-unverified'):emit('input-corruption',row.get('error') or row['status'],severity='warning',context=row)
    if not corrupted(manifest):
        (a.output/'summary.json').write_text(json.dumps(dict(corruption_detected=False,rebuild_performed=False,baseline=str(baseline.resolve())),indent=2));return 0
    evidence=a.evidence
    if evidence is None:evidence=runner.call('forensic_residuals',[a.source,a.plan,manifest,a.output/'evidence'],a.output/'evidence')
    elif json.loads((evidence/'input-plan.json').read_text())!=plan:raise ValueError('evidence belongs to another plan')
    original_baseline=baseline;original_manifest=manifest;revised=a.existing_clone or a.output/'rebuilt.vhdx';copylog=a.clone_manifest or a.output/'clone-manifest.jsonl';active_previous=a.previous_refinement;clone_ready=bool(a.existing_clone);errors=[];bit_output=None;audit_output=None
    if 'residual-audit' in requested:
        audit_output=a.output/'residual-audit'
        try:runner.call('inspect_residual_failures',[evidence,audit_output])
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='rebuild.py:94')
            errors.append(dict(tool='residual-audit',error=str(e)))
    if 'bit-repair' in requested:
        bit_output=a.output/'indexed-bit-repair';repair_exe=a.bit_repair_exe or ((a.native.parent if a.native else TOOLS.parent/'build')/'repair_frame_bits.exe')
        try:
            if not repair_exe.is_file():raise ValueError('bit-repair executable unavailable')
            bit_args=[a.source,manifest,evidence,a.mapping_directory or '-',repair_exe,bit_output]
            if a.reuse_bit_negative_attempts:bit_args+=['--reuse-negative-attempts',a.reuse_bit_negative_attempts]
            runner.call('recover_indexed_bit_frames',bit_args)
            repairs=json.loads((bit_output/'supplemental-placements.json').read_text())
            if repairs and not a.search_only:
                # Original-index repairs can be checked before an NTFS parser
                # is usable; never apply an unvalidated metadata repair.
                runner.call('validate_supplemental_files',[a.source,original_baseline,a.mft or '-',original_manifest,evidence,a.mapping_directory or '-',bit_output/'supplemental-placements.json',a.output/'indexed-bit-validation'])
                if not clone_ready:runner.call('clone_sparse_file',[original_baseline,revised,copylog]);clone_ready=True
                empty=a.output/'empty-mappings.json';empty.write_text('[]');early=a.output/'metadata-repair-refinement.jsonl';args=[a.source,original_baseline,revised,copylog,manifest,(a.mapping_directory/'accepted-mappings.json') if a.mapping_directory else empty,early,'--supplemental',bit_output/'supplemental-placements.json']
                if active_previous:args+=['--previous-refinement',active_previous]
                runner.call('refine_vhdx',args);active_previous=early;baseline=revised
                # A separate analysis manifest makes the proven original
                # frame readable to every later stage. The original manifest
                # remains the authority for write restrictions/preservation.
                repaired={(m['partition'],m['disk_offset'],m['length']) for m in repairs}
                analysis_manifest=a.output/'analysis-manifest.jsonl'
                with original_manifest.open() as inp,analysis_manifest.open('x') as out:
                    for line in inp:
                        row=json.loads(line)
                        if row.get('operation')=='range' and (row.get('partition'),row.get('disk_offset'),row.get('length')) in repaired:row['status']='recovered-original-index-bit-repair'
                        out.write(json.dumps(row)+'\n')
                manifest=analysis_manifest
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='rebuild.py:120')
            errors.append(dict(tool='bit-repair',error=str(e)))
    mft=a.mft;inventory=a.inventory
    if mft is None:
        prep=a.output/'filesystem';runner.call('prepare_rebuild',[baseline,manifest,evidence/'layout.json',prep]);mft=prep/'mft.bin';inventory=prep/'affected-files.jsonl'
    current=a.mapping_directory
    if current is None:current=runner.call('map_orphan_frames',[a.source,a.plan,manifest,evidence,baseline,mft,a.output/'initial-mapping','--file-inventory',inventory,'--pe-anchors','--appx-anchors'],a.output/'initial-mapping')
    initial=current;round_number=0;fixed_point=False;catalog_members_for_rescue=None
    def maps(path):return json.loads((path/'accepted-mappings.json').read_text())
    def stage(tool,args):
        nonlocal current
        output=a.output/f'{runner.serial+1:04d}-{tool}'
        try:
            runner.call(tool,args+[output]);new=maps(output);old=maps(current);prior={m['disk_offset']:m for m in new}
            if len(new)<len(old) or any(prior.get(m['disk_offset'])!=m for m in old):raise ValueError('stage contradicted an existing accepted mapping')
            current=output
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='rebuild.py:135')
            errors.append(dict(tool=tool,error=str(e)))
    while not a.rounds or round_number<a.rounds:
        before=len(maps(current));round_number+=1;print(json.dumps(dict(round=round_number,mappings=before)),flush=True)
        for name in DEFAULT_STAGES.split(','):
            if name not in requested or name in ('residual-audit','bit-repair','metadata-rescue'):continue
            common=[a.source,baseline,mft,inventory,manifest,evidence,current]
            if name in ('appx','signed-pe','structured','zip-files','pdf','wal','ese','png','chromium-streams'):
                tool=dict(appx='extend_appx_mappings',**{'signed-pe':'extend_signed_pe_mappings','chromium-streams':'recover_chromium_streams','zip-files':'recover_zip_files'},structured='extend_structured_files',pdf='recover_pdf_xrefs',wal='recover_sqlite_wal',ese='recover_ese_pages',png='recover_png_crc_grid')[name]
                args=common
                # Output positional precedes options; stage accepts option
                # arguments only through explicit helper below.
                stage(tool,args)
                if name=='ese':
                    # A separate pass uses already known boundary bytes.
                    out=a.output/f'{runner.serial+1:04d}-ese-boundaries'
                    try:runner.call(tool,[a.source,baseline,mft,inventory,manifest,evidence,current,out,'--cross-boundary']);current=out
                    except Exception as e:
                        _audit_caught(e, locals(), expected=False, site='rebuild.py:151')
                        errors.append(dict(tool=tool,error=str(e)))
            elif name=='cab':stage('extend_cab_mappings',common+[a.seven_zip])
            elif name=='duplicates':
                pairs=a.output/f'duplicate-pairs-{round_number:03d}.json'
                try:
                    runner.call('discover_duplicate_pairs',[mft,inventory,current/'accepted-mappings.json',pairs])
                    if json.loads(pairs.read_text()):
                        out=a.output/f'{runner.serial+1:04d}-duplicates';args=[a.source,baseline,mft,manifest,evidence,current,out,'--pairs-json',pairs,'--allow-boundary','--stream-large-files','--allow-partial-donor']
                        if a.metadata_identity:args+=['--allow-metadata-duplicates']
                        runner.call('recover_duplicate_files',args);current=out
                except Exception as e:
                    _audit_caught(e, locals(), expected=False, site='rebuild.py:161')
                    errors.append(dict(tool='duplicates',error=str(e)))
            elif name=='chakra':
                from rebuild_context import Context
                ctx=Context(a.source,baseline,mft,manifest,evidence,current)
                for row in map(json.loads,inventory.open()):
                    header=b''
                    try:
                        rec=ctx.fs.mft.get(row['record'])
                        if rec.size()<26:continue
                        stream=rec.open();header=stream.read(26)
                        if header[:4]!=b'ChBc':continue
                        out=a.output/f'{runner.serial+1:04d}-chakra';runner.call('recover_chakra_offsets',[a.source,baseline,mft,manifest,evidence,current,out,'--record',row['record']]);current=out
                    except Exception as e:
                        _audit_caught(e, locals(), expected=False, site='rebuild.py:173')
                        if 'header' in locals() and header[:4]==b'ChBc':errors.append(dict(tool='chakra',record=row['record'],error=str(e)))
                ctx.close()
            elif name in ('fat-directories','fat-signed-pe','fat-joint-pe','ntfs-joint-pe'):
                tool={'fat-directories':'recover_fat_directories','fat-signed-pe':'recover_fat_signed_pe','fat-joint-pe':'recover_fat_multiframe_pe','ntfs-joint-pe':'recover_fat_multiframe_pe'}[name]
                if name=='ntfs-joint-pe':
                    for minimum,maximum in ((8192,4*1024**2),(4*1024**2+1,256*1024**2)):
                        out=a.output/f'{runner.serial+1:04d}-ntfs-joint'
                        try:runner.call(tool,[a.source,baseline,manifest,evidence,current,out,'--partition',2,'--mft',mft,'--inventory',inventory,'--minimum-missing',1,'--minimum-file-size',minimum,'--maximum-file-size',maximum,'--per-file-budget',a.per_file_budget]);current=out
                        except Exception as e:
                            _audit_caught(e, locals(), expected=False, site='rebuild.py:182')
                            errors.append(dict(tool=name,error=str(e)))
                else:stage(tool,[a.source,baseline,manifest,evidence,current])
            elif name=='fat-duplicates':stage('recover_fat_duplicates',[a.source,baseline,mft,manifest,evidence,current])
            elif name=='installer-hashes':
                collected=a.output/f'installer-hashes-{round_number:03d}'
                try:
                    runner.call('collect_installer_hashes',[a.source,baseline,mft,inventory,manifest,evidence,current,collected])
                    if json.loads((collected/'hash-targets.json').read_text()):stage('recover_file_hashes',[a.source,baseline,mft,manifest,evidence,current,collected/'hash-targets.json'])
                except Exception as e:
                    _audit_caught(e, locals(), expected=False, site='rebuild.py:190')
                    errors.append(dict(tool=name,error=str(e)))
            elif name=='manifest-hashes':
                collected=a.output/f'manifest-hashes-{round_number:03d}'
                try:
                    runner.call('collect_manifest_hashes',[a.source,baseline,mft,inventory,manifest,evidence,current,collected])
                    if json.loads((collected/'hash-targets.json').read_text()):stage('recover_file_hashes',[a.source,baseline,mft,manifest,evidence,current,collected/'hash-targets.json'])
                except Exception as e:
                    _audit_caught(e,locals(),site='component-manifest-hashes')
                    errors.append(dict(tool=name,error=str(e)))
            elif name=='catalog-hashes':
                collected=a.output/f'catalog-hashes-{round_number:03d}'
                try:
                    runner.call('collect_catalog_hashes',[a.source,baseline,mft,manifest,evidence,current,collected])
                    catalog_members_for_rescue=collected/'catalog-members.jsonl'
                    stage('recover_catalog_files',[a.source,baseline,mft,inventory,manifest,evidence,current,collected/'catalog-members.jsonl'])
                    out=a.output/f'{runner.serial+1:04d}-recover_catalog_sequences'
                    runner.call('recover_catalog_sequences',[a.source,baseline,mft,inventory,manifest,evidence,current,collected/'catalog-members.jsonl',out,'--per-file-budget',a.per_file_budget])
                    stage('bind_inf_catalog_candidates',[a.source,baseline,mft,inventory,manifest,evidence,current,out/'recovered_files'])
                except Exception as e:
                    _audit_caught(e, locals(), expected=False, site='rebuild.py:199')
                    errors.append(dict(tool=name,error=str(e)))
        if len(maps(current))==before:fixed_point=True;break
    validated=a.output/'validated-mappings';runner.call('validate_mapped_files',[a.source,baseline,mft,inventory,evidence/'layout.json',initial,current,validated,'--baseline-manifest',manifest]);current=validated
    supplements={}
    if a.previous_refinement:
        for row in map(json.loads,a.previous_refinement.open()):
            if row.get('operation')=='placed-supplement':supplements[(row['disk_offset'],row['length'])]={k:v for k,v in row.items() if k!='operation'}
    paths=list(a.output.glob('*-recover_catalog_files/supplemental-placements.json'))+list(a.output.glob('*-bind_inf_catalog_candidates/supplemental-placements.json'))+list(a.output.glob('*-recover_file_hashes/supplemental-placements.json'))
    if bit_output and (bit_output/'supplemental-placements.json').exists():paths.append(bit_output/'supplemental-placements.json')
    for path in paths:
        for m in json.loads(path.read_text()):
            key=(m['disk_offset'],m['length'])
            if key in supplements and supplements[key]['sha256']!=m['sha256']:raise ValueError('conflicting independently validated file slices')
            supplements.setdefault(key,m)
    supplemental=a.output/'supplemental-placements.json';supplemental.write_text(json.dumps(list(supplements.values()),indent=2))
    if supplements:runner.call('validate_supplemental_files',[a.source,baseline,mft,manifest,evidence,current,supplemental,a.output/'supplemental-validation'])
    if not a.search_only:
        if not clone_ready:runner.call('clone_sparse_file',[original_baseline,revised,copylog])
        journal=a.output/'refinement-manifest.jsonl';args=[a.source,original_baseline,revised,copylog,original_manifest,current/'accepted-mappings.json',journal,'--supplemental',supplemental]
        if active_previous:args+=['--previous-refinement',active_previous]
        runner.call('refine_vhdx',args);args=[original_baseline,revised,copylog,journal,a.output/'baseline-preservation.json']
        if a.previous_refinement:args+=['--previous-refinement',a.previous_refinement,'--previous-validation',a.previous_validation]
        runner.call('verify_refined_clone',args)
        runner.process('qemu-container-check',[str(a.qemu_img),'check',str(revised)])
    runner.call('export_unresolved',[evidence,current/'accepted-mappings.json',a.output/'decoded-residual'])
    runner.call('refinement_coverage',[a.source,evidence,current/'accepted-mappings.json',a.output/'encoded-residual'])
    rescue_args=[evidence,current/'accepted-mappings.json',a.output/'recovered_files']
    if catalog_members_for_rescue:rescue_args+=['--catalog-members',catalog_members_for_rescue]
    runner.call('rescue_unplaced_files',rescue_args)
    if 'metadata-rescue' in requested:runner.call('rescue_unreadable_records',[a.source,baseline,mft,manifest,evidence,current,a.output/'recovered_files/metadata-records'])
    shutil.copy2(supplemental,a.output/'recovered_files/verified-supplemental-placements.json')
    if audit_output and (audit_output/'partial-decoded.bin').exists():
        target=a.output/'recovered_files/incomplete-decoding';target.mkdir();shutil.copy2(audit_output/'partial-decoded.bin',target/'partial-decoded.bin');shutil.copy2(audit_output/'summary.json',target/'partial-decoded.bin.json')
    if bit_output:
        target=a.output/'recovered_files/indexed-bit-repair';target.mkdir()
        for item in bit_output.glob('*-decoded.bin*'):shutil.copy2(item,target/item.name)
        if (bit_output/'summary.json').exists():shutil.copy2(bit_output/'summary.json',target/'summary.json')
    candidates=a.output/'recovered_files/candidates'
    verified_files={r.get('record'):r for r in json.loads((validated/'file-validation.json').read_text()) if r.get('valid')}
    supplemental_proof=a.output/'supplemental-validation/summary.json'
    if supplemental_proof.exists():
        for r in json.loads(supplemental_proof.read_text())['validated_files_or_frames']:
            if r.get('valid') and r.get('kind')=='component-manifest-file-slices':verified_files[r['record']]=r
    bound_records={e['record'] for m in maps(current) for e in m.get('evidence',[]) if isinstance(e.get('hash_source'),dict) and e['hash_source'].get('kind')=='original-inf-catalog-reference-and-named-member'}
    zip_records={e['record'] for m in maps(current) for e in m.get('evidence',[]) if e.get('method')=='zip-original-member-crcs-and-directory'}
    hash_records={e['record'] for m in maps(current) for e in m.get('evidence',[]) if e.get('method')=='original-whole-file-hash-completion'}
    for directory in sorted(list(a.output.glob('*-recover_chromium_streams/recovered_files'))+list(a.output.glob('*-recover_catalog_sequences/recovered_files'))+list(a.output.glob('*-recover_zip_files/recovered_files'))+list(a.output.glob('*-recover_file_hashes/recovered_files'))):
        target=candidates/directory.parent.name;target.mkdir(parents=True,exist_ok=False)
        for item in directory.iterdir():
            if not item.is_file():continue
            shutil.copy2(item,target/item.name)
            if item.name.endswith('.json') and item.with_suffix('').is_file():
                meta=json.loads(item.read_text())
                if meta.get('kind')=='catalog-sequence-candidate':
                    resolved=[r['record'] for r in meta.get('possible_locations',[]) if r['record'] in bound_records and verified_files.get(r['record'],{}).get('sha256')==meta['sha256']]
                    if resolved:
                        meta.update(placement_status='original-inf-catalog-and-runlist-validated',historical_component_version_binding=True,vhdx_insertion_authorized=True,vhdx_written_by_rebuild=not a.search_only,validated_records=resolved,placement_validation=str((validated/'file-validation.json').resolve()))
                        (target/item.name).write_text(json.dumps(meta,indent=2))
                elif meta.get('kind')=='whole-file-hash-candidate':
                    resolved=[r['record'] for r in meta.get('possible_locations',[]) if r['record'] in hash_records and verified_files.get(r['record'],{}).get('sha256')==meta['sha256']]
                    if resolved:
                        meta.update(content_also_restored_by_validated_frames=not a.search_only,validated_records=resolved,placement_validation=str((validated/'file-validation.json').resolve()))
                        (target/item.name).write_text(json.dumps(meta,indent=2))
                elif meta.get('kind')=='zip-reconstruction-candidate':
                    resolved=[r['record'] for r in meta.get('possible_locations',[]) if r['record'] in zip_records and verified_files.get(r['record'],{}).get('sha256')==meta['sha256']]
                    if resolved:
                        meta.update(placement_status='original-independent-crcs-and-runlist-validated',vhdx_insertion_authorized=True,vhdx_written_by_rebuild=not a.search_only,validated_records=resolved,placement_validation=str((validated/'file-validation.json').resolve()))
                        (target/item.name).write_text(json.dumps(meta,indent=2))
    runner.call('enrich_recovered_metadata',[a.output/'recovered_files',baseline,mft,inventory,evidence/'layout.json'])
    manifest_records={e['record'] for m in maps(current) for e in m.get('evidence',[]) if isinstance(e.get('hash_source'),dict) and e['hash_source'].get('kind')=='original-component-manifest-file-hash'}
    manifest_records.update(e['record'] for m in supplements.values() for e in m.get('evidence',[]) if e.get('method')=='component-manifest-validated-file-slice')
    mark_manifest_restorations(a.output/'recovered_files',verified_files,manifest_records,not a.search_only)
    for path in protected:
        if (path.stat().st_size,path.stat().st_mtime_ns)!=stats[str(path.resolve())]:raise ValueError('protected input changed')
    summary=dict(schema_version=1,corruption_detected=True,vhdx=str(revised.resolve()) if not a.search_only else None,search_only=a.search_only,accepted_mappings=len(maps(current)),supplemental_destinations=len(supplements),supplemental_bytes=sum(m['length'] for m in supplements.values()),mapping_directory=str(current.resolve()),recovered_files=str((a.output/'recovered_files').resolve()),rounds=round_number,no_additions_in_last_round=fixed_point,all_requested_stages_succeeded=not errors,stage_errors=errors,enabled_stages=sorted(requested),excluded_stages=sorted(set(DEFAULT_STAGES.split(','))-requested),protected_input_stats_unchanged=True,limits=dict(per_file_budget=a.per_file_budget,rounds=a.rounds,metadata_identity=a.metadata_identity),scope='Unresolved placements are exported separately. Full-frame residual accounting retains complete enclosing frames for partial validated slices, whose known disk ranges are listed separately. Convergence means no further additions from the implemented bounded searches, never universal unmappability or a complete/bootable filesystem.')
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2),flush=True);return 2


if __name__=='__main__':
    try:
        result=main()
    except SystemExit as failure:
        if ACTIVE_RUNNER is not None:ACTIVE_RUNNER.audit.finish(failure.code,failure if failure.code else None)
        raise
    except BaseException as failure:
        if ACTIVE_RUNNER is not None:ACTIVE_RUNNER.audit.finish(130 if isinstance(failure,KeyboardInterrupt) else 1,failure)
        traceback.print_exc();sys.exit(130 if isinstance(failure,KeyboardInterrupt) else 1)
    else:
        if ACTIVE_RUNNER is not None:ACTIVE_RUNNER.audit.finish(result)
        sys.exit(result)
