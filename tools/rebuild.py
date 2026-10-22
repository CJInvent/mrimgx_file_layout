"""Opt-in forensic rebuild: discover, iterate, validate, refine and rescue.

Never launches a recovered program or writes to the source/baseline/evidence.
Native strict conversion remains the default. All stages use the same reusable
methods as interactive forensic work, with machine-readable logs and failures.
"""
import argparse,hashlib,json,os,pathlib,subprocess,sys,time
from make_recovery_plan import make_plan
from forensic_residuals import root_layout

TOOLS=pathlib.Path(__file__).resolve().parent
DEFAULT_STAGES='appx,cab,signed-pe,structured,pdf,duplicates,chakra,wal,ese,fat-directories,fat-duplicates,fat-signed-pe,fat-joint-pe,ntfs-joint-pe,png,installer-hashes,catalog-hashes'


def corrupted(manifest):
    complete=None;hits=0
    for row in map(json.loads,manifest.open()):
        if row.get('status') in ('unknown-zero-index','unrecoverable','reconstructed-unverified'):hits+=1
        complete=row
    if not complete or complete.get('operation')!='complete':raise ValueError('baseline manifest incomplete')
    return bool(hits)


class Runner:
    def __init__(self,output):self.output=output;self.events=[];self.serial=0
    def call(self,tool,args,output=None,allowed=(0,)):
        self.serial+=1;name=f'{self.serial:04d}-{tool}';log=self.output/'logs'/(name+'.log');command=[sys.executable,str(TOOLS/(tool+'.py'))]+[str(x) for x in args];began=time.monotonic();print(json.dumps(dict(stage=name,event='begin',log=str(log))),flush=True)
        with log.open('x') as stream:code=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT).returncode
        event=dict(stage=name,command=command,exit_code=code,seconds=time.monotonic()-began,log=str(log.resolve()),success=code in allowed);self.events.append(event);(self.output/'stages.json').write_text(json.dumps(self.events,indent=2));print(json.dumps(event),flush=True)
        if code not in allowed:raise RuntimeError(f'{name} failed ({code}); see {log}')
        return output


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=pathlib.Path);ap.add_argument('--plan',type=pathlib.Path,help='optional existing fingerprinted plan; otherwise discover corroborated index arrays and boot frames')
    ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--native',type=pathlib.Path);ap.add_argument('--baseline',type=pathlib.Path);ap.add_argument('--manifest',type=pathlib.Path);ap.add_argument('--evidence',type=pathlib.Path);ap.add_argument('--mft',type=pathlib.Path);ap.add_argument('--inventory',type=pathlib.Path);ap.add_argument('--mapping-directory',type=pathlib.Path)
    ap.add_argument('--qemu-img',type=pathlib.Path,required=True);ap.add_argument('--seven-zip',type=pathlib.Path,required=True)
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
    if a.plan is None:
        from discover_rebuild_plan import discover,bootstrap_boot
        a.output.mkdir(exist_ok=False);(a.output/'logs').mkdir();plan,discovery=discover(a.source);plan,discovery['boot_recovery']=bootstrap_boot(a.source,plan);a.plan=a.output/'discovered-plan.json';a.plan.open('x').write(json.dumps(plan,indent=2));(a.output/'plan-discovery.json').open('x').write(json.dumps(discovery,indent=2))
    else:
        plan=json.loads(a.plan.read_text());a.output.mkdir(exist_ok=False);(a.output/'logs').mkdir()
    if make_plan(a.source,plan)!=plan:raise ValueError('source/plan fingerprint mismatch')
    layout=root_layout(a.source);parts=layout['disks'][0]['partitions']
    if len(parts)<3 or parts[2]['_header']['block_size']!=143360:raise ValueError('current mapping suite requires Windows NTFS at partition 2 with 143360-byte frames; unsupported geometry is not guessed')
    protected=[p for p in (a.source,a.plan,a.baseline,a.manifest,a.mft,a.inventory) if p];stats={str(p.resolve()):(p.stat().st_size,p.stat().st_mtime_ns) for p in protected};runner=Runner(a.output)
    baseline=a.baseline;manifest=a.manifest
    if baseline is None:
        if not a.native:ap.error('--native required to create a baseline')
        baseline=a.output/'baseline.vhdx';manifest=a.output/'baseline-manifest.jsonl'
        command=[str(a.native), '--recover-plan',str(a.source),str(a.plan),str(baseline),str(manifest),'--direct-vhdx',str(a.qemu_img)]
        with (a.output/'logs/baseline.log').open('x') as log:code=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT).returncode
        if code not in (0,2):raise RuntimeError('baseline conversion failed; preserved output is incomplete')
    if not corrupted(manifest):
        (a.output/'summary.json').write_text(json.dumps(dict(corruption_detected=False,rebuild_performed=False,baseline=str(baseline.resolve())),indent=2));return 0
    evidence=a.evidence
    if evidence is None:evidence=runner.call('forensic_residuals',[a.source,a.plan,manifest,a.output/'evidence'],a.output/'evidence')
    elif json.loads((evidence/'input-plan.json').read_text())!=plan:raise ValueError('evidence belongs to another plan')
    mft=a.mft;inventory=a.inventory
    if mft is None:
        prep=a.output/'filesystem';runner.call('prepare_rebuild',[baseline,manifest,evidence/'layout.json',prep]);mft=prep/'mft.bin';inventory=prep/'affected-files.jsonl'
    current=a.mapping_directory
    if current is None:current=runner.call('map_orphan_frames',[a.source,a.plan,manifest,evidence,baseline,mft,a.output/'initial-mapping','--file-inventory',inventory,'--pe-anchors','--appx-anchors'],a.output/'initial-mapping')
    initial=current;errors=[];round_number=0;fixed_point=False
    def maps(path):return json.loads((path/'accepted-mappings.json').read_text())
    def stage(tool,args):
        nonlocal current
        output=a.output/f'{runner.serial+1:04d}-{tool}'
        try:
            runner.call(tool,args+[output]);new=maps(output);old=maps(current);prior={m['disk_offset']:m for m in new}
            if len(new)<len(old) or any(prior.get(m['disk_offset'])!=m for m in old):raise ValueError('stage contradicted an existing accepted mapping')
            current=output
        except Exception as e:errors.append(dict(tool=tool,error=str(e)))
    while not a.rounds or round_number<a.rounds:
        before=len(maps(current));round_number+=1;print(json.dumps(dict(round=round_number,mappings=before)),flush=True)
        for name in DEFAULT_STAGES.split(','):
            if name not in requested:continue
            common=[a.source,baseline,mft,inventory,manifest,evidence,current]
            if name in ('appx','signed-pe','structured','pdf','wal','ese','png'):
                tool=dict(appx='extend_appx_mappings',**{'signed-pe':'extend_signed_pe_mappings'},structured='extend_structured_files',pdf='recover_pdf_xrefs',wal='recover_sqlite_wal',ese='recover_ese_pages',png='recover_png_crc_grid')[name]
                args=common
                # Output positional precedes options; stage accepts option
                # arguments only through explicit helper below.
                stage(tool,args)
                if name=='ese':
                    # A separate pass uses already known boundary bytes.
                    out=a.output/f'{runner.serial+1:04d}-ese-boundaries'
                    try:runner.call(tool,[a.source,baseline,mft,inventory,manifest,evidence,current,out,'--cross-boundary']);current=out
                    except Exception as e:errors.append(dict(tool=tool,error=str(e)))
            elif name=='cab':stage('extend_cab_mappings',common+[a.seven_zip])
            elif name=='duplicates':
                pairs=a.output/f'duplicate-pairs-{round_number:03d}.json'
                try:
                    runner.call('discover_duplicate_pairs',[mft,inventory,current/'accepted-mappings.json',pairs])
                    if json.loads(pairs.read_text()):
                        out=a.output/f'{runner.serial+1:04d}-duplicates';args=[a.source,baseline,mft,manifest,evidence,current,out,'--pairs-json',pairs,'--allow-boundary','--stream-large-files','--allow-partial-donor']
                        if a.metadata_identity:args+=['--allow-metadata-duplicates']
                        runner.call('recover_duplicate_files',args);current=out
                except Exception as e:errors.append(dict(tool='duplicates',error=str(e)))
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
                        if 'header' in locals() and header[:4]==b'ChBc':errors.append(dict(tool='chakra',record=row['record'],error=str(e)))
            elif name in ('fat-directories','fat-signed-pe','fat-joint-pe','ntfs-joint-pe'):
                tool={'fat-directories':'recover_fat_directories','fat-signed-pe':'recover_fat_signed_pe','fat-joint-pe':'recover_fat_multiframe_pe','ntfs-joint-pe':'recover_fat_multiframe_pe'}[name]
                if name=='ntfs-joint-pe':
                    for minimum,maximum in ((8192,4*1024**2),(4*1024**2+1,256*1024**2)):
                        out=a.output/f'{runner.serial+1:04d}-ntfs-joint'
                        try:runner.call(tool,[a.source,baseline,manifest,evidence,current,out,'--partition',2,'--mft',mft,'--inventory',inventory,'--minimum-missing',1,'--minimum-file-size',minimum,'--maximum-file-size',maximum,'--per-file-budget',a.per_file_budget]);current=out
                        except Exception as e:errors.append(dict(tool=name,error=str(e)))
                else:stage(tool,[a.source,baseline,manifest,evidence,current])
            elif name=='fat-duplicates':stage('recover_fat_duplicates',[a.source,baseline,mft,manifest,evidence,current])
            elif name=='installer-hashes':
                collected=a.output/f'installer-hashes-{round_number:03d}'
                try:
                    runner.call('collect_installer_hashes',[a.source,baseline,mft,inventory,manifest,evidence,current,collected])
                    if json.loads((collected/'hash-targets.json').read_text()):stage('recover_file_hashes',[a.source,baseline,mft,manifest,evidence,current,collected/'hash-targets.json'])
                except Exception as e:errors.append(dict(tool=name,error=str(e)))
            elif name=='catalog-hashes':
                collected=a.output/f'catalog-hashes-{round_number:03d}'
                try:
                    runner.call('collect_catalog_hashes',[a.source,baseline,mft,manifest,evidence,current,collected])
                    stage('recover_catalog_files',[a.source,baseline,mft,inventory,manifest,evidence,current,collected/'catalog-members.jsonl'])
                except Exception as e:errors.append(dict(tool=name,error=str(e)))
        if len(maps(current))==before:fixed_point=True;break
    validated=a.output/'validated-mappings';runner.call('validate_mapped_files',[a.source,baseline,mft,inventory,evidence/'layout.json',initial,current,validated]);current=validated
    revised=None
    if not a.search_only:
        revised=a.existing_clone or a.output/'rebuilt.vhdx';copylog=a.clone_manifest or a.output/'clone-manifest.jsonl'
        if not a.existing_clone:runner.call('clone_sparse_file',[baseline,revised,copylog])
        journal=a.output/'refinement-manifest.jsonl';args=[a.source,baseline,revised,copylog,manifest,current/'accepted-mappings.json',journal]
        if a.previous_refinement:args+=['--previous-refinement',a.previous_refinement]
        runner.call('refine_vhdx',args);args=[baseline,revised,copylog,journal,a.output/'baseline-preservation.json']
        if a.previous_refinement:args+=['--previous-refinement',a.previous_refinement,'--previous-validation',a.previous_validation]
        runner.call('verify_refined_clone',args)
        check=subprocess.run([str(a.qemu_img),'check',str(revised)],capture_output=True,text=True);(a.output/'qemu-check.txt').write_text(check.stdout+check.stderr)
        if check.returncode:raise ValueError('rebuilt container QEMU check failed')
    runner.call('export_unresolved',[evidence,current/'accepted-mappings.json',a.output/'decoded-residual'])
    runner.call('refinement_coverage',[a.source,evidence,current/'accepted-mappings.json',a.output/'encoded-residual'])
    runner.call('rescue_unplaced_files',[evidence,current/'accepted-mappings.json',a.output/'recovered_files'])
    runner.call('enrich_recovered_metadata',[a.output/'recovered_files',baseline,mft,inventory,evidence/'layout.json'])
    for path in protected:
        if (path.stat().st_size,path.stat().st_mtime_ns)!=stats[str(path.resolve())]:raise ValueError('protected input changed')
    summary=dict(schema_version=1,corruption_detected=True,vhdx=str(revised.resolve()) if revised else None,search_only=a.search_only,accepted_mappings=len(maps(current)),mapping_directory=str(current.resolve()),recovered_files=str((a.output/'recovered_files').resolve()),rounds=round_number,no_additions_in_last_round=fixed_point,all_requested_stages_succeeded=not errors,stage_errors=errors,enabled_stages=sorted(requested),excluded_stages=sorted(set(DEFAULT_STAGES.split(','))-requested),protected_input_stats_unchanged=True,limits=dict(per_file_budget=a.per_file_budget,rounds=a.rounds,metadata_identity=a.metadata_identity),scope='Unresolved placements are exported separately. Convergence means no further additions from the implemented bounded searches, never universal unmappability or a complete/bootable filesystem.')
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2),flush=True);return 2


if __name__=='__main__':sys.exit(main())
