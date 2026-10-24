"""Export CAB members/prefixes from known original compression blocks only."""
import argparse,collections,hashlib,json,pathlib,subprocess,os,re
from rebuild_context import Context
from cab_member_rescue import metadata,folder_prefix,prefix_members,write_prefix_cabinet
from zip_directory import known
from rebuild_audit import caught,emit


def extract_member(seven_zip,cabinet,name,output,maximum):
    digest=hashlib.sha256();count=0;bounded=False
    with subprocess.Popen([str(seven_zip),'x','-so','-bd','-y','-spd','--',str(cabinet),name],stdout=subprocess.PIPE,stderr=subprocess.PIPE) as process:
        while True:
            data=process.stdout.read(min(65536,maximum-count+1))
            if not data:break
            if count+len(data)>maximum:
                bounded=True;data=data[:maximum-count];process.kill()
            output.write(data);digest.update(data);count+=len(data)
            if bounded:break
        stderr=process.stderr.read().decode('utf-8',errors='replace');code=process.wait()
    return dict(decoded_bytes=count,sha256=digest.hexdigest(),decoder_exit_code=code,decoder_error=stderr,output_bound_reached=bounded)


def extract_batch(seven_zip,cabinet,members,folder):
    """Only our generated flat names/attributes can become decoder paths."""
    if len({m['generated_name'] for m in members})!=len(members) or any(not re.fullmatch(r'member-\d{5}\.bin',m['generated_name']) for m in members):raise ValueError('CAB decoder filename is not a unique generated ID')
    folder.mkdir();result=subprocess.run([str(seven_zip),'x','-bd','-y','-o'+str(folder),'--',str(cabinet)],capture_output=True,text=True,errors='replace')
    folder.with_suffix('.log').write_text(result.stdout+result.stderr)
    names={m['generated_name'] for m in members}
    if any(not path.is_file() or path.is_symlink() or path.name not in names for path in folder.iterdir()):raise ValueError('CAB decoder produced an unexpected path')
    if any((folder/m['generated_name']).exists() and (folder/m['generated_name']).stat().st_size>m['available_bytes'] for m in members):raise ValueError('CAB decoder output exceeds declared source prefix size')
    return result


def export_container(stream,size,holes,owner,folder,seven_zip,counts,audit,maximum_encoded_prefix=1024**3,maximum_decoded_prefix=2*1024**3,maximum_total_bytes=256*1024**3,*,info=None,source_context=None):
    info=metadata(stream,size,holes) if info is None else info;stopped=False
    folder.mkdir(parents=True)
    for original_folder in info['folders']:
        prefix=folder_prefix(stream,info['cabinet_bytes'],holes,original_folder,maximum_encoded_prefix,maximum_decoded_prefix,allow_bad_checksums=True);members=prefix_members(info,prefix)
        detail=dict(record=owner['record'],path=owner.get('path'),folder=original_folder['index'],prefix=prefix)
        if source_context:detail['source_context']=source_context
        (folder/(str(original_folder['index'])+'-source-prefix.json')).write_text(json.dumps(dict(original_metadata=info,**detail),indent=2))
        if prefix['stopped_reason']:emit('cab-source-prefix-stop',prefix['stopped_reason'],severity='warning',context=dict(record=owner['record'],folder=original_folder['index'],known_decoded_prefix_bytes=prefix['decoded_prefix_bytes']))
        if prefix['stopped_reason'] and 'bound reached' in prefix['stopped_reason']:emit('search-limit',prefix['stopped_reason'],severity='warning',context=dict(record=owner['record']))
        bad=[b for b in prefix['blocks'] if not b['original_checksum_valid']]
        if bad:emit('cab-original-checksum-mismatch','Original CAB compressed-block checksums differ; downstream output remains uncertain',severity='warning',context=dict(record=owner['record'],folder=original_folder['index'],blocks=len(bad)))
        if not prefix['blocks'] or not members:continue
        selected=[];remaining=maximum_total_bytes-counts['exported_bytes']
        for member in members:
            if remaining<=0:stopped=True;break
            amount=min(member['available_bytes'],remaining);selected.append(dict(member,available_bytes=amount,complete_original_member=member['complete_original_member'] and amount==member['size']));remaining-=amount
            if amount<member['available_bytes']:stopped=True;break
        members=selected
        if not members:break
        cabinet=folder/(str(original_folder['index'])+'-decoder-prefix.cab')
        with cabinet.open('xb') as output:write_prefix_cabinet(stream,info['cabinet_bytes'],holes,prefix,members,output)
        batch_folder=folder/(str(original_folder['index'])+'-decoder-batch');batch=extract_batch(seven_zip,cabinet,members,batch_folder)
        if batch.returncode:emit('cab-batch-decoder-error','CAB batch decoder reported damage; members are individually retried',severity='warning',context=dict(record=owner['record'],folder=original_folder['index'],exit_code=batch.returncode,log=str(batch_folder.with_suffix('.log').resolve())))
        for member in members:
            remaining=maximum_total_bytes-counts['exported_bytes']
            if remaining<=0:stopped=True;break
            path=folder/(str(original_folder['index'])+'-'+member['generated_name'])
            extracted=batch_folder/member['generated_name']
            if batch.returncode==0 and extracted.is_file():
                if path.exists() or extracted.resolve().parent!=batch_folder.resolve() or path.resolve().parent!=folder.resolve():raise ValueError('CAB generated output path changed')
                os.replace(extracted,path);digest=hashlib.sha256();count=0
                with path.open('rb') as data:
                    while chunk:=data.read(65536):digest.update(chunk);count+=len(chunk)
                result=dict(decoded_bytes=count,sha256=digest.hexdigest(),decoder_exit_code=0,decoder_error=batch.stderr,output_bound_reached=False)
            else:
                with path.open('xb') as output:result=extract_member(seven_zip,cabinet,member['generated_name'],output,min(member['available_bytes'],remaining))
            valid=member['complete_original_member'] and member['original_block_checksums_agree'] and result['decoder_exit_code']==0 and result['decoded_bytes']==member['size'] and not result['output_bound_reached']
            meta=dict(schema_version=1,kind='original-cab-member' if valid else 'uncertain-cab-member-prefix',valid=valid,archive_record=owner['record'],archive_sequence=owner['sequence'],archive_path=owner.get('path'),member_name=member['name'],original_size=member['size'],original_folder=member['folder'],original_folder_offset=member['folder_offset'],original_member_directory_binding_proven=True,original_whole_file_digest_available=False,filesystem_placement_unknown=True,vhdx_insertion_authorized=False,source_member=member,original_metadata_bytes=info['original_metadata_bytes'],original_metadata_sha256=info['original_metadata_sha256'],source_prefix_metadata=str((folder/(str(original_folder['index'])+'-source-prefix.json')).resolve()),derived_decoder_cabinet=str(cabinet.resolve()),source_compressed_bytes_unchanged=True,generated_decoder_checksum_fields_neutralized=len(bad),possible_locations=[dict(archive_record=owner['record'],archive_path=owner.get('path'),member_name=member['name'],placement_confirmed=False)],scope='External source-known CAB member or uncertain prefix only. Generated CAB names and decoder metadata differ from the original. Bad original checksums remain recorded and propagate uncertainty; no source bytes or VHDX contents are repaired from this export.',**result)
            if source_context:meta['source_context']=source_context
            meta.update(batch_decoder_exit_code=batch.returncode,generated_decoder_file_attributes=0x20)
            path.with_suffix('.bin.json').write_text(json.dumps(meta,indent=2));audit.write(json.dumps(dict(output=str(path.resolve()),**meta))+'\n');audit.flush();counts['valid_members' if valid else 'uncertain_members']+=1;counts['exported_bytes']+=result['decoded_bytes']
            if not valid:emit('cab-member-integrity','CAB member is incomplete, downstream of a bad original checksum, or decoder reported damage',severity='warning',context=meta)
        if stopped:break
    return stopped


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','seven_zip','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-encoded-prefix',type=int,default=1024**3);ap.add_argument('--maximum-decoded-prefix',type=int,default=2*1024**3);ap.add_argument('--maximum-total-bytes',type=int,default=256*1024**3)
    a=ap.parse_args()
    if min(a.maximum_encoded_prefix,a.maximum_decoded_prefix,a.maximum_total_bytes)<1:ap.error('CAB rescue limits must be positive')
    a.output.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);counts=collections.Counter();stopped=False
    try:
        with a.inventory.open() as inventory,(a.output/'member-audit.jsonl').open('x') as audit:
            for row in map(json.loads,inventory):
                typed=False
                try:
                    rec=ctx.fs.mft.get(row['record'])
                    if rec.header.Flags&2 or rec.size()<36:continue
                    stream=rec.open()
                    if stream.read(4)!=b'MSCF':continue
                    typed=True
                    holes=ctx.holes(rec)
                    if not holes or not known(holes,0,4):continue
                    counts['damaged_cabinets_examined']+=1;info=metadata(stream,rec.size(),holes)
                except Exception as error:
                    caught(error,dict(record=row['record']),expected=not typed,site='cab-member-discovery');continue
                stopped=export_container(stream,rec.size(),holes,dict(record=row['record'],sequence=rec.header.SequenceNumber,path=row.get('path')),a.output/str(row['record']),a.seven_zip,counts,audit,a.maximum_encoded_prefix,a.maximum_decoded_prefix,a.maximum_total_bytes,info=info)
                print(json.dumps(dict(record=row['record'],counts=dict(counts))),flush=True)
                if stopped:break
        if stopped:emit('search-limit','CAB member total export bound reached',severity='warning',context=dict(maximum_total_bytes=a.maximum_total_bytes))
        result=dict(counts=dict(counts),total_output_bound_reached=stopped,limits=dict(maximum_encoded_prefix=a.maximum_encoded_prefix,maximum_decoded_prefix=a.maximum_decoded_prefix,maximum_total_bytes=a.maximum_total_bytes),scope='Only damaged CAB containers with original known metadata are examined, by content regardless of suffix. Unknown compressed bytes never reach a decoder. Complete members and uncertain prefixes remain external, with original metadata and decoder evidence; no placement authority or original certificate trust is asserted.')
        (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
    finally:ctx.close()


if __name__=='__main__':main()
