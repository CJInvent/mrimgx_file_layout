"""Export allocation-proven CFB streams and all known parts outside the VHDX."""
import argparse,collections,hashlib,json,pathlib,errno
from rebuild_context import Context
from cfb_member_rescue import Compound,known_parts,KnownStream
from rescue_cab_members import export_container as export_cab_container
from zip_directory import known
from rebuild_audit import caught,emit
from rescue_unplaced_files import carved_files,catalog_filename


def groups(parts):
    result=[]
    for part in parts:
        if result and result[-1]['logical_offset']+result[-1]['bytes']==part['logical_offset']:
            result[-1]['bytes']+=part['bytes'];result[-1]['source_ranges'].append(part)
        else:result.append(dict(logical_offset=part['logical_offset'],bytes=part['bytes'],source_ranges=[part]))
    return result


def carve_group(path,metadata,files,maximum=32*1024**2):
    """Overlap windows only inside one contiguous, entirely known stream part."""
    count=total=0;seen=set();window=maximum*2;step=window-maximum
    with path.open('rb') as stream:
        for start in range(0,path.stat().st_size,step):
            stream.seek(start);data=stream.read(window)
            for offset,body,suffix,validation in carved_files(data,maximum=maximum):
                logical=metadata['logical_stream_offset']+start+offset;digest=hashlib.sha256(body).hexdigest();key=(logical,digest)
                if key in seen:continue
                seen.add(key);target=files/(digest+'.'+suffix);side=target.with_suffix(target.suffix+'.json');witness=dict(source_encoding='allocation-proven-cfb-stream',archive_record=metadata['archive_record'],archive_path=metadata['archive_path'],compound_stream=metadata['stream_path'],stream_logical_offset=logical,known_part=str(path.resolve()),known_part_metadata=str(path.with_suffix('.bin.json').resolve()),known_part_sha256=metadata['sha256'])
                if target.exists():
                    if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:raise ValueError('existing carved content differs')
                    meta=json.loads(side.read_text());keys={json.dumps(v,sort_keys=True) for v in meta.get('provenance',[])}
                    if json.dumps(witness,sort_keys=True) not in keys:meta.setdefault('provenance',[]).append(witness)
                else:
                    with target.open('xb') as output:output.write(body)
                    meta=dict(schema_version=1,kind='carved-file',placement_status='unresolved',vhdx_insertion_authorized=False,file_type=suffix,bytes=len(body),sha256=digest,validation=validation,original_filename=catalog_filename(validation),possible_locations=[],provenance=[witness],scope='Internally checked file carved only from an allocation-proven, entirely known compound stream part. Container provenance does not establish a standalone historical filesystem path.')
                    count+=1;total+=len(body)
                    with (files.parent/'index.jsonl').open('a') as index:index.write(json.dumps(dict(path=str(target.relative_to(files.parent)),metadata=str(side.relative_to(files.parent)),**meta))+'\n')
                side.write_text(json.dumps(meta,indent=2))
            if len(data)<window:break
    return count,total


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','seven_zip','output','carved_files'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-total-bytes',type=int,default=256*1024**3);ap.add_argument('--maximum-carved-file-bytes',type=int,default=32*1024**2)
    a=ap.parse_args()
    if min(a.maximum_total_bytes,a.maximum_carved_file_bytes)<1:ap.error('CFB rescue limits must be positive')
    a.output.mkdir();a.carved_files.mkdir(exist_ok=True);ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);counts=collections.Counter();stopped=False
    try:
        with a.inventory.open() as inventory,(a.output/'stream-audit.jsonl').open('x') as audit:
            for row in map(json.loads,inventory):
                compound=None;typed=False
                try:
                    rec=ctx.fs.mft.get(row['record'])
                    if rec.header.Flags&2 or rec.size()<512:continue
                    stream=rec.open()
                    if stream.read(8)!=bytes.fromhex('d0cf11e0a1b11ae1'):continue
                    typed=True;holes=ctx.holes(rec)
                    if not holes or not known(holes,0,8):continue
                    counts['damaged_compound_files_examined']+=1;compound=Compound(stream,rec.size(),holes);folder=a.output/str(row['record']);folder.mkdir();proof=folder/'allocation-metadata.json';proof.write_text(json.dumps(dict(archive_record=row['record'],archive_sequence=rec.header.SequenceNumber,archive_path=row.get('path'),source_metadata_ranges=compound.metadata_ranges,sector_bytes=compound.sector,scope='Every original header/DIFAT/FAT/directory/miniFAT span used for stream membership is known and hashed before any stream is exported. Stream paths name original compound entries, not standalone filesystem paths.'),indent=2))
                    for member in compound.streams():
                        parts=known_parts(member,holes);complete=sum(p['bytes'] for p in parts)==member['size'];counts['original_streams_examined']+=1
                        spans=groups(parts)
                        if not spans and not member['size']:spans=[dict(logical_offset=0,bytes=0,source_ranges=[])]
                        if not spans:
                            counts['streams_without_known_data']+=1;audit.write(json.dumps(dict(record=row['record'],stream=member,kind='compound-stream-data-unavailable'))+'\n');continue
                        for index,part in enumerate(spans):
                            if counts['exported_bytes']+part['bytes']>a.maximum_total_bytes:stopped=True;break
                            path=folder/(str(member['directory_entry'])+'-'+str(index)+'-'+str(part['logical_offset'])+'.bin');digest=hashlib.sha256();written=0
                            with path.open('xb') as output:
                                for original in part['source_ranges']:
                                    position=original['file_offset'];remaining=original['bytes']
                                    if not known(holes,position,position+remaining):raise ValueError('CFB source became unavailable before export')
                                    stream.seek(position)
                                    while remaining:
                                        data=stream.read(min(65536,remaining))
                                        if not data:raise ValueError('short CFB source stream read')
                                        output.write(data);digest.update(data);written+=len(data);remaining-=len(data)
                            if written!=part['bytes']:raise ValueError('CFB source part length differs')
                            meta=dict(schema_version=1,kind='original-compound-stream' if complete else 'partial-compound-stream-part',valid=complete,complete_original_stream=complete,archive_record=row['record'],archive_sequence=rec.header.SequenceNumber,archive_path=row.get('path'),stream_path=member['stream_path'],original_stream_size=member['size'],logical_stream_offset=part['logical_offset'],bytes=written,sha256=digest.hexdigest(),original_directory_entry=member['directory_entry'],original_directory_entry_offset=member['source_entry_offset'],original_directory_entry_sha256=member['source_entry_sha256'],source_ranges=part['source_ranges'],allocation_metadata=str(proof.resolve()),original_container_membership_proven=True,original_whole_stream_digest_available=False,filesystem_placement_unknown=True,vhdx_insertion_authorized=False,possible_locations=[dict(archive_record=row['record'],archive_path=row.get('path'),compound_stream=member['stream_path'],stream_offset=part['logical_offset'],placement_confirmed=False)],scope='Exact source-known compound stream or contiguous known part. Allocation metadata proves container membership only. Unavailable intervals are separate gaps and are never zero-filled or joined. This export never authorizes a VHDX write or a standalone historical filename.')
                            path.with_suffix('.bin.json').write_text(json.dumps(meta,indent=2));audit.write(json.dumps(dict(output=str(path.resolve()),**meta))+'\n');audit.flush();counts['complete_stream_exports' if complete else 'known_part_exports']+=1;counts['exported_bytes']+=written;added,added_bytes=carve_group(path,meta,a.carved_files,a.maximum_carved_file_bytes);counts['additional_carved_files']+=added;counts['additional_carved_file_bytes']+=added_bytes
                        if stopped:break
                        view=KnownStream(stream,rec.size(),member['size'],parts)
                        if member['size']>=36 and known(view.holes,0,4) and view.read(4)==b'MSCF':
                            child_counts=collections.Counter()
                            try:
                                remaining=a.maximum_total_bytes-counts['exported_bytes']
                                if remaining<=0:stopped=True;break
                                context=dict(kind='allocation-proven-compound-stream',archive_record=row['record'],archive_sequence=rec.header.SequenceNumber,compound_stream=member['stream_path'],compound_directory_entry=member['directory_entry'],compound_entry_sha256=member['source_entry_sha256'],original_stream_size=member['size'],source_ranges=parts,allocation_metadata=str(proof.resolve()))
                                stopped=export_cab_container(view,member['size'],view.holes,dict(record=row['record'],sequence=rec.header.SequenceNumber,path=row.get('path')),folder/'nested-cab'/str(member['directory_entry']),a.seven_zip,child_counts,audit,maximum_total_bytes=remaining,source_context=context)
                                counts['nested_cabinets_examined']+=1
                            except ValueError as error:
                                caught(error,dict(record=row['record']),site='compound-nested-cab-rescue');counts['nested_cab_errors']+=1;audit.write(json.dumps(dict(record=row['record'],stream=member['stream_path'],error=str(error),kind='nested-cab-rescue-error'))+'\n');audit.flush()
                            finally:
                                counts['nested_cab_valid_members']+=child_counts['valid_members'];counts['nested_cab_uncertain_members']+=child_counts['uncertain_members'];counts['nested_cab_exported_bytes']+=child_counts['exported_bytes'];counts['exported_bytes']+=child_counts['exported_bytes']
                        if stopped:break
                    print(json.dumps(dict(record=row['record'],counts=dict(counts))),flush=True)
                except Exception as error:
                    caught(error,dict(record=row['record']),expected=not typed,site='compound-member-rescue')
                    if typed:counts['compound_errors']+=1;audit.write(json.dumps(dict(record=row['record'],path=row.get('path'),error=str(error),kind='compound-rescue-error'))+'\n');audit.flush()
                    if isinstance(error,OSError) and error.errno in {errno.EACCES,errno.EPERM,errno.EIO,errno.ENOSPC,errno.EBADF}:raise
                    if any(text in str(error) for text in ('source became unavailable','short CFB source stream','CFB source part length','existing carved content differs')):raise
                finally:
                    if compound:compound.close()
                if stopped:break
        if stopped:emit('search-limit','CFB stream total export bound reached',severity='warning',context=dict(maximum_total_bytes=a.maximum_total_bytes))
        result=dict(counts=dict(counts),total_output_bound_reached=stopped,limits=dict(maximum_total_bytes=a.maximum_total_bytes,maximum_carved_file_bytes=a.maximum_carved_file_bytes,carve_window_bytes=2*a.maximum_carved_file_bytes,nested_cab_encoded_prefix_bytes=1024**3,nested_cab_decoded_prefix_bytes=2*1024**3),scope='Damaged compound containers identified by known source content, regardless of suffix. Complete streams, every known logical part, internally checked nested files and source-known nested cabinet members are separate external exports with JSON metadata. Missing intervals are never decoder input or placement authority.')
        (a.output/'summary.json').write_text(json.dumps(result,indent=2))
        original_summary=a.carved_files.parent/'summary.json'
        if original_summary.exists():
            summary=json.loads(original_summary.read_text());summary['counts']['carved_files']=summary['counts'].get('carved_files',0)+counts['additional_carved_files'];summary['counts']['carved_file_bytes']=summary['counts'].get('carved_file_bytes',0)+counts['additional_carved_file_bytes'];summary['compound_member_rescue']=str((a.output/'summary.json').resolve());original_summary.write_text(json.dumps(summary,indent=2))
        print(json.dumps(result),flush=True)
    finally:ctx.close()


if __name__=='__main__':main()
