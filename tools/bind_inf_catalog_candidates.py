"""Bind reconstructed INFs to original catalog references and named members.

Only a complete surviving [Version] section naming a catalog in the original
NTFS directory, plus that freshly checked catalog's File member attribute,
provides an original whole-file hash. Sequence nomination alone never does.
"""
from rebuild_audit import caught as _audit_caught
import argparse,collections,hashlib,json,pathlib,re,sqlite3
from rebuild_context import Context
from recover_duplicate_files import file_extents,frame_pieces
from recover_file_hashes import reconstruct,distinctive_hash_bound
from windows_metadata import catalog_members


def original_catalog_names(prefix):
    text=prefix.decode('utf-16-le' if prefix.startswith(b'\xff\xfe') else 'utf-8-sig',errors='strict').lstrip('\ufeff');sections=list(re.finditer(r'(?m)^[ \t]*\[([^\]\r\n]+)\][^\r\n]*\r?$',text));names=set()
    for i,section in enumerate(sections):
        if section.group(1).strip().casefold()!='version':continue
        if i+1==len(sections):raise ValueError('complete original Version section did not survive')
        body=text[section.end():sections[i+1].start()]
        for match in re.finditer(r'(?im)^[ \t]*CatalogFile(?:\.[\w.]+)?[ \t]*=[ \t]*([^;\r\n]+)',body):
            name=match.group(1).strip().strip('"')
            if not re.fullmatch(r'[\w .-]+\.cat',name,re.I) or name in ('.','..'):raise ValueError('indirect or unsafe catalog filename')
            names.add(name)
    if not names:raise ValueError('no literal original catalog reference')
    return sorted(names,key=str.casefold)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','candidates','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);accepted=ctx.maps[:];plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);by_id={};contents={}
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(ctx.stride,)):
            frames[f[6]].append(f);by_id[f[0]]=f
            if f[6] not in contents:
                corpus.seek(f[3]);data=corpus.read(ctx.stride)
                if hashlib.sha256(data).hexdigest()!=f[6]:raise ValueError('corpus differs')
                contents[f[6]]=data
    pending=collections.defaultdict(list);supplemental=[];reports=[]
    for sidecar in sorted(a.candidates.glob('*.bin.json')):
        metadata=json.loads(sidecar.read_text())
        if metadata.get('kind')!='catalog-sequence-candidate':continue
        for location in metadata.get('possible_locations',[]):
            path=location.get('path') or ''
            if pathlib.PureWindowsPath(path).suffix.casefold()!='.inf':continue
            report=dict(record=location['record'],path=path,candidate=str(sidecar.resolve()));reports.append(report)
            try:
                number=location['record'];record=ctx.fs.mft.get(number);size=record.size();holes=ctx.holes(record);bases=sorted({base for lo,hi,base in holes});extents=file_extents(record,size);pieces={b:frame_pieces(extents,b,ctx.stride) for b in bases};template=record.open().read()
                named_inf=ctx.fs.mft.get(path)
                if named_inf.size()!=size or file_extents(named_inf,size)!=extents or pathlib.PureWindowsPath(path).name.casefold() not in {n.casefold() for n in record.filenames(ignore_dos=True)}:raise ValueError('original INF namespace and MFT runlist disagree')
                if not bases:report['skipped']='no missing frames';continue
                first=min(lo for lo,hi,base in holes);names=original_catalog_names(template[:first]);proof=metadata['catalog_validation'];catalog_record,catalog_data=ctx.read_complete(proof['catalog_record'],64*1024**2)
                if hashlib.sha256(catalog_data).hexdigest()!=proof['catalog_sha256']:raise ValueError('original catalog content differs')
                matched=[]
                for name in names:
                    candidate_path=str(pathlib.PureWindowsPath(path).parent/name)
                    try:
                        named=ctx.fs.mft.get(candidate_path)
                        if named.size()==len(catalog_data) and not ctx.holes(named) and named.open().read()==catalog_data:matched.append(candidate_path)
                    except Exception as _audit_error:
                        _audit_caught(_audit_error, None, expected=True, site='bind_inf_catalog_candidates.py:60')
                        continue
                if not matched:raise ValueError('referenced catalog not readable in original NTFS directory')
                exported=a.output/f'{number}-original.cat'
                if not exported.exists():
                    with exported.open('xb') as out:out.write(catalog_data)
                members=list(catalog_members(exported));filename=pathlib.PureWindowsPath(path).name.casefold();oid={'sha1':'1.3.14.3.2.26','sha256':'2.16.840.1.101.3.4.2.1'}[proof['algorithm']]
                named_members=[m for m in members if any(attr.get('tag','').casefold()=='file' and attr.get('text','').casefold()==filename for attr in m.get('attributes',[])) and m.get('subject_oid')=='1.3.6.1.4.1.311.2.1.25' and m.get('algorithm_oid')==oid]
                if {m.get('digest') for m in named_members}!={proof['digest']}:raise ValueError('original named catalog member is absent or ambiguous')
                data=sidecar.with_suffix('').read_bytes()
                if len(data)!=size or hashlib.sha256(data).hexdigest()!=metadata['sha256'] or hashlib.new(proof['algorithm'],data).hexdigest()!=proof['digest']:raise ValueError('candidate does not match original named file hash')
                assignment={}
                for p in metadata['provenance']:
                    base=p['candidate_disk_offset']-ctx.origin;f=by_id[p['frame']]
                    if base not in pieces or [list(x) for x in pieces[base]]!=p['file_pieces'] or (f[1],f[2],f[6])!=(p['source_offset'],p['stored_length'],p['decoded_sha256']):raise ValueError('candidate source/runlist provenance differs')
                    decoded=ctx.decode(f[1],f[2])
                    if decoded!=contents[f[6]] or hashlib.md5(decoded).digest()!=f[5]:raise ValueError('source revalidation failed')
                    assignment[base]=f[6]
                if set(assignment)!=set(bases) or reconstruct(template,bases,pieces,[assignment[b] for b in bases],contents)!=data:raise ValueError('candidate changes surviving original bytes or runlist')
                binding=dict(original_catalog_paths=matched,original_inf_prefix_bytes=first,original_inf_prefix_sha256=hashlib.sha256(template[:first]).hexdigest(),catalog_member_filename=filename,catalog_record=proof['catalog_record'],catalog_sha256=proof['catalog_sha256'],catalog_signature_hash_rechecked=True)
                # Keep a mixed-boundary file entirely in the supplemental
                # channel, so its complete hash can be validated without
                # mistaking any partial source frame for a complete mapping.
                full_file_frames=True
                for base in bases:
                    sha=assignment[base];parts=b''.join(contents[sha][off:off+n] for off,logical,n in pieces[base]);alternatives=[s for s,d in contents.items() if all(d[off:off+n]==contents[sha][off:off+n] for off,logical,n in pieces[base])]
                    if len(alternatives)!=1 or not distinctive_hash_bound(parts):full_file_frames=False;break
                for base in bases:
                    sha=assignment[base];f=frames[sha][0];parts=b''.join(contents[sha][off:off+n] for off,logical,n in pieces[base]);alternatives=[s for s,d in contents.items() if all(d[off:off+n]==contents[sha][off:off+n] for off,logical,n in pieces[base])]
                    evidence=dict(method='original-whole-file-hash-completion',record=number,file_size=size,algorithm=proof['algorithm'],expected_digest=proof['digest'],hash_source=dict(kind='original-inf-catalog-reference-and-named-member',**binding),historical_component_version_binding=True,source_order_only_nominated=True)
                    if full_file_frames:pending[base].append((sha,evidence))
                    else:
                        for off,logical,n in pieces[base]:
                            part=contents[sha][off:off+n];supplemental.append(dict(partition=2,disk_offset=ctx.origin+base+off,length=n,source_offset=f[1],stored_length=f[2],source_decoded_length=ctx.stride,source_decoded_md5=f[5].hex(),source_decoded_sha256=sha,decoded_slice_offset=off,decoded_md5=hashlib.md5(part).hexdigest(),sha256=hashlib.sha256(part).hexdigest(),evidence=[dict(method='catalog-validated-file-slice',record=number,path=path,file_size=size,file_logical_offset=logical,hash_kind='flat',algorithm=proof['algorithm'],expected_digest=proof['digest'],catalog=proof,historical_component_version_binding=True,binding=binding,enclosing_frame_placement_authorized=False)]))
                report.update(valid=True,binding=binding,original_digest=proof['digest'])
            except Exception as e:
                _audit_caught(e, locals(), expected=False, site='bind_inf_catalog_candidates.py:94')
                report['error']=str(e)
            print(json.dumps(report),flush=True)
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({sha for sha,e in items})!=1:conflicts.append(base);continue
        sha=items[0][0];f=frames[sha][0];accepted.append(dict(partition=2,reserved=False,block=base//ctx.stride,disk_offset=ctx.origin+base,length=ctx.stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=sha,frames=[x[0] for x in frames[sha]],evidence=[e for s,e in items]));plan['partitions'][2].setdefault('overrides',{})[str(base//ctx.stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Original surviving INF catalog reference, same-directory NTFS catalog and named member digest bind the original whole-file hash; full frame boundary also unique.')
    for name,value in (('accepted-mappings.json',accepted),('recovery-plan.json',plan),('supplemental-placements.json',supplemental),('binding-evidence.json',reports)):(a.output/name).write_text(json.dumps(value,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),new_placements=len(accepted)-len(ctx.maps),supplemental_destinations=len(supplemental),supplemental_bytes=sum(m['length'] for m in supplemental),conflicts=conflicts,targets=len(reports));(a.output/'summary.json').write_text(json.dumps(result,indent=2));ctx.close();db.close();print(json.dumps(result),flush=True)


if __name__=='__main__':main()
