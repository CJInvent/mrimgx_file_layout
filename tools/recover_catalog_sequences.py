"""Rescue catalog-checked multi-frame candidates outside the VHDX.

Source order only nominates combinations. A bounded search against a set of
catalog versions cannot establish the unique historical file, so even complete
hash matches remain external candidates with their possible NTFS metadata.
"""
from rebuild_audit import caught as _audit_caught
import argparse,collections,hashlib,json,pathlib,sqlite3
from rebuild_context import Context
from recover_duplicate_files import file_extents,frame_pieces
from recover_catalog_files import pe_hash_regions,catalog_digest
from recover_file_hashes import reconstruct


def projected_multi_hash(template,regions,bases,pieces,algorithm):
    patches=sorted((logical,off,n,i) for i,base in enumerate(bases) for off,logical,n in pieces[base]);state=hashlib.new(algorithm);steps=[];variable=False
    for lo,hi in regions:
        cursor=lo
        for logical,off,n,i in patches:
            start=max(lo,logical);stop=min(hi,logical+n)
            if stop<=start:continue
            fixed=template[cursor:start]
            if variable:
                if fixed:steps.append((None,fixed))
            else:state.update(fixed)
            steps.append((i,(off+start-logical,stop-start)));variable=True;cursor=stop
        fixed=template[cursor:hi]
        if variable:
            if fixed:steps.append((None,fixed))
        else:state.update(fixed)
    def digest(assignment,contents):
        h=state.copy()
        for i,value in steps:
            if i is None:h.update(value)
            else:off,n=value;h.update(contents[assignment[i]][off:off+n])
        return h.hexdigest()
    return digest


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','catalog_members','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-file-size',type=int,default=4*1024**2);ap.add_argument('--maximum-missing',type=int,default=8);ap.add_argument('--per-file-budget',type=int,default=300000);ap.add_argument('--only-record',type=int)
    a=ap.parse_args()
    if a.maximum_missing<2 or a.per_file_budget<1:ap.error('invalid search bounds')
    a.output.mkdir(exist_ok=False);external=a.output/'recovered_files';external.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);catalogs=collections.defaultdict(dict)
    for row in map(json.loads,a.catalog_members.open()):
        kind={'1.3.6.1.4.1.311.2.1.15':'pe','1.3.6.1.4.1.311.2.1.25':'flat'}.get(row.get('subject_oid'));algorithm={'1.3.14.3.2.26':'sha1','2.16.840.1.101.3.4.2.1':'sha256'}.get(row.get('algorithm_oid'))
        if kind and algorithm and row.get('signature_hash_verified'):catalogs[(kind,algorithm)].setdefault(row['digest'],dict(catalog_record=row['catalog_record'],catalog_sha256=row['catalog_sha256'],reference=row.get('reference')))
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames={};contents={};sequence=[]
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=? ORDER BY source_offset,id',(ctx.stride,)):
            sha=f[6];sequence.append(sha);frames.setdefault(sha,f)
            if sha not in contents:
                corpus.seek(f[3]);data=corpus.read(ctx.stride)
                if hashlib.sha256(data).hexdigest()!=sha:raise ValueError('corpus differs')
                contents[sha]=data
    ordered=list(contents);reports=[];count=0;exported_bytes=0
    with (a.output/'sequence-evidence.jsonl').open('x') as log:
        for row in map(json.loads,a.inventory.open()):
            if a.only_record is not None and row['record']!=a.only_record:continue
            try:
                record=ctx.fs.mft.get(row['record']);size=record.size()
                if not 32768<size<=a.maximum_file_size:continue
                bases=sorted({base for lo,hi,base in ctx.holes(record)})
                if not 2<=len(bases)<=a.maximum_missing:continue
                extents=file_extents(record,size);pieces={base:frame_pieces(extents,base,ctx.stride) for base in bases};bases.sort(key=lambda b:pieces[b][0][1]);template=record.open().read();mask=bytearray(b'\1'*size)
                if len(template)!=size:raise ValueError('short file')
                for base in bases:
                    for off,logical,n in pieces[base]:mask[logical:logical+n]=bytes(n)
                known=bytes(b for b,m in zip(template,mask) if m)
                if len(known)<4096 or len(set(known))<32 or len({known[i:i+32] for i in range(0,len(known)-31,32)})<64:continue
                kind='pe' if template[:2]==b'MZ' and all(mask[:min(4096,size)]) else 'flat';regions=pe_hash_regions(template) if kind=='pe' else [(0,size)];hashers={alg:projected_multi_hash(template,regions,bases,pieces,alg) for alg in ('sha1','sha256') if catalogs.get((kind,alg))};seen=set();found=set();report=dict(record=row['record'],path=row.get('path'),missing_frames=len(bases),file_bytes=size,known_file_bytes=len(known),checked=0,candidates=0)
                for seq in (sequence,ordered):
                    for k in range(len(seq)-len(bases)+1):
                        assignment=tuple(seq[k:k+len(bases)])
                        if assignment in seen:continue
                        if report['checked']>=a.per_file_budget:break
                        seen.add(assignment);report['checked']+=1
                        for alg,calculate in hashers.items():
                            digest=calculate(assignment,contents);proof=catalogs[(kind,alg)].get(digest)
                            if proof is None:continue
                            data=reconstruct(template,bases,pieces,assignment,contents);sha=hashlib.sha256(data).hexdigest()
                            if sha in found:break
                            if catalog_digest(data,alg,kind)!=digest:raise ValueError('projected catalog digest differs')
                            provenance=[]
                            for base,s in zip(bases,assignment):
                                f=frames[s];decoded=ctx.decode(f[1],f[2])
                                if decoded!=contents[s] or hashlib.md5(decoded).digest()!=f[5]:raise ValueError('original source revalidation failed')
                                provenance.append(dict(candidate_disk_offset=ctx.origin+base,frame=f[0],source_offset=f[1],stored_length=f[2],decoded_sha256=s,file_pieces=pieces[base]))
                            target=external/f"record-{row['record']}-{sha}.candidate.bin"
                            with target.open('xb') as out:out.write(data)
                            metadata=dict(schema_version=1,kind='catalog-sequence-candidate',bytes=len(data),sha256=sha,placement_status='candidate-historical-version-unbound',vhdx_insertion_authorized=False,possible_locations=[dict(record=row['record'],path=row.get('path'),file_extents=extents)],catalog_validation=dict(algorithm=alg,digest=digest,hash_kind=kind,**proof),historical_component_version_binding=False,source_order_only_nominated=True,bounded_search=True,provenance=provenance,note='Catalog membership validates the assembled content; this bounded combination search does not establish the unique historical version or authorize filesystem insertion.')
                            target.with_suffix(target.suffix+'.json').write_text(json.dumps(metadata,indent=2));found.add(sha);count+=1;exported_bytes+=len(data);report['candidates']+=1;break
                report['budget_reached']=report['checked']>=a.per_file_budget;reports.append(report);log.write(json.dumps(report)+'\n');log.flush();print(json.dumps(report),flush=True)
            except Exception as e:
                _audit_caught(e, locals(), expected=False, site='recover_catalog_sequences.py:95')
                report=dict(record=row['record'],error=str(e));reports.append(report);log.write(json.dumps(report)+'\n');log.flush()
    ctx.close();db.close()
    for name in ('accepted-mappings.json','recovery-plan.json'):(a.output/name).write_bytes((a.mapping_directory/name).read_bytes())
    summary=dict(accepted_destinations=len(ctx.maps),accepted_bytes=sum(m['length'] for m in ctx.maps),new_placements=0,targets=len(reports),external_candidates=count,external_candidate_bytes=exported_bytes,per_file_budget=a.per_file_budget,maximum_missing=a.maximum_missing,scope='Only source-ordered candidate windows were tested; all matching reconstructions remain outside VHDX with candidate metadata. No exhaustive uniqueness claim.')
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
