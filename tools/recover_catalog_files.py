"""Complete one-frame NTFS holes against surviving signed catalog member hashes.

Requires at least 4 KiB of distinctive surviving file bytes, original runlists,
and one unique full-frame result. Catalog membership validates content, not
certificate trust or the complete historical component-version relationship.
"""
import argparse,collections,hashlib,json,pathlib,sqlite3
from rebuild_context import Context
from recover_duplicate_files import file_extents,frame_pieces
from recover_file_hashes import reconstruct,distinctive_hash_bound


def pe_hash_regions(data):
    import pefile
    pe=pefile.PE(data=data,fast_load=True);cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];end=len(data)
    if cert.Size:
        if cert.VirtualAddress+cert.Size!=end:raise ValueError('PE certificate overlay unsupported')
        end=cert.VirtualAddress
    section_end=pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in sorted(pe.sections,key=lambda s:s.PointerToRawData):
        if not section.SizeOfRawData:continue
        if section.PointerToRawData!=section_end:raise ValueError('noncontiguous PE layout')
        section_end+=section.SizeOfRawData
    checksum=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum');security=cert.get_file_offset()
    if not checksum+4<=security or security+8>section_end or section_end>end:raise ValueError('PE hash bounds')
    return [(0,checksum),(checksum+4,security),(security+8,end)]


def catalog_digest(data,algorithm,kind):
    h=hashlib.new(algorithm)
    for lo,hi in pe_hash_regions(data) if kind=='pe' else [(0,len(data))]:h.update(data[lo:hi])
    return h.hexdigest()


def projected_hash(template,regions,patches,algorithm):
    """Cache fixed hash prefixes; stream candidate pieces without full copies."""
    state=hashlib.new(algorithm);steps=[];variable=False
    for lo,hi in regions:
        cursor=lo
        for offset,logical,length in sorted(patches,key=lambda x:x[1]):
            start=max(lo,logical);stop=min(hi,logical+length)
            if stop<=start:continue
            known=template[cursor:start]
            if variable:
                if known:steps.append((False,known))
            else:state.update(known)
            steps.append((True,(offset+start-logical,stop-start)));variable=True;cursor=stop
        known=template[cursor:hi]
        if variable:
            if known:steps.append((False,known))
        else:state.update(known)
    def digest(candidate):
        h=state.copy()
        for ispatch,value in steps:
            if ispatch:off,n=value;h.update(candidate[off:off+n])
            else:h.update(value)
        return h.hexdigest()
    return digest


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','catalog_members','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-file-size',type=int,default=4*1024**2);a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);accepted=ctx.maps[:];previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());catalogs=collections.defaultdict(dict);algorithms={'1.3.14.3.2.26':'sha1','2.16.840.1.101.3.4.2.1':'sha256'}
    for row in map(json.loads,a.catalog_members.open()):
        kind={'1.3.6.1.4.1.311.2.1.15':'pe','1.3.6.1.4.1.311.2.1.25':'flat'}.get(row.get('subject_oid'));algorithm=algorithms.get(row.get('algorithm_oid'))
        if not kind or not algorithm or not row.get('signature_hash_verified'):continue
        catalogs[(kind,algorithm)].setdefault(row['digest'],dict(catalog_record=row['catalog_record'],catalog_sha256=row['catalog_sha256'],reference=row.get('reference')))
    print(json.dumps(dict(catalog_hashes={str(k):len(v) for k,v in catalogs.items()})),flush=True)
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);contents={}
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(ctx.stride,)):
            frames[f[6]].append(f)
            if f[6] not in contents:
                corpus.seek(f[3]);data=corpus.read(ctx.stride)
                if hashlib.sha256(data).hexdigest()!=f[6]:raise ValueError('corpus mismatch')
                contents[f[6]]=data
    pending=collections.defaultdict(list);reports=[]
    for row in map(json.loads,a.inventory.open()):
        try:
            record=ctx.fs.mft.get(row['record']);size=record.size()
            if not 32768<size<=a.maximum_file_size:continue
            holes=ctx.holes(record);bases=sorted({base for lo,hi,base in holes})
            if len(bases)!=1:continue
            base=bases[0];extents=file_extents(record,size);pieces={base:frame_pieces(extents,base,ctx.stride)};template=record.open().read();mask=bytearray(b'\x01'*size)
            for off,logical,n in pieces[base]:mask[logical:logical+n]=bytes(n)
            known=bytes(b for b,m in zip(template,mask) if m)
            if len(known)<4096 or len(set(known))<32 or len({known[i:i+32] for i in range(0,len(known)-31,32)})<64:continue
            # Header must survive before deriving PE byte-exclusion ranges.
            ispe=template[:2]==b'MZ' and all(mask[:min(4096,size)]);kind='pe' if ispe else 'flat';regions=pe_hash_regions(template) if ispe else [(0,size)];solutions=[]
            hashers={algorithm:projected_hash(template,regions,pieces[base],algorithm) for algorithm in ('sha1','sha256') if catalogs.get((kind,algorithm))}
            for sha,data in contents.items():
                for algorithm,calculate in hashers.items():
                    members=catalogs.get((kind,algorithm))
                    if not members:continue
                    expected=calculate(data)
                    if expected in members:solutions.append((sha,algorithm,expected,members[expected]));break
            report=dict(record=row['record'],path=row.get('path'),size=size,base=base,known_file_bytes=len(known),kind=kind,solutions=len(solutions));reports.append(report)
            if len({sha for sha,alg,digest,proof in solutions})==1 and solutions:
                sha,algorithm,expected,proof=solutions[0];parts=b''.join(contents[sha][off:off+n] for off,logical,n in pieces[base])
                alternatives=[s for s,data in contents.items() if all(data[off:off+n]==contents[sha][off:off+n] for off,logical,n in pieces[base])]
                if not distinctive_hash_bound(parts) or len(alternatives)!=1:report['rejected']='insufficient distinctive bytes or ambiguous full-frame boundary'
                else:pending[base].append((sha,dict(method='signed-catalog-file-completion',record=row['record'],file_size=size,hash_kind=kind,algorithm=algorithm,expected_digest=expected,catalog=proof,known_file_bytes=len(known),signature_hash_verified=True,historical_component_version_binding=False)))
            print(json.dumps(report),flush=True)
        except Exception:continue
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({sha for sha,e in items})!=1:conflicts.append(base);continue
        sha=items[0][0];f=frames[sha][0];data=ctx.decode(f[1],f[2])
        if len(data)!=ctx.stride or hashlib.sha256(data).hexdigest()!=sha or hashlib.md5(data).digest()!=f[5]:raise ValueError('source mismatch')
        accepted.append(dict(partition=2,reserved=False,block=base//ctx.stride,disk_offset=ctx.origin+base,length=ctx.stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=sha,frames=[x[0] for x in frames[sha]],evidence=[e for s,e in items]));plan['partitions'][2].setdefault('overrides',{})[str(base//ctx.stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Surviving original file bytes/runlist and unique signed-catalog content digest completion. Historical component-version binding is inferred, original index digest unavailable.')
    for name,value in (('accepted-mappings.json',accepted),('recovery-plan.json',plan),('catalog-completion-evidence.json',reports)):(a.output/name).write_text(json.dumps(value,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),new_placements=len(accepted)-previous,targets=len(reports),conflicts=conflicts);(a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
