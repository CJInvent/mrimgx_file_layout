"""Locate missing NTFS frames against independently surviving whole-file hashes.

Candidate source order only nominates reconstructions. Acceptance requires the
original expected file hash, original MFT extents and a unique whole-frame SHA
at each address among all tested successful reconstructions. No donor bytes are
written. Inputs, baseline and original evidence stay read-only.
"""
import argparse,bisect,collections,functools,hashlib,itertools,json,pathlib,sqlite3
import zstandard
from safe_vhdx import VHDX
from mapped_volume import MappedVolume
from dissect.ntfs import NTFS
from recover_duplicate_files import file_extents,frame_pieces


def distinctive_hash_bound(data):
    """Substantial varied bytes, bound by an independent whole-file digest."""
    return len(data)>=16384 and len(set(data))>=32 and len({bytes(data[i:i+32]) for i in range(0,len(data)-31,32)})>=256


def reconstruct(template,bases,pieces,assignment,contents):
    data=bytearray(template)
    for base,sha in zip(bases,assignment):
        for offset,logical,length in pieces[base]:data[logical:logical+length]=contents[sha][offset:offset+length]
    return data


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','targets','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-file-size',type=int,default=64*1024**2)
    ap.add_argument('--per-file-budget',type=int,default=200000)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][2];origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2};ranges=[]
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    source=a.source.open('rb')
    @functools.lru_cache(maxsize=64)
    def decode(offset,length):source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    view=MappedVolume(VHDX(a.baseline),origin,p['_geometry']['length'],mapped,decode);fs=NTFS(view);fs.mft.fh=a.mft.open('rb')
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);contents={};sequence=[]
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=? ORDER BY source_offset',(stride,)):
            frames[f[6]].append(f);sequence.append(f[6])
            if f[6] not in contents:
                corpus.seek(f[3]);data=corpus.read(stride)
                if hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('corpus mismatch')
                contents[f[6]]=data
    ordered=list(dict.fromkeys(sequence));index_sources=dict(db.execute('SELECT block,source_offset FROM entries WHERE partition=2 AND reserved=0 AND incorporated=1 AND stored_length>0'))
    for base,m in mapped.items():index_sources[base//stride]=m['source_offset']
    index_blocks=sorted(index_sources);source_positions=[frames[sha][0][1] for sha in ordered];pending=collections.defaultdict(list);reports=[]
    for target in json.loads(a.targets.read_text()):
        report=dict(target=target,checked=0);reports.append(report)
        try:
            record=fs.mft.get(target['record']);size=record.size()
            if size!=target['size'] or not 0<size<=a.maximum_file_size:raise ValueError('target size differs or exceeds bound')
            algorithm=target['algorithm'];expected=bytes.fromhex(target['digest']);hashlib.new(algorithm)
            extents=file_extents(record,size);bases=sorted({base for logical,physical,length in extents for base in range(physical//stride*stride,physical+length,stride) if unknown(base)})
            if not bases:report['skipped']='no unknown frames';continue
            pieces={base:frame_pieces(extents,base,stride) for base in bases};bases.sort(key=lambda base:pieces[base][0][1]);template=record.open().read();solutions=[];seen=set()
            if len(template)!=size:raise ValueError('short target read')
            def check(assignment):
                if assignment in seen or report['checked']>=a.per_file_budget:return
                seen.add(assignment);report['checked']+=1
                data=reconstruct(template,bases,pieces,assignment,contents)
                if hashlib.new(algorithm,data).digest()==expected:solutions.append(assignment)
            if len(bases)==1:
                for sha in ordered:check((sha,))
            else:
                # Both full source sequence and first-occurrence sequence are
                # merely candidate generators; neither implies disk adjacency.
                for seq in (sequence,ordered):
                    for k in range(len(seq)-len(bases)+1):check(tuple(seq[k:k+len(bases)]))
                if len(bases)<=5:
                    positions=[]
                    for base in bases:
                        k=bisect.bisect_left(index_blocks,base//stride)
                        positions.extend(index_sources[index_blocks[i]] for i in range(max(0,k-1),min(len(index_blocks),k+1)))
                    if positions:
                        left=bisect.bisect_left(source_positions,min(positions));right=bisect.bisect_right(source_positions,max(positions))
                        for pad in (0,2,4,8):
                            pool=ordered[max(0,left-pad):right+pad]
                            import math
                            if len(pool)>=len(bases) and math.perm(len(pool),len(bases))<=a.per_file_budget-report['checked']:
                                for assignment in itertools.permutations(pool,len(bases)):check(assignment)
            report.update(missing_frames=len(bases),solutions=len(solutions))
            if solutions:
                for i,base in enumerate(bases):
                    matches={solution[i] for solution in solutions}
                    if len(matches)!=1:continue
                    sha=matches.pop();parts=b''.join(contents[sha][off:off+n] for off,logical,n in pieces[base])
                    # The file hash excludes bytes outside this file. Check
                    # every corpus frame for alternatives identical inside
                    # the file, even if our sequence search did not try them.
                    alternatives=[s for s,data in contents.items() if all(data[off:off+n]==contents[sha][off:off+n] for off,logical,n in pieces[base])]
                    if len(alternatives)!=1:
                        report.setdefault('ambiguous_full_frame_boundaries',[]).append(dict(base=base,candidates=len(alternatives)));continue
                    if not distinctive_hash_bound(parts):
                        report.setdefault('rejected_small_or_repetitive_boundaries',[]).append(base);continue
                    evidence=dict(method='original-whole-file-hash-completion',record=target['record'],file_size=size,algorithm=algorithm,expected_digest=expected.hex(),hash_source=target.get('hash_source'),all_tested_solutions=len(solutions),source_order_only_nominated=True,validated_file_bytes_in_frame=len(parts))
                    pending[base].append((sha,evidence))
        except Exception as e:report['error']=repr(e)
        print(json.dumps(report),flush=True)
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({sha for sha,evidence in items})!=1:conflicts.append(base);continue
        sha=items[0][0];f=frames[sha][0];data=decode(f[1],f[2])
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=sha or hashlib.md5(data).digest()!=f[5]:raise ValueError('source mismatch')
        accepted.append(dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=sha,frames=[x[0] for x in frames[sha]],evidence=[e for s,e in items]))
        plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Original whole-file digest plus MFT runlist validates missing source frame; source order only nominated candidates.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'file-hash-evidence.json').write_text(json.dumps(reports,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),new_placements=len(accepted)-previous,targets=len(reports),conflicts=conflicts);(a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
