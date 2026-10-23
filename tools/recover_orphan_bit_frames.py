"""Try every encoded bit of undecodable orphan frames against original hashes.

Source pointers in damaged index entries are not trusted to identify these
orphans. Matching complete original target MD5s authorize only their original
indexed addresses, with fresh source/index revalidation before placement.
"""
import argparse,bisect,collections,hashlib,json,pathlib,re,sqlite3,subprocess,sys
import zstandard
from indexed_donor_reconstruction import OriginalIndex
from rebuild_audit import emit


def encoded_frame_length(raw):
    params=zstandard.get_frame_parameters(raw);cursor=zstandard.frame_header_size(raw);last=False
    while not last:
        if cursor+3>len(raw):raise ValueError('truncated Zstd block header')
        header=int.from_bytes(raw[cursor:cursor+3],'little');cursor+=3;last=bool(header&1);kind=(header>>1)&3;n=header>>3
        if kind==3:raise ValueError('reserved Zstd block type')
        if n>128*1024:raise ValueError('Zstd block size bounds')
        cursor+=1 if kind==1 else n
        if cursor>len(raw):raise ValueError('Zstd block exceeds residual range')
    cursor+=4 if params.has_checksum else 0
    if cursor>len(raw):raise ValueError('truncated Zstd checksum')
    return cursor,params.content_size


def near_magic_candidates(evidence,db):
    magic=bytes.fromhex('28b52ffd');variants={bytes(b^(1<<bit) if i==byte else b for i,b in enumerate(magic)):(byte,bit) for byte in range(4) for bit in range(8)};pattern=re.compile(b'|'.join(re.escape(v) for v in variants));known=sorted((p,p+n) for p,n in db.execute('SELECT source_offset,stored_length FROM frames'));starts=[lo for lo,hi in known]
    with (evidence/'source-residual.bin').open('rb') as stream,(evidence/'source-residual-map.jsonl').open() as regions:
        for region in map(json.loads,regions):
            stream.seek(region['export_offset']);data=stream.read(region['length'])
            if len(data)!=region['length']:raise ValueError('Short residual evidence while scanning damaged magic')
            for match in pattern.finditer(data):
                position=region['source_offset']+match.start();k=bisect.bisect_right(starts,position)-1
                if k>=0 and position<known[k][1]:continue
                byte,bit=variants[match.group()]
                yield dict(source_offset=position,remaining_range_bytes=len(data)-match.start(),magic_bit_repair=dict(byte_offset=byte,bit=bit),error='One-bit damaged Zstd magic outside all decoded frames')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','evidence','mapping_directory','repair_exe','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--residual-audit',type=pathlib.Path);ap.add_argument('--known-reconstructions',type=pathlib.Path);a=ap.parse_args();a.output.mkdir(exist_ok=False)
    if not a.residual_audit:
        a.residual_audit=a.output/'residual-audit';subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('inspect_residual_failures.py')),str(a.evidence),str(a.residual_audit)],check=True)
    audit=json.loads((a.residual_audit/'summary.json').read_text());index=OriginalIndex(a.source,a.evidence);db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);maps=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());placed={m['disk_offset'] for m in maps}
    if a.known_reconstructions:placed.update(m['disk_offset'] for m in json.loads(a.known_reconstructions.read_text()))
    by_size=collections.defaultdict(lambda:collections.defaultdict(list));requests=[];reports=[];targets=[]
    try:
        for block,address,n,digest in db.execute('SELECT block,disk_offset,decoded_length,digest FROM entries WHERE partition=2 AND reserved=0 AND incorporated=0 AND digest!=zeroblob(16)'):
            if address in placed or not 0<n<=4*1024**2:continue
            entry=index.entry(block)
            if digest.hex()!=entry['expected_md5']:raise ValueError('Orphan repair cached original index digest differs')
            p=index.layout['disks'][0]['partitions'][2]
            if n!=p['_header']['block_size'] or address!=p['_geometry']['start']+block*n:continue
            row=dict(block=block,disk_offset=address,length=n,md5=digest.hex(),original_index=entry);by_size[n][digest.hex()].append(row);targets.append(row)
        (a.output/'targets.json').write_text(json.dumps(targets,indent=2));lists={}
        for size,items in by_size.items():
            path=a.output/(str(size)+'-digests.txt');path.write_text('\n'.join(sorted(items))+'\n');lists[size]=path
        candidates=audit['retried_candidates']+list(near_magic_candidates(a.evidence,db));seen=set()
        for ordinal,candidate in enumerate(candidates):
            if candidate.get('eof') or not (candidate.get('error') or candidate.get('header_error')):continue
            if candidate['source_offset'] in seen:continue
            seen.add(candidate['source_offset'])
            report=dict(candidate);reports.append(report);offset=candidate['source_offset'];index.stream.seek(offset);raw=index.stream.read(min(candidate['remaining_range_bytes'],5*1024**2))
            try:
                probe=bytearray(raw)
                if candidate.get('magic_bit_repair'):hint=candidate['magic_bit_repair'];probe[hint['byte_offset']]^=1<<hint['bit']
                n,size=encoded_frame_length(probe)
            except (ValueError,zstandard.ZstdError) as error:report['skipped']=str(error);emit('orphan-bit-search-boundary',str(error),severity='warning',context=report);continue
            if size not in lists:report['skipped']='no unplaced original indexed hashes of this decoded length';continue
            raw=raw[:n];original=a.output/(str(ordinal)+'-original.bin');original.write_bytes(raw);fixed=a.output/(str(ordinal)+'-repaired.bin');log=a.output/(str(ordinal)+'-native.json');progress=a.output/(str(ordinal)+'-progress.log')
            report.update(encoded_bytes=n,original_encoded_sha256=hashlib.sha256(raw).hexdigest(),target_digests=len(by_size[size]),target_list_sha256=hashlib.sha256(lists[size].read_bytes()).hexdigest())
            with log.open('x') as output,progress.open('x') as errors:code=subprocess.run([str(a.repair_exe),str(original),str(fixed),'@'+str(lists[size]),str(size)],stdout=output,stderr=errors).returncode
            if code not in (0,2):raise RuntimeError('Native orphan batch repair failed; see '+str(progress))
            native=json.loads(log.read_text());report.update(exit_code=code,native=native)
            if native.get('status')!='input-already-matches' and native.get('tested_bytes')!=n:raise ValueError('Native orphan search did not cover every encoded byte')
            if code==2:
                emit('orphan-bit-search-complete','No unique single-bit repair matches the surviving original hash set',context=report);continue
            encoded=fixed.read_bytes() if native['status']=='unique-original-md5-repair' else raw;decoded=zstandard.ZstdDecompressor().decompress(encoded,max_output_size=4*1024**2);digest=hashlib.md5(decoded).hexdigest();sha=hashlib.sha256(decoded).hexdigest()
            if len(decoded)!=size or digest not in by_size[size] or sum((x^y).bit_count() for x,y in zip(raw,encoded)) not in (0,1) or len(raw)!=len(encoded):raise ValueError('Native orphan repair source/original digest differs')
            repair=dict(encoded_path=str(fixed.resolve()),original_encoded_sha256=hashlib.sha256(raw).hexdigest(),repaired_encoded_sha256=hashlib.sha256(encoded).hexdigest()) if encoded!=raw else None
            part=dict(source_offset=offset,stored_length=n,decoded_length=size,decoded_md5=digest,decoded_sha256=sha,target_offset=0,decoded_offset=0,length=size)
            if repair:part['encoded_bit_repair']=repair
            for target in by_size[size][digest]:
                mapping=dict(partition=2,reserved=False,block=target['block'],disk_offset=target['disk_offset'],length=size,source_offset=offset,stored_length=n,source_encoding='original-index-md5-source-parts',decoded_md5=digest,sha256=sha,source_parts=[part],evidence=[dict(method='original-index-md5-source-parts-reconstruction',original_index=target['original_index'],nomination=dict(kind='undecodable-orphan-single-bit-original-hash-set',native_result=native))]);index.validate(mapping);requests.append(mapping)
            path=a.output/(str(ordinal)+'-decoded.bin');path.write_bytes(decoded);path.with_suffix('.bin.json').write_text(json.dumps(dict(kind='original-index-verified-orphan-repair',sha256=sha,requests=[m for m in requests if m['sha256']==sha],vhdx_written=False),indent=2));report['decoded_sha256']=sha
            (a.output/'reports.json').write_text(json.dumps(reports,indent=2))
        (a.output/'reports.json').write_text(json.dumps(reports,indent=2));(a.output/'supplemental-placements.json').write_text(json.dumps(requests,indent=2))
        for name in ('accepted-mappings.json','recovery-plan.json'):(a.output/name).write_bytes((a.mapping_directory/name).read_bytes())
        summary=dict(accepted_destinations=len(maps),new_placements=0,reconstructed_indexed_frames=len(requests),reconstructed_bytes=sum(m['length'] for m in requests),original_hash_targets=len(targets),orphan_candidates=len(reports),complete_native_bit_searches=sum('native' in r for r in reports),scope='Complete encoded single-bit tests of undecodable nonnested orphan frames against all surviving unplaced original Windows full-frame hashes. Unsupported boundaries and absent hashes are explicit; no multi-bit exhaustiveness claim.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
    finally:index.close();db.close()


if __name__=='__main__':main()
