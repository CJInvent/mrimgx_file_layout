"""Reconstruct missing indexed frames from real source parts, requiring exact original MD5.

Native hash reuse, file names/sizes and ZIP member identities only nominate
source bytes. Acceptance always requires the complete original target index MD5.
No donor file, archive metadata or cached reconstruction authorizes placement.
"""
import argparse,collections,hashlib,json,mmap,pathlib,sqlite3,struct,time,zipfile
from rebuild_context import Context
from discover_duplicate_pairs import candidate_records
from recover_duplicate_files import file_extents,frame_pieces
from recover_file_hashes import full_frame_covered
from indexed_donor_reconstruction import OriginalIndex,SourceParts
from placement_payload import assemble_source_parts
from rebuild_audit import caught,emit

ARCHIVES={'.zip','.docx','.xlsx','.pptx','.docm','.xlsm','.pptm','.jar','.vsix','.nupkg','.appx','.msix'}


def archive_members(ctx,record):
    size=record.size();holes=ctx.holes(record);stream=record.open();start=max(0,size-65557);stream.seek(start);tail=stream.read(size-start);end=tail.rfind(b'PK\x05\x06')
    if end<0 or end+22>len(tail):raise ValueError('archive end record unavailable')
    sig,disk,cd_disk,nd,n,cd_size,cd_off,comment=struct.unpack_from('<4s4H2IH',tail,end);eof=start+end
    if disk or cd_disk or nd!=n or n==65535 or cd_size>128*1024**2 or eof+22+comment!=size or cd_off+cd_size!=eof:raise ValueError('unsupported/invalid archive directory bounds')
    if any(lo<size and hi>cd_off for lo,hi,base in holes):raise ValueError('original archive directory intersects missing bytes')
    result=[]
    with zipfile.ZipFile(stream) as archive:
        if len(archive.infolist())!=n:raise ValueError('original archive directory member count differs')
        for info in archive.infolist():
            if info.flag_bits&1 or info.header_offset<0:continue
            stream.seek(info.header_offset);header=stream.read(30)
            if len(header)!=30 or header[:4]!=b'PK\x03\x04' or any(lo<info.header_offset+30 and hi>info.header_offset for lo,hi,base in holes):continue
            names,extra=struct.unpack_from('<HH',header,26);lo=info.header_offset+30+names+extra;hi=lo+info.compress_size
            if hi>cd_off:continue
            result.append(dict(key=(info.filename,info.CRC,info.file_size,info.compress_size,info.compress_type),start=lo,stop=hi,record=record.segment))
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--known-reconstructions',type=pathlib.Path);ap.add_argument('--per-file-budget',type=int,default=300000)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);cache=a.output/'reconstructed-frames';cache.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);index=OriginalIndex(a.source,a.evidence);db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);known=json.loads(a.known_reconstructions.read_text()) if a.known_reconstructions else [];resolver=SourceParts(ctx,index,known);known_offsets={m['disk_offset'] for m in known};counts=collections.Counter();reports=[];solutions={};targets={};last=time.monotonic()
    for block,address,length,digest in db.execute('SELECT block,disk_offset,decoded_length,digest FROM entries WHERE partition=2 AND reserved=0 AND incorporated=0 AND digest!=zeroblob(16)'):
        base=address-ctx.origin
        if address in known_offsets or base in ctx.mapped or length!=ctx.stride or not any(lo<=base and base+length<=hi for lo,hi in ctx.ranges):continue
        original=index.entry(block)
        if original['expected_md5']!=digest.hex():raise ValueError('cached target digest differs from original source index')
        targets[base]=dict(block=block,disk_offset=address,length=length,original=original)
    def attempt(base,parts,nomination):
        data=assemble_source_parts(index.stream,parts,ctx.stride);target=targets[base]
        if hashlib.md5(data).hexdigest()!=target['original']['expected_md5']:counts['candidate_md5_nonmatches']+=1;return False
        sha=hashlib.sha256(data).hexdigest()
        if base in solutions and solutions[base]['sha256']!=sha:raise ValueError('different source reconstructions share an original target MD5')
        mapping=dict(partition=2,reserved=False,block=target['block'],disk_offset=target['disk_offset'],length=ctx.stride,source_offset=parts[0]['source_offset'],stored_length=parts[0]['stored_length'],source_encoding='original-index-md5-source-parts',decoded_md5=target['original']['expected_md5'],sha256=sha,source_parts=parts,evidence=[dict(method='original-index-md5-source-parts-reconstruction',original_index=target['original'],nomination=nomination)])
        index.validate(mapping);solutions.setdefault(base,mapping);path=cache/(str(mapping['disk_offset'])+'-'+sha+'.bin')
        if not path.exists():path.write_bytes(data);path.with_suffix('.bin.json').write_text(json.dumps(mapping,indent=2))
        counts['matching_reconstructions']+=1;return True
    # Existing verified source frames are eligible even when they were consumed
    # by the baseline and therefore never appeared in the orphan-only corpus.
    by_digest=collections.defaultdict(list)
    for base,target in targets.items():by_digest[target['original']['expected_md5']].append(base)
    for digest,bases in by_digest.items():
        for block,position,stored,decoded in db.execute('SELECT block,source_offset,stored_length,decoded_length FROM entries WHERE partition=2 AND reserved=0 AND incorporated=1 AND digest=?',(bytes.fromhex(digest),)):
            if decoded!=ctx.stride:continue
            try:
                parts=resolver.physical(block*ctx.stride,ctx.stride,0)
                for base in bases:attempt(base,parts,dict(kind='verified-native-index-hash-reuse',donor_block=block))
            except Exception as error:caught(error,dict(donor_block=block),expected=True,site='indexed-native-donor-probe')
    owners=collections.defaultdict(list);wanted_records={}
    with a.inventory.open() as stream:
        for row in map(json.loads,stream):
            number=row['record']
            try:
                record=ctx.fs.mft.get(number)
                if record.header.Flags&2 or record.size()<ctx.stride:continue
                extents=file_extents(record,record.size());bases={base for lo,hi,base in ctx.holes(record)}&targets.keys()
                for base in bases:
                    if base in solutions:continue
                    pieces=frame_pieces(extents,base,ctx.stride)
                    if full_frame_covered(pieces,ctx.stride):owners[number].append((base,pieces));wanted_records[number]=record
            except Exception as error:caught(error,dict(record=number),expected=True,site='indexed-target-file-probe')
    by_name=collections.defaultdict(set);by_size=collections.defaultdict(set);archive_records=set();metadata={}
    with a.mft.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
        for number,names,size in candidate_records(raw):
            if size<ctx.stride:continue
            metadata[number]=(names,size);by_size[size].add(number)
            for name in names:by_name[name.casefold()].add(number)
            if any(pathlib.PureWindowsPath(name).suffix.casefold() in ARCHIVES for name in names):archive_records.add(number)
    for number,record in wanted_records.items():
        metadata[number]=(record.filenames(ignore_dos=True),record.size())
        for name in metadata[number][0]:by_name[name.casefold()].add(number)
        by_size[record.size()].add(number)
    donor_extents={};attempted=set();budgets=collections.Counter()
    def try_file(number,donor,shift,kind,items):
        try:
            rec=ctx.fs.mft.get(donor)
            if donor not in donor_extents:donor_extents[donor]=file_extents(rec,rec.size())
        except Exception as error:caught(error,dict(donor_record=donor),expected=True,site='indexed-donor-extents-probe');counts['donor_probes_rejected']+=1;return
        for base,pieces in items:
            key=(number,donor,shift,base)
            if key in attempted or base in solutions:continue
            attempted.add(key)
            if budgets[number]>=a.per_file_budget:counts['per_file_budget_reached']+=1;return
            try:
                if any(logical+shift<0 or logical+shift+n>rec.size() for off,logical,n in pieces):continue
                budgets[number]+=1;parts=[]
                for off,logical,n in pieces:parts.extend(resolver.file(donor_extents[donor],logical+shift,n,off))
                attempt(base,parts,dict(kind=kind,target_record=number,donor_record=donor,logical_shift=shift))
            except Exception as error:caught(error,dict(target_record=number,donor_record=donor,logical_shift=shift),expected=True,site='indexed-file-donor-probe');counts['donor_probes_rejected']+=1
    for number,items in owners.items():
        record=wanted_records[number];names=record.filenames(ignore_dos=True);donors=set(by_size[record.size()])
        for name in names:donors.update(by_name[name.casefold()])
        for donor in sorted(donors-{number}):try_file(number,donor,0,'file-name-or-size-nomination-original-index-md5-required',items)
        if time.monotonic()-last>10:print(json.dumps(dict(phase='file-donors',targets=len(targets),reconstructed=len(solutions),candidate_attempts=sum(budgets.values()))),flush=True);last=time.monotonic()
    wanted_members=collections.defaultdict(list)
    for number,items in owners.items():
        if all(base in solutions for base,pieces in items):continue
        if not any(pathlib.PureWindowsPath(n).suffix.casefold() in ARCHIVES for n in metadata[number][0]):continue
        try:
            for member in archive_members(ctx,wanted_records[number]):
                for base,pieces in items:
                    if base not in solutions and all(member['start']<=logical and logical+n<=member['stop'] for off,logical,n in pieces):wanted_members[member['key']].append((number,base,pieces,member['start']))
        except Exception as error:caught(error,dict(record=number),expected=True,site='indexed-target-archive-probe')
    if wanted_members:
        for donor in sorted(archive_records):
            try:
                record=ctx.fs.mft.get(donor)
                for member in archive_members(ctx,record):
                    for number,base,pieces,start in wanted_members.get(member['key'],[]):
                        if donor==number or base in solutions:continue
                        try_file(number,donor,member['start']-start,'zip-member-metadata-nomination-original-index-md5-required',[(base,pieces)])
            except Exception as error:caught(error,dict(record=donor),expected=True,site='indexed-donor-archive-probe')
            if all(base in solutions for items in wanted_members.values() for number,base,pieces,start in items):break
    requests=list(solutions.values());(a.output/'supplemental-placements.json').write_text(json.dumps(requests,indent=2))
    for name in ('accepted-mappings.json','recovery-plan.json'):(a.output/name).write_bytes((a.mapping_directory/name).read_bytes())
    if counts['per_file_budget_reached']:emit('search-limit','Indexed donor reconstruction per-file budget reached',severity='warning',context=dict(counts))
    summary=dict(accepted_destinations=len(ctx.maps),accepted_bytes=sum(m['length'] for m in ctx.maps),new_placements=0,reconstructed_indexed_frames=len(requests),reconstructed_bytes=sum(m['length'] for m in requests),original_nonzero_hash_targets=len(targets),target_files=len(owners),candidate_attempts=sum(budgets.values()),counts=counts,scope='Only complete payloads matching their exact original index MD5 are reconstructed. Every byte comes from independently revalidated original encoded source frames. No filename, archive CRC, source order or cached reconstructed file authorizes a write.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);ctx.close();index.close();db.close()


if __name__=='__main__':main()
