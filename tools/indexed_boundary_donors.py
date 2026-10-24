"""Joint file-tail donors with source-backed zero padding, original MD5 required."""
import collections,hashlib,itertools
from recover_duplicate_files import file_extents
from placement_payload import assemble_source_parts
from rebuild_audit import caught,emit


def padded_parts(parts,zero,size):
    result=[];cursor=0
    for part in sorted(parts,key=lambda p:p['target_offset']):
        start=part['target_offset'];stop=start+part['length']
        if start<cursor or not cursor<=start<stop<=size:raise ValueError('joint boundary donors overlap or exceed frame')
        if start>cursor:result.append(dict(zero,target_offset=cursor,decoded_offset=cursor,length=start-cursor))
        result.append(part);cursor=stop
    if cursor<size:result.append(dict(zero,target_offset=cursor,decoded_offset=cursor,length=size-cursor))
    return result


def search(ctx,index,resolver,db,targets,solutions,owners,metadata,by_name,by_size,budget,attempt,counts):
    zero_digest=hashlib.md5(bytes(ctx.stride)).digest();row=db.execute('SELECT block FROM entries WHERE partition=2 AND incorporated=1 AND digest=? AND decoded_length=? LIMIT 1',(zero_digest,ctx.stride)).fetchone()
    if row is None:return
    zero_parts=resolver.physical(row[0]*ctx.stride,ctx.stride,0)
    if len(zero_parts)!=1 or assemble_source_parts(index.stream,zero_parts,ctx.stride)!=bytes(ctx.stride):raise ValueError('source-backed zero padding does not match original zero frame')
    zero=zero_parts[0];extents={}
    for base,items in owners.items():
        if base in solutions:continue
        groups=[];used=0;limited=False
        for number,pieces in items:
            names,size=metadata[number];donors=set(by_size.get(size,set()))
            for name in names:donors.update(by_name.get(name.casefold(),set()))
            choices={}
            for donor in sorted(donors-{number}):
                if used>=budget:limited=True;break
                used+=1
                try:
                    record=ctx.fs.mft.get(donor)
                    if donor not in extents:extents[donor]=file_extents(record,record.size())
                    parts=[]
                    for offset,logical,length in pieces:parts.extend(resolver.file(extents[donor],logical,length,offset))
                    padded=padded_parts(parts,zero,ctx.stride);body=assemble_source_parts(index.stream,padded,ctx.stride);digest=hashlib.sha256(body).hexdigest()
                    choices.setdefault(digest,(parts,dict(target_record=number,donor_record=donor)))
                except Exception as error:caught(error,dict(target_record=number,donor_record=donor),expected=True,site='indexed-boundary-donor-probe')
            groups.append(list(choices.values()))
            if limited or not choices:break
        if len(groups)==len(items) and all(groups):
            for selection in itertools.product(*groups):
                if used>=budget:limited=True;break
                used+=1
                try:parts=padded_parts([part for contribution,nomination in selection for part in contribution],zero,ctx.stride)
                except ValueError:counts['boundary_overlapping_owner_nominations']+=1;continue
                if attempt(base,parts,dict(kind='joint-file-boundaries-and-source-backed-zero-padding-original-index-md5-required',owners=[nomination for contribution,nomination in selection],padding_source_block=row[0])):break
        counts['boundary_candidate_attempts']+=used
        if limited:emit('search-limit','Joint boundary donor per-frame budget reached',severity='warning',context=dict(block=targets[base]['block'],candidate_attempts=used,budget=budget))
