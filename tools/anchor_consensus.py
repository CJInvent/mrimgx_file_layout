"""Resolve competing frame candidates by intersecting original file constraints.

Repeated icons or signed DLLs can nominate several enclosing frames. A vote or
source proximity cannot break that tie. A candidate must satisfy every bounded
constraint nominated at the same original NTFS address.
"""
import hashlib
import struct
from pe_anchors import image_digest,resource_culture_binding
from rebuild_audit import caught


def satisfies(data, constraint):
    offset=constraint['offset'];length=constraint['length']
    if offset<0 or length<=0 or offset+length>len(data):return False
    piece=data[offset:offset+length]
    if constraint['kind']=='chromium-key':
        if len(piece)<24 or piece[:8]!=bytes.fromhex('305c72a71b6dfbfc'):return False
        version,key_length=struct.unpack_from('<II',piece,8)
        if version!=5 or not 0<key_length<8192 or 24+key_length>len(piece):return False
        stem=f'{int.from_bytes(hashlib.sha1(piece[24:24+key_length]).digest()[:8],"little"):016x}'
        return stem==constraint['stem']
    if constraint['kind']=='sha256':return hashlib.sha256(piece).hexdigest()==constraint['digest']
    if constraint['kind']=='pe-image':
        try:
            actual=image_digest(piece)
            return actual['algorithm']==constraint['algorithm'] and actual['digest']==constraint['digest']
        except Exception as error:
            caught(error,None,expected=True,site='anchor-consensus-pe-candidate')
            return False
    raise ValueError('unknown anchor constraint')


def unique_consensus(candidates,constraints):
    """Return a unique content digest, never choose by anchor count or order."""
    if len({c['record'] for c in constraints})<2:return None
    matches={digest for digest,data in candidates.items() if all(satisfies(data,c) for c in constraints)}
    return next(iter(matches)) if len(matches)==1 else None


def constraints_for(items,fs,base,length):
    constraints=[];unsupported=[]
    for item in items:
        method=item['method']
        if method not in ('chromium-key-mft-runlist','appx-blockmap-sha256-mft-runlist','pe-identity-mft-runlist'):
            unsupported.append(method);continue
        for anchor in item['detail']['anchors']:
            try:
                number=anchor['record'];record=fs.mft.get(number)
                if not record.header.Flags&1 or record.is_dir():raise ValueError('inactive anchor record')
                if 'sequence' in anchor and record.header.SequenceNumber!=anchor['sequence']:raise ValueError('anchor record sequence changed')
                if any(a.header.flags&0x4001 for a in record.attributes.DATA if a.name==''):raise ValueError('compressed/encrypted anchor')
                runs=record.dataruns();size=record.size()
                if method=='chromium-key-mft-runlist':
                    if not runs or runs[0][0] is None:raise ValueError('missing first cluster')
                    offset=runs[0][0]*4096-base
                    # Only the first cluster is needed: keys may extend farther,
                    # in which case this constraint is unavailable, never guessed.
                    span=min(size,runs[0][1]*4096,length-offset)
                    if offset<0 or span<24 or record.filename.casefold()!=anchor['filename'].casefold():raise ValueError('cache anchor bounds/name')
                    constraints.append(dict(kind='chromium-key',record=number,offset=offset,length=span,stem=anchor['filename'][:16]))
                elif method=='appx-blockmap-sha256-mft-runlist':
                    if anchor.get('cross_frame'):raise ValueError('cross-frame hash not bounded to this candidate')
                    from recover_duplicate_files import file_extents
                    logical=anchor['logical_offset'];span=anchor['length'];offset=anchor['frame_offset']
                    projections=[physical+logical-start for start,physical,n in file_extents(record,size) if start<=logical and logical+span<=start+n]
                    if projections!=[base+offset] or offset<0 or offset+span>length:raise ValueError('Appx anchor runlist projection')
                    constraints.append(dict(kind='sha256',record=number,offset=offset,length=span,digest=anchor['digest']))
                else:
                    digest=anchor.get('image_digest');offset=anchor['page_offset']
                    if not digest or len(runs)!=1 or runs[0][0] is None or runs[0][0]*4096!=base+offset or size!=anchor['size'] or size>runs[0][1]*4096 or offset<0 or offset+size>length:raise ValueError('PE image is not wholly bounded to this candidate')
                    constraints.append(dict(kind='pe-image',record=number,offset=offset,length=size,algorithm=digest['algorithm'],digest=digest['digest']))
            except Exception as error:
                caught(error,dict(method=method,anchor=anchor),expected=True,site='anchor-consensus-unavailable-constraint')
                # Do not discard a contradictory/unreadable original anchor and
                # then claim the remaining subset resolved its conflict.
                unsupported.append(dict(method=method,record=anchor.get('record'),error=str(error)))
    unique={tuple(sorted(c.items())):c for c in constraints}
    return list(unique.values()),unsupported


def resolve(items,frames,read_frame,fs,base,length):
    original_items=items;items=[];rejected=[]
    for item in original_items:
        try:
            if item['method']=='pe-identity-mft-runlist':
                for anchor in item['detail']['anchors']:
                    record=fs.mft.get(anchor['record']);offset=anchor['page_offset'];size=anchor['size']
                    if anchor['filename'].casefold().endswith('.resources.dll') and 0<=offset<offset+size<=length:
                        data=read_frame(frames[item['frame']])
                        resource_culture_binding(data[offset:offset+size],record.full_path(),anchor['filename'])
            items.append(item)
        except Exception as error:
            caught(error,dict(frame=item['frame'],method=item['method']),expected=True,site='anchor-consensus-original-resource-identity')
            rejected.append(dict(frame=item['frame'],method=item['method'],error=str(error)))
    constraints,unsupported=constraints_for(items,fs,base,length)
    report=dict(constraints=constraints,unavailable_constraints=unsupported,rejected_original_identity_anchors=rejected,resolved=False)
    if unsupported:return original_items,report
    candidates={frames[item['frame']]['sha256']:read_frame(frames[item['frame']]) for item in items}
    winner=unique_consensus(candidates,constraints)
    if winner is None:return original_items,report
    report.update(resolved=True,selected_sha256=winner,candidate_sha256=sorted(candidates),scope='Every bounded original anchor must agree; at least two independent NTFS records; no vote, ordering or adjacency selection.')
    selected=[dict(item,detail=dict(item['detail'],cross_candidate_consensus=report)) for item in items if frames[item['frame']]['sha256']==winner]
    return selected,report
