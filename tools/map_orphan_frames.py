"""Map a residual frame catalog without modifying any input or disk image.

Exact and partial index hashes, surviving index addresses and NTFS directory
runlists are independent evidence channels. All non-exact results remain
reconstructed, and conflicting bytes at a destination are rejected.
"""
from rebuild_audit import caught as _audit_caught
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import re
import sqlite3
import struct

import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.util import apply_fixup
from dissect.util.stream import RangeStream


def partial_digest_matches(original, candidate, minimum=8):
    surviving = [(i, b) for i, b in enumerate(original) if b]
    return len(surviving) >= minimum and all(candidate[i] == b for i, b in surviving)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'plan', 'manifest', 'evidence', 'baseline', 'mft', 'output'):
        ap.add_argument(name, type=pathlib.Path)
    ap.add_argument('--file-inventory', type=pathlib.Path)
    ap.add_argument('--pe-anchors', action='store_true')
    ap.add_argument('--appx-anchors', action='store_true')
    args = ap.parse_args()
    args.output.mkdir(exist_ok=False)
    plan = json.loads(args.plan.read_text())
    from make_recovery_plan import make_plan
    if make_plan(args.source,plan)!=plan:raise ValueError('source/plan fingerprints differ')
    layout = json.loads((args.evidence/'layout.json').read_text())
    db = sqlite3.connect((args.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro', uri=True)
    db.execute('PRAGMA query_only=ON')
    parts = layout['disks'][0]['partitions']
    ranges = collections.defaultdict(list)
    for line in args.manifest.open():
        j = json.loads(line)
        if j.get('operation') == 'range' and j.get('status') in ('unknown-zero-index', 'unrecoverable'):
            ranges[j['partition']].append((j['disk_offset'], j['disk_offset']+j['length']))
    for rs in ranges.values(): rs.sort()
    starts = {p: [a for a,b in rs] for p,rs in ranges.items()}
    def unresolved(p, dest, length):
        k = bisect.bisect_right(starts.get(p, []), dest)-1
        return k >= 0 and ranges[p][k][0] <= dest and dest+length <= ranges[p][k][1]
    frames = {row[0]: dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row))
              for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames')}
    by_digest = collections.defaultdict(list)
    by_source = collections.defaultdict(list)
    for f in frames.values(): by_digest[f['md5']].append(f); by_source[f['source_offset']].append(f)
    proposals = collections.defaultdict(list)
    stats = collections.Counter()
    log = (args.output/'mapping-evidence.jsonl').open('x')
    def propose(f, pi, reserved, block, dest, length, method, detail):
        if f['decoded_length'] != length:
            stats['rejected_length'] += 1; return
        if not unresolved(pi,dest,length):
            stats['already_present_or_not_unresolved'] += 1; return
        if not reserved and str(block) in plan['partitions'][pi].get('overrides',{}):
            stats['existing_override'] += 1; return
        item = dict(frame=f['id'],partition=pi,reserved=bool(reserved),block=block,
                    disk_offset=dest,length=length,method=method,detail=detail)
        proposals[(pi,reserved,block,dest,length)].append(item)
        log.write(json.dumps(item)+'\n'); stats[method] += 1
    # Restrict the digest join to absent original entries: common zero hashes
    # otherwise generate enormous duplicate match arrays.
    pending = list(db.execute('SELECT partition,reserved,block,disk_offset,decoded_length,source_offset,stored_length,digest FROM entries WHERE incorporated=0'))
    print('frames',len(frames),'nonincorporated surviving entries',len(pending),flush=True)
    for pi,res,b,d,l,pos,n,digest in pending:
        for f in by_digest.get(digest,[]):
            propose(f,pi,res,b,d,l,'exact-index-md5',dict(original_source_offset=pos,original_stored_length=n))
        # Zero-overwritten digest bytes may leave a useful cryptographic prefix,
        # suffix or mask. Require 64 surviving bits AND address or size agreement.
        if digest != bytes(16) and 0 in digest:
            for f in frames.values():
                if f['decoded_length'] == l and (pos == f['source_offset'] or n == f['stored_length']) and partial_digest_matches(digest,f['md5']):
                    propose(f,pi,res,b,d,l,'partial-index-md5',dict(surviving_bytes=sum(bool(x) for x in digest),original_digest=digest.hex(),source_address_agrees=pos==f['source_offset'],stored_length_agrees=n==f['stored_length']))
        # An entirely lost digest still permits placement via the original
        # exact source address and encoded length. Do not ignore nonzero
        # contradictory digest bytes or ordinary hash mismatches.
        for f in by_source.get(pos,[]):
            if n == f['stored_length'] and digest == bytes(16):
                propose(f,pi,res,b,d,l,'surviving-index-address',dict(original_digest='all-zero',stored_length=n))
    v = VHDX(args.baseline)
    ntfses = {}
    for pi,p in enumerate(parts):
        if p['_file_system']['type'] != 'NTFS': continue
        ntfses[pi] = NTFS(RangeStream(v,p['_geometry']['start'],p['_geometry']['length']))
        if pi == 2: ntfses[pi].mft.fh = args.mft.open('rb',buffering=8*1024**2)
    recordslog = (args.output/'ntfs-evidence.jsonl').open('x')
    with (args.evidence/'orphan-decoded.bin').open('rb') as decoded:
        for fid,roff,sig,valid in db.execute('SELECT frame,decoded_offset,signature,fixup_valid FROM records'):
            f=frames[fid]; decoded.seek(f['export_offset']+roff)
            raw=decoded.read(4096 if sig=='INDX' else 1024)
            report=dict(frame=fid,decoded_offset=roff,signature=sig,fixup_valid=bool(valid),mappings=[])
            if not valid:
                report['raw_prefix']=raw[:64].hex(); recordslog.write(json.dumps(report)+'\n');continue
            fixed=apply_fixup(raw)
            if sig != 'INDX': continue
            vcn=struct.unpack_from('<Q',fixed,16)[0]
            offset,used,allocated=struct.unpack_from('<III',fixed,24)
            cursor=24+offset; parents=set(); errors=[]
            while cursor+16 <= min(24+used,4096):
                elen,klen,flags=struct.unpack_from('<HHH',fixed,cursor+8)
                if elen<16 or cursor+elen>min(24+used,4096) or klen>elen-16:
                    errors.append('invalid directory entry bounds');break
                if not flags&2 and klen>=66:
                    parents.add(struct.unpack_from('<Q',fixed,cursor+16)[0])
                if flags&2: break
                cursor+=elen
            report.update(vcn=vcn,parents=sorted(parents),errors=errors)
            page_maps=[]
            for pi,fs in ntfses.items():
                try:
                    if fs.cluster_size!=4096 or fs._index_size!=4096 or not parents or errors: raise ValueError('unsupported geometry or invalid entries')
                    addresses=set()
                    for parent in parents:
                        r=fs.mft.get(parent & ((1<<48)-1))
                        if r.header.SequenceNumber != parent>>48 or not r.is_dir() or not r.header.Flags&1: raise ValueError('parent sequence/type/in-use mismatch')
                        hits=[]
                        for attr in r.attributes[ATTRIBUTE_TYPE_CODE.INDEX_ALLOCATION]:
                            if attr.name!='$I30':continue
                            logical=attr.header.lowest_vcn
                            for lcn,count in attr.dataruns():
                                if lcn is not None and logical<=vcn<logical+count: hits.append((lcn+vcn-logical)*4096)
                                logical+=count
                        if len(set(hits))!=1: raise ValueError('no unique parent runlist address')
                        addresses.update(hits)
                    if len(addresses)!=1: raise ValueError('parents disagree on page address')
                    p=parts[pi]; base=addresses.pop()-roff; stride=p['_header']['block_size']
                    origin=p['_file_system'].get('lcn0_offset',0)-p['_file_system'].get('start',0)
                    if base<origin or (base-origin)%stride: raise ValueError('frame block alignment')
                    block=(base-origin)//stride; dest=p['_geometry']['start']+base
                    if block>=plan['partitions'][pi]['count'] or base+f['decoded_length']>p['_geometry']['length']:raise ValueError('partition bounds')
                    evidence=dict(partition=pi,block=block,disk_offset=dest,parents=sorted(parents),vcn=vcn,page_offset=roff)
                    report['mappings'].append(evidence);page_maps.append((pi,block,dest,stride,evidence))
                except Exception as ex:
                    _audit_caught(ex, None, expected=True, site='map_orphan_frames.py:147')
                    report.setdefault('rejections',[]).append(dict(partition=pi,error=str(ex)))
            for pi,b,d,l,evidence in page_maps:
                propose(f,pi,False,b,d,l,'ntfs-indx-runlist',evidence)
            recordslog.write(json.dumps(report)+'\n')
    recordslog.close()
    # Chromium's on-disk cache filename is the first 64 bits of SHA-1(key),
    # interpreted little-endian. Match that identifier to surviving MFT names,
    # then use the file's physical runlist (not compressed frame ordering).
    # Format reference: Chromium net/disk_cache/simple/simple_util.cc and
    # simple_entry_format.h. URLs/keys are never copied into public tool output.
    if args.file_inventory:
        names=collections.defaultdict(set)
        all_names=collections.defaultdict(set)
        for line in args.file_inventory.open():
            row=json.loads(line); name=(row.get('path') or '').split('\\')[-1].lower()
            all_names[name].add(row['record'])
            if re.fullmatch(r'[0-9a-f]{16}_[01]',name): names[name].add(row['record'])
        fs=ntfses[2]; p=parts[2]; stride=p['_header']['block_size']; anchor_cache={}
        def first_cluster(record):
            if record not in anchor_cache:
                r=fs.mft.get(record)
                if not r.header.Flags&1 or r.is_dir():raise ValueError('inactive or directory')
                if any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):raise ValueError('compressed or encrypted stream')
                runs=r.dataruns()
                if not runs or runs[0][0] is None:raise ValueError('no nonresident starting run')
                anchor_cache[record]=(runs[0][0]*4096,r.size(),r.header.SequenceNumber)
            return anchor_cache[record]
        with (args.evidence/'orphan-decoded.bin').open('rb') as decoded:
            for f in frames.values():
                if f['decoded_length']!=stride:continue
                decoded.seek(f['export_offset']); data=decoded.read(f['decoded_length'])
                anchors=[]
                for off in range(0,len(data)-24,4096):
                    if data[off:off+8]!=bytes.fromhex('305c72a71b6dfbfc'):continue
                    version,klen=struct.unpack_from('<II',data,off+8)
                    if version!=5 or not 0<klen<8192 or off+24+klen>len(data):continue
                    key=data[off+24:off+24+klen]
                    stem=f'{int.from_bytes(hashlib.sha1(key).digest()[:8],"little"):016x}'
                    possible=[]
                    for suffix in ('_0','_1'):
                        for record in names.get(stem+suffix,[]):
                            try:
                                address,size,sequence=first_cluster(record)
                                base=address-off
                                if base<0 or base%stride or size<24+klen:continue
                                possible.append((base,record,stem+suffix,sequence))
                            except Exception as _audit_error:
                                _audit_caught(_audit_error, None, expected=True, site='map_orphan_frames.py:193')
                                continue
                    bases={a[0] for a in possible}
                    if len(bases)==1:anchors.extend(possible)
                bases={a[0] for a in anchors}
                if len(bases)>1:
                    stats['contradictory_cache_anchors']+=1
                    continue
                if bases:
                    base=bases.pop()
                    propose(f,2,False,base//stride,p['_geometry']['start']+base,stride,'chromium-key-mft-runlist',
                            dict(anchor_count=len(anchors),anchors=[dict(record=a[1],filename=a[2],sequence=a[3]) for a in anchors]))
        if args.pe_anchors:
            from pe_anchors import candidates
            mapped_frames={i['frame'] for items in proposals.values() for i in items}
            with (args.evidence/'orphan-decoded.bin').open('rb') as decoded, (args.output/'pe-evidence.jsonl').open('x') as pelog:
                for f in frames.values():
                    if f['id'] in mapped_frames or f['decoded_length']!=stride:continue
                    decoded.seek(f['export_offset']);data=decoded.read(f['decoded_length'])
                    maps,errors=candidates(data,fs,all_names,stride,lambda base:unresolved(2,p['_geometry']['start']+base,stride))
                    for base,evidence in maps:
                        propose(f,2,False,base//stride,p['_geometry']['start']+base,stride,'pe-identity-mft-runlist',dict(anchors=evidence))
                    if maps or errors:pelog.write(json.dumps(dict(frame=f['id'],mappings=maps,rejections=errors))+'\n')
        if args.appx_anchors:
            from appx_anchors import targets,match
            groups,appstats,errors=targets(fs,args.file_inventory,stride,lambda base:unresolved(2,p['_geometry']['start']+base,stride))
            (args.output/'appx-target-summary.json').write_text(json.dumps(dict(statistics=appstats,rejections=errors),indent=2))
            print('Appx hash targets',appstats,flush=True)
            mapped_frames={i['frame'] for items in proposals.values() for i in items}
            with (args.evidence/'orphan-decoded.bin').open('rb') as decoded:
                for index,f in enumerate(frames.values()):
                    if f['id'] in mapped_frames or f['decoded_length']!=stride:continue
                    decoded.seek(f['export_offset']);data=decoded.read(f['decoded_length'])
                    for base,evidence in match(data,groups):
                        propose(f,2,False,base//stride,p['_geometry']['start']+base,stride,'appx-blockmap-sha256-mft-runlist',dict(anchors=evidence))
                    if index%500==0:print('Appx frames processed',index,flush=True)
    # A frame must have one inferred destination across all its metadata pages.
    frame_targets=collections.defaultdict(set)
    for key,items in proposals.items():
        for item in items:frame_targets[item['frame']].add(key)
    ambiguous_frames={fid for fid,targets in frame_targets.items() if len(targets)>1 and
                      any(i['method']!='exact-index-md5' for key in targets for i in proposals[key] if i['frame']==fid)}
    # Identical zero frames legitimately match multiple original exact hashes;
    # structural assertions with different destinations must be investigated.
    accepted=[]; conflicts=[]
    with args.source.open('rb') as src, (args.evidence/'orphan-decoded.bin').open('rb') as decoded:
        for key,items in sorted(proposals.items()):
            if any(i['frame'] in ambiguous_frames for i in items):
                conflicts.append(dict(target=key,reason='frame has contradictory destination evidence',evidence=items));continue
            candidates={frames[i['frame']]['sha256'] for i in items}
            if len(candidates)!=1:
                conflicts.append(dict(target=key,evidence=items));continue
            f=frames[items[0]['frame']]
            src.seek(f['source_offset']); raw=src.read(f['stored_length'])
            dec=zstandard.ZstdDecompressor().decompressobj();data=dec.decompress(raw)
            if not dec.eof or dec.unused_data or len(data)!=f['decoded_length'] or hashlib.sha256(data).hexdigest()!=f['sha256'] or hashlib.md5(data).digest()!=f['md5']:raise ValueError('source frame revalidation failed')
            decoded.seek(f['export_offset'])
            if decoded.read(len(data))!=data:raise ValueError('evidence differs from source')
            pi,res,b,d,l=key
            item=dict(partition=pi,reserved=bool(res),block=b,disk_offset=d,length=l,
                      source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=sorted(set(i['frame'] for i in items)),evidence=items)
            accepted.append(item)
            if not res:
                plan['partitions'][pi].setdefault('overrides',{})[str(b)]=dict(source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),reason='Pass 2 mapping: '+', '.join(sorted(set(i['method'] for i in items)))+'; see separate mapping provenance; non-exact mappings reconstructed.')
    log.close()
    (args.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2))
    (args.output/'conflicts.json').write_text(json.dumps(conflicts,indent=2))
    (args.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    summary=dict(frames=len(frames),accepted_destinations=len(accepted),accepted_bytes=sum(a['length'] for a in accepted),conflicts=len(conflicts),evidence_counts=stats)
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2),flush=True)


if __name__=='__main__':main()
