"""Map INDX frames using original SDS descriptors or LogFile LSN plus runlists."""
import argparse,collections,hashlib,json,pathlib,sqlite3
from rebuild_context import Context
from component_manifest_hashes import OriginalManifestReader
from ntfs_metadata_links import security_link,LogFileLinks
from rebuild_audit import caught


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);reader=OriginalManifestReader(a.baseline,a.mft,ctx.layout,a.manifest);counts=collections.Counter();reports=[];proposals=collections.defaultdict(list);log=None
    try:log=LogFileLinks(reader)
    except Exception as error:caught(error,{},expected=True,site='ntfs-logfile-availability');counts['logfile_unavailable']+=1
    placed={fid for m in ctx.maps for fid in m['frames']};db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for fid,page,valid,exported in db.execute("SELECT r.frame,r.decoded_offset,r.fixup_valid,f.export_offset FROM records r JOIN frames f ON r.frame=f.id WHERE r.signature='INDX'"):
            if fid in placed or not valid:continue
            counts['unplaced_index_pages']+=1;report=dict(frame=fid,page_offset=page);reports.append(report);corpus.seek(exported+page);raw=corpus.read(4096);proof=None
            try:proof=security_link(ctx.fs,raw)
            except Exception as error:caught(error,dict(frame=fid,page_offset=page),expected=True,site='ntfs-security-index-probe');report['security_rejected']=str(error)
            if proof is None and log is not None:
                try:proof=log.directory_link(ctx.fs,raw)
                except Exception as error:caught(error,dict(frame=fid,page_offset=page),expected=True,site='ntfs-logfile-directory-probe');report['log_rejected']=str(error)
            if proof is None:continue
            base=proof['page_address']-page
            if base<0 or base%ctx.stride or base+ctx.stride>ctx.p['_geometry']['length'] or base in ctx.mapped or not any(lo<=base and base+ctx.stride<=hi for lo,hi in ctx.ranges):report['rejected']='destination not aligned/unresolved';continue
            proof=dict(method='ntfs-cross-file-index-address',page_offset=page,**proof);report['proof']=proof;proposals[fid].append((ctx.origin+base,proof));counts[proof['kind']]+=1
    candidates=collections.defaultdict(list);conflicts=[]
    for fid,items in proposals.items():
        addresses={address for address,proof in items}
        if len(addresses)!=1:conflicts.append(dict(frame=fid,reason='metadata pages disagree on frame address'));continue
        candidates[addresses.pop()].append((fid,[proof for address,proof in items]))
    maps=list(ctx.maps);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());new=[]
    for address,items in sorted(candidates.items()):
        frames=[db.execute('SELECT id,source_offset,stored_length,decoded_length,md5,sha256 FROM frames WHERE id=?',(fid,)).fetchone() for fid,proofs in items]
        if len({f[5] for f in frames})!=1:conflicts.append(dict(disk_offset=address,reason='different source content nominated'));continue
        f=frames[0];data=ctx.decode(f[1],f[2])
        if len(data)!=ctx.stride or f[3]!=ctx.stride or hashlib.md5(data).digest()!=f[4] or hashlib.sha256(data).hexdigest()!=f[5]:raise ValueError('metadata frame original source revalidation failed')
        block=(address-ctx.origin)//ctx.stride;mapping=dict(partition=2,reserved=False,block=block,disk_offset=address,length=ctx.stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[4].hex(),sha256=f[5],frames=[f[0] for f in frames],evidence=[proof for fid,proofs in items for proof in proofs]);maps.append(mapping);new.append(mapping)
        plan['partitions'][2].setdefault('overrides',{})[str(block)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[4].hex(),reason='Original cross-file NTFS metadata and active named-index runlist corroborate the source frame address; no adjacency inference.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(maps,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'reports.json').write_text(json.dumps(reports,indent=2));summary=dict(accepted_destinations=len(maps),accepted_bytes=sum(m['length'] for m in maps),new_placements=len(new),counts=counts,conflicts=conflicts,scope='Read-only source proposals from independently cross-checked SDS descriptors or original LogFile transactions plus active index-owner runlists. Independent validation and VHDX write checks remain separate.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);reader.close();ctx.close();db.close()


if __name__=='__main__':main()
