"""Map FAT directory frames using dot self-clusters, parents and live FAT chains.

Requires agreeing FAT copies, valid directory-entry metadata and child chains.
Fully known parents must actually reference the child; missing parent pages are
allowed only with multiple independent valid child entries. Source order unused.
"""
from rebuild_audit import caught as _audit_caught
import argparse,bisect,collections,hashlib,io,json,pathlib,sqlite3,struct
import zstandard
from mapped_volume import MappedVolume
from safe_vhdx import VHDX
from dissect.fat import FATFS
from dissect.fat.fat import DirectoryEntry
from dissect.fat.exceptions import LastEmptyDirectoryError,EmptyDirectoryError
from dissect.util.stream import RangeStream


def cluster_at(data,offset):
    return struct.unpack_from('<H',data,offset+26)[0]|struct.unpack_from('<H',data,offset+20)[0]<<16


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--partition',type=int,default=0)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);pi=a.partition
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][pi];origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==pi};ranges=[]
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('partition')==pi and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    source=a.source.open('rb')
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    v=VHDX(a.baseline);fat=FATFS(MappedVolume(v,origin,p['_geometry']['length'],mapped,decode));data_start=fat.first_data_sector*fat.sector_size;cs=fat.cluster_size
    if fat.bpb.BPB_NumFATs!=2:raise ValueError('requires two FAT copies')
    copies=[]
    for i in range(2):
        v.seek(origin+(fat.bpb.BPB_RsvdSecCnt+i*fat.fat_size)*fat.sector_size);copies.append(v.read(fat.fat_size*fat.sector_size))
    if copies[0]!=copies[1]:raise ValueError('FAT copies differ')
    rawfat=copies[0];maxcluster=len(rawfat)//4;rootcluster=fat.bpb_ext.BPB_RootClus
    def chain(cluster):
        seen=set()
        while cluster<0x0ffffff8:
            if not 2<=cluster<maxcluster or cluster in seen:raise ValueError('invalid or cyclic FAT chain')
            seen.add(cluster);cluster=struct.unpack_from('<I',rawfat,cluster*4)[0]&0x0fffffff
            if len(seen)>100000:raise ValueError('chain bound')
        return sorted(seen)
    known={rootcluster:dict(path='/',children=set(),missing=False)}
    def walk(entry,path='/',depth=0):
        if depth>32:raise ValueError('directory depth bound')
        cluster=getattr(entry,'cluster',rootcluster);item=known.setdefault(cluster,dict(path=path,children=set(),missing=False))
        for c in chain(cluster):
            base=data_start+((c-2)*cs//stride)*stride
            if unknown(base):item['missing']=True
        for child in entry.iterdir():
            if child.name in ('.','..'):continue
            if child.is_directory():
                item['children'].add(child.cluster);walk(child,path.rstrip('/')+'/'+child.name,depth+1)
    walk(fat.root)
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);candidates=[]
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(stride,)):
            corpus.seek(f[3]);data=corpus.read(stride)
            for pos in range(0,stride-cs+1,cs):
                page=data[pos:pos+cs]
                if page[:11]!=b'.          ' or page[32:43]!=b'..         ' or page[11]!=16 or page[43]!=16:continue
                cluster=cluster_at(page,0);parent=cluster_at(page,32) or rootcluster;base=data_start+(cluster-2)*cs-pos
                if base<data_start or (base-data_start)%stride or not unknown(base):continue
                try:
                    own=chain(cluster);chain(parent);children=[];stream=io.BytesIO(page);stream.seek(64)
                    while stream.tell()<len(page):
                        start=stream.tell()
                        try:child=DirectoryEntry(fat,stream)
                        except LastEmptyDirectoryError as _audit_error:
                            _audit_caught(_audit_error, None, expected=True, site='recover_fat_directories.py:76')
                            break
                        except EmptyDirectoryError as _audit_error:
                            _audit_caught(_audit_error, None, expected=True, site='recover_fat_directories.py:77')
                            continue
                        if stream.tell()<=start:raise ValueError('directory parser made no progress')
                        if child.is_volume_id():continue
                        if child.dirent.DIR_Attr&0xc0:raise ValueError('directory attribute reserved bits')
                        if child.cluster:
                            child_chain=chain(child.cluster)
                            if len(child_chain)*cs<child.size:raise ValueError('child FAT chain shorter than size')
                        elif child.size:raise ValueError('nonempty child without cluster')
                        children.append(dict(name=child.name,cluster=child.cluster,size=child.size,directory=child.is_directory()))
                    candidates.append(dict(frame=f,base=base,decoded_offset=pos,cluster=cluster,parent=parent,children=children))
                except Exception as _audit_error:
                    _audit_caught(_audit_error, None, expected=True, site='recover_fat_directories.py:87')
                    continue
    bycluster=collections.defaultdict(list)
    for c in candidates:bycluster[c['cluster']].append(c)
    pending=collections.defaultdict(list);reports=[]
    for c in candidates:
        parent=known.get(c['parent']);cross=[x for x in bycluster[c['parent']] if any(ch['directory'] and ch['cluster']==c['cluster'] for ch in x['children'])]
        referenced=bool(parent and c['cluster'] in parent['children']) or bool(cross)
        supported=referenced or bool(parent and parent['missing'] and len([ch for ch in c['children'] if ch['cluster']])>=2)
        if not supported:continue
        evidence=dict(method='fat-dot-self-cluster-parent-live-chains',decoded_offset=c['decoded_offset'],self_cluster=c['cluster'],parent_cluster=c['parent'],parent_path=parent['path'] if parent else None,parent_references_child=referenced,parent_has_missing_pages=bool(parent and parent['missing']),children=c['children'],fat_copies_sha256=hashlib.sha256(rawfat).hexdigest())
        pending[c['base']].append((c['frame'],evidence));reports.append(dict(frame=c['frame'][0],base=c['base'],evidence=evidence))
    conflicts=[]
    for base,items in sorted(pending.items()):
        if len({f[6] for f,e in items})!=1:conflicts.append(base);continue
        f=items[0][0];source.seek(f[1]);data=zstandard.ZstdDecompressor().decompress(source.read(f[2]))
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source validation')
        accepted.append(dict(partition=pi,reserved=False,block=(base-data_start)//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=sorted({f[0] for f,e in items}),evidence=[e for f,e in items]))
        plan['partitions'][pi].setdefault('overrides',{})[str((base-data_start)//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='FAT directory dot self-cluster gives address; parent relationship, multiple live child chains and matching FAT copies corroborate. Original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'directory-evidence.json').write_text(json.dumps(reports,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),directory_additions=len(accepted)-previous,candidate_directory_pages=len(candidates),conflicts=conflicts)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
