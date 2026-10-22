"""Solve missing FAT PE frames using the complete embedded image digest.

Keeps all independently known file bytes, follows original FAT extents and
checks PE OriginalFilename plus language resources where the header was lost.
Never executes code or asserts certificate trust.
"""
import argparse,bisect,collections,functools,hashlib,json,locale,pathlib,re,sqlite3
import pefile,zstandard
from dissect.fat import FATFS
from safe_vhdx import VHDX
from mapped_volume import MappedVolume
from recover_fat_duplicates import fat_extents
from pe_anchors import image_digest


def name_variants(filename):
    variants={filename,filename.replace('.efi','.exe')}
    if filename.endswith('.mui'):variants.update((filename[:-4],filename[:-4].replace('.efi','.exe')))
    if filename in ('bootmgfw.efi.mui','bootmgr.efi.mui'):variants.add('bootmgr.exe')
    return variants


def pe_identity(data,path):
    pe=pefile.PE(data=data,fast_load=True);pe.parse_data_directories(directories=[2]);names=set();languages=set()
    for group in getattr(pe,'FileInfo',[]):
        for info in group:
            for table in getattr(info,'StringTable',[]):
                value=table.entries.get(b'OriginalFilename')
                if value:names.add(value.decode('utf-8',errors='strict').rstrip('\0').casefold())
                try:languages.add(int(table.LangID[:4],16))
                except Exception:pass
    filename=path.split('/')[-1].casefold();variants=name_variants(filename)
    if not names&variants:raise ValueError('PE OriginalFilename differs from FAT entry: '+repr(sorted(names)))
    parent=path.split('/')[-2].casefold()
    if filename.endswith('.mui') and re.fullmatch(r'[a-z]{2,3}-[a-z]{2,4}',parent):
        matching={n for n in languages if locale.windows_locale.get(n,'').replace('_','-').casefold()==parent}
        if not matching:raise ValueError('PE language differs from FAT directory')
    return dict(original_filenames=sorted(names),languages=sorted(languages))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);pi=0
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][pi];origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==pi};ranges=[]
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('partition')==pi and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    source=a.source.open('rb')
    @functools.lru_cache(maxsize=128)
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    v=VHDX(a.baseline);fat=FATFS(MappedVolume(v,origin,p['_geometry']['length'],mapped,decode));data_start=fat.first_data_sector*fat.sector_size
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);contents={}
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(stride,)):
            frames[f[6]].append(f)
            if f[6] not in contents:corpus.seek(f[3]);contents[f[6]]=corpus.read(stride)
    reports=[];pending=collections.defaultdict(list);targets=0
    def walk(entry,path=''):
        nonlocal targets
        for child in entry.iterdir():
            if child.name in ('.','..'):continue
            full=path+'/'+child.name
            if child.is_directory():walk(child,full);continue
            if not 8192<=child.size<=4*1024**2:continue
            extents=fat_extents(child,fat);bases={b for l,p,n in extents for b in range((p-data_start)//stride*stride+data_start,p+n,stride) if unknown(b)}
            if len(bases)!=1:continue
            targets+=1;base=next(iter(bases));template=child.open().read();patches=[]
            for logical,physical,length in extents:
                lo=max(base,physical);hi=min(base+stride,physical+length)
                if hi>lo:patches.append((logical+lo-physical,logical+hi-physical,lo-base))
            matches=[]
            for sha,data in contents.items():
                candidate=bytearray(template)
                for lo,hi,offset in patches:candidate[lo:hi]=data[offset:offset+hi-lo]
                try:
                    info=image_digest(bytes(candidate));identity=pe_identity(bytes(candidate),full);matches.append((sha,info,identity))
                except Exception:continue
            report=dict(path=full,base=base,matched_hashes=[s for s,i,d in matches]);reports.append(report)
            if len(matches)==1:
                sha,info,identity=matches[0];pending[base].append((frames[sha],dict(method='fat-chain-complete-embedded-pe-image-digest',fat_path=full,image_digest=info,identity=identity,patches=[dict(logical_start=lo,logical_end=hi,decoded_offset=o) for lo,hi,o in patches])))
    walk(fat.root);conflicts=[]
    for base,items in sorted(pending.items()):
        if len({fs[0][6] for fs,e in items})!=1:conflicts.append(base);continue
        f=items[0][0][0];data=decode(f[1],f[2])
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source validation')
        accepted.append(dict(partition=pi,reserved=False,block=(base-data_start)//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=sorted({f[0] for fs,e in items for f in fs}),evidence=[e for fs,e in items]))
        plan['partitions'][pi].setdefault('overrides',{})[str((base-data_start)//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Complete embedded PE image digest validates FAT-runlist reconstruction; OriginalFilename and language identity agree. Original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'signed-fat-evidence.json').write_text(json.dumps(reports,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),signed_fat_additions=len(accepted)-previous,targets=targets,conflicts=conflicts)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
