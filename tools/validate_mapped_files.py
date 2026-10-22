"""Independently validate new signed PE/PNG files through a read-only overlay.

Writes a fresh mapping snapshot with observed validation flags corrected only
for newly proposed mappings. Existing applied base mappings remain identical.
"""
import argparse,functools,hashlib,json,pathlib,zstandard
from safe_vhdx import VHDX
from mapped_volume import MappedVolume
from dissect.fat import FATFS
from dissect.ntfs import NTFS
from pe_anchors import image_digest
from recover_png_crc_grid import validate_png


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','layout','base_mapping_directory','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);parts=json.loads(a.layout.read_text())['disks'][0]['partitions'];base=json.loads((a.base_mapping_directory/'accepted-mappings.json').read_text());maps=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());original={m['disk_offset']:m for m in base};mapped={i:{m['disk_offset']-p['_geometry']['start']:m for m in maps if m['partition']==i} for i,p in enumerate(parts)};source=a.source.open('rb')
    @functools.lru_cache(maxsize=128)
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    v=VHDX(a.baseline);fat=FATFS(MappedVolume(v,parts[0]['_geometry']['start'],parts[0]['_geometry']['length'],mapped[0],decode));ntfs=NTFS(MappedVolume(v,parts[2]['_geometry']['start'],parts[2]['_geometry']['length'],mapped[2],decode));ntfs.mft.fh=a.mft.open('rb');inventory={r['record']:r for r in map(json.loads,a.inventory.open())};paths={(r.get('path') or '').replace('\\','/').strip('/').casefold():n for n,r in inventory.items()};results={}
    for m in maps:
        if m['disk_offset'] in original:
            if m!=original[m['disk_offset']]:raise ValueError('changed base mapping')
            continue
        for e in m['evidence']:
            method=e.get('method','');path=e.get('fat_path') or e.get('file_path')
            if 'complete-embedded-pe-image-digest' in method and path:
                key=(m['partition'],path)
                if key not in results:
                    if m['partition']==0:data=fat.get(path).open().read()
                    else:data=ntfs.mft.get(paths[path.strip('/').casefold()]).open().read()
                    info=image_digest(data)
                    if info['digest']!=e['image_digest']['digest'] or info['algorithm']!=e['image_digest']['algorithm']:raise ValueError('unexpected PE digest')
                    results[key]=dict(partition=m['partition'],path=path,kind='PE',size=len(data),sha256=hashlib.sha256(data).hexdigest(),embedded_image_digest=info,valid=True)
                e['image_digest']=dict(e['image_digest'],matches=True)
            elif method=='png-idat-grid-cross-crc-complete-zlib-validation':
                number=e['record'];key=(2,str(number))
                if key not in results:
                    data=ntfs.mft.get(number).open().read();validation=validate_png(data);sha=hashlib.sha256(data).hexdigest()
                    if sha!=e['file_sha256_observed'] or validation!=e['validation']:raise ValueError('PNG projection differs')
                    results[key]=dict(partition=2,record=number,path=inventory[number].get('path'),kind='PNG',size=len(data),sha256=sha,validation=validation,valid=True)
            elif method=='original-whole-file-hash-completion':
                number=e['record'];key=(2,str(number),'file-hash')
                if key not in results:
                    data=ntfs.mft.get(number).open().read()
                    if len(data)!=e['file_size'] or hashlib.new(e['algorithm'],data).hexdigest()!=e['expected_digest']:raise ValueError('original whole-file hash reconstruction differs')
                    results[key]=dict(partition=2,record=number,path=inventory.get(number,{}).get('path'),kind='original-file-hash',size=len(data),sha256=hashlib.sha256(data).hexdigest(),original_digest=dict(algorithm=e['algorithm'],expected=e['expected_digest']),valid=True)
            elif method=='signed-catalog-file-completion':
                from recover_catalog_files import catalog_digest
                number=e['record'];key=(2,str(number),'catalog')
                if key not in results:
                    data=ntfs.mft.get(number).open().read()
                    if len(data)!=e['file_size'] or catalog_digest(data,e['algorithm'],e['hash_kind'])!=e['expected_digest']:raise ValueError('signed catalog file reconstruction differs')
                    results[key]=dict(partition=2,record=number,path=inventory.get(number,{}).get('path'),kind='catalog-file-hash',size=len(data),sha256=hashlib.sha256(data).hexdigest(),catalog=e['catalog'],valid=True)
    (a.output/'accepted-mappings.json').write_text(json.dumps(maps,indent=2));(a.output/'recovery-plan.json').write_bytes((a.mapping_directory/'recovery-plan.json').read_bytes());(a.output/'file-validation.json').write_text(json.dumps(list(results.values()),indent=2));summary=dict(valid=True,validated_files=len(results),pe_files=sum(x['kind']=='PE' for x in results.values()),png_files=sum(x['kind']=='PNG' for x in results.values()),accepted_destinations=len(maps),accepted_bytes=sum(m['length'] for m in maps),scope='Read-only source-backed overlay; saving to VHDX and post-write checks are separate.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
