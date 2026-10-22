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
                    binding=e.get('hash_source') or {}
                    if isinstance(binding,dict) and binding.get('kind')=='original-inf-catalog-reference-and-named-member':
                        from bind_inf_catalog_candidates import original_catalog_names
                        from windows_metadata import catalog_members
                        prefix=data[:binding['original_inf_prefix_bytes']]
                        if hashlib.sha256(prefix).hexdigest()!=binding['original_inf_prefix_sha256']:raise ValueError('original INF prefix differs')
                        names={x.casefold() for x in original_catalog_names(prefix)};cat=ntfs.mft.get(binding['catalog_record']).open().read()
                        if hashlib.sha256(cat).hexdigest()!=binding['catalog_sha256']:raise ValueError('original INF catalog differs')
                        for path in binding['original_catalog_paths']:
                            if pathlib.PureWindowsPath(path).name.casefold() not in names or ntfs.mft.get(path).open().read()!=cat:raise ValueError('original INF catalog path differs')
                        exported=a.output/f'{number}-independent-original.cat'
                        with exported.open('xb') as out:out.write(cat)
                        oid={'sha1':'1.3.14.3.2.26','sha256':'2.16.840.1.101.3.4.2.1'}[e['algorithm']]
                        members=[m for m in catalog_members(exported) if m.get('algorithm_oid')==oid and m.get('subject_oid')=='1.3.6.1.4.1.311.2.1.25' and any(x.get('tag','').casefold()=='file' and x.get('text','').casefold()==binding['catalog_member_filename'] for x in m.get('attributes',[]))]
                        if {m.get('digest') for m in members}!={e['expected_digest']}:raise ValueError('independent named catalog digest differs')
                    results[key]=dict(partition=2,record=number,path=inventory.get(number,{}).get('path'),kind='original-file-hash',size=len(data),sha256=hashlib.sha256(data).hexdigest(),original_digest=dict(algorithm=e['algorithm'],expected=e['expected_digest']),valid=True)
            elif method=='signed-catalog-file-completion':
                from recover_catalog_files import catalog_digest
                number=e['record'];key=(2,str(number),'catalog')
                if key not in results:
                    data=ntfs.mft.get(number).open().read()
                    if len(data)!=e['file_size'] or catalog_digest(data,e['algorithm'],e['hash_kind'])!=e['expected_digest']:raise ValueError('signed catalog file reconstruction differs')
                    results[key]=dict(partition=2,record=number,path=inventory.get(number,{}).get('path'),kind='catalog-file-hash',size=len(data),sha256=hashlib.sha256(data).hexdigest(),catalog=e['catalog'],valid=True)
            elif method=='chromium-original-stream-crcs-and-key-identity':
                from recover_chromium_streams import layout,validate
                number=e['record'];key=(2,str(number),'chromium')
                if key not in results:
                    data=ntfs.mft.get(number).open().read();info=layout(data,e['filename']);validate(data,info)
                    if info!=e['stream_layout'] or hashlib.sha256(data).hexdigest()!=e['file_sha256_observed']:raise ValueError('Chromium reconstruction differs')
                    results[key]=dict(partition=2,record=number,path=inventory.get(number,{}).get('path'),kind='chromium-cache',size=len(data),sha256=e['file_sha256_observed'],stream_layout=info,valid=True)
            elif method=='zip-original-member-crcs-and-directory':
                from recover_zip_files import validate_archive,original_crossing_crcs,independently_crossing
                from recover_duplicate_files import file_extents,frame_pieces
                number=e['record'];key=(2,str(number),'original-zip-crcs')
                if key not in results:
                    data=ntfs.mft.get(number).open().read();members=validate_archive(data)
                    if len(data)!=e['file_size'] or hashlib.sha256(data).hexdigest()!=e['file_sha256_observed']:raise ValueError('ZIP reconstructed file differs')
                    # Exclude this proposed frame: checksum fields used as
                    # original constraints must be readable independently.
                    known_maps={base:row for base,row in mapped[2].items() if row['disk_offset']!=m['disk_offset']};original_fs=NTFS(MappedVolume(v,parts[2]['_geometry']['start'],parts[2]['_geometry']['length'],known_maps,decode));original_fs.mft.fh=a.mft.open('rb');rec=original_fs.mft.get(number);template=rec.open().read();pieces=frame_pieces(file_extents(rec,rec.size()),m['disk_offset']-parts[2]['_geometry']['start'],parts[2]['_header']['block_size']);original_fs.mft.fh.close()
                    if [list(x) for x in pieces]!=e['original_missing_pieces']:raise ValueError('ZIP original runlist projection differs')
                    mask=bytearray(b'\1'*len(data))
                    for off,logical,n in pieces:mask[logical:logical+n]=bytes(n)
                    crcs=original_crossing_crcs(template,mask,members,pieces)
                    if not independently_crossing(crcs) or crcs!=e['original_crossing_crcs']:raise ValueError('independent original ZIP CRC coverage differs')
                    results[key]=dict(partition=2,record=number,path=inventory.get(number,{}).get('path'),kind='original-zip-crcs',size=len(data),sha256=e['file_sha256_observed'],original_crossing_crcs=crcs,valid=True)
    (a.output/'accepted-mappings.json').write_text(json.dumps(maps,indent=2));(a.output/'recovery-plan.json').write_bytes((a.mapping_directory/'recovery-plan.json').read_bytes());(a.output/'file-validation.json').write_text(json.dumps(list(results.values()),indent=2));summary=dict(valid=True,validated_files=len(results),pe_files=sum(x['kind']=='PE' for x in results.values()),png_files=sum(x['kind']=='PNG' for x in results.values()),accepted_destinations=len(maps),accepted_bytes=sum(m['length'] for m in maps),scope='Read-only source-backed overlay; saving to VHDX and post-write checks are separate.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
