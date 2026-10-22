"""Add candidate original names, paths and runlists to external file sidecars.

Size/name matches are metadata leads only, never authority to insert a file in
the VHDX. The carved bytes, baseline and original MFT stay unchanged.
"""
from rebuild_audit import caught as _audit_caught
import argparse,collections,hashlib,json,mmap,pathlib
from discover_duplicate_pairs import candidate_records
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def enrich(recovered,baseline,mft,inventory,layout):
    files=[];sizes=set();paths={x['record']:x.get('path') for x in map(json.loads,inventory.open())}
    for side in (recovered/'files').glob('*.json'):
        info=json.loads(side.read_text());content=side.with_suffix('').read_bytes()
        if hashlib.sha256(content).hexdigest()!=info['sha256']:raise ValueError('carved file changed')
        if info.get('file_type')=='exe' or any(k in info.get('validation',{}) for k in ('catalog_image_digest','embedded_image_digest')):
            try:
                import pefile
                pe=pefile.PE(data=content,fast_load=True);pe.parse_data_directories(directories=[2]);strings={}
                for group in getattr(pe,'FileInfo',[]):
                    for item in group:
                        for table in getattr(item,'StringTable',[]):strings.update({k.decode(errors='replace'):v.decode(errors='replace').rstrip('\0') for k,v in table.entries.items()})
                info['embedded_pe_identity']=strings;info['original_filename']=strings.get('OriginalFilename') or info.get('original_filename')
            except Exception as _audit_error:
                _audit_caught(_audit_error, None, expected=True, site='enrich_recovered_metadata.py:26')
                pass
        sizes.add(info['bytes']);files.append((side,info))
    bysize=collections.defaultdict(list);p=layout['disks'][0]['partitions'][2];volume=VHDX(baseline);fs=NTFS(RangeStream(volume,p['_geometry']['start'],p['_geometry']['length']));cache=mft.open('rb');fs.mft.fh=cache
    try:
        with mmap.mmap(cache.fileno(),0,access=mmap.ACCESS_READ) as raw:
            for number,names,size in candidate_records(raw):
                if size not in sizes:continue
                try:
                    record=fs.mft.get(number);names=record.filenames(ignore_dos=True)
                    if not names or record.size()!=size:continue
                    try:path=record.full_path()
                    except Exception as _audit_error:
                        _audit_caught(_audit_error, locals(), expected=False, site='enrich_recovered_metadata.py:37')
                        path=paths.get(number)
                    bysize[size].append(dict(record=number,sequence=record.header.SequenceNumber,names=names,path=path,size=size,physical_cluster_runs=list(record.dataruns()),partition=2,cluster_bytes=fs.cluster_size,partition_disk_offset=p['_geometry']['start']))
                except Exception as _audit_error:
                    _audit_caught(_audit_error, locals(), expected=False, site='enrich_recovered_metadata.py:39')
                    continue
        count=0
        for side,info in files:
            candidates=[];original=(info.get('original_filename') or '').casefold();suffix=info['file_type']
            for candidate in bysize[info['bytes']]:
                names=candidate['names']
                if original and not any(name.casefold()==original for name in names):continue
                if not original and not any(pathlib.PureWindowsPath(name).suffix.casefold()=='.'+suffix for name in names):continue
                candidates.append(dict(candidate,matching_basis='embedded original name and exact size' if original else 'file type and exact size',placement_confirmed=False))
            info['possible_locations']=candidates;info['metadata_scope']='Candidates only. File names, lengths and runlists do not independently authorize a filesystem placement.';side.write_text(json.dumps(info,indent=2));count+=bool(candidates)
    finally:cache.close();volume.fh.close()
    result=dict(files_examined=len(files),files_with_candidate_metadata=count,bytes_unchanged=True,baseline_and_mft_read_only=True);(recovered/'metadata-enrichment.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('recovered_files','baseline','mft','inventory','layout'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();enrich(a.recovered_files,a.baseline,a.mft,a.inventory,json.loads(a.layout.read_text()))
