"""Discover original component Identity hashes without guessing payload paths."""
import argparse,collections,hashlib,json,mmap,pathlib,time
from component_manifest_hashes import component_paths,manifest_constraint,OriginalManifestReader
from discover_duplicate_pairs import candidate_records
from rebuild_context import Context
from rebuild_audit import caught


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-file-size',type=int,default=64*1024**2);a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);reader=OriginalManifestReader(a.baseline,a.mft,ctx.layout,a.manifest);groups=collections.defaultdict(list);reports=[];counts=collections.Counter();targets=[]
    last=time.monotonic()
    for row in map(json.loads,a.inventory.open()):
        counts['inventory_records_scanned']+=1
        if time.monotonic()-last>10:print(json.dumps(dict(phase='target-paths',counts=counts,component_manifest_names=len(groups))),flush=True);last=time.monotonic()
        try:
            record=ctx.fs.mft.get(row['record'])
            if record.header.Flags&2 or not 0<record.size()<=a.maximum_file_size or not ctx.holes(record):continue
            for path in record.full_paths(ignore_dos=True):
                location=component_paths(path)
                if location is None:continue
                for manifest_path in location['manifest_paths']:groups[pathlib.PureWindowsPath(manifest_path).name.casefold()].append(dict(record=row['record'],sequence=record.header.SequenceNumber,size=record.size(),target_path=path,manifest_path=manifest_path))
            counts['incomplete_files_scanned']+=1
        except Exception as e:caught(e,dict(number=row['record']),expected=True,site='manifest-target-probe');counts['target_rejections']+=1
    with a.mft.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
        for number,names,size in candidate_records(raw):
            if time.monotonic()-last>10:print(json.dumps(dict(phase='original-manifests',mft_record=number,targets=len(targets),manifest_probes=len(reports))),flush=True);last=time.monotonic()
            possible={n.casefold() for n in names}&groups.keys()
            if not possible:continue
            for name in possible:
                for target in groups[name]:
                    report=dict(target_record=target['record'],manifest_record=number,target_path=target['target_path'],manifest_path=target['manifest_path']);reports.append(report)
                    try:
                        record,data=reader.read(number,target['manifest_path']);constraint=manifest_constraint(target['target_path'],target['manifest_path'],data);binding=dict(kind='original-component-manifest-file-hash',target_path=target['target_path'],target_sequence=target['sequence'],manifest_record=number,manifest_sequence=record.header.SequenceNumber,manifest_path=target['manifest_path'],manifest_sha256=hashlib.sha256(data).hexdigest(),identity=constraint['identity'],file_name=constraint['file_name'],transform=constraint['transform'],original_baseline_bytes_only=True)
                        targets.append(dict(record=target['record'],size=target['size'],algorithm=constraint['algorithm'],digest=constraint['digest'],hash_source=binding));report.update(algorithm=constraint['algorithm'],digest=constraint['digest'],matched=True)
                    except Exception as e:caught(e,dict(number=number),expected=True,site='original-manifest-binding-probe');report['rejected']=str(e)
    digests=collections.defaultdict(set)
    for target in targets:digests[(target['record'],target['algorithm'])].add(target['digest'])
    conflicts={record for (record,algorithm),values in digests.items() if len(values)>1};unique={}
    for target in targets:
        if target['record'] not in conflicts:unique.setdefault((target['record'],target['algorithm'],target['digest']),target)
    (a.output/'hash-targets.json').write_text(json.dumps(list(unique.values()),indent=2));(a.output/'reports.json').write_text(json.dumps(reports,indent=2));reader.close();ctx.close();summary=dict(counts=counts,component_manifest_names=len(groups),manifest_probes=len(reports),targets=len(unique),conflicting_records=sorted(conflicts),scope='Only hashes with the Identity transform, an exact original component/manifest path relation and matching assembly identity are used. Manifest bytes must survive in the baseline independently of proposed mappings.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
