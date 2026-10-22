"""Discover intact catalogs and preserve signature-verified member hashes."""
import argparse,collections,hashlib,json,mmap,pathlib,time
from rebuild_context import Context
from discover_duplicate_pairs import candidate_records
from windows_metadata import catalog_members


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);cache=a.output/'catalog-cache';cache.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);counts=collections.Counter();seen=set();updated=time.monotonic()
    with a.mft.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as raw,(a.output/'catalog-members.jsonl').open('x') as log,(a.output/'reports.jsonl').open('x') as reports:
        for number,names,size in candidate_records(raw):
            if not any(n.casefold().endswith('.cat') for n in names) or size>64*1024**2:continue
            counts['catalog_records']+=1
            try:
                rec,data=ctx.read_complete(number,64*1024**2);names=rec.filenames(ignore_dos=True);sha=hashlib.sha256(data).hexdigest()
                if sha in seen:counts['duplicates']+=1;continue
                seen.add(sha);path=cache/(str(number)+'.cat');path.open('xb').write(data)
                for row in catalog_members(path):
                    row.update(catalog_record=number,catalog_names=names,catalog_sha256=sha);log.write(json.dumps(row)+'\n');counts['members']+=1
                counts['signature_hash_verified']+=1
            except Exception as e:counts['rejected']+=1;reports.write(json.dumps(dict(record=number,names=names,error=str(e)))+'\n')
            if time.monotonic()-updated>20:print(json.dumps(counts),flush=True);updated=time.monotonic();log.flush()
    (a.output/'summary.json').write_text(json.dumps(counts,indent=2));print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
