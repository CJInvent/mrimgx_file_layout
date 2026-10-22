"""Automatically discover intact MSI metadata and nominate incomplete file hashes."""
from rebuild_audit import caught as _audit_caught
import argparse,collections,hashlib,json,mmap,pathlib
from rebuild_context import Context
from discover_duplicate_pairs import candidate_records
from windows_metadata import installer_hashes


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);cache=a.output/'installer-cache';cache.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory);hashes=[];reports=[];seen=set()
    with a.mft.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as raw:
        for number,names,size in candidate_records(raw):
            if not any(n.casefold().endswith('.msi') for n in names) or size>512*1024**2:continue
            report=dict(record=number,names=names);reports.append(report)
            try:
                record,data=ctx.read_complete(number);sha=hashlib.sha256(data).hexdigest()
                if sha in seen:report['skipped']='duplicate content';continue
                seen.add(sha);path=cache/(str(number)+'.msi');path.open('xb').write(data);report.update(size=len(data),sha256=sha);n=0
                for h in installer_hashes(path):h.update(package_record=number,package_sha256=sha,package_path=str(path.resolve()));hashes.append(h);n+=1
                report['hashes']=n
            except Exception as e:
                _audit_caught(e, locals(), expected=False, site='collect_installer_hashes.py:22')
                report['error']=repr(e)
            print(json.dumps(report),flush=True)
    byname=collections.defaultdict(list)
    for h in hashes:byname[(h['name'].casefold(),h['size'])].append(h)
    targets=[]
    for row in map(json.loads,a.inventory.open()):
        try:
            record=ctx.fs.mft.get(row['record'])
            if not ctx.holes(record):continue
            for h in byname.get((record.filename.casefold(),record.size()),[]):targets.append(dict(record=row['record'],size=record.size(),algorithm='md5',digest=h['md5'],hash_source=dict(method='MsiFileHash',package_record=h['package_record'],package_sha256=h['package_sha256'],file_key=h['key'])))
        except Exception as _audit_error:
            _audit_caught(_audit_error, locals(), expected=False, site='collect_installer_hashes.py:32')
            continue
    for name,value in (('hash-targets.json',targets),('installer-hashes.json',hashes),('reports.json',reports)):(a.output/name).write_text(json.dumps(value,indent=2))
    result=dict(packages=len(reports),hashes=len(hashes),targets=len(targets));(a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
