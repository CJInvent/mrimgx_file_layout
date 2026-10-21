"""Reconcile encoded source coverage after refinement and preserve its complement."""
import argparse
import hashlib
import json
import pathlib
from forensic_residuals import merge_ranges,complement


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','evidence','mappings','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    old=json.loads((a.evidence/'coverage-summary.json').read_text());ranges=[]
    if old['source_size']!=a.source.stat().st_size or old['data_region_end']+old['metadata_bytes']!=old['source_size']:raise ValueError('source/coverage size mismatch')
    for line in (a.evidence/'source-coverage.jsonl').open():
        row=json.loads(line)
        if row['status']=='incorporated-encoded-data':ranges.append((row['source_offset'],row['source_offset']+row['length']))
    for m in json.loads(a.mappings.read_text()):
        start=m['source_offset'];end=start+m['stored_length']
        if not 0<=start<end<=old['data_region_end']:raise ValueError('source bounds')
        ranges.append((start,end))
    covered=merge_ranges(ranges);gaps=list(complement(covered,old['data_region_end']));before=a.source.stat()
    with a.source.open('rb') as source,(a.output/'encoded-location-unresolved.bin').open('xb') as binary,(a.output/'encoded-residual-map.jsonl').open('x') as log:
        for lo,hi in gaps:
            source.seek(lo);remaining=hi-lo;offset=binary.tell();sha=hashlib.sha256()
            while remaining:
                data=source.read(min(8*1024**2,remaining))
                if not data:raise ValueError('source short read')
                binary.write(data);sha.update(data);remaining-=len(data)
            log.write(json.dumps(dict(source_offset=lo,length=hi-lo,export_offset=offset,sha256=sha.hexdigest()))+'\n')
    after=a.source.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('source changed')
    with (a.output/'source-coverage.jsonl').open('x') as log:
        for status,rs in (('incorporated-encoded-data',covered),('not-incorporated-encoded-data',gaps),('metadata-and-footer',[(old['data_region_end'],before.st_size)])):
            for lo,hi in rs:log.write(json.dumps(dict(status=status,source_offset=lo,length=hi-lo))+'\n')
    incorporated=sum(hi-lo for lo,hi in covered);residual=sum(hi-lo for lo,hi in gaps)
    if incorporated+residual+old['metadata_bytes']!=before.st_size:raise ValueError('source accounting does not close')
    result=dict(source_size=before.st_size,incorporated_encoded_bytes=incorporated,newly_incorporated_encoded_bytes=incorporated-old['incorporated_encoded_bytes'],not_incorporated_encoded_bytes=residual,residual_ranges=len(gaps),metadata_bytes=old['metadata_bytes'],accounting_exact=True,source_stat_unchanged=True,mappings_sha256=hashlib.sha256(a.mappings.read_bytes()).hexdigest(),scope='Physical ranges selected by baseline plus refined placements, not historical reads. Identical alternative frames may have represented content while remaining physically unselected. Original metadata/footer and all earlier evidence remain preserved.')
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':main()
