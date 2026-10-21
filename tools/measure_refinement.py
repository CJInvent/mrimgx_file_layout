"""Measure restored allocated clusters and file runlist coverage, not file validity."""
import argparse
import bisect
import collections
import json
import pathlib


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('mappings','inventory','allocation_bitmap','layout','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    mappings=json.loads(a.mappings.read_text());layout=json.loads(a.layout.read_text());origin=layout['disks'][0]['partitions'][2]['_geometry']['start']
    ranges=sorted((m['disk_offset'],m['disk_offset']+m['length']) for m in mappings if m['partition']==2)
    ends=[end for start,end in ranges]
    def covered(start,length):
        stop=start+length;k=bisect.bisect_right(ends,start);total=0
        while k<len(ranges) and ranges[k][0]<stop:
            lo,hi=ranges[k];total+=max(0,min(hi,stop)-max(lo,start));k+=1
        return total
    bitmap=a.allocation_bitmap.read_bytes();clusters=set();stats=collections.Counter()
    for start,stop in ranges:
        for c in range((start-origin)//4096,(stop-origin+4095)//4096):
            if bitmap[c//8]&(1<<(c%8)):clusters.add(c)
    stats['newly_restored_allocated_clusters']=len(clusters)
    stats['newly_restored_allocated_cluster_bytes']=len(clusters)*4096
    with (a.output/'file-coverage-impact.jsonl').open('x') as out:
        for line in a.inventory.open():
            row=json.loads(line);data_before=0;data_remaining=0;index_before=0;index_remaining=0;restored=0
            for hit in row['ranges']:
                if hit['status']=='reconstructed-unverified':continue
                missing=hit['length'];recovered=covered(hit['disk_offset'],missing);restored+=recovered
                if hit['type']==128:data_before+=missing;data_remaining+=missing-recovered
                else:index_before+=missing;index_remaining+=missing-recovered
            if restored:
                stats['mft_records_with_improved_coverage']+=1
                if data_before and not data_remaining:stats['mft_records_all_previously_missing_data_ranges_filled']+=1
                if (data_before+index_before) and not(data_remaining+index_remaining):stats['mft_records_all_previously_missing_data_and_index_ranges_filled']+=1
                out.write(json.dumps(dict(record=row['record'],path=row.get('path'),restored_bytes=restored,missing_data_before=data_before,missing_data_remaining=data_remaining,missing_index_before=index_before,missing_index_remaining=index_remaining))+'\n')
    result=dict(counts=stats,note='Coverage of original allocated clusters and active MFT DATA/INDEX_ALLOCATION runlists, including slack and extension records. Filling missing ranges is not independent validation of complete file content. Original reconstructed ranges remain reconstructed.')
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))


if __name__=='__main__':main()
