"""Export location-unresolved frames after mapping, without altering evidence.

Exact original exports remain authoritative. This derived stream preserves
unresolved frame boundaries and source offsets; concatenation is not disk order.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import sqlite3


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('evidence','mappings','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads(a.mappings.read_text())
    placed=collections.defaultdict(list)
    hashes=collections.defaultdict(list)
    for m in accepted:
        for fid in m['frames']:placed[fid].append(m['disk_offset'])
        hashes[m['sha256']].append(m['disk_offset'])
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    stats=collections.Counter();unique=set()
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus, (a.output/'location-unresolved-decoded.bin').open('xb') as dst, (a.output/'frame-disposition.jsonl').open('x') as log:
        for fid,pos,n,offset,length,md5,sha in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames ORDER BY id'):
            item=dict(frame=fid,source_offset=pos,stored_length=n,original_export_offset=offset,decoded_length=length,md5=md5.hex(),sha256=sha)
            if fid in placed:
                item.update(status='mapped-to-revised-vhdx',destinations=placed[fid]);stats['mapped_frames']+=1;stats['mapped_corpus_bytes']+=length
            else:
                corpus.seek(offset);data=corpus.read(length)
                if len(data)!=length or hashlib.sha256(data).hexdigest()!=sha:raise ValueError('evidence corpus hash mismatch')
                padding=(-dst.tell())%512;dst.write(bytes(padding));item['export_offset']=dst.tell();dst.write(data)
                item['status']='location-unresolved'
                if sha in hashes:
                    item['content_already_represented_at']=hashes[sha];stats['unresolved_duplicate_content_frames']+=1
                else:
                    count=db.execute('SELECT count(*) FROM entries WHERE incorporated=1 AND decoded_length=? AND digest=?',(length,md5)).fetchone()[0]
                    if count:item['baseline_exact_index_content_matches']=count;stats['unresolved_content_matching_baseline_frames']+=1
                stats['location_unresolved_frames']+=1;stats['location_unresolved_bytes']+=length
                if sha not in unique:unique.add(sha);stats['unique_unresolved_content_bytes']+=length
            log.write(json.dumps(item)+'\n')
    stats['unique_unresolved_hashes']=len(unique)
    result=dict(counts=stats,original_evidence=str(a.evidence.resolve()),scope='Remaining addresses unresolved by implemented methods; not proof of impossibility. Duplicate content retained. Raw encoded ranges, failures and metadata are preserved in the original evidence directory. Export adjacency is not original disk adjacency.')
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':main()
