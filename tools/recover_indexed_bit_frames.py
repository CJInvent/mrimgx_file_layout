"""Exhaustively try one encoded-bit repairs against original indexed MD5 values.

Every repaired frame is an external derivative. Only unique native repairs that
decode to the original indexed length/MD5 produce supplemental placement requests.
"""
import argparse,hashlib,json,pathlib,sqlite3,subprocess
import zstandard


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifest','evidence','mapping_directory','repair_exe','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--reuse-negative-attempts',type=pathlib.Path,help='reuse completed exhaustive zero-match tests only when their original encoded input is byte-identical')
    a=ap.parse_args();a.output.mkdir(exist_ok=False);db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);maps=[] if str(a.mapping_directory)=='-' else json.loads((a.mapping_directory/'accepted-mappings.json').read_text());mapped={(m['partition'],m['disk_offset'],m['length']) for m in maps};reports=[];requests=[];before=a.source.stat();errors=[];data_end=json.loads((a.evidence/'coverage-summary.json').read_text())['data_region_end']
    targets=[row for row in map(json.loads,a.manifest.open()) if row.get('status')=='unrecoverable' and (row['partition'],row['disk_offset'],row['length']) not in mapped]
    # A temporary key table permits one sequential scan of a read-only
    # evidence catalog, rather than a full scan per damaged index entry.
    db.execute('CREATE TEMP TABLE wanted(partition,disk_offset,PRIMARY KEY(partition,disk_offset))')
    db.executemany('INSERT OR IGNORE INTO wanted VALUES(?,?)',[(r['partition'],r['disk_offset']) for r in targets]);by_target={}
    for entry in db.execute('SELECT e.source_offset,e.stored_length,e.digest,e.decoded_length,e.partition,e.reserved,e.block,e.disk_offset FROM entries e JOIN wanted w ON e.partition=w.partition AND e.disk_offset=w.disk_offset'):by_target.setdefault((entry[4],entry[7]),[]).append(entry)
    with a.source.open('rb') as source:
        for row in targets:
            entries=by_target.get((row['partition'],row['disk_offset']),[])
            if len(entries)!=1:errors.append(dict(row=row,error='ambiguous original index entry'));continue
            offset,stored,md5,length,partition,reserved,block,disk_offset=entries[0];report=dict(source_offset=offset,encoded_bytes=stored,original_md5=md5.hex(),decoded_length=length,partition=partition,block=block,disk_offset=disk_offset);reports.append(report)
            if not 0<stored<=5*1024**2 or not 0<length<=4*1024**2 or not 0<=offset<offset+stored<=data_end or md5==bytes(16):report['skipped']='source/native bounds or missing original digest';continue
            source.seek(offset);raw=source.read(stored)
            if len(raw)!=stored:raise ValueError('source short read')
            if len(raw)<4 or sum((a^b).bit_count() for a,b in zip(raw[:4],bytes.fromhex('28b52ffd')))>1 or sum(bool(b) for b in md5)<12:report['skipped']='not a normal Zstd magic within one bit, or insufficient original digest bytes';continue
            if a.reuse_negative_attempts:
                old=a.reuse_negative_attempts/f'{partition}-{block}.log';old_input=a.reuse_negative_attempts/f'{partition}-{block}-original.bin'
                try:
                    cached=json.loads(old.read_text())
                    if cached.get('status')=='no-unique-single-bit-repair' and cached.get('original_decoded_md5')==md5.hex() and cached.get('decoded_bytes')==length and cached.get('matches')==0 and cached.get('tested_bytes')==len(raw) and old_input.read_bytes()==raw:
                        report.update(status='no-unique-single-bit-repair',reused_negative_log=str(old.resolve()),reused_log_sha256=hashlib.sha256(old.read_bytes()).hexdigest());print(json.dumps(dict(event='reused-complete-negative-test',**report)),flush=True);continue
                except (OSError,ValueError):pass
            input_path=a.output/f'{partition}-{block}-original.bin';fixed=a.output/f'{partition}-{block}-repaired.bin'
            with input_path.open('xb') as out:out.write(raw)
            print(json.dumps(dict(event='bit-search-begin',**report)),flush=True)
            try:
                with (a.output/f'{partition}-{block}.progress.log').open('x') as progress:
                    result=subprocess.run([str(a.repair_exe),str(input_path),str(fixed),md5.hex(),str(length)],stdout=subprocess.PIPE,stderr=progress,text=True)
            except OSError as e:report['error']=str(e);errors.append(dict(row=report,error=str(e)));continue
            (a.output/f'{partition}-{block}.log').write_text(result.stdout);report['returncode']=result.returncode
            if result.returncode==2:report['status']='no-unique-single-bit-repair';continue
            if result.returncode:errors.append(dict(row=report,error='native failure; see progress log'));continue
            native=json.loads(result.stdout)
            if native['status']=='input-already-matches':fixed=input_path
            elif native['status']!='unique-original-md5-repair':raise ValueError('unexpected native repair result')
            encoded=fixed.read_bytes();data=zstandard.ZstdDecompressor().decompress(encoded)
            if len(data)!=length or hashlib.md5(data).digest()!=md5:raise ValueError('native repair did not reproduce original indexed MD5/length')
            decoded=a.output/f'{partition}-{block}-decoded.bin'
            with decoded.open('xb') as out:out.write(data)
            proof=dict(method='unique-original-index-md5-bit-repair',original_md5=md5.hex(),native_result=native,partition=partition,block=block,original_index_disk_offset=disk_offset);request=dict(partition=partition,disk_offset=disk_offset,length=length,source_offset=offset,stored_length=stored,decoded_md5=md5.hex(),sha256=hashlib.sha256(data).hexdigest(),evidence=[proof])
            if fixed!=input_path:request['encoded_bit_repair']=dict(encoded_path=str(fixed.resolve()),original_encoded_sha256=hashlib.sha256(raw).hexdigest(),repaired_encoded_sha256=hashlib.sha256(encoded).hexdigest())
            requests.append(request);report.update(status=native['status'],decoded_sha256=request['sha256'],decoded_path=str(decoded.resolve()))
            (decoded.with_suffix('.bin.json')).write_text(json.dumps(dict(kind='verified-repaired-frame',placement_status='original-index-address-validated',vhdx_written=False,**request),indent=2))
    after=a.source.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('source changed')
    (a.output/'supplemental-placements.json').write_text(json.dumps(requests,indent=2));(a.output/'reports.json').write_text(json.dumps(reports,indent=2));summary=dict(attempted=len(reports),verified_repairs=len(requests),verified_decoded_bytes=sum(m['length'] for m in requests),source_stat_unchanged=True,errors=errors,scope='Exhaustive single encoded-bit flips within native bounds only; no unique repair excludes this repair class, not every possible reconstruction. Original encoded input and repair derivatives are preserved.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
    if errors:raise RuntimeError('some bit-repair attempts failed; inspect reports')


if __name__=='__main__':main()
