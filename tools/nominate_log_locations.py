"""Add unproven original path hints to recovered gzip logs, never authorize writes."""
import argparse,collections,datetime,hashlib,json,mmap,pathlib,re,struct,zlib
from discover_duplicate_pairs import candidate_records
from rebuild_audit import emit


def filename_time(name):
    match=re.search(r'_(\d{4}-\d{2}-\d{2})_(\d{6})_\d+-\d+\.loggz$',name,re.I)
    if match:
        try:return datetime.datetime.strptime(match[1]+match[2],'%Y-%m-%d%H%M%S')
        except ValueError:pass
    return None


def log_time(data):
    try:return datetime.datetime.strptime(data[:38].decode('utf-16-le'),'%m/%d/%Y %H:%M:%S')
    except (ValueError,UnicodeDecodeError):return None


def matching_names(names,size,expected_size,start):
    if size!=expected_size or start is None:return []
    return [name for name in names if filename_time(name)==start]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('mft','inventory','recovered_files','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();wanted=collections.defaultdict(list);counts=collections.Counter();report=[]
    for side in (a.recovered_files/'files').glob('*.gz.json'):
        meta=json.loads(side.read_text());data=side.with_suffix('').read_bytes()
        if len(data)!=meta['bytes'] or hashlib.sha256(data).hexdigest()!=meta['sha256']:raise ValueError('Recovered gzip changed before metadata nomination')
        decoder=zlib.decompressobj(31);plain=decoder.decompress(data,256*1024**2+1)
        if not decoder.eof or decoder.unused_data or len(plain)>256*1024**2:raise ValueError('Recovered gzip integrity/expansion bound differs')
        start=log_time(plain)
        if start is not None:wanted[(len(data),start)].append((side,meta))
    paths={r['record']:r for r in map(json.loads,a.inventory.open())}
    with a.mft.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
        for number,names,size in candidate_records(raw):
            for name in names:
                start=filename_time(name)
                if (size,start) not in wanted:continue
                record=raw[number*1024:(number+1)*1024];seq=struct.unpack_from('<H',record,16)[0];location=dict(record=number,sequence=seq,path=paths.get(number,{}).get('path'),original_filename=name,original_size=size,original_mft_record_sha256=hashlib.sha256(record).hexdigest(),original_affected_ranges=paths.get(number,{}).get('ranges',[]),evidence_kind='file-size-and-embedded-log-start-time-nomination',embedded_log_start_time=start.isoformat(),placement_confirmed=False,historical_path_binding_proven=False,original_whole_file_digest_available=False,note='Filename second and complete gzip size agree with decoded log start time. Process/thread identity and historical file digest are unproven; this is a candidate location only.')
                for side,meta in wanted[(size,start)]:
                    locations=meta.setdefault('possible_locations',[])
                    if not any(r.get('record')==number and r.get('evidence_kind')==location['evidence_kind'] for r in locations):locations.append(location);counts['candidate_locations']+=1
                    meta['vhdx_insertion_authorized']=False;side.write_text(json.dumps(meta,indent=2));report.append(dict(file=str(side.with_suffix('').resolve()),sha256=meta['sha256'],location=location));emit('candidate-file-location','Original metadata nominates a possible recovered log location',context=report[-1])
    summary=dict(counts=dict(counts),files_with_log_start_time=sum(map(len,wanted.values())),nominations=report,scope='Metadata hints only. No source, MFT or image writes; file size and embedded timestamp do not authorize a historical filesystem placement.');a.output.write_text(json.dumps(summary,indent=2));print(json.dumps(dict(counts=dict(counts),files_with_log_start_time=summary['files_with_log_start_time'])),flush=True)


if __name__=='__main__':main()
