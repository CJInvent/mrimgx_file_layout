"""Retry undecoded residual candidates and inspect raw metadata for NTFS records."""
import argparse
import bisect
import hashlib
import json
import pathlib
import sqlite3

import zstandard
from dissect.ntfs.util import apply_fixup


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('evidence',type=pathlib.Path);ap.add_argument('output',type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    known_ranges=sorted((pos,pos+n) for pos,n in db.execute('SELECT source_offset,stored_length FROM frames'))
    starts=[lo for lo,hi in known_ranges];results=[];raw_records=[];nested=0
    with (a.evidence/'source-residual.bin').open('rb') as residual, (a.output/'partial-decoded.bin').open('xb') as partial:
        for line in (a.evidence/'source-residual-map.jsonl').open():
            item=json.loads(line);residual.seek(item['export_offset']);data=residual.read(item['length']);off=0
            while True:
                off=data.find(bytes.fromhex('28b52ffd'),off)
                if off<0:break
                position=item['source_offset']+off;off+=4
                k=bisect.bisect_right(starts,position)-1
                if k>=0 and position<known_ranges[k][1]:
                    nested+=1;continue
                raw=data[off-4:off-4+5*1024**2];report=dict(source_offset=position,remaining_range_bytes=len(data)-(off-4))
                try:
                    p=zstandard.get_frame_parameters(raw);report.update(declared_size=p.content_size,checksum=p.has_checksum)
                    decoder=zstandard.ZstdDecompressor().decompressobj();chunks=[]
                    for start in range(0,len(raw),64):
                        try:
                            chunk=decoder.decompress(raw[start:start+64]);chunks.append(chunk)
                            if sum(map(len,chunks))>4*1024**2:raise ValueError('partial output limit')
                            if decoder.eof:break
                        except Exception as ex:
                            report.update(error=str(ex),error_input_offset=position+start);break
                    decoded=b''.join(chunks);report.update(decoded_prefix_bytes=len(decoded),eof=decoder.eof)
                    if decoded:
                        report.update(export_offset=partial.tell(),sha256=hashlib.sha256(decoded).hexdigest());partial.write(decoded)
                except Exception as ex:report['header_error']=str(ex)
                results.append(report)
            for signature,length in ((b'FILE',1024),(b'INDX',4096)):
                offset=0
                while True:
                    offset=data.find(signature,offset)
                    if offset<0:break
                    if len(data)-offset>=length:
                        try:apply_fixup(data[offset:offset+length]);raw_records.append(dict(source_offset=item['source_offset']+offset,signature=signature.decode(),length=length,fixup_valid=True))
                        except Exception:pass
                    offset+=4
    metadata=(a.evidence/'source-metadata-tail.bin').read_bytes();start=json.loads((a.evidence/'coverage-summary.json').read_text())['data_region_end']
    for signature,length in ((b'FILE',1024),(b'INDX',4096)):
        offset=0
        while True:
            offset=metadata.find(signature,offset)
            if offset<0:break
            if len(metadata)-offset>=length:
                try:apply_fixup(metadata[offset:offset+length]);raw_records.append(dict(source_offset=start+offset,signature=signature.decode(),length=length,fixup_valid=True))
                except Exception:pass
            offset+=4
    result=dict(retried_candidates=results,raw_fixup_valid_records=raw_records,nested_magic_hits_skipped=nested,scope='Bytewise raw residual and metadata search, plus bounded incremental decompression of candidates outside all decoded frame intervals. Nested compressed signatures are not independent orphan frames.')
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))


if __name__=='__main__':main()
