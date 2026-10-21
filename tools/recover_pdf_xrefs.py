"""Map frames using original PDF cross-reference addresses and NTFS file extents.

Requires two distinct object headers agreeing on one frame base. Original classic
tables or xref streams require original startxref/EOF anchors; no rebuilt xref.
"""
import argparse
import bisect
import collections
import functools
import hashlib
import json
import io
import logging
import pathlib
import re
import sqlite3

import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def classic_xrefs(data):
    anchors=list(re.finditer(rb'startxref\s+(\d+)\s+%%EOF',data[-8192:]))
    if not anchors:return {}
    cursor=int(anchors[-1][1]);visited=set();entries={}
    while cursor not in visited:
        visited.add(cursor)
        if data[cursor:cursor+4]!=b'xref':break
        position=cursor+4
        while True:
            position+=re.match(rb'\s*',data[position:]).end()
            section=re.match(rb'(\d+)\s+(\d+)\s*\r?\n',data[position:])
            if not section:break
            first,n=map(int,section.groups());position+=section.end()
            if n>len(data)//18:raise ValueError('xref entry count')
            for number in range(first,first+n):
                entry=re.match(rb'(\d{10}) (\d{5}) ([nf])[ \r\n]+',data[position:])
                if not entry:raise ValueError('invalid xref entry')
                position+=entry.end()
                if entry[3]==b'n':
                    offset=int(entry[1])
                    if offset>=len(data):raise ValueError('xref offset out of file')
                    entries.setdefault((number,int(entry[2])),offset)
        trailer=data[position:position+2048].split(b'startxref',1)[0]
        if not trailer.lstrip().startswith(b'trailer'):raise ValueError('missing original xref trailer')
        prev=re.search(rb'/Prev\s+(\d+)',trailer)
        if not prev:break
        cursor=int(prev[1])
    return entries


def stream_xrefs(data):
    from pypdf import PdfReader
    anchors=list(re.finditer(rb'startxref\s+(\d+)\s+%%EOF',data[-8192:]))
    if not anchors:return {}
    offset=int(anchors[-1][1]);header=data[offset:offset+8192]
    if not re.match(rb'\d+\s+\d+\s+obj\b',header) or not re.search(rb'/Type\s*/XRef\b',header):return {}
    class OriginalReader(PdfReader):
        def _rebuild_xref_table(self,stream):raise ValueError('xref rebuild disallowed')
    # Original xref bytes remain authoritative even if the beginning of the
    # file is missing. The parser may warn about that header; never manufacture
    # source bytes or let it reconstruct object addresses from signatures.
    logger=logging.getLogger('pypdf');oldlevel=logger.level;logger.setLevel(logging.ERROR)
    try:reader=OriginalReader(io.BytesIO(data),strict=False)
    finally:logger.setLevel(oldlevel)
    entries={}
    for generation,objects in reader.xref.items():
        for number,position in objects.items():
            if number and 0<position<len(data):entries[(number,generation)]=position
    return entries


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted)
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][2]
    origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2}
    ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        if base in mapped:return False
        k=bisect.bisect_right(starts,base)-1
        return k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']));fs.mft.fh=a.mft.open('rb',buffering=8*1024**2)
    source=a.source.open('rb');targets=collections.defaultdict(list);parsed=0;errors=[]
    @functools.lru_cache(maxsize=256)
    def source_frame(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    for row in map(json.loads,a.inventory.open()):
        if not (row.get('path') or '').lower().endswith('.pdf'):continue
        try:
            r=fs.mft.get(row['record'])
            if r.size()>64*1024**2 or any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):continue
            data=bytearray(r.open().read());runs=[];logical=0
            for lcn,count in r.dataruns():
                if lcn is not None:runs.append((logical,logical+count*4096,lcn*4096))
                logical+=count*4096
            for base,m in mapped.items():
                for lo,hi,physical in runs:
                    start=max(physical,base);end=min(physical+hi-lo,base+stride)
                    if end>start:
                        decoded=source_frame(m['source_offset'],m['stored_length']);offset=lo+start-physical;n=min(end-start,len(data)-offset)
                        if n>0:data[offset:offset+n]=decoded[start-base:start-base+n]
            entries=classic_xrefs(data) or stream_xrefs(data)
            if entries:
                parsed+=1
                for (number,generation),offset in entries.items():
                    for lo,hi,physical in runs:
                        if lo<=offset<hi:targets[(number,generation)].append(dict(record=row['record'],address=physical+offset-lo,file_offset=offset))
        except Exception as ex:errors.append(dict(record=row['record'],error=str(ex)))
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);used={fid for m in accepted for fid in m['frames']};pending=collections.defaultdict(list)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus,(a.output/'pdf-evidence.jsonl').open('x') as log:
        for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
            f=dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row))
            if f['id'] in used or f['decoded_length']!=stride:continue
            corpus.seek(f['export_offset']);data=corpus.read(stride);votes=collections.defaultdict(list)
            for obj in re.finditer(rb'(?<![0-9])([0-9]{1,8})[ \t]+([0-9]{1,5})[ \t]+obj[\s<]',data):
                number,generation=map(int,obj.groups())
                for t in targets.get((number,generation),[]):
                    base=t['address']-obj.start()
                    if base>=0 and base%stride==0 and unknown(base):votes[base].append(dict(t,object=number,generation=generation,frame_offset=obj.start()))
            qualified={base:rows for base,rows in votes.items() if len({(e['record'],e['object'],e['generation']) for e in rows})>=2}
            if len(qualified)!=1:continue
            base,evidence=next(iter(qualified.items()));log.write(json.dumps(dict(frame=f['id'],base=base,anchors=evidence))+'\n');pending[base].append((f,evidence))
    conflicts=[]
    for base,rows in sorted(pending.items()):
        if len({f['sha256'] for f,e in rows})!=1:conflicts.append(base);continue
        f=rows[0][0];data=source_frame(f['source_offset'],f['stored_length'])
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f['sha256'] or hashlib.md5(data).digest()!=f['md5']:raise ValueError('source revalidation')
        m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=sorted({f['id'] for f,e in rows}),evidence=[dict(method='pdf-original-xref-mft-runlist',detail=e) for f,e in rows])
        accepted.append(m);plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),reason='Multiple distinct PDF object headers map through original xref offsets and NTFS MFT runlists to one unique frame base; reconstructed, original digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),pdf_additions=len(accepted)-previous,parsed_pdf_xrefs=parsed,conflicts=conflicts,rejected_pdf_xrefs=errors)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:v for k,v in result.items() if k!='rejected_pdf_xrefs'}),flush=True)


if __name__=='__main__':main()
