"""Revisit external NTFS attribute lists through the recovered read-only overlay.

An initially unreadable nonresident ATTRIBUTE_LIST can silently hide DATA runs.
Raw record headers nominate records only; the normal NTFS parser and original
missing ranges determine inventory entries. Inventory never authorizes writes.
"""
import argparse,bisect,collections,json,mmap,pathlib,struct
from dissect.ntfs.util import apply_fixup
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from rebuild_context import Context
from rebuild_audit import caught


def external_attribute_list_records(data,record_size=1024):
    for start in range(0,len(data)-record_size+1,record_size):
        raw=data[start:start+record_size]
        if raw[:4]!=b'FILE' or not struct.unpack_from('<H',raw,22)[0]&1:continue
        # Attribute headers are 8-byte aligned, so their type cannot straddle
        # the sector fixup word. This inexpensive filter only nominates records.
        if b'\x20\0\0\0' not in raw:continue
        try:
            fixed=apply_fixup(raw);pos=struct.unpack_from('<H',fixed,20)[0]
            if pos<48 or pos%8:raise ValueError('invalid first attribute offset')
            while pos+24<=record_size:
                kind,length=struct.unpack_from('<II',fixed,pos)
                if kind==0xffffffff:break
                if length<24 or length%8 or pos+length>record_size:raise ValueError('invalid attribute bounds')
                if kind==32 and fixed[pos+8]==1:
                    yield start//record_size;break
                pos+=length
        except Exception as error:caught(error,dict(record=start//record_size),site='inventory-refresh-nomination')


def refresh(source,baseline,mft,inventory,manifest,evidence,mapping_directory,output):
    output.mkdir(exist_ok=False);ctx=Context(source,baseline,mft,manifest,evidence,mapping_directory)
    rows={r['record']:r for r in map(json.loads,inventory.open())};previous=set(rows);counts=collections.Counter();ranges=[]
    for r in map(json.loads,manifest.open()):
        if r.get('operation')=='range' and r.get('partition')==2 and r.get('status') in ('unknown-zero-index','unrecoverable','reconstructed-unverified'):
            ranges.append((r['disk_offset']-ctx.origin,r['disk_offset']+r['length']-ctx.origin,r['status']))
    ranges.sort();ends=[hi for lo,hi,status in ranges]
    if any(ends[i]<ends[i-1] for i in range(1,len(ends))):raise ValueError('overlapping missing ranges require normalization')
    with mft.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw,(output/'reports.jsonl').open('x') as reports:
        for number in external_attribute_list_records(raw,ctx.fs._record_size):
            counts['external_attribute_list_records']+=1
            try:
                record=ctx.fs.mft.get(number);hits=[]
                for typ in (ATTRIBUTE_TYPE_CODE.DATA,ATTRIBUTE_TYPE_CODE.INDEX_ALLOCATION):
                    for name in {a.header.name for a in record.attributes[typ]}:
                        if all(a.header.resident for a in record.attributes.find(name,typ)):continue
                        for lcn,n in record.dataruns(name,typ):
                            if lcn is None:continue
                            lo=lcn*ctx.fs.cluster_size;hi=(lcn+n)*ctx.fs.cluster_size;k=bisect.bisect_right(ends,lo)
                            while k<len(ranges) and ranges[k][0]<hi:
                                a,b,status=ranges[k];hits.append(dict(stream=name,type=int(typ),disk_offset=ctx.origin+max(lo,a),length=min(hi,b)-max(lo,a),status=status));k+=1
                if hits:
                    try:path=record.full_path()
                    except Exception as error:
                        caught(error,dict(record=number),site='inventory-refresh-path');path=record.filename
                    rows[number]=dict(record=number,path=path,ranges=hits)
                    if number not in previous:counts['new_affected_records']+=1;reports.write(json.dumps(dict(record=number,path=path,reason='external attribute list readable through current source-backed overlay'))+'\n')
            except Exception as error:
                counts['unreadable_records']+=1;caught(error,dict(record=number),site='inventory-refresh-record')
    with (output/'affected-files.jsonl').open('x') as stream:
        for number in sorted(rows):stream.write(json.dumps(rows[number])+'\n')
    summary=dict(counts=counts,previous_affected_records=len(previous),affected_records=len(rows),mapping_directory=str(mapping_directory.resolve()),scope='Discovery inventory only. Source, MFT, baseline and previous inventory unchanged; placement still requires independent validation.')
    (output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);ctx.close()


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    refresh(**vars(ap.parse_args()))
