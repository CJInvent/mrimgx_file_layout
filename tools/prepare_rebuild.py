"""Discover NTFS MFT records and affected files from a read-only baseline."""
from rebuild_audit import caught as _audit_caught
import argparse,bisect,collections,json,pathlib,time
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.util.stream import RangeStream


def prepare(baseline,manifest,layout,output,partition=2):
    output.mkdir(exist_ok=False);p=layout['disks'][0]['partitions'][partition];origin=p['_geometry']['start'];v=VHDX(baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']))
    if fs.cluster_size!=4096:raise ValueError('mapping stages currently require 4096-byte NTFS clusters')
    cache=output/'mft.bin';mftsize=fs.mft.get(0).size()
    with cache.open('xb') as dst:
        fs.mft.fh.seek(0);remaining=mftsize
        while remaining:
            data=fs.mft.fh.read(min(8*1024**2,remaining))
            if not data:raise ValueError('short MFT stream')
            dst.write(data);remaining-=len(data)
    fs.mft.fh=cache.open('rb');ranges=[]
    for row in map(json.loads,manifest.open()):
        if row.get('partition')==partition and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable','reconstructed-unverified'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin,row['status']))
    ranges.sort();ends=[hi for lo,hi,status in ranges];counts=collections.Counter();last=time.monotonic();size=fs._record_size;allocated=None
    try:
        record=fs.mft.get(0);bitmap_type=ATTRIBUTE_TYPE_CODE.BITMAP
        for lcn,n in record.dataruns('',bitmap_type):
            if lcn is None:raise ValueError('sparse MFT allocation bitmap')
            if any(status in ('unknown-zero-index','unrecoverable') and lo<(lcn+n)*4096 and hi>lcn*4096 for lo,hi,status in ranges):raise ValueError('MFT allocation bitmap crosses missing data')
        if record.size('',bitmap_type)>2*1024**2:raise ValueError('excessive MFT bitmap')
        allocated=record.open('',bitmap_type).read()
        if len(allocated)*8<mftsize//size:raise ValueError('short MFT allocation bitmap')
    except Exception as _audit_error:
        _audit_caught(_audit_error, locals(), expected=False, site='prepare_rebuild.py:31')
        allocated=None
    with (output/'affected-files.jsonl').open('x') as out:
        for number in range(mftsize//size):
            try:
                if allocated is not None and not allocated[number//8]&(1<<(number%8)):
                    counts['unallocated_records']+=1;continue
                record=fs.mft.get(number)
                if not record.header.Flags&1:continue
                counts['active_records']+=1;hits=[]
                for typ in (ATTRIBUTE_TYPE_CODE.DATA,ATTRIBUTE_TYPE_CODE.INDEX_ALLOCATION):
                    for name in {a.header.name for a in record.attributes[typ]}:
                        if all(a.header.resident for a in record.attributes.find(name,typ)):continue
                        for lcn,n in record.dataruns(name,typ):
                            if lcn is None:continue
                            lo=lcn*4096;hi=(lcn+n)*4096;k=bisect.bisect_right(ends,lo)
                            while k<len(ranges) and ranges[k][0]<hi:
                                a,b,status=ranges[k];hits.append(dict(stream=name,type=int(typ),disk_offset=origin+max(lo,a),length=min(hi,b)-max(lo,a),status=status));k+=1
                if hits:
                    try:path=record.full_path()
                    except Exception as _audit_error:
                        _audit_caught(_audit_error, locals(), expected=False, site='prepare_rebuild.py:50')
                        path=record.filename
                    out.write(json.dumps(dict(record=number,path=path,ranges=hits))+'\n');counts['affected_records']+=1
            except Exception as e:
                _audit_caught(e, locals(), expected=False, site='prepare_rebuild.py:52')
                counts['unreadable_records']+=1
                if counts['unreadable_records']<=10:print('MFT',number,str(e),flush=True)
            if time.monotonic()-last>10:print(json.dumps(dict(record=number,counts=counts)),flush=True);last=time.monotonic();out.flush()
    (output/'summary.json').write_text(json.dumps(dict(counts=counts,partition=partition,mft_bytes=mftsize,mft_allocation_bitmap_readable=allocated is not None,scope='Original allocated DATA/INDEX runlist overlaps; unreadable allocated records may hide additional files. Unknown MFT bitmap falls back to parsing record slots.'),indent=2))
    return cache,output/'affected-files.jsonl'


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','manifest','layout','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--partition',type=int,default=2);a=ap.parse_args();prepare(a.baseline,a.manifest,json.loads(a.layout.read_text()),a.output,a.partition)
