"""Recheck the complete cached entry catalog against original raw index bytes."""
import argparse,hashlib,itertools,json,sqlite3,struct
from make_recovery_plan import make_plan,read_at
from forensic_residuals import root_layout


def expected_rows(stream,size,plan,layout,failed):
    for pi,(spec,p) in enumerate(zip(plan['partitions'],layout['disks'][0]['partitions'])):
        for reserved in (True,False):
            count=spec['reserved_count'] if reserved else spec['count']
            if not count:continue
            offset=spec['reserved_offset'] if reserved else spec['entries_offset'];raw=read_at(stream,offset,count*30,size)
            stride=4*1024**2 if reserved else p['_header']['block_size'];origin=p['_geometry']['start']+(p['_geometry'].get('boot_sector_offset',0) if reserved else p['_file_system'].get('lcn0_offset',0)-p['_file_system'].get('start',0));limit=origin+p['_file_system']['reserved_sectors_byte_length'] if reserved else p['_geometry']['start']+p['_geometry']['length']
            for block,(position,digest,n,file_number) in enumerate(struct.iter_unpack('<q16sIH',raw)):
                address=origin+block*stride
                if address>=limit:continue
                override=None if reserved else spec.get('overrides',{}).get(str(block));incorporated=bool(n and not override and (pi,reserved,block) not in failed)
                if n or position or digest!=bytes(16):yield(pi,int(reserved),block,address,min(stride,limit-address),position,n,digest,int(incorporated))


def compare(expected,actual):
    count=0;ledger=hashlib.sha256()
    for wanted,cached in itertools.zip_longest(expected,actual):
        if wanted!=cached:raise ValueError('Original source index and cached entry catalog differ at row '+str(count)+': '+str((wanted,cached)))
        ledger.update(repr(wanted).encode());count+=1
    return dict(valid=True,verified_entries=count,ledger_sha256=ledger.hexdigest())


def main():
    import pathlib
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','evidence','manifest','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();plan=json.loads((a.evidence/'input-plan.json').read_text());layout=root_layout(a.source)
    if make_plan(a.source,plan)!=plan or json.loads((a.evidence/'layout.json').read_text())!=layout:raise ValueError('Catalog source layout/plan fingerprint differs')
    failed={(r['partition'],r.get('reserved',False),r['block']) for r in map(json.loads,a.manifest.open()) if r.get('status')=='unrecoverable'}
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    try:
        with a.source.open('rb') as stream:result=compare(expected_rows(stream,a.source.stat().st_size,plan,layout,failed),db.execute('SELECT partition,reserved,block,disk_offset,decoded_length,source_offset,stored_length,digest,incorporated FROM entries ORDER BY partition,reserved DESC,block'))
        a.output.write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
    finally:db.close()


if __name__=='__main__':main()
