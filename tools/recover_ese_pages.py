"""Map ESE large pages using verified self-addresses and database header bounds.

Requires two full XOR/ECC-valid pages agreeing per frame, unique placement among
affected databases, and collective exact maximum DBTIME and OBJID agreement
with the original checksum-valid database header. Structural inference, not an
original backup digest. No page correction or database recovery is performed.
"""
from rebuild_audit import caught as _audit_caught
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import sqlite3
import struct
import zstandard
from safe_vhdx import VHDX
from ese_checksums import valid_large_page
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--cross-boundary',action='store_true',help='validate page checksums spanning already mapped neighboring frames')
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text())
    p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][2];origin=p['_geometry']['start'];stride=p['_header']['block_size'];used={f for m in accepted for f in m['frames']};mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2};ranges=[]
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    def known_range(lo,hi,candidate=None):
        k=max(0,bisect.bisect_right(starts,lo)-1)
        for l,h in ranges[k:]:
            if l>=hi:break
            cursor=max(lo,l);stop=min(hi,h)
            while cursor<stop:
                base=cursor//stride*stride
                if base not in mapped and base!=candidate:return False
                cursor=min(stop,base+stride)
        return True
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']));fs.mft.fh=a.mft.open('rb');source=a.source.open('rb');targets=[];errors=[];contents={};surviving=collections.defaultdict(list)
    for row in map(json.loads,a.inventory.open()):
        if not (row.get('path') or '').lower().endswith('.edb'):continue
        try:
            r=fs.mft.get(row['record']);runs=list(r.dataruns())
            if len(runs)!=1 or runs[0][0] is None or any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):continue
            physical=runs[0][0]*4096;head=bytearray(r.open().read(4096))
            for mb,m in mapped.items():
                lo=max(physical,mb);hi=min(physical+4096,mb+m['length'])
                if hi>lo:
                    source.seek(m['source_offset']);data=zstandard.ZstdDecompressor().decompress(source.read(m['stored_length']));head[lo-physical:hi-physical]=data[lo-mb:hi-mb]
            if len(head)!=4096 or head[4:8]!=bytes.fromhex('efcdab89'):continue
            page=struct.unpack_from('<I',head,236)[0]
            if page not in (16384,32768) or not any(unknown(b) for b in range(physical//stride*stride,physical+r.size(),stride)):continue
            check=0x89abcdef
            for word, in struct.iter_unpack('<I',head[4:]):check^=word
            if check!=struct.unpack_from('<I',head)[0]:raise ValueError('header checksum')
            targets.append(dict(record=row['record'],size=r.size(),physical=physical,page_size=page,dbtime=struct.unpack_from('<Q',head,16)[0],last_objid=struct.unpack_from('<I',head,212)[0],signature=head[24:52].hex()))
            if a.cross_boundary:
                if r.size()>64*1024**2:raise ValueError('cross-boundary database exceeds memory bound')
                data=bytearray(r.open().read())
                for mb,m in mapped.items():
                    lo=max(physical,mb);hi=min(physical+r.size(),mb+m['length'])
                    if hi>lo:
                        source.seek(m['source_offset']);decoded=zstandard.ZstdDecompressor().decompress(source.read(m['stored_length']));data[lo-physical:hi-physical]=decoded[lo-mb:hi-mb]
                contents[row['record']]=data
                for offset in range(2*page,len(data)-page+1,page):
                    if known_range(physical+offset,physical+offset+page) and valid_large_page(data[offset:offset+page]):
                        surviving[row['record']].append(dict(pgno=struct.unpack_from('<I',data,offset+64)[0],dbtime=struct.unpack_from('<Q',data,offset+8)[0],objid=struct.unpack_from('<I',data,offset+24)[0]))
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='recover_ese_pages.py:75')
            errors.append(dict(record=row['record'],error=str(e)))
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);results=[];pending=collections.defaultdict(list)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
            if f[0] in used or f[4]!=stride:continue
            corpus.seek(f[3]);data=corpus.read(stride);votes=collections.defaultdict(list)
            for t in targets:
                page=t['page_size']
                for pos in range(0,stride-page+1,4096):
                    pgno=struct.unpack_from('<I',data,pos+64)[0];dbtime=struct.unpack_from('<Q',data,pos+8)[0];objid=struct.unpack_from('<I',data,pos+24)[0];logical=(pgno+1)*page-pos;base=t['physical']+logical
                    if not 0<pgno<t['size']//page-1 or not 0<dbtime<=t['dbtime'] or not 0<objid<=t['last_objid'] or logical<0 or logical+stride>t['size'] or base%stride or not unknown(base):continue
                    if valid_large_page(data[pos:pos+page]):votes[(t['record'],base)].append(dict(decoded_offset=pos,pgno=pgno,dbtime=dbtime,objid=objid))
            if a.cross_boundary:
                for (record,base),pages in list(votes.items()):
                    if len(pages)!=1 or record not in contents:continue
                    t=next(t for t in targets if t['record']==record);page=t['page_size'];physical=t['physical'];logical=base-physical
                    for offset in sorted({logical//page*page,(logical+stride)//page*page}):
                        if offset<2*page or offset+page>t['size'] or not known_range(physical+offset,physical+offset+page,base):continue
                        piece=bytearray(contents[record][offset:offset+page]);lo=max(offset,logical);hi=min(offset+page,logical+stride)
                        if hi<=lo or hi-lo==page:continue
                        piece[lo-offset:hi-offset]=data[lo-logical:hi-logical]
                        if valid_large_page(piece) and struct.unpack_from('<I',piece,64)[0]==offset//page-1:
                            pages.append(dict(decoded_offset=offset-logical,pgno=offset//page-1,dbtime=struct.unpack_from('<Q',piece,8)[0],objid=struct.unpack_from('<I',piece,24)[0],cross_boundary=True))
            qualified={key:pages for key,pages in votes.items() if len(pages)>=2}
            if len(qualified)==1:
                (record,base),pages=next(iter(qualified.items()));item=dict(frame=f[0],record=record,base=base,pages=pages);results.append(item);pending[record].append((f,item))
    conflicts=[];groups=[]
    for t in targets:
        items=pending[t['record']];pages=surviving[t['record']]+[page for f,item in items for page in item['pages']]
        if len(pages)<6 or (len(items)<3 and not surviving[t['record']]) or max((p['dbtime'] for p in pages),default=0)!=t['dbtime'] or max((p['objid'] for p in pages),default=0)!=t['last_objid']:continue
        groups.append(dict(target=t,frames=len(items),checksum_valid_pages=len(pages)));bybase=collections.defaultdict(list)
        for f,item in items:bybase[item['base']].append((f,item))
        for base,rows in sorted(bybase.items()):
            if len({f[6] for f,item in rows})!=1:conflicts.append(base);continue
            f=rows[0][0];source.seek(f[1]);data=zstandard.ZstdDecompressor().decompress(source.read(f[2]))
            if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source revalidation')
            evidence=[dict(method='ese-large-page-checksums-self-addresses-header-bounds',database=t,group_frames=len(items),group_pages=len(pages),pages=item['pages']) for f,item in rows]
            accepted.append(dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=[f[0] for f,item in rows],evidence=evidence))
            plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Multiple full ESE pages validate all XOR/ECC checksums and self-page addresses; unique affected-file runlist/grid and exact collective DBTIME/OBJID maxima match original database header. Structural identity inference; original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'ese-candidates.json').write_text(json.dumps(results,indent=2))
    result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),ese_additions=len(accepted)-previous,groups=groups,conflicts=conflicts,errors=errors)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
