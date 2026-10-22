"""Recover PNG file frames through IDAT grids, crossing CRCs and full validation.

Proposals stay local until every missing file byte is resolved, all PNG chunk
CRCs validate, and the zlib/Adler stream has the exact expected scanline size.
No source-order inference and no executable content is evaluated.
"""
from rebuild_audit import caught as _audit_caught
import argparse,bisect,collections,functools,hashlib,json,math,pathlib,sqlite3,struct,zlib
import zstandard
from safe_vhdx import VHDX
from mapped_volume import MappedVolume
from dissect.ntfs import NTFS
from recover_duplicate_files import file_extents


def chunk(data,offset):
    if offset<0 or offset+12>len(data):raise ValueError('PNG chunk header bounds')
    n=struct.unpack_from('>I',data,offset)[0];end=offset+n+12
    if end>len(data):raise ValueError('PNG chunk bounds')
    if zlib.crc32(data[offset+4:end-4])&0xffffffff!=struct.unpack_from('>I',data,end-4)[0]:raise ValueError('PNG chunk CRC')
    return data[offset+4:offset+8],n,end


def first_idat(data):
    if data[:8]!=b'\x89PNG\r\n\x1a\n':raise ValueError('PNG signature')
    offset=8
    while offset+12<=len(data):
        n=struct.unpack_from('>I',data,offset)[0]
        if data[offset+4:offset+8]==b'IDAT':return offset,n
        typ,n,offset=chunk(data,offset)
    raise ValueError('missing IDAT header')


def validate_png(data):
    first_idat(data);offset=8;idat=[];header=None;palette=None;idat_ended=False
    while offset<len(data):
        start=offset;typ,n,offset=chunk(data,offset)
        if typ not in (b'IHDR',b'PLTE',b'IDAT',b'IEND') and 65<=typ[0]<=90:raise ValueError('unknown critical PNG chunk')
        if typ==b'IHDR':
            if start!=8 or n!=13 or header is not None:raise ValueError('IHDR placement')
            header=struct.unpack_from('>IIBBBBB',data,start+8)
        if typ==b'PLTE':
            if palette is not None or not n or n%3 or n>768:raise ValueError('PNG palette')
            palette=n//3
        if typ==b'IDAT':
            if idat_ended:raise ValueError('nonconsecutive IDAT chunks')
            idat.append(data[start+8:start+8+n])
        elif idat:idat_ended=True
        if typ==b'IEND':
            if n or offset!=len(data):raise ValueError('IEND/overlay bounds')
            break
    else:raise ValueError('missing IEND')
    if header is None:raise ValueError('missing IHDR')
    width,height,depth,color,compression,filter_method,interlace=header;channels={0:1,2:3,3:1,4:2,6:4}.get(color)
    if not channels or depth not in (1,2,4,8,16) or compression or filter_method or interlace not in (0,1) or not width or not height:raise ValueError('unsupported PNG header')
    if color in (2,4,6) and depth not in (8,16) or color==3 and depth==16:raise ValueError('PNG color/depth combination')
    if color==3 and (palette is None or palette>1<<depth):raise ValueError('indexed PNG palette')
    passes=[(0,0,1,1)] if not interlace else [(0,0,8,8),(4,0,8,8),(0,4,4,8),(2,0,4,4),(0,2,2,4),(1,0,2,2),(0,1,1,2)]
    layouts=[]
    for x,y,dx,dy in passes:
        w=max(0,(width-x+dx-1)//dx);h=max(0,(height-y+dy-1)//dy)
        if w and h:layouts.append((h,1+(w*channels*depth+7)//8))
    expected=sum(h*n for h,n in layouts)
    if expected>256*1024**2:raise ValueError('PNG pixel bound')
    dec=zlib.decompressobj();raw=dec.decompress(b''.join(idat),expected+1)
    if len(raw)!=expected or not dec.eof or dec.unused_data or dec.unconsumed_tail:raise ValueError('PNG zlib/Adler or scanline size')
    pos=0
    for h,n in layouts:
        for _ in range(h):
            if raw[pos]>4:raise ValueError('PNG scanline filter')
            pos+=n
    return dict(width=width,height=height,depth=depth,color=color,interlace=interlace,decoded_scanline_bytes=expected,idat_chunks=len(idat))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);pi=2
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text());previous=len(accepted);plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text());p=json.loads((a.evidence/'layout.json').read_text())['disks'][0]['partitions'][pi];origin=p['_geometry']['start'];stride=p['_header']['block_size'];mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==pi};ranges=[]
    for row in map(json.loads,a.baseline_manifest.open()):
        if row.get('partition')==pi and row.get('status') in ('unknown-zero-index','unrecoverable'):ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[lo for lo,hi in ranges]
    def unknown(base):
        k=bisect.bisect_right(starts,base)-1
        return base not in mapped and k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    source=a.source.open('rb')
    @functools.lru_cache(maxsize=64)
    def decode(offset,length):
        source.seek(offset);return zstandard.ZstdDecompressor().decompress(source.read(length))
    v=VHDX(a.baseline);fs=NTFS(MappedVolume(v,origin,p['_geometry']['length'],mapped,decode));fs.mft.fh=a.mft.open('rb');db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);frames=collections.defaultdict(list);data_by_hash={};anchors=collections.defaultdict(list)
    with (a.evidence/'orphan-decoded.bin').open('rb') as corpus:
        for f in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames WHERE decoded_length=?',(stride,)):
            frames[f[6]].append(f)
            if f[6] in data_by_hash:continue
            corpus.seek(f[3]);data=corpus.read(stride);data_by_hash[f[6]]=data;position=0
            while True:
                position=data.find(b'IDAT',position)
                if position<0:break
                h=position-4;position+=4
                try:
                    typ,n,end=chunk(data,h)
                    if n>=4096:anchors[n].append((f[6],h))
                except Exception as _audit_error:
                    _audit_caught(_audit_error, None, expected=True, site='recover_png_crc_grid.py:102')
                    pass
    proposals=collections.defaultdict(list);reports=[]
    for row in map(json.loads,a.inventory.open()):
        path=row.get('path') or ''
        if pathlib.PureWindowsPath(path).suffix.casefold() not in ('.png','.apng','.jpg','.jpeg'):continue
        report=dict(record=row['record'],path=path);reports.append(report)
        try:
            r=fs.mft.get(row['record']);size=r.size()
            if not 32768<=size<=32*1024**2:continue
            extents=file_extents(r,size)
            if len(extents)!=1:continue
            physical=extents[0][1];buffer=bytearray(r.open().read());first,n=first_idat(buffer);step=n+12
            if not n or n>1024**2:continue
            missing={b for b in range(physical//stride*stride,physical+size,stride) if unknown(b)}
            if not missing:continue
            known=bytearray(b'\1')*size
            for base in missing:
                lo=max(0,base-physical);hi=min(size,base+stride-physical);known[lo:hi]=b'\0'*(hi-lo)
            candidates=collections.defaultdict(set);g=math.gcd(step,stride);period=stride//g;inverse=pow(step//g,-1,period)
            for sha,h in anchors[n]:
                delta=h-physical-first
                if delta%g:continue
                start=(delta//g*inverse)%period
                for number in range(start,max(0,(size-first)//step)+1,period):
                    logical=first+number*step-h;base=physical+logical
                    if logical>=0 and base in missing:candidates[base].add(sha)
            local={};progress=True
            while progress:
                progress=False
                for base in missing-local.keys():
                    logical=base-physical;lo=max(0,logical);hi=min(size,logical+stride);matches=[]
                    for sha in candidates[base]:
                        data=data_by_hash[sha];candidate=buffer[:];candidate[lo:hi]=data[lo-logical:hi-logical];cross=0;complete=0;bad=False
                        for number in range(max(0,(lo-first)//step-1),max(0,(hi-first)//step)+2):
                            pos=first+number*step
                            if pos<first or pos>=size:continue
                            try:typ,length,end=chunk(candidate,pos)
                            except Exception as _audit_error:
                                _audit_caught(_audit_error, None, expected=True, site='recover_png_crc_grid.py:139')
                                if lo<=pos and pos+step<=hi:bad=True
                                continue
                            if typ!=b'IDAT' or end<=lo or pos>=hi:continue
                            outside=known[pos:min(end,lo)].count(1)+known[max(pos,hi):end].count(1)
                            outside_size=max(0,min(end,lo)-pos)+max(0,end-max(pos,hi))
                            if outside!=outside_size:continue
                            if outside_size>=256:cross+=1
                            elif outside_size==0:complete+=1
                        if not bad and cross and complete:matches.append(sha)
                    if len(matches)==1:
                        sha=matches[0];buffer[lo:hi]=data_by_hash[sha][lo-logical:hi-logical];known[lo:hi]=b'\1'*(hi-lo);local[base]=sha;progress=True
                if not progress:
                    # An encoder may vary IDAT sizes after its first chunk.
                    # Follow the actually known chunk prefix instead of a grid.
                    for base in sorted(missing-local.keys()):
                        logical=base-physical;lo=max(0,logical);hi=min(size,logical+stride);pos=8
                        while pos+8<=lo and known[pos:pos+8].count(1)==8:
                            length=struct.unpack_from('>I',buffer,pos)[0];end=pos+length+12
                            if end>lo:break
                            if end<=pos or end>size:break
                            pos=end
                        if pos>=lo or lo-pos<256 or known[pos:lo].count(1)!=lo-pos:continue
                        matches=[]
                        for sha,data in data_by_hash.items():
                            candidate=buffer[:];candidate[lo:hi]=data[lo-logical:hi-logical]
                            try:
                                typ,length,end=chunk(candidate,pos)
                                if typ!=b'IDAT' or not lo<end<=hi:continue
                                count=0
                                while end+12<=hi:
                                    if end+struct.unpack_from('>I',candidate,end)[0]+12>hi:break
                                    typ,length,nextend=chunk(candidate,end)
                                    if typ!=b'IDAT':break
                                    count+=1;end=nextend
                                if count:matches.append(sha)
                            except Exception as _audit_error:
                                _audit_caught(_audit_error, None, expected=True, site='recover_png_crc_grid.py:175')
                                continue
                        if len(matches)==1:
                            sha=matches[0];buffer[lo:hi]=data_by_hash[sha][lo-logical:hi-logical];known[lo:hi]=b'\1'*(hi-lo);local[base]=sha;progress=True;break
            remaining=missing-local.keys()
            if len(remaining)==1:
                base=next(iter(remaining));logical=base-physical;lo=max(0,logical);hi=min(size,logical+stride);matches=[]
                for sha,data in data_by_hash.items():
                    candidate=buffer[:];candidate[lo:hi]=data[lo-logical:hi-logical]
                    try:validate_png(bytes(candidate));matches.append(sha)
                    except Exception as _audit_error:
                        _audit_caught(_audit_error, None, expected=True, site='recover_png_crc_grid.py:184')
                        continue
                if len(matches)==1:
                    sha=matches[0];buffer[lo:hi]=data_by_hash[sha][lo-logical:hi-logical];known[lo:hi]=b'\1'*(hi-lo);local[base]=sha
            report.update(missing_frames=len(missing),provisional_frames=len(local))
            report['provisional_frame_ids']={str(b):frames[s][0][0] for b,s in local.items()}
            if known.count(0):continue
            validation=validate_png(bytes(buffer));report['validation']=validation;whole=hashlib.sha256(buffer).hexdigest()
            for base,sha in local.items():proposals[base].append((frames[sha],dict(method='png-idat-grid-cross-crc-complete-zlib-validation',record=row['record'],file_sha256_observed=whole,validation=validation,first_idat=first,regular_idat_payload=n)))
        except Exception as e:
            _audit_caught(e, locals(), expected=False, site='recover_png_crc_grid.py:192')
            report['rejected']=str(e)
    conflicts=[]
    for base,items in sorted(proposals.items()):
        if len({fs[0][6] for fs,e in items})!=1:conflicts.append(base);continue
        f=items[0][0][0];data=decode(f[1],f[2])
        if len(data)!=stride or hashlib.sha256(data).hexdigest()!=f[6] or hashlib.md5(data).digest()!=f[5]:raise ValueError('source validation')
        accepted.append(dict(partition=pi,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),sha256=f[6],frames=sorted({f[0] for fs,e in items for f in fs}),evidence=[e for fs,e in items]))
        plan['partitions'][pi].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f[1],stored_length=f[2],decoded_md5=f[5].hex(),reason='Original PNG header and MFT runlist; IDAT grid and crossing CRCs identify frames, then complete file chunk CRCs and zlib/Adler scanline validation pass. Original target digest unavailable.')
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));(a.output/'png-evidence.json').write_text(json.dumps(reports,indent=2));result=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),png_additions=len(accepted)-previous,conflicts=conflicts);(a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
