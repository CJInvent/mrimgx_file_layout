"""Original index MD5 is the authority; donor metadata only nominates bytes."""
import bisect,hashlib,json,struct
from make_recovery_plan import make_plan
from placement_payload import payload


class OriginalIndex:
    def __init__(self,source,evidence):
        self.plan=json.loads((evidence/'input-plan.json').read_text());self.layout=json.loads((evidence/'layout.json').read_text())
        if make_plan(source,self.plan)!=self.plan:raise ValueError('original index reconstruction plan/source fingerprint differs')
        self.stream=source.open('rb')

    def entry(self,block,partition=2):
        spec=self.plan['partitions'][partition]
        if not 0<=block<spec['count']:raise ValueError('original index block bounds')
        offset=spec['entries_offset']+30*block;self.stream.seek(offset);raw=self.stream.read(30)
        if len(raw)!=30:raise ValueError('short original index entry')
        position,digest,length,file_number=struct.unpack('<Q16sIH',raw)
        return dict(entry_offset=offset,original_source_offset=position,original_stored_length=length,original_file_number=file_number,expected_md5=digest.hex(),entries_md5=spec['entries_md5'])

    def validate(self,mapping):
        if mapping.get('source_encoding')!='original-index-md5-source-parts' or mapping['partition']!=2 or mapping.get('reserved',False):raise ValueError('unsupported original-index reconstruction')
        p=self.layout['disks'][0]['partitions'][2];stride=p['_header']['block_size'];block=mapping['block'];entry=self.entry(block)
        if entry['expected_md5']=='00'*16 or mapping['length']!=stride or mapping['disk_offset']!=p['_geometry']['start']+block*stride or mapping['disk_offset']+stride>p['_geometry']['start']+p['_geometry']['length'] or entry['expected_md5']!=mapping['decoded_md5']:raise ValueError('reconstructed target differs from original index address/digest')
        proofs=[e for e in mapping.get('evidence',[]) if e.get('method')=='original-index-md5-source-parts-reconstruction']
        if len(proofs)!=1 or proofs[0]['original_index']!=entry:raise ValueError('original index reconstruction evidence differs')
        data=payload(self.stream,mapping)
        if hashlib.md5(data).hexdigest()!=entry['expected_md5']:raise ValueError('reconstructed payload does not match original index MD5')
        return data

    def close(self):self.stream.close()


class SourceParts:
    def __init__(self,ctx,index,known):self.ctx=ctx;self.index=index;self.known={m['disk_offset']-ctx.origin:m for m in known};self.frames={}

    def physical(self,address,length,target_offset):
        result=[];ctx=self.ctx
        while length:
            base=address//ctx.stride*ctx.stride;off=address-base;n=min(length,ctx.stride-off)
            if base in self.known:
                m=self.known[base];cursor=off
                for p in sorted(m['source_parts'],key=lambda p:p['target_offset']):
                    lo=max(off,p['target_offset']);hi=min(off+n,p['target_offset']+p['length'])
                    if hi<=lo:continue
                    if lo!=cursor:raise ValueError('known reconstruction source-parts gap')
                    result.append(dict(p,target_offset=target_offset+lo-off,decoded_offset=p['decoded_offset']+lo-p['target_offset'],length=hi-lo));cursor=hi
                if cursor!=off+n:raise ValueError('known reconstruction does not cover donor slice')
            else:
                if base in ctx.mapped:
                    m=ctx.mapped[base];position,stored,expected=m['source_offset'],m['stored_length'],m['decoded_md5']
                else:
                    k=bisect.bisect_right(ctx.ends,base)
                    if k<len(ctx.ranges) and ctx.ranges[k][0]<base+ctx.stride:raise ValueError('donor source frame remains unresolved')
                    entry=self.index.entry(base//ctx.stride);position,stored,expected=entry['original_source_offset'],entry['original_stored_length'],entry['expected_md5']
                    if entry['original_file_number'] or not 0<stored<=ctx.stride+1024**2 or position<0 or position+stored>ctx.layout['_header']['index_file_position']:raise ValueError('original donor source entry bounds/reference')
                key=(position,stored)
                if key not in self.frames:
                    data=ctx.decode(position,stored)
                    if len(data)>ctx.stride or hashlib.md5(data).hexdigest()!=expected:raise ValueError('donor original full-frame MD5 differs')
                    self.frames[key]=dict(source_offset=position,stored_length=stored,decoded_length=len(data),decoded_md5=expected,decoded_sha256=hashlib.sha256(data).hexdigest())
                packet=self.frames[key]
                if off+n>packet['decoded_length']:raise ValueError('donor piece exceeds original source frame')
                result.append(dict(packet,target_offset=target_offset,decoded_offset=off,length=n))
            address+=n;target_offset+=n;length-=n
        return result

    def file(self,extents,logical,length,target_offset):
        parts=[];cursor=logical;stop=logical+length
        for start,physical,n in extents:
            lo=max(logical,start);hi=min(stop,start+n)
            if hi<=lo:continue
            if lo!=cursor:raise ValueError('donor logical extent gap')
            parts.extend(self.physical(physical+lo-start,hi-lo,target_offset+lo-logical));cursor=hi
        if cursor!=stop:raise ValueError('donor file does not cover requested logical bytes')
        return parts


def analysis_manifest(original,requests,output,status='recovered-original-index-md5-source-parts'):
    """Split missing ranges exactly; never label an enclosing range recovered."""
    restored=sorted((m['partition'],m['disk_offset'],m['disk_offset']+m['length']) for m in requests)
    with original.open() as source,output.open('x') as target:
        for line in source:
            row=json.loads(line)
            if row.get('operation')!='range' or row.get('status') not in ('unknown-zero-index','unrecoverable','reconstructed-unverified'):target.write(line);continue
            start=row['disk_offset'];stop=start+row['length'];hits=[(max(start,lo),min(stop,hi)) for pi,lo,hi in restored if pi==row['partition'] and lo<stop and hi>start];cuts=sorted({start,stop,*[x for pair in hits for x in pair]})
            for lo,hi in zip(cuts,cuts[1:]):
                known=any(a<=lo and hi<=b for a,b in hits);piece=dict(row,disk_offset=lo,length=hi-lo)
                if known:piece.update(status=status,analysis_only=True)
                target.write(json.dumps(piece)+'\n')
