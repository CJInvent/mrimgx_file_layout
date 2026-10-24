"""Prove CFB allocation metadata before mapping compound streams to source bytes."""
import array,hashlib,struct,sys,bisect
import olefile
from zip_directory import known

END=0xfffffffe
FREE=0xffffffff


def chain(table,start,count=None,maximum=None):
    seen=set();result=[];limit=len(table) if maximum is None else min(len(table),maximum)
    while start!=END:
        if start>=len(table) or start in seen or len(result)>=limit:raise ValueError('CFB allocation cycle, invalid sector or chain bound')
        seen.add(start);result.append(start);start=table[start]
    if count is not None and len(result)!=count:raise ValueError('CFB declared stream length differs from allocation chain')
    return result


def words(raw):
    result=array.array('I');result.frombytes(raw)
    if sys.byteorder!='little':result.byteswap()
    return result


class Compound:
    def __init__(self,stream,size,holes=(),maximum_directory_bytes=32*1024**2):
        self.stream=stream;self.size=size;self.holes=holes;self.metadata_ranges=[]
        def read(offset,length):
            if offset<0 or offset+length>size or not known(holes,offset,offset+length):raise ValueError('CFB allocation metadata intersects unavailable source')
            stream.seek(offset);raw=stream.read(length)
            if len(raw)!=length:raise ValueError('short CFB allocation metadata')
            self.metadata_ranges.append(dict(file_offset=offset,bytes=length,sha256=hashlib.sha256(raw).hexdigest()));return raw
        header=read(0,512)
        if header[:8]!=bytes.fromhex('d0cf11e0a1b11ae1') or header[28:30]!=b'\xfe\xff':raise ValueError('unsupported CFB signature or byte order')
        major,shift,mini=struct.unpack_from('<HxxHH',header,26)
        if (major,shift) not in ((3,9),(4,12)) or mini!=6:raise ValueError('unsupported CFB sector geometry')
        self.sector=1<<shift;self.count=size//self.sector-1
        if self.count<1 or size%self.sector:raise ValueError('CFB physical sector bounds')
        nfat,first_dir=struct.unpack_from('<II',header,44);first_mini,nmini,first_difat,ndifat=struct.unpack_from('<4I',header,60)
        if not 0<nfat<=self.count or ndifat>self.count or nmini>self.count or struct.unpack_from('<I',header,56)[0]!=4096:raise ValueError('CFB allocation table bounds')
        ids=[sid for sid in words(header[76:512]) if sid!=FREE];difats=[];current=first_difat
        for _ in range(ndifat):
            if current>=self.count or current in difats:raise ValueError('CFB DIFAT cycle or bounds')
            difats.append(current);row=words(read((current+1)*self.sector,self.sector));ids.extend(sid for sid in row[:-1] if sid!=FREE);current=row[-1]
        if ndifat and current not in (END,FREE):raise ValueError('CFB DIFAT termination')
        if len(ids)!=nfat or len(set(ids))!=nfat or any(sid>=self.count for sid in ids):raise ValueError('CFB FAT identity/count differs')
        self.fat=array.array('I')
        for sid in ids:self.fat.extend(words(read((sid+1)*self.sector,self.sector)))
        if len(self.fat)<self.count or any(self.fat[sid]!=0xfffffffd for sid in ids) or any(self.fat[sid]!=0xfffffffc for sid in difats):raise ValueError('CFB allocation table ownership markers differ')
        self.fat=self.fat[:self.count];self.directory=chain(self.fat,first_dir,maximum=maximum_directory_bytes//self.sector)
        for sid in self.directory:read((sid+1)*self.sector,self.sector)
        self.minifat=array.array('I')
        if nmini:
            for sid in chain(self.fat,first_mini,count=nmini):self.minifat.extend(words(read((sid+1)*self.sector,self.sector)))
        self.ole=olefile.OleFileIO(stream,write_mode=False,raise_defects=olefile.DEFECT_INCORRECT)
        try:
            if self.ole.fat!=self.fat:raise ValueError('independent CFB FAT parse differs')
            self.root=chain(self.fat,self.ole.root.isectStart,count=(self.ole.root.size+self.sector-1)//self.sector) if self.ole.root.size else []
        except BaseException:self.ole.close();raise

    def streams(self):
        for path in self.ole.listdir(streams=True,storages=False):
            sid=self.ole._find(path);entry=self.ole.direntries[sid];length=entry.size;unit=64 if entry.is_minifat else self.sector
            sectors=chain(self.minifat if entry.is_minifat else self.fat,entry.isectStart,count=(length+unit-1)//unit) if length else []
            ranges=[];logical=0
            for sector in sectors:
                amount=min(unit,length-logical)
                if entry.is_minifat:
                    root_offset=sector*64
                    if root_offset+amount>self.ole.root.size:raise ValueError('CFB mini stream exceeds original root stream')
                    position=(self.root[root_offset//self.sector]+1)*self.sector+root_offset%self.sector
                else:position=(sector+1)*self.sector
                if position+amount>self.size:raise ValueError('CFB stream exceeds original file')
                if ranges and ranges[-1]['file_offset']+ranges[-1]['bytes']==position:ranges[-1]['bytes']+=amount
                else:ranges.append(dict(logical_offset=logical,file_offset=position,bytes=amount))
                logical+=amount
            directory_offset=(self.directory[sid//(self.sector//128)]+1)*self.sector+(sid%(self.sector//128))*128
            self.stream.seek(directory_offset);original=self.stream.read(128)
            yield dict(directory_entry=sid,stream_path=path,size=length,mini_stream=entry.is_minifat,source_entry_offset=directory_offset,source_entry_sha256=hashlib.sha256(original).hexdigest(),source_ranges=ranges)

    def close(self):self.ole.close()


def known_parts(member,holes):
    """Keep every known interval, including intervals after an unavailable gap."""
    parts=[]
    for item in member['source_ranges']:
        start=item['file_offset'];end=start+item['bytes'];position=start
        for lo,hi,*_ in sorted(holes):
            if hi<=position or lo>=end:continue
            if lo>position:parts.append(dict(logical_offset=item['logical_offset']+position-start,file_offset=position,bytes=lo-position))
            position=max(position,min(end,hi))
        if position<end:parts.append(dict(logical_offset=item['logical_offset']+position-start,file_offset=position,bytes=end-position))
    return parts


class KnownStream:
    """Read a child stream through proven source ranges; never synthesize gaps."""
    def __init__(self,source,source_size,size,parts):
        self.source=source;self.size=size;self.parts=sorted(parts,key=lambda p:p['logical_offset']);self.starts=[p['logical_offset'] for p in self.parts];self.position=0;self.holes=[];self._cache_offset=-1;self._cache=b'';end=0
        for part in self.parts:
            start=part['logical_offset'];stop=start+part['bytes']
            if start<end or not 0<=start<=stop<=size or not 0<=part['file_offset']<=part['file_offset']+part['bytes']<=source_size:raise ValueError('Known child stream source bounds differ')
            if start>end:self.holes.append((end,start,0))
            end=stop
        if end<size:self.holes.append((end,size,0))

    def seek(self,offset,whence=0):
        position=offset if whence==0 else self.position+offset if whence==1 else self.size+offset if whence==2 else -1
        if not 0<=position<=self.size:raise ValueError('Known child stream seek exceeds original size')
        self.position=position;return position

    def tell(self):return self.position

    def read(self,length=-1):
        length=self.size-self.position if length<0 else min(length,self.size-self.position)
        if not known(self.holes,self.position,self.position+length):raise ValueError('Known child stream read intersects unavailable source')
        chunks=[];remaining=length
        while remaining:
            index=bisect.bisect_right(self.starts,self.position)-1
            if index<0:raise ValueError('Known child stream has no source range')
            part=self.parts[index];offset=self.position-part['logical_offset'];amount=min(remaining,part['bytes']-offset)
            if amount<=0:raise ValueError('Known child stream source range ended')
            if not self._cache_offset<=self.position<=self.position+amount<=self._cache_offset+len(self._cache):
                prefetch=max(amount,min(65536,part['bytes']-offset));self.source.seek(part['file_offset']+offset);self._cache=self.source.read(prefetch);self._cache_offset=self.position
                if len(self._cache)!=prefetch:raise ValueError('Short known child stream source read')
            data=self._cache[self.position-self._cache_offset:self.position-self._cache_offset+amount]
            chunks.append(data);self.position+=amount;remaining-=amount
        return b''.join(chunks)
