"""Read-only volume view combining a baseline with validated source mappings."""
import bisect
import io


class MappedVolume(io.RawIOBase):
    def __init__(self,baseline,origin,size,mappings,decode):
        self.baseline=baseline;self.origin=origin;self.size=size;self.mappings=mappings;self.decode=decode;self.pos=0;self.starts=sorted(mappings)
        if any(self.starts[i]+mappings[self.starts[i]]['length']>self.starts[i+1] for i in range(len(self.starts)-1)):raise ValueError('overlapping source mappings')

    def readable(self):return True
    def seekable(self):return True
    def tell(self):return self.pos
    def seek(self,offset,whence=0):
        position=offset if whence==0 else self.pos+offset if whence==1 else self.size+offset if whence==2 else -1
        if position<0:raise ValueError('negative seek')
        self.pos=position;return position

    def read(self,length=-1):
        if length<0:raise ValueError('unbounded volume read')
        length=max(0,min(length,self.size-self.pos));address=self.pos;self.baseline.seek(self.origin+address);data=bytearray(self.baseline.read(length))
        if len(data)!=length:raise ValueError('short baseline volume read')
        k=max(0,bisect.bisect_right(self.starts,address)-1)
        for base in self.starts[k:]:
            if base>=address+length:break
            m=self.mappings[base];lo=max(address,base);hi=min(address+length,base+m['length'])
            if hi>lo:
                decoded=self.decode(m['source_offset'],m['stored_length'])
                if len(decoded)!=m['length']:raise ValueError('decoded mapped length')
                data[lo-address:hi-address]=decoded[lo-base:hi-base]
        self.pos+=length;return bytes(data)
