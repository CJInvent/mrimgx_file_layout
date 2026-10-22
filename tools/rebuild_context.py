"""Shared read-only filesystem and missing-range discovery for rebuild stages."""
import bisect,functools,json,pathlib
import zstandard
from safe_vhdx import VHDX
from mapped_volume import MappedVolume
from dissect.ntfs import NTFS
from recover_duplicate_files import file_extents


class Context:
    def __init__(self,source,baseline,mft,manifest,evidence,mapping_directory):
        self.layout=json.loads((evidence/'layout.json').read_text());self.p=self.layout['disks'][0]['partitions'][2];self.origin=self.p['_geometry']['start'];self.stride=self.p['_header']['block_size'];self.maps=json.loads((mapping_directory/'accepted-mappings.json').read_text());self.mapped={m['disk_offset']-self.origin:m for m in self.maps if m['partition']==2};self.ranges=[]
        for row in map(json.loads,manifest.open()):
            if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):self.ranges.append((row['disk_offset']-self.origin,row['disk_offset']+row['length']-self.origin))
        self.ranges.sort();self.ends=[hi for lo,hi in self.ranges];self.source=source.open('rb')
        @functools.lru_cache(maxsize=128)
        def decode(offset,length):self.source.seek(offset);return zstandard.ZstdDecompressor().decompress(self.source.read(length))
        self.decode=decode;self.volume=MappedVolume(VHDX(baseline),self.origin,self.p['_geometry']['length'],self.mapped,decode);self.fs=NTFS(self.volume);self.fs.mft.fh=mft.open('rb')

    def holes(self,record):
        result=[]
        for logical,physical,length in file_extents(record,record.size()):
            hi=physical+length;k=bisect.bisect_right(self.ends,physical)
            while k<len(self.ranges) and self.ranges[k][0]<hi:
                lo=max(physical,self.ranges[k][0]);stop=min(hi,self.ranges[k][1])
                while lo<stop:
                    base=lo//self.stride*self.stride;end=min(stop,base+self.stride)
                    if base not in self.mapped:result.append((logical+lo-physical,logical+end-physical,base))
                    lo=end
                k+=1
        return result

    def read_complete(self,number,maximum=512*1024**2):
        record=self.fs.mft.get(number)
        if record.size()>maximum or self.holes(record):raise ValueError('incomplete or excessive file')
        data=record.open().read()
        if len(data)!=record.size():raise ValueError('short file')
        return record,data
