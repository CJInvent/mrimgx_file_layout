"""Known original 7z metadata and exact byte mappings for COPY folders."""
import collections,hashlib,io
import py7zr
from cfb_member_rescue import KnownStream

MAGIC=bytes.fromhex('377abcaf271c')


class GuardedInput(io.RawIOBase):
    def __init__(self,source,size,holes):
        self.reads=[];parts=[];position=0
        for lo,hi,*_ in sorted(holes):
            lo=max(0,min(size,lo));hi=max(0,min(size,hi))
            if lo>position:parts.append(dict(logical_offset=position,file_offset=position,bytes=lo-position))
            position=max(position,hi)
        if position<size:parts.append(dict(logical_offset=position,file_offset=position,bytes=size-position))
        self.view=KnownStream(source,size,size,parts)

    def read(self,length=-1):
        if length<0 or length>16*1024**2:raise ValueError('7z metadata read exceeds explicit bound')
        start=self.view.tell();data=self.view.read(length);self.reads.append(dict(file_offset=start,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()));return data

    def seek(self,offset,whence=0):return self.view.seek(offset,whence)
    def tell(self):return self.view.tell()
    def readable(self):return True
    def seekable(self):return True


def copy_members(stream,size,holes=()):
    """No extraction is delegated to py7zr; non-COPY folders stay unsupported."""
    guarded=GuardedInput(stream,size,holes);members=[];unsupported=[]
    with py7zr.SevenZipFile(guarded,mode='r') as archive:
        if archive.needs_password():raise ValueError('encrypted 7z metadata/members are unsupported')
        main=archive.header.main_streams
        if main is None:return [],dict(metadata_reads=guarded.reads,unsupported_folders=[],scope='Original 7z metadata only; no data folders.')
        pack=main.packinfo;folders=main.unpackinfo.folders;locations={};pack_index=0
        for index,folder in enumerate(folders):
            count=len(folder.packed_indices)
            if count<1 or pack_index+count>len(pack.packsizes):raise ValueError('7z packed stream count/bounds differ')
            supported=len(folder.coders)==1 and folder.coders[0]['method']==b'\0' and folder.coders[0].get('numinstreams',1)==folder.coders[0].get('numoutstreams',1)==count==1 and len(folder.unpacksizes)==1 and pack.packsizes[pack_index]==folder.unpacksizes[0]
            if supported:
                start=archive.afterheader+pack.packpos+pack.packpositions[pack_index];stop=start+pack.packsizes[pack_index]
                if not 0<=start<=stop<=size:raise ValueError('7z COPY stream exceeds original file')
                locations[id(folder)]=dict(folder=index,start=start,bytes=pack.packsizes[pack_index])
            else:unsupported.append(dict(folder=index,coders=[coder['method'].hex() for coder in folder.coders]))
            pack_index+=count
        if pack_index!=len(pack.packsizes):raise ValueError('7z unassigned packed streams')
        offsets=collections.Counter()
        for file in archive.files:
            folder=file.folder
            if folder is None:continue
            location=locations.get(id(folder));logical=offsets[id(folder)];offsets[id(folder)]+=file.uncompressed
            if location is None:continue
            if logical+file.uncompressed>location['bytes']:raise ValueError('7z member exceeds COPY folder')
            if file.is_directory:continue
            name=file.filename;crc=file.crc32;start=location['start']+logical
            members.append(dict(key=(name,crc,file.uncompressed,file.uncompressed,0),start=start,stop=start+file.uncompressed,archive_format='7z-copy',folder=location['folder']))
        for folder in folders:
            location=locations.get(id(folder))
            if location and offsets[id(folder)]!=location['bytes']:raise ValueError('7z COPY member sizes do not cover folder')
    return members,dict(metadata_reads=guarded.reads,unsupported_folders=unsupported,scope='Only original header reads through source-known ranges. COPY source positions require original folder/member lengths to agree. No compressed method is silently treated as stored data.')
