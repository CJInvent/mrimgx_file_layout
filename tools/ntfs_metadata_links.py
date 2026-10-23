"""Cross-file address proofs for non-filename and parentless NTFS index pages.

Disk layout facts checked against NTFS structures and the Linux NTFS3 LFS
implementation. This independently implemented reader never replays a log or
repairs filesystem metadata. Unsupported geometry/records yield no address.
"""
import functools,hashlib,struct
from dissect.ntfs.util import apply_fixup
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE as Kind


def index_page(raw):
    if len(raw)!=4096 or raw[:4]!=b'INDX':raise ValueError('not a supported INDX page')
    fixed=apply_fixup(raw);entry,used,allocated=struct.unpack_from('<III',fixed,24)
    if entry<16 or entry%8 or used<entry+16 or used>allocated or allocated>4072:raise ValueError('index page bounds')
    rows=[];cursor=24+entry
    while cursor+16<=24+used:
        n,key,flags=struct.unpack_from('<HHH',fixed,cursor+8)
        if n<16 or n%8 or cursor+n>24+used or key>n-16-(8 if flags&1 else 0) or flags&~3:raise ValueError('index entry bounds')
        if flags&2:
            if key or cursor+n!=24+used:raise ValueError('invalid index terminal entry')
            return fixed,rows
        rows.append((cursor,n,key,flags));cursor+=n
    raise ValueError('missing index terminal entry')


def index_address(record,name,vcn):
    if not record.header.Flags&1:raise ValueError('inactive index owner')
    roots=[a for a in record.attributes[Kind.INDEX_ROOT] if a.name==name]
    if len(roots)!=1:raise ValueError('missing/ambiguous named index root')
    root=roots[0].data()
    if len(root)<32 or struct.unpack_from('<I',root,8)[0]!=4096 or root[12]!=1:raise ValueError('unsupported index-root geometry')
    if record.size(name,Kind.INDEX_ALLOCATION)<(vcn+1)*4096:raise ValueError('VCN outside original index allocation')
    hits=[];logical=0
    for lcn,n in record.dataruns(name,Kind.INDEX_ALLOCATION):
        if n<=0:raise ValueError('invalid original index run length')
        if lcn is not None and logical<=vcn<logical+n:hits.append((lcn+vcn-logical)*4096)
        logical+=n
    if len(set(hits))!=1:raise ValueError('no unique original index runlist address')
    return hits[0],root


def descriptor_hash(body):
    if len(body)<20 or len(body)%4 or body[0]!=1 or not struct.unpack_from('<H',body,2)[0]&0x8000:raise ValueError('unsupported self-relative security descriptor')
    value=0
    for (word,) in struct.iter_unpack('<I',body):value=(((value<<3)|(value>>29))+word)&0xffffffff
    return value


def security_link(fs,raw):
    if fs.cluster_size!=4096 or fs._index_size!=4096:raise ValueError('unsupported security index geometry')
    fixed,entries=index_page(raw);record=fs.mft.get(9)
    if '$Secure' not in record.filenames() or not record.header.Flags&1:raise ValueError('original active Secure record unavailable')
    size=record.size('$SDS');stream=record.open('$SDS');ids=[];names=set();witness=hashlib.sha256()
    for cursor,n,key,flags in entries:
        data_off,data_len=struct.unpack_from('<HH',fixed,cursor)
        if key not in (4,8) or data_len!=20 or data_off<16+key or data_off+20>n-(8 if flags&1 else 0):raise ValueError('not a security index entry')
        header=fixed[cursor+data_off:cursor+data_off+20];value,number,offset,length=struct.unpack('<IIQI',header)
        if not 20<length<=65536 or offset%16 or offset+length>size:raise ValueError('security descriptor extent bounds')
        stream.seek(offset);data=stream.read(length)
        if len(data)!=length or data[:20]!=header or descriptor_hash(data[20:])!=value:raise ValueError('original SDS descriptor/header differs')
        expected=header[:8] if key==8 else header[4:8]
        if fixed[cursor+16:cursor+16+key]!=expected:raise ValueError('security index key differs from original SDS')
        names.add('$SDH' if key==8 else '$SII');ids.append(number);witness.update(data)
    if len(names)!=1 or len(set(ids))<3:raise ValueError('insufficient independent security index entries')
    name=names.pop();vcn=struct.unpack_from('<Q',fixed,16)[0];address,root=index_address(record,name,vcn)
    if struct.unpack_from('<II',root)!=(0,18 if name=='$SDH' else 16):raise ValueError('security index root collation/type differs')
    return dict(kind='ntfs-security-index-sds-runlist',owner_record=9,owner_sequence=record.header.SequenceNumber,index_name=name,page_vcn=vcn,page_lsn=struct.unpack_from('<Q',fixed,8)[0],page_address=address,index_root_sha256=hashlib.sha256(root).hexdigest(),descriptor_ids=ids,descriptor_witness_sha256=witness.hexdigest())


class LogFileLinks:
    def __init__(self,reader):
        record=self.record=reader.fs.mft.get(2)
        if record.filename!='$LogFile':raise ValueError('original LogFile record differs')
        record,self.raw=reader.read(2,record.full_path(),256*1024**2);self.sha=hashlib.sha256(self.raw).hexdigest();configs=[]
        for start in (0,4096):
            page=apply_fixup(self.raw[start:start+4096])
            if page[:4]!=b'RSTR' or struct.unpack_from('<II',page,16)!=(4096,4096) or struct.unpack_from('<H',page,28)[0]!=2:raise ValueError('unsupported LogFile restart format')
            area=struct.unpack_from('<H',page,24)[0]
            if area<32 or area%8 or area+64>4096:raise ValueError('LogFile restart area bounds')
            bits=struct.unpack_from('<I',page,area+16)[0];size=struct.unpack_from('<Q',page,area+24)[0];header,data_off=struct.unpack_from('<HH',page,area+36);clients=struct.unpack_from('<H',page,area+8)[0];client_off=struct.unpack_from('<H',page,area+22)[0]
            if size!=len(self.raw) or not 32<=bits<=60 or header!=48 or not 48<=data_off<=512 or data_off%8 or not 0<clients<=16 or client_off<64 or area+client_off+clients*96>4096:raise ValueError('unsupported LogFile restart geometry')
            client_info=[]
            for i in range(clients):
                pos=area+client_off+i*96;seq=struct.unpack_from('<H',page,pos+20)[0];n=struct.unpack_from('<I',page,pos+28)[0]
                if n>64 or n%2:raise ValueError('invalid LogFile client name bounds')
                client_info.append((seq,page[pos+32:pos+32+n].decode('utf-16-le')))
            configs.append((bits,header,data_off,tuple(client_info)))
        if configs[0]!=configs[1]:raise ValueError('LogFile restart copies disagree on geometry/clients')
        self.bits,self.header,self.data_off,self.clients=configs[0]

    @functools.lru_cache(maxsize=64)
    def page(self,start):
        if start<8192 or start%4096 or start+4096>len(self.raw):raise ValueError('LogFile record page bounds')
        raw=self.raw[start:start+4096]
        if raw[:4]!=b'RCRD':raise ValueError('LogFile record page signature')
        return apply_fixup(raw)

    def transaction(self,lsn):
        if not lsn:raise ValueError('missing index page LSN')
        offset=(lsn&((1<<(64-self.bits))-1))*8;start=offset//4096*4096;pos=offset-start;page=self.page(start)
        if pos<self.data_off or pos+self.header>4096:raise ValueError('LogFile record header offset')
        this,prev,undo,length,seq,client,typ,trans,flags=struct.unpack_from('<QQQIHHIIH',page,pos)
        if this!=lsn or typ!=1 or not 40<=length<=65536 or client>=len(self.clients) or self.clients[client]!=(seq,'NTFS'):raise ValueError('LogFile LSN/client/type/length mismatch')
        pieces=[];remaining=length;cursor=pos+self.header;page_count=0
        while remaining:
            n=min(remaining,4096-cursor);pieces.append(page[cursor:cursor+n]);remaining-=n
            if not remaining:break
            if not flags&1 or page_count>=20:raise ValueError('unsupported LogFile continuation')
            start+=4096
            if start==len(self.raw):start=16384
            page=self.page(start);cursor=self.data_off;page_count+=1
        data=b''.join(pieces);fields=struct.unpack_from('<12HQ',data);redo,undo_op,ro,rn,uo,un,attr,nlcns,record_off,attr_off,cluster_off,reserved,vcn=fields
        if nlcns!=1 or record_off or cluster_off or not 16<=attr_off<4096 or attr_off%8 or min(ro,uo)<40 or ro+rn>len(data) or uo+un>len(data):raise ValueError('unsupported LogFile index target bounds')
        lcn=struct.unpack_from('<Q',data,32)[0]
        if not lcn:raise ValueError('missing LogFile target LCN')
        return dict(lsn=lsn,record_offset=offset,redo=redo,undo=undo_op,target_vcn=vcn,target_lcn=lcn,redo_data=data[ro:ro+rn],undo_data=data[uo:uo+un],payload_sha256=hashlib.sha256(data).hexdigest())

    def directory_link(self,fs,raw):
        fixed,entries=index_page(raw);lsn=struct.unpack_from('<Q',fixed,8)[0];vcn=struct.unpack_from('<Q',fixed,16)[0];transaction=self.transaction(lsn)
        if transaction['target_vcn']!=vcn:raise ValueError('index/log target VCN differs')
        owners=set()
        for operation,data in ((transaction['redo'],transaction['redo_data']),(transaction['undo'],transaction['undo_data'])):
            if operation!=14 or len(data)<16:continue
            n,key,flags=struct.unpack_from('<HHH',data,8)
            if flags&2 or key<66 or n>len(data) or n<16+key or key>n-16-(8 if flags&1 else 0):continue
            value=data[16:16+key];name_length=value[64]
            if 66+name_length*2>key or value[65]>3:continue
            value[66:66+name_length*2].decode('utf-16-le');owners.add(struct.unpack_from('<Q',value)[0])
        if len(owners)!=1:raise ValueError('no unique directory owner in LogFile index entry')
        parent=owners.pop();record=fs.mft.get(parent&((1<<48)-1))
        if record.header.SequenceNumber!=parent>>48 or not record.is_dir():raise ValueError('LogFile directory owner sequence/type differs')
        address,root=index_address(record,'$I30',vcn)
        if struct.unpack_from('<II',root)!=(48,1) or address!=transaction['target_lcn']*4096:raise ValueError('LogFile target differs from original directory index runlist')
        return dict(kind='ntfs-logfile-lsn-directory-runlist',owner_record=record.segment,owner_sequence=record.header.SequenceNumber,index_name='$I30',page_vcn=vcn,page_lsn=lsn,page_address=address,index_root_sha256=hashlib.sha256(root).hexdigest(),logfile_record=2,logfile_sequence=self.record.header.SequenceNumber,logfile_sha256=self.sha,transaction_offset=transaction['record_offset'],transaction_payload_sha256=transaction['payload_sha256'],redo=transaction['redo'],undo=transaction['undo'])
