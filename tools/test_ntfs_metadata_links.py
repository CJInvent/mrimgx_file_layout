"""Synthetic cross-file NTFS metadata proofs, independent of backup contents."""
import io,struct,unittest
from types import SimpleNamespace as NS
from ntfs_metadata_links import index_page,index_address,descriptor_hash,security_link,LogFileLinks
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE as Kind


def fixups(page,offset=40):
    page=bytearray(page);struct.pack_into('<HH',page,4,offset,9);word=b'\x5a\xa5';page[offset:offset+2]=word
    for i in range(1,9):
        at=i*512-2;page[offset+2*i:offset+2*i+2]=page[at:at+2];page[at:at+2]=word
    return bytes(page)


def index_fixture(entries=b'',vcn=5,lsn=0):
    page=bytearray(4096);page[:4]=b'INDX';struct.pack_into('<QQ',page,8,lsn,vcn);struct.pack_into('<III',page,24,40,40+len(entries)+16,4072);page[64:64+len(entries)]=entries;struct.pack_into('<HHH',page,64+len(entries)+8,16,0,2)
    return fixups(page)


def owner_fixture(name,collation,segment=9,sequence=9):
    root=bytearray(32);struct.pack_into('<III',root,0,48 if name=='$I30' else 0,collation,4096);root[12]=1
    attr=NS(name=name,data=lambda:bytes(root));record=NS(segment=segment,header=NS(Flags=3 if name=='$I30' else 1,SequenceNumber=sequence),is_dir=lambda:name=='$I30',filenames=lambda:['$Secure'])
    record.attributes={Kind.INDEX_ROOT:[attr]};record.size=lambda stream,typ=None:32*4096;record.dataruns=lambda stream,typ:[(1000,32)]
    return record


def log_fixture(flags=1):
    raw=bytearray(6*4096);offset=4*4096+3936;lsn=(1<<24)|(offset//8)
    for start in (0,4096):
        page=bytearray(4096);page[:4]=b'RSTR';struct.pack_into('<IIHHH',page,16,4096,4096,48,0,2);area=48;struct.pack_into('<H',page,area+8,1);struct.pack_into('<I',page,area+16,40);struct.pack_into('<H',page,area+22,64);struct.pack_into('<Q',page,area+24,len(raw));struct.pack_into('<HH',page,area+36,48,64);struct.pack_into('<H',page,area+64+20,7);struct.pack_into('<I',page,area+64+28,8);page[area+64+32:area+64+40]='NTFS'.encode('utf-16-le');raw[start:start+4096]=fixups(page,30)
    entry=bytearray(136);struct.pack_into('<Q',entry,0,(1<<48)|55);struct.pack_into('<HHH',entry,8,136,114,0);struct.pack_into('<Q',entry,16,(9<<48)|42);entry[16+64]=24;entry[16+65]=1;entry[16+66:16+114]=('x'*24).encode('utf-16-le')
    payload=bytearray(176);struct.pack_into('<12HQ',payload,0,15,14,40,0,40,136,224,1,0,64,0,8,5);struct.pack_into('<Q',payload,32,1005);payload[40:]=entry
    page1=bytearray(4096);page1[:4]=b'RCRD';page2=bytearray(4096);page2[:4]=b'RCRD';struct.pack_into('<QQQIHHIIH',page1,3936,lsn,0,0,len(payload),7,0,1,3,flags);page1[3984:]=payload[:112];page2[64:128]=payload[112:];raw[4*4096:5*4096]=fixups(page1);raw[5*4096:]=fixups(page2)
    record=NS(filename='$LogFile',header=NS(SequenceNumber=1),full_path=lambda:'$LogFile');reader=NS(fs=NS(mft=NS(get=lambda number:record)),read=lambda number,path,maximum:(record,bytes(raw)))
    return reader,lsn,bytes(raw)


class NtfsMetadataLinkTests(unittest.TestCase):
    def test_index_fixups_bounds_and_terminal_are_required(self):
        raw=index_fixture();self.assertEqual(index_page(raw)[1],[]);bad=bytearray(raw);bad[510]^=1
        with self.assertRaises(ValueError):index_page(bytes(bad))
        with self.assertRaises(ValueError):index_page(raw[:-1])
        bad=bytearray(4096);bad[:4]=b'INDX';struct.pack_into('<III',bad,24,40,4080,4072)
        with self.assertRaises(ValueError):index_page(fixups(bad))

    def test_security_hash_and_named_index_root_are_bound(self):
        body=struct.pack('<BBHIIII',1,0,0x8000,0,0,0,0);self.assertEqual(descriptor_hash(body),0x1800)
        with self.assertRaises(ValueError):descriptor_hash(body[:-1])
        record=owner_fixture('$SDH',18);self.assertEqual(index_address(record,'$SDH',5)[0],1005*4096)
        with self.assertRaises(ValueError):index_address(record,'$SDH',32)
        record.header.Flags=0
        with self.assertRaises(ValueError):index_address(record,'$SDH',5)

    def test_security_index_requires_multiple_original_sds_descriptors(self):
        body=struct.pack('<BBHIIII',1,0,0x8000,0,0,0,0);sds=bytearray(192);entries=bytearray()
        for i in range(3):
            header=struct.pack('<IIQI',descriptor_hash(body),256+i,i*64,40);sds[i*64:i*64+40]=header+body;entry=bytearray(48);struct.pack_into('<HH',entry,0,24,20);struct.pack_into('<HHH',entry,8,48,8,0);entry[16:24]=header[:8];entry[24:44]=header;entries+=entry
        record=owner_fixture('$SDH',18);record.open=lambda name:io.BytesIO(sds);record.size=lambda name,typ=None:len(sds) if name=='$SDS' else 32*4096;fs=NS(cluster_size=4096,_index_size=4096,mft=NS(get=lambda number:record));raw=index_fixture(entries)
        proof=security_link(fs,raw);self.assertEqual(proof['descriptor_ids'],[256,257,258]);self.assertEqual(proof['page_address'],1005*4096)
        sds[20]^=1
        with self.assertRaises(ValueError):security_link(fs,raw)
        sds[20]^=1
        with self.assertRaises(ValueError):security_link(fs,index_fixture(entries[:48]))

    def test_logfile_multi_page_transaction_is_bound_to_lsn_and_client(self):
        reader,lsn,raw=log_fixture();log=LogFileLinks(reader);transaction=log.transaction(lsn);self.assertEqual(transaction['target_lcn'],1005);self.assertEqual(len(transaction['undo_data']),136)
        with self.assertRaises(ValueError):log.transaction(lsn+1)
        reader2,lsn2,raw2=log_fixture(flags=0)
        with self.assertRaises(ValueError):LogFileLinks(reader2).transaction(lsn2)
        self.assertEqual(raw,reader.read(2,'$LogFile',256*1024**2)[1])

    def test_logfile_address_requires_current_owner_sequence_and_runlist(self):
        reader,lsn,raw=log_fixture();log=LogFileLinks(reader);record=owner_fixture('$I30',1,42,9);fs=NS(mft=NS(get=lambda number:record));page=index_fixture(lsn=lsn)
        proof=log.directory_link(fs,page);self.assertEqual(proof['owner_record'],42);self.assertEqual(proof['page_address'],1005*4096)
        record.header.SequenceNumber=10
        with self.assertRaises(ValueError):log.directory_link(fs,page)
        record.header.SequenceNumber=9;record.dataruns=lambda name,typ:[(2000,32)]
        with self.assertRaises(ValueError):log.directory_link(fs,page)

    def test_logfile_restart_corruption_is_rejected(self):
        reader,lsn,raw=log_fixture();bad=bytearray(raw);bad[510]^=1;record=reader.fs.mft.get(2);reader.read=lambda number,path,maximum:(record,bytes(bad))
        with self.assertRaises(ValueError):LogFileLinks(reader)
