"""Read-only ESE XOR/ECC checksum validation, derived from Microsoft's format.

Reference: microsoft/Extensible-Storage-Engine, checksum_amd64.cxx
(Copyright Microsoft Corporation, MIT License). Never corrects page bytes.
"""
import struct


def xe_checksum(data,pgno,header=True):
    if len(data) not in (1024,2048,4096,8192):raise ValueError('unsupported checksum block size')
    columns=[0,0,0,0];p=0;index=0xff800000
    for number,row in enumerate(struct.iter_unpack('<IIII',data)):
        if number==0 and header:row=(0,0,row[2],row[3])
        parity=0
        for n,value in enumerate(row):columns[n]^=value;parity^=value
        if parity.bit_count()&1:p^=index
        index=(index+0xff800080)&0xffffffff
    c0,c1,c2,c3=columns
    if (c0^c1).bit_count()&1:p|=0x00400000
    if (c2^c3).bit_count()&1:p|=0x00000040
    r0=c0^c2;r1=c1^c3;r2=r0^r1
    if r0.bit_count()&1:p|=0x00200000
    if r1.bit_count()&1:p|=0x00000020
    r=0;index=0xffff0000
    for bit in range(32):
        if r2&(1<<bit):r^=index
        index=(index+0xffff0001)&0xffffffff
    ecc=(p&0xffe0ffe0&((len(data)<<19)-1))|(r&0x001f001f)
    return (ecc<<32)|(r2^pgno)


def valid_large_page(data):
    if len(data) not in (16384,32768):return False
    pgno=struct.unpack_from('<I',data,64)[0];flags=struct.unpack_from('<I',data,36)[0]
    if not pgno or not flags&0x2000:return False
    block=len(data)//4
    stored=[struct.unpack_from('<Q',data,offset)[0] for offset in (0,40,48,56)]
    return all(xe_checksum(data[i*block:(i+1)*block],pgno,i==0)==stored[i] for i in range(4))
