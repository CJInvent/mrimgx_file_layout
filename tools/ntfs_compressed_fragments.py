"""Bounded structural rescue of complete LZNT1 units; no address authority."""
import ctypes,functools,os,struct


@functools.lru_cache(maxsize=1)
def native_decoder():
    if os.name!='nt':raise NotImplementedError('Bounded native LZNT1 rescue requires Windows')
    function=ctypes.WinDLL('ntdll').RtlDecompressBuffer;function.argtypes=[ctypes.c_ushort,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.POINTER(ctypes.c_ulong)];function.restype=ctypes.c_long
    return function


def decode_unit(data):
    cursor=0;parts=[];decoder=native_decoder()
    for ordinal in range(16):
        if cursor+2>len(data):raise ValueError('truncated LZNT1 chunk header')
        header=struct.unpack_from('<H',data,cursor)[0]
        if header&0xf000 not in (0x3000,0xb000):raise ValueError('LZNT1 chunk signature')
        n=(header&4095)+3
        if cursor+n>len(data):raise ValueError('LZNT1 chunk exceeds available frame bytes')
        packet=data[cursor:cursor+n];src=ctypes.create_string_buffer(packet);dst=ctypes.create_string_buffer(4096);actual=ctypes.c_ulong()
        if decoder(2,dst,4096,src,len(packet),ctypes.byref(actual)) or actual.value!=4096:raise ValueError('LZNT1 chunk is invalid or not a complete 4096-byte chunk')
        parts.append(dst.raw[:actual.value]);cursor+=n
    return cursor,b''.join(parts)


def compressed_units(data):
    for start in range(0,len(data)-3,4096):
        if data[start+1]&0xf0 not in (0x30,0xb0):continue
        try:consumed,decoded=decode_unit(data[start:start+16*4098])
        except (ValueError,OSError):continue
        yield start,consumed,decoded
