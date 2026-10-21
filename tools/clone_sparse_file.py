"""Clone a Windows sparse file into a new file; preserve input and log extents.

Copies physical allocated ranges at their original offsets, including metadata.
The destination is exclusively created. No mounts, repairs or source writes.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import msvcrt
import pathlib
import struct
import time


def control(file, code, input_bytes=b'', output_size=0):
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    ioctl=kernel.DeviceIoControl
    ioctl.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]
    ioctl.restype=wintypes.BOOL
    ib=ctypes.create_string_buffer(input_bytes) if input_bytes else None
    ob=ctypes.create_string_buffer(output_size) if output_size else None
    returned=wintypes.DWORD()
    ok=ioctl(msvcrt.get_osfhandle(file.fileno()),code,ib,len(input_bytes),ob,output_size,ctypes.byref(returned),None)
    if not ok:raise ctypes.WinError(ctypes.get_last_error())
    return ob.raw[:returned.value] if ob else b''


def clone(source, destination, manifest):
    if source.resolve()==destination.resolve():raise ValueError('source equals destination')
    before=source.stat(); total=0; started=time.monotonic(); last=started
    with source.open('rb',buffering=0) as src, destination.open('xb',buffering=0) as dst, manifest.open('x') as log:
        control(dst,0x900c4) # FSCTL_SET_SPARSE
        ranges=control(src,0x940cf,struct.pack('<qq',0,before.st_size),16*1024**2)
        extents=list(struct.iter_unpack('<qq',ranges))
        # Windows CRT _chsize_s (used by Python truncate) explicitly writes
        # zeroes while growing. SetEndOfFile preserves sparse holes directly.
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.SetFilePointerEx.argtypes=[wintypes.HANDLE,ctypes.c_longlong,wintypes.LPVOID,wintypes.DWORD]
        kernel.SetEndOfFile.argtypes=[wintypes.HANDLE]
        handle=msvcrt.get_osfhandle(dst.fileno())
        if not kernel.SetFilePointerEx(handle,before.st_size,None,0) or not kernel.SetEndOfFile(handle):raise ctypes.WinError(ctypes.get_last_error())
        log.write(json.dumps(dict(operation='begin',source=str(source.resolve()),size=before.st_size,mtime_ns=before.st_mtime_ns,extents=len(extents)))+'\n');log.flush()
        for offset,length in extents:
            src.seek(offset);dst.seek(offset);remaining=length
            while remaining:
                data=src.read(min(64*1024**2,remaining))
                if not data:raise EOFError('short clone input')
                if dst.write(data)!=len(data):raise OSError('short clone write')
                log.write(json.dumps(dict(offset=src.tell()-len(data),length=len(data),sha256=hashlib.sha256(data).hexdigest()))+'\n')
                remaining-=len(data);total+=len(data)
                if time.monotonic()-last>15:
                    print(json.dumps(dict(copied=total,allocated_total=sum(n for _,n in extents),elapsed=time.monotonic()-started)),flush=True);log.flush();last=time.monotonic()
        after=source.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('source changed during clone')
        log.write(json.dumps(dict(operation='complete',copied=total,source_stat_unchanged=True,elapsed=time.monotonic()-started))+'\n')
    print('clone complete',total,flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','destination','manifest'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();clone(a.source,a.destination,a.manifest)
