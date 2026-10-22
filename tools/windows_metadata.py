"""Read-only Windows Installer and catalog APIs; never install or execute files."""
import ctypes as c
import ctypes.wintypes as w
import struct


def installer_hashes(path):
    lib=c.WinDLL('msi')
    def api(name,args,result=w.UINT):
        f=getattr(lib,name);f.argtypes=args;f.restype=result;return f
    op=api('MsiOpenDatabaseW',[w.LPCWSTR,w.LPCWSTR,c.POINTER(w.UINT)]);ov=api('MsiDatabaseOpenViewW',[w.UINT,w.LPCWSTR,c.POINTER(w.UINT)]);execute=api('MsiViewExecute',[w.UINT,w.UINT]);fetch=api('MsiViewFetch',[w.UINT,c.POINTER(w.UINT)]);gs=api('MsiRecordGetStringW',[w.UINT,w.UINT,w.LPWSTR,c.POINTER(w.DWORD)]);gi=api('MsiRecordGetInteger',[w.UINT,w.UINT],c.c_int);close=api('MsiCloseHandle',[w.UINT])
    def query(db,sql,kinds):
        view=w.UINT();code=ov(db,sql,c.byref(view))
        if code:raise ValueError(('MsiDatabaseOpenView',code,sql))
        try:
            code=execute(view,0)
            if code:raise ValueError(('MsiViewExecute',code))
            while True:
                rec=w.UINT();code=fetch(view,c.byref(rec))
                if code==259:break
                if code:raise ValueError(('MsiViewFetch',code))
                try:
                    row=[]
                    for i,kind in enumerate(kinds,1):
                        if kind=='i':row.append(gi(rec,i));continue
                        n=w.DWORD(32768);buf=c.create_unicode_buffer(n.value);code=gs(rec,i,buf,c.byref(n))
                        if code:raise ValueError(('MsiRecordGetString',code))
                        row.append(buf.value)
                    yield row
                finally:close(rec)
        finally:close(view)
    db=w.UINT();code=op(str(path),None,c.byref(db))
    if code:raise ValueError(('MsiOpenDatabase READONLY',code))
    try:
        files={x[0]:x[1:] for x in query(db,'SELECT `File`, `FileName`, `FileSize` FROM `File`','ssi')}
        for key,*parts in query(db,'SELECT `File_`, `HashPart1`, `HashPart2`, `HashPart3`, `HashPart4` FROM `MsiFileHash`','siiii'):
            if key not in files:continue
            name,size=files[key];yield dict(key=key,name=name.split('|')[-1],size=size,hash_parts=parts,md5=struct.pack('<4I',*(n&0xffffffff for n in parts)).hex())
    finally:close(db)


def catalog_members(path):
    class Blob(c.Structure):_fields_=[('size',w.DWORD),('data',c.c_void_p)]
    class Attr(c.Structure):_fields_=[('oid',c.c_char_p),('value',Blob)]
    class Indirect(c.Structure):_fields_=[('data',Attr),('algorithm',Attr),('digest',Blob)]
    class Member(c.Structure):_fields_=[('size',w.DWORD),('tag',w.LPWSTR),('name',w.LPWSTR),('guid',c.c_byte*16),('flags',w.DWORD),('indirect',c.POINTER(Indirect)),('version',w.DWORD),('reserved',w.DWORD),('handle',w.HANDLE),('encoded',Blob),('info',Blob)]
    class CatAttr(c.Structure):_fields_=[('size',w.DWORD),('tag',w.LPWSTR),('type',w.DWORD),('length',w.DWORD),('data',c.c_void_p),('reserved',w.DWORD)]
    lib=c.WinDLL('wintrust',use_last_error=True);lib.CryptCATOpen.argtypes=[w.LPWSTR,w.DWORD,c.c_size_t,w.DWORD,w.DWORD];lib.CryptCATOpen.restype=w.HANDLE;lib.CryptCATClose.argtypes=[w.HANDLE];lib.CryptCATClose.restype=w.BOOL;lib.CryptCATEnumerateMember.argtypes=[w.HANDLE,c.POINTER(Member)];lib.CryptCATEnumerateMember.restype=c.POINTER(Member);lib.CryptCATEnumerateAttr.argtypes=[w.HANDLE,c.POINTER(Member),c.POINTER(CatAttr)];lib.CryptCATEnumerateAttr.restype=c.POINTER(CatAttr)
    # EXISTING plus VERIFYSIGHASH: no create, registration, trust-store changes,
    # certificate-trust assertion or executable loading.
    handle=lib.CryptCATOpen(str(path),0x10000004,0,0,0)
    if handle in (None,c.c_void_p(-1).value):raise ValueError(('CryptCATOpen/signature',c.get_last_error()))
    try:
        member=None
        while True:
            member=lib.CryptCATEnumerateMember(handle,member)
            if not member:break
            m=member.contents;attributes=[];attr=None
            while True:
                attr=lib.CryptCATEnumerateAttr(handle,member,attr)
                if not attr:break
                a=attr.contents;value=c.string_at(a.data,a.length);attributes.append(dict(tag=a.tag,type=a.type,value_hex=value.hex(),text=value.decode('utf-16-le',errors='replace').rstrip('\0')))
            row=dict(reference=m.tag,name=m.name,attributes=attributes,signature_hash_verified=True)
            if m.indirect:
                info=m.indirect.contents;row.update(algorithm_oid=info.algorithm.oid.decode(),subject_oid=info.data.oid.decode(),digest=c.string_at(info.digest.data,info.digest.size).hex())
            yield row
    finally:lib.CryptCATClose(handle)
