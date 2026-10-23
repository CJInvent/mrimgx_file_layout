"""Original signed MSIX part hashes; no trust-store changes or code execution.

Digest layout: microsoft/msix-packaging src/inc/internal/AppxSignature.hpp.
Only complete baseline signature bytes can authorize their named package parts.
"""
import ctypes as c,ctypes.wintypes as w,hashlib,pathlib

PARTS={'AXBM':'AppxBlockMap.xml','AXCI':'AppxMetadata\\CodeIntegrity.cat','AXCT':'[Content_Types].xml'}


def verified_content(blob):
    class Parameters(c.Structure):_fields_=[('size',w.DWORD),('encoding',w.DWORD),('provider',c.c_size_t),('callback',c.c_void_p),('argument',c.c_void_p)]
    lib=c.WinDLL('crypt32',use_last_error=True);fn=lib.CryptVerifyMessageSignature;fn.argtypes=[c.POINTER(Parameters),w.DWORD,c.c_void_p,w.DWORD,c.c_void_p,c.POINTER(w.DWORD),c.c_void_p];fn.restype=w.BOOL
    parameters=Parameters(c.sizeof(Parameters),0x10001,0,None,None);source=c.create_string_buffer(blob);length=w.DWORD()
    if not fn(c.byref(parameters),0,source,len(blob),None,c.byref(length),None):raise ValueError('Appx signature verification failed '+hex(c.get_last_error()))
    if not 0<length.value<=4*1024**2:raise ValueError('detached or excessive Appx signed content')
    output=c.create_string_buffer(length.value)
    if not fn(c.byref(parameters),0,source,len(blob),output,c.byref(length),None):raise ValueError('Appx signature verification failed '+hex(c.get_last_error()))
    return output.raw[:length.value]


def digest_list(blob):
    if blob[:4]!=b'APPX' or len(blob) not in (148,184):raise ValueError('unsupported Appx digest list')
    result={}
    for i in range(4,len(blob),36):
        name=blob[i:i+4].decode('ascii')
        if name not in ('AXPC','AXCD','AXCT','AXBM','AXCI') or name in result:raise ValueError('invalid/duplicate Appx digest name')
        result[name]=blob[i+4:i+36].hex()
    if not {'AXPC','AXCD','AXCT','AXBM'}<=result.keys():raise ValueError('missing Appx digest name')
    return result


def signature_hashes(raw):
    from asn1crypto import cms,core,algos
    class Indirect(core.Sequence):_fields=[('data',core.Any),('message_digest',algos.DigestInfo)]
    if not 4<len(raw)<=4*1024**2 or raw[:4]!=b'PKCX':raise ValueError('invalid original Appx signature header/bounds')
    verified=verified_content(raw[4:]);ci=cms.ContentInfo.load(raw[4:],strict=True)
    if ci['content_type'].native!='signed_data':raise ValueError('not signed Appx data')
    encap=ci['content']['encap_content_info']
    if encap['content_type'].dotted!='1.3.6.1.4.1.311.2.1.4':raise ValueError('unexpected Appx signed content OID')
    body=encap['content'].contents;n=len(body);length=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big');encoded=b'\x30'+length+body
    if verified not in (body,encoded):raise ValueError('Appx verified content differs from parsed content')
    digest=Indirect.load(encoded,strict=True)['message_digest']
    if digest['digest_algorithm']['algorithm'].native!='sha256':raise ValueError('unsupported Appx part hash algorithm')
    return digest_list(digest['digest'].native)


def package_path(target,part):
    path=pathlib.PureWindowsPath(target);parts=path.parts;tail=pathlib.PureWindowsPath(PARTS[part]).parts
    if len(parts)!=3+len(tail) or [p.casefold() for p in parts[:2]]!=['program files','windowsapps'] or tuple(p.casefold() for p in parts[3:])!=tuple(p.casefold() for p in tail) or any('<' in p or '>' in p or p in ('.','..') for p in parts):raise ValueError('Appx target is not an exact named installed-package part')
    return str(pathlib.PureWindowsPath(*parts[:3]))


def verify_binding(reader,record,binding,algorithm,digest,fs=None):
    if not isinstance(binding,dict) or binding.get('kind')!='original-appx-signature-file-hash' or algorithm!='sha256' or not record.header.Flags&1 or record.header.Flags&2 or record.header.SequenceNumber!=binding['target_sequence'] or binding['target_path'].casefold() not in {p.casefold() for p in record.full_paths(ignore_dos=True)}:raise ValueError('original Appx target reference differs')
    package=package_path(binding['target_path'],binding['part']);path=package+'\\AppxSignature.p7x'
    if binding['signature_path'].casefold()!=path.casefold():raise ValueError('Appx signature package/path differs')
    if binding.get('signature_source')=='source-backed-mapped-overlay':
        if fs is None:raise ValueError('mapped original Appx signature requires source-backed filesystem')
        signature=fs.mft.get(binding['signature_record'])
        if not signature.header.Flags&1 or signature.header.Flags&2 or path.casefold() not in {p.casefold() for p in signature.full_paths(ignore_dos=True)} or not 0<signature.size()<=4*1024**2:raise ValueError('mapped original Appx signature reference/bounds differs')
        data=signature.open().read()
        if len(data)!=signature.size():raise ValueError('short mapped original Appx signature')
    else:signature,data=reader.read(binding['signature_record'],path)
    if signature.header.SequenceNumber!=binding['signature_sequence'] or hashlib.sha256(data).hexdigest()!=binding['signature_sha256']:raise ValueError('original Appx signature reference/content differs')
    if signature_hashes(data).get(binding['part'])!=digest:raise ValueError('original signed Appx part hash differs')
    return True
