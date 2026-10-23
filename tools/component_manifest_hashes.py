"""Bind original component payload paths to surviving Identity file hashes."""
import base64,bisect,json,pathlib,re,xml.etree.ElementTree as ET
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream
from recover_duplicate_files import file_extents

COMPONENT=re.compile(r'^(amd64|x86|wow64|arm64|arm|msil)_(.+)_([0-9a-f]{16})_(\d+\.\d+\.\d+\.\d+)_([^_]+)_([0-9a-f]{16})$',re.I)
IDENTITY='urn:schemas-microsoft-com:HashTransforms.Identity'
ALGORITHMS={'http://www.w3.org/2000/09/xmldsig#sha1':'sha1','http://www.w3.org/2000/09/xmldsig#sha256':'sha256','http://www.w3.org/2001/04/xmlenc#sha256':'sha256'}


def local(tag):return tag.rsplit('}',1)[-1]


def component_paths(target_path):
    if not isinstance(target_path,str) or '<' in target_path or '>' in target_path:return None
    path=pathlib.PureWindowsPath(target_path)
    for index,name in enumerate(path.parts[:-1]):
        match=COMPONENT.fullmatch(name)
        if not match:continue
        root=pathlib.PureWindowsPath(*path.parts[:index]);relative=pathlib.PureWindowsPath(*path.parts[index+1:]);manifest=name+'.manifest';paths=[str(root/manifest)]
        if root.name.casefold()=='winsxs':paths.append(str(root/'Manifests'/manifest))
        return dict(component=name,identity_fields=match.groups(),relative_file=str(relative),manifest_paths=paths)


def manifest_constraint(target_path,manifest_path,data):
    location=component_paths(target_path)
    if location is None or manifest_path.casefold() not in {p.casefold() for p in location['manifest_paths']}:raise ValueError('manifest path does not bind original component directory')
    if len(data)>4*1024**2:raise ValueError('manifest size bound')
    class NoDtd(ET.TreeBuilder):
        def doctype(self,*args):raise ValueError('manifest DTD unsupported')
    root=ET.fromstring(data,parser=ET.XMLParser(target=NoDtd()))
    if root.tag not in ('{urn:schemas-microsoft-com:asm.v1}assembly','{urn:schemas-microsoft-com:asm.v3}assembly'):raise ValueError('not a supported component assembly manifest')
    identities=[e.attrib for e in root if local(e.tag)=='assemblyIdentity']
    if len(identities)!=1:raise ValueError('component identity ambiguous')
    identity=identities[0];arch,name,token,version,language,tail=location['identity_fields'];actual_name=identity.get('name','').casefold();pattern=name.casefold()
    name_matches=actual_name==pattern
    if pattern.count('..')==1:
        prefix,suffix=pattern.split('..');name_matches=bool(prefix and suffix and actual_name.startswith(prefix) and actual_name.endswith(suffix) and len(actual_name)>=len(prefix)+len(suffix))
    actual_language=identity.get('language','neutral').casefold();actual_language='none' if actual_language=='neutral' else actual_language
    if not name_matches or identity.get('processorArchitecture','').casefold()!=arch.casefold() or identity.get('publicKeyToken','').casefold()!=token.casefold() or identity.get('version')!=version or actual_language!=language.casefold():raise ValueError('original component manifest identity differs')
    entries=[]
    for entry in root:
        if local(entry.tag)!='file':continue
        name=entry.get('name','');relative=pathlib.PureWindowsPath(name)
        if relative.is_absolute() or relative.drive or '..' in relative.parts:continue
        source_names=[v for k,v in entry.attrib.items() if local(k)=='sourceName' and v]
        if source_names and any(pathlib.PureWindowsPath(v)!=relative for v in source_names):continue
        if str(relative).casefold()!=location['relative_file'].casefold():continue
        for hashed in entry:
            if local(hashed.tag)!='hash':continue
            transforms=[e.get('Algorithm') for e in hashed.iter() if local(e.tag)=='Transform']
            methods=[e.get('Algorithm') for e in hashed.iter() if local(e.tag)=='DigestMethod'];values=[e.text or '' for e in hashed.iter() if local(e.tag)=='DigestValue']
            if transforms!=[IDENTITY] or len(methods)!=1 or len(values)!=1 or methods[0] not in ALGORITHMS:continue
            algorithm=ALGORITHMS[methods[0]];digest=base64.b64decode(''.join(values[0].split()),validate=True)
            if len(digest)!={'sha1':20,'sha256':32}[algorithm]:raise ValueError('component digest size')
            entries.append(dict(algorithm=algorithm,digest=digest.hex(),identity=identity,file_name=name,transform=IDENTITY))
    if not entries:raise ValueError('no supported original Identity hash for component file')
    for algorithm in {r['algorithm'] for r in entries}:
        if len({r['digest'] for r in entries if r['algorithm']==algorithm})!=1:raise ValueError('contradictory original component file hashes')
    return sorted(entries,key=lambda r:r['algorithm']=='sha256',reverse=True)[0]


class OriginalManifestReader:
    """Read manifests without mappings or unknown/reconstructed baseline bytes."""
    def __init__(self,baseline,mft,layout,manifest):
        p=layout['disks'][0]['partitions'][2];self.origin=p['_geometry']['start'];self.v=VHDX(baseline);self.fs=NTFS(RangeStream(self.v,self.origin,p['_geometry']['length']));self.cache=mft.open('rb');self.fs.mft.fh=self.cache;self.ranges=[];last=None
        with manifest.open() as stream:
            for line in stream:
                last=json.loads(line)
                if last.get('operation')=='range' and last.get('partition')==2 and last.get('status') in ('unknown-zero-index','unrecoverable','reconstructed-unverified'):self.ranges.append((last['disk_offset']-self.origin,last['disk_offset']-self.origin+last['length']))
        if last is None or last.get('operation')!='complete':raise ValueError('original baseline manifest incomplete')
        merged=[]
        for lo,hi in sorted(self.ranges):
            if merged and lo<=merged[-1][1]:merged[-1]=(merged[-1][0],max(merged[-1][1],hi))
            else:merged.append((lo,hi))
        self.ranges=merged;self.ends=[hi for lo,hi in self.ranges]

    def read(self,number,path,maximum=4*1024**2):
        record=self.fs.mft.get(number)
        if not record.header.Flags&1 or record.header.Flags&2:raise ValueError('original manifest is not an active file')
        if path.casefold() not in {p.casefold() for p in record.full_paths(ignore_dos=True)}:raise ValueError('original manifest record/path differs')
        size=record.size()
        if not 0<size<=maximum:raise ValueError('original manifest size bound')
        if not record.resident:
            for logical,physical,length in file_extents(record,size):
                k=bisect.bisect_right(self.ends,physical)
                if k<len(self.ranges) and self.ranges[k][0]<physical+length:raise ValueError('original manifest intersects unavailable baseline data')
        data=record.open().read()
        if len(data)!=size:raise ValueError('short original manifest')
        return record,data

    def close(self):self.cache.close();self.v.fh.close()


def verify_binding(reader,record,binding,algorithm,digest):
    if not record.header.Flags&1 or record.header.Flags&2 or not isinstance(binding,dict) or binding.get('kind')!='original-component-manifest-file-hash' or record.header.SequenceNumber!=binding['target_sequence'] or binding['target_path'].casefold() not in {p.casefold() for p in record.full_paths(ignore_dos=True)}:raise ValueError('original target component reference differs')
    manifest,data=reader.read(binding['manifest_record'],binding['manifest_path'])
    import hashlib
    if manifest.header.SequenceNumber!=binding['manifest_sequence'] or hashlib.sha256(data).hexdigest()!=binding['manifest_sha256']:raise ValueError('original component manifest bytes/reference differ')
    constraint=manifest_constraint(binding['target_path'],binding['manifest_path'],data)
    if constraint['algorithm']!=algorithm or constraint['digest']!=digest:raise ValueError('original component manifest file hash differs')
    return constraint
