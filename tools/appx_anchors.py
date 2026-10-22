"""Match orphan bytes to SHA-256 file blocks recorded in surviving AppxBlockMap.

All mappings use original NTFS file runlists; package metadata is never downloaded.
"""
from rebuild_audit import caught as _audit_caught
import base64
import collections
import hashlib
import json
import pathlib
import xml.etree.ElementTree as ET


def targets(fs, inventory, stride, allowed, known_read=None):
    packages=collections.defaultdict(list)
    for line in inventory.open():
        row=json.loads(line);path=row.get('path') or ''
        components=path.split('\\')
        if len(components)>3 and components[:2]==['Program Files','WindowsApps']:
            packages['\\'.join(components[:3])].append((row['record'],'\\'.join(components[3:])))
    groups=collections.defaultdict(list);stats=collections.Counter();errors=[]
    for package,files in sorted(packages.items()):
        try:
            raw=fs.mft.get(package+'\\AppxBlockMap.xml').open().read()
            root=ET.fromstring(raw)
            if not root.attrib.get('HashMethod','').endswith('sha256'):raise ValueError('unsupported hash method')
            mapping={node.attrib['Name'].replace('/','\\').lower():node for node in root if node.tag.endswith('File')}
            stats['readable_package_blockmaps']+=1
            for number,name in files:
                node=mapping.get(name.lower())
                if node is None:continue
                r=fs.mft.get(number);size=r.size()
                if size!=int(node.attrib['Size']) or not r.header.Flags&1:continue
                if any(attr.header.flags&0x4001 for attr in r.attributes.DATA if attr.name==''):
                    stats['compressed_or_encrypted_streams_skipped']+=1;continue
                runs=r.dataruns();logical=0;extents=[]
                for lcn,count in runs:
                    if lcn is not None:extents.append((logical,logical+count*4096,lcn*4096))
                    logical+=count*4096
                position=0
                for block in node:
                    if not block.tag.endswith('Block'):continue
                    length=min(65536,size-position)
                    digest=base64.b64decode(block.attrib['Hash'],validate=True)
                    if len(digest)!=32 or length<=0:raise ValueError('bad block hash or size')
                    for lo,hi,physical in extents:
                        if lo<=position and position+length<=hi:
                            address=physical+position-lo;base=address-address%stride;off=address-base
                            if off+length<=stride and allowed(base):
                                groups[(off,length)].append(dict(base=base,digest=digest,record=number,
                                    logical_offset=position,filename=name,package=package,blockmap_sha256=hashlib.sha256(raw).hexdigest()))
                            elif known_read and off+length>stride:
                                endbase=(address+length-1)//stride*stride
                                unknown=[b for b in (base,endbase) if allowed(b)]
                                if len(unknown)==1:
                                    target=unknown[0];lo=max(address,target);hi=min(address+length,target+stride)
                                    template=known_read(address,length)
                                    groups[(lo-target,hi-lo)].append(dict(base=target,digest=digest,record=number,
                                        logical_offset=position,filename=name,package=package,blockmap_sha256=hashlib.sha256(raw).hexdigest(),
                                        template=template,template_offset=lo-address))
                    position+=length
        except Exception as ex:
            _audit_caught(ex, locals(), expected=False, site='appx_anchors.py:61')
            errors.append(dict(package=package,error=str(ex)))
    stats['hash_target_groups']=len(groups);stats['hash_targets']=sum(map(len,groups.values()))
    return groups,dict(stats),errors


def match(data, groups):
    found=[]
    for (off,length),entries in groups.items():
        digest=hashlib.sha256(data[off:off+length]).digest()
        for e in entries:
            check=digest
            if 'template' in e:
                template=e['template'];p=e['template_offset']
                check=hashlib.sha256(template[:p]+data[off:off+length]+template[p+length:]).digest()
            if check==e['digest']:
                evidence={k:v for k,v in e.items() if k not in ('template','digest')}
                evidence.update(frame_offset=off,length=length,digest=check.hex(),cross_frame='template' in e)
                found.append((e['base'],evidence))
    bases={b for b,e in found}
    if len(bases)==1:return [(bases.pop(),[e for b,e in found])]
    return []
