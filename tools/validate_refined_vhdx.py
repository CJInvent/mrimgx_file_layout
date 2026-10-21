"""Read-only VHDX headers/BAT/GPT validation and normal NTFS path lookup."""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import zlib
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.hash.crc32c import crc32c
from dissect.util.stream import RangeStream


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('vhdx','layout','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--qemu-img',type=pathlib.Path,required=True)
    ap.add_argument('--partition',type=int,default=2)
    ap.add_argument('--ntfs-path',default='Windows/System32/drivers/etc/hosts')
    ap.add_argument('--expected-sha256',required=True)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    before=a.vhdx.stat();v=VHDX(a.vhdx);checks=[];locations=[];states={}
    with a.vhdx.open('rb') as f:
        for offset,length,sig in ((65536,4096,b'head'),(131072,4096,b'head'),(196608,65536,b'regi'),(262144,65536,b'regi')):
            f.seek(offset);data=bytearray(f.read(length));expected=struct.unpack_from('<I',data,4)[0];data[4:8]=bytes(4)
            if data[:4]!=sig or crc32c(bytes(data))!=expected:raise ValueError('container CRC32C')
            checks.append(dict(offset=offset,crc32c_valid=True))
        for block in range(v.bat._pb_count):
            entry=v.bat.pb(block);states[entry.state]=states.get(entry.state,0)+1
            if entry.state not in (0,2,6):raise ValueError('unsupported BAT state')
            if entry.state==6:
                offset=entry.file_offset_mb*1024**2
                if offset<4*1024**2 or offset+v.block_size>a.vhdx.stat().st_size:raise ValueError('BAT bounds')
                locations.append(offset)
    locations.sort()
    if any(y-x<v.block_size for x,y in zip(locations,locations[1:])):raise ValueError('BAT overlap')
    v.seek(512);gpt=bytearray(v.read(512));size,crc=struct.unpack_from('<II',gpt,12);gpt[16:20]=bytes(4)
    if gpt[:8]!=b'EFI PART' or not 92<=size<=512 or zlib.crc32(gpt[:size])!=crc:raise ValueError('GPT header CRC')
    lba,n,entry_size,crc=struct.unpack_from('<QIII',gpt,72)
    if n*entry_size>1024**2:raise ValueError('GPT entries bounds')
    v.seek(lba*512)
    if zlib.crc32(v.read(n*entry_size))!=crc:raise ValueError('GPT entries CRC')
    v.seek(v.size-512);secondary=v.read(512)[:8]==b'EFI PART'
    p=json.loads(a.layout.read_text())['disks'][0]['partitions'][a.partition]
    fs=NTFS(RangeStream(v,p['_geometry']['start'],p['_geometry']['length']))
    data=fs.mft.get(a.ntfs_path.replace('/','\\')).open().read();sha=hashlib.sha256(data).hexdigest()
    if sha!=a.expected_sha256:raise ValueError('known NTFS path content differs')
    with (a.output/'known-path-content.bin').open('xb') as out:out.write(data)
    qemu=subprocess.run([str(a.qemu_img),'check',str(a.vhdx)],capture_output=True,text=True)
    if qemu.returncode:raise ValueError('QEMU container check: '+qemu.stdout+qemu.stderr)
    after=a.vhdx.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('VHDX changed during validation')
    result=dict(valid=True,vhdx=str(a.vhdx.resolve()),virtual_size=v.size,file_size=before.st_size,header_and_region_checks=checks,payload_states=states,bat_bounds_and_nonoverlap_valid=True,primary_gpt_crcs_valid=True,secondary_gpt_present=secondary,known_ntfs_path=a.ntfs_path,known_path_bytes=len(data),known_path_sha256=sha,normal_ntfs_path_lookup=True,qemu_check=qemu.stdout+qemu.stderr,vhdx_stat_unchanged=True,scope='Container validity, mapped content readback and known path access do not assert a complete or bootable restored filesystem.')
    with (a.output/'summary.json').open('x') as out:json.dump(result,out,indent=2)
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':main()
