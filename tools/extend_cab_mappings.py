"""Map CAB fragments using checksums across known boundaries and NTFS runlists.

Candidate placements are accepted only after a complete 7-Zip test of every
member in every compression folder touched by a proposed frame.
Never executes recovered members. Cabinet checksums are XOR, not cryptographic;
these placements remain explicitly reconstructed and separately evidenced.
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import sqlite3
import struct
import subprocess

import numpy as np
import zstandard
from safe_vhdx import VHDX
from dissect.ntfs import NTFS
from dissect.util.stream import RangeStream


def checksum(data):
    end=len(data)//4*4
    value=int(np.bitwise_xor.reduce(np.frombuffer(data[:end],dtype='<u4'),initial=np.uint32(0)))
    # CAB remainder bytes form a big-endian tail, unlike complete DWORDs.
    return value^int.from_bytes(data[end:],'big')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','baseline_manifest','evidence','mapping_directory','seven_zip','output'):
        ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False)
    accepted=json.loads((a.mapping_directory/'accepted-mappings.json').read_text())
    plan=json.loads((a.mapping_directory/'recovery-plan.json').read_text())
    layout=json.loads((a.evidence/'layout.json').read_text());p=layout['disks'][0]['partitions'][2]
    origin=p['_geometry']['start'];stride=p['_header']['block_size']
    ranges=[]
    for line in a.baseline_manifest.open():
        row=json.loads(line)
        if row.get('partition')==2 and row.get('operation')=='range' and row.get('status') in ('unknown-zero-index','unrecoverable'):
            ranges.append((row['disk_offset']-origin,row['disk_offset']+row['length']-origin))
    ranges.sort();starts=[x[0] for x in ranges]
    mapped={m['disk_offset']-origin:m for m in accepted if m['partition']==2}
    def unknown(base, extra):
        if base in mapped or base in extra:return False
        k=bisect.bisect_right(starts,base)-1
        return k>=0 and ranges[k][0]<=base and base+stride<=ranges[k][1]
    v=VHDX(a.baseline);fs=NTFS(RangeStream(v,origin,p['_geometry']['length']))
    fs.mft.fh=a.mft.open('rb',buffering=8*1024**2)
    db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
    corpus=(a.evidence/'orphan-decoded.bin').open('rb');source=a.source.open('rb')
    used={fid for m in accepted for fid in m['frames']};frames=[]
    for row in db.execute('SELECT id,source_offset,stored_length,export_offset,decoded_length,md5,sha256 FROM frames'):
        f=dict(zip(('id','source_offset','stored_length','export_offset','decoded_length','md5','sha256'),row))
        if f['id'] in used or f['decoded_length']!=stride:continue
        corpus.seek(f['export_offset']);f['data']=corpus.read(stride);frames.append(f)
    before=len(accepted);reports=[]
    for line in a.inventory.open():
        row=json.loads(line);path=row.get('path') or ''
        if not path.lower().endswith('.cab'):continue
        r=fs.mft.get(row['record'])
        if r.size()<1024**2:continue
        print('CAB record',row['record'],'size',r.size(),flush=True)
        filedata=bytearray(r.open().read());extents=[];logical=0
        for lcn,count in r.dataruns():
            if lcn is not None:extents.append((logical,logical+count*4096,lcn*4096))
            logical+=count*4096
        def overlay(base,data):
            for lo,hi,physical in extents:
                start=max(physical,base);end=min(physical+hi-lo,base+len(data))
                if end>start:
                    logical_start=lo+start-physical;n=min(end-start,len(filedata)-logical_start)
                    if n>0:filedata[logical_start:logical_start+n]=data[start-base:start-base+n]
        for base,m in mapped.items():
            if not any(physical<base+stride and base<physical+hi-lo for lo,hi,physical in extents):continue
            source.seek(m['source_offset']);overlay(base,zstandard.ZstdDecompressor().decompress(source.read(m['stored_length'])))
        report=dict(record=row['record'],path=path,size=len(filedata),additions=0,errors=[])
        if filedata[:4]!=b'MSCF':report['errors'].append('missing CAB header');reports.append(report);continue
        cabsize=struct.unpack_from('<I',filedata,8)[0];folders,flags=struct.unpack_from('<HH',filedata,26)[0],struct.unpack_from('<H',filedata,30)[0]
        if flags or cabsize!=len(filedata):report['errors'].append('split/reserved CAB or cabinet size differs');reports.append(report);continue
        table=[struct.unpack_from('<IHH',filedata,36+i*8) for i in range(folders)]
        def segments(lo,hi):
            out=[]
            for start,end,physical in extents:
                x=max(start,lo);y=min(end,hi)
                if y>x:out.append((x,y,physical+x-start))
            return out
        extra={};evidence=[];checks=0
        for folder,(position,count,compression) in enumerate(table):
            for block in range(count):
                header=bytes(filedata[position:position+8])
                if len(header)!=8:report['errors'].append('short CFDATA header');break
                csum,n,uncomp=struct.unpack('<IHH',header);end=position+8+n
                if not csum or not n or not 0<uncomp<=32768 or end>len(filedata):
                    report['errors'].append(dict(folder=folder,block=block,offset=position,error='unavailable or unsupported CFDATA header'));break
                spans=segments(position,end);missing=set()
                for lo,hi,physical in spans:
                    base=physical-physical%stride
                    while base<physical+hi-lo:
                        if unknown(base,extra):missing.add(base)
                        base+=stride
                if missing:
                    if len(missing)!=1 or any(unknown(physical-physical%stride,extra) for lo,hi,physical in segments(position,position+8)):
                        report['errors'].append(dict(folder=folder,offset=position,error='checksum/header not independently known'));break
                    base=next(iter(missing));template=bytes(filedata[position:end]);matches=[]
                    for f in frames:
                        if f['id'] in used or any(f['id']==x['id'] for x in extra.values()):continue
                        candidate=bytearray(template)
                        for lo,hi,physical in spans:
                            x=max(physical,base);y=min(physical+hi-lo,base+stride)
                            if y>x:candidate[lo-position+x-physical:lo-position+y-physical]=f['data'][x-base:y-base]
                        if checksum(candidate[8:])^checksum(candidate[4:8])==csum:matches.append(f)
                    if len({f['sha256'] for f in matches})!=1:
                        report['errors'].append(dict(folder=folder,offset=position,error='no unique checksum mapping',matches=len(matches)));break
                    f=matches[0];extra[base]=f;overlay(base,f['data'])
                    evidence.append(dict(base=base,frame=f['id'],record=row['record'],folder=folder,cfdata_block=block,cfdata_offset=position,expected_checksum=csum,compression=compression))
                actual=checksum(filedata[position+8:end])^checksum(filedata[position+4:position+8])
                if actual!=csum:report['errors'].append(dict(folder=folder,offset=position,error='CFDATA checksum mismatch'));break
                checks+=1;position=end
        report.update(checksummed_blocks=checks,proposed_frames=len(extra),evidence=evidence)
        if extra:
            export=a.output/f'candidate-record-{row["record"]}.cab';export.write_bytes(filedata)
            print('CAB proposed frames',len(extra),'testing archive',flush=True)
            test=subprocess.run([str(a.seven_zip),'t','-bd',str(export)],capture_output=True,text=True,errors='replace')
            (a.output/f'cab-test-{row["record"]}.txt').write_text(test.stdout+test.stderr)
            report['archive_test_returncode']=test.returncode
            folder_set={e['folder'] for e in evidence}
            folder_errors={e['folder'] for e in report['errors'] if isinstance(e,dict) and 'folder' in e}
            folder_test_ok=test.returncode==0
            if not folder_test_ok and not folder_set.intersection(folder_errors):
                listing=subprocess.run([str(a.seven_zip),'l','-slt',str(export)],capture_output=True,text=True,errors='replace',check=True)
                members=[]
                for section in listing.stdout.split('\n\n'):
                    info=dict(line.split(' = ',1) for line in section.splitlines() if ' = ' in line)
                    if info.get('Block','').isdigit() and int(info['Block']) in folder_set:
                        name=info.get('Path','')
                        if not name or '\n' in name or '\r' in name:raise ValueError('invalid cabinet member name')
                        members.append(name)
                if members:
                    selection=a.output/f'tested-members-{row["record"]}.txt'
                    selection.write_text('\n'.join(members)+'\n',encoding='utf-8')
                    selected=subprocess.run([str(a.seven_zip),'t','-bd','-spd','-scsUTF-8',str(export),'@'+str(selection)],capture_output=True,text=True,errors='replace')
                    (a.output/f'cab-affected-folders-test-{row["record"]}.txt').write_text(selected.stdout+selected.stderr)
                    report.update(affected_folders=sorted(folder_set),tested_members=len(members),affected_folders_test_returncode=selected.returncode)
                    folder_test_ok=selected.returncode==0
            if folder_test_ok:
                for base,f in sorted(extra.items()):
                    source.seek(f['source_offset']);data=zstandard.ZstdDecompressor().decompress(source.read(f['stored_length']))
                    if data!=f['data'] or hashlib.sha256(data).hexdigest()!=f['sha256']:raise ValueError('CAB source revalidation')
                    m=dict(partition=2,reserved=False,block=base//stride,disk_offset=origin+base,length=stride,source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),sha256=f['sha256'],frames=[f['id']],evidence=[dict(method='cab-boundary-checksum-runlist-affected-folders-test',detail=e) for e in evidence if e['base']==base])
                    accepted.append(m);mapped[base]=m;used.add(f['id'])
                    plan['partitions'][2].setdefault('overrides',{})[str(base//stride)]=dict(source_offset=f['source_offset'],stored_length=f['stored_length'],decoded_md5=f['md5'].hex(),reason='CAB boundary checksum plus original MFT runlist, CFDATA checks and complete 7-Zip tests of all members in affected compression folders; reconstructed, original MD5 unavailable.')
                report['additions']=len(extra)
        reports.append(report)
    (a.output/'cab-evidence.json').write_text(json.dumps(reports,indent=2))
    (a.output/'accepted-mappings.json').write_text(json.dumps(accepted,indent=2))
    (a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2))
    summary=dict(accepted_destinations=len(accepted),accepted_bytes=sum(m['length'] for m in accepted),cab_additions=len(accepted)-before)
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)


if __name__=='__main__':main()
