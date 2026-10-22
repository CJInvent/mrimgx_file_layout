"""Rescue file data behind malformed UTF-16 FILE_NAME attributes, outside VHDX.

Only a private parser copy substitutes invalid code units. Original MFT bytes,
data attributes, source, mappings and image bytes are never rewritten.
"""
import argparse,hashlib,json,mmap,pathlib,re,struct
from dissect.ntfs.util import apply_fixup,segment_reference
from rebuild_context import Context
from rebuild_audit import caught,emit


def parser_copy(raw):
    """Return fixed-up parser bytes and lossless name evidence, or None.

    Reject extension records, attribute lists and malformed bounds. Filename
    replacement keeps the same number of UTF-16 code units and offsets.
    """
    if raw[:4]!=b'FILE':return None
    data=bytearray(apply_fixup(raw));flags=struct.unpack_from('<H',data,22)[0]
    if not flags&1 or flags&2 or struct.unpack_from('<Q',data,32)[0]:return None
    used=struct.unpack_from('<I',data,24)[0];pos=struct.unpack_from('<H',data,20)[0]
    if not 48<=pos<used<=len(data):raise ValueError('MFT attribute bounds')
    names=[];changed=False;ended=False
    while pos+4<=used:
        kind=struct.unpack_from('<I',data,pos)[0]
        if kind==0xffffffff:ended=True;break
        if pos+24>used:raise ValueError('short MFT attribute')
        length=struct.unpack_from('<I',data,pos+4)[0]
        if length<24 or length%8 or pos+length>used:raise ValueError('MFT attribute length')
        if kind==32:return None
        if kind==48:
            if data[pos+8]:raise ValueError('nonresident FILE_NAME')
            size=struct.unpack_from('<I',data,pos+16)[0];off=struct.unpack_from('<H',data,pos+20)[0]
            if off<24 or size<66 or off+size>length:raise ValueError('FILE_NAME bounds')
            value=pos+off;n=data[value+64];start=value+66;stop=start+2*n
            if 66+2*n!=size:raise ValueError('FILE_NAME name length')
            original=bytes(data[start:stop]);invalid=False
            try:name=original.decode('utf-16-le')
            except UnicodeDecodeError:
                # Decode one code unit at a time only where it is unpaired;
                # valid surrogate pairs and all original evidence survive.
                name=original.decode('utf-16-le',errors='surrogatepass');safe=''.join('\ufffd' if 0xd800<=ord(c)<=0xdfff else c for c in name).encode('utf-16-le')
                if len(safe)!=len(original):raise ValueError('filename parser substitution changed length')
                data[start:stop]=safe;changed=True;invalid=True
            parent=struct.unpack_from('<Q',data,value)[0]
            names.append(dict(raw_utf16_hex=original.hex(),display_name=original.decode('utf-16-le',errors='replace'),invalid_utf16=invalid,parent_record=parent&((1<<48)-1),parent_sequence=parent>>48,namespace=data[value+65]))
        pos+=length
    if not ended:raise ValueError('missing MFT attribute end')
    return (bytes(data),names) if changed else None


def directory_names(ctx,number,sequence,names):
    found=[]
    for parent_number,parent_sequence in {(n['parent_record'],n['parent_sequence']) for n in names}:
        try:
            parent=ctx.fs.mft.get(parent_number)
            if parent.header.SequenceNumber!=parent_sequence:continue
            for entry in parent.index('$I30').entries():
                if segment_reference(entry.header.FileReference)!=number or entry.header.FileReference.SequenceNumber!=sequence:continue
                key=entry.key
                if len(key)<66 or len(key)!=66+2*key[64]:continue
                reference=struct.unpack_from('<Q',key)[0]
                if reference!=(parent_sequence<<48|parent_number):continue
                name=key[66:].decode('utf-16-le');parent_path=parent.full_path()
                found.append(dict(record=number,sequence=sequence,path=parent_path+'\\'+name,name=name,parent_record=parent_number,parent_sequence=parent_sequence,matching_basis='surviving directory entry with matching child and parent record/sequence',placement_confirmed=False))
        except Exception as e:caught(e,dict(number=number),site='metadata-rescue-directory')
    return found


def rescue(source,baseline,mft,manifest,evidence,mapping_directory,output):
    output.mkdir(exist_ok=False);ctx=Context(source,baseline,mft,manifest,evidence,mapping_directory);reports=[];saved=0;total=0
    try:
        with mft.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
            for start in range(0,len(raw)-1023,1024):
                if raw[start:start+4]!=b'FILE':continue
                number=start//1024
                try:parsed=parser_copy(raw[start:start+1024])
                except Exception as e:caught(e,dict(number=number),expected=True,site='metadata-rescue-record-probe');continue
                if parsed is None:continue
                data,names=parsed;row=dict(record=number,names=names)
                try:
                    record=ctx.fs.mft.get(number);record.data=data
                    size=record.size()
                    if size>256*1024**2 or (not record.resident and ctx.holes(record)):raise ValueError('incomplete or excessive file behind malformed name')
                    content=record.open().read()
                    if len(content)!=size:raise ValueError('short file behind malformed name')
                    locations=directory_names(ctx,number,record.header.SequenceNumber,names);directory_filenames={loc['name'] for loc in locations};original_filename=next(iter(directory_filenames)) if len(directory_filenames)==1 else None
                    suffix=pathlib.PureWindowsPath(original_filename).suffix.lower() if original_filename else '.bin'
                    if not re.fullmatch(r'\.[a-z0-9]{1,12}',suffix):suffix='.bin'
                    sha=hashlib.sha256(content).hexdigest();target=output/(str(number)+'-'+sha+suffix)
                    with target.open('xb') as dst:dst.write(content)
                    info=dict(schema_version=1,kind='malformed-name-file',record=number,sequence=record.header.SequenceNumber,sha256=sha,bytes=size,file_type=suffix[1:],original_filename=original_filename,placement_status='original-runlist-data-preserved-external',vhdx_insertion_authorized=False,original_names=names,possible_locations=locations,resident_data=record.resident,physical_cluster_runs=[] if record.resident else list(record.dataruns()),partition=2,cluster_bytes=ctx.fs.cluster_size,partition_disk_offset=ctx.origin,original_mft_record_sha256=hashlib.sha256(raw[start:start+1024]).hexdigest(),validation=dict(original_sector_fixups_valid=True,data_attributes_unchanged=True,missing_runlist_ranges=False,original_whole_file_digest_available=False),note='Only the in-memory parser copy substitutes malformed filename code units. No MFT/image metadata is repaired. Directory entries nominate original names; original UTF-16 bytes and record references are retained.')
                    target.with_suffix(target.suffix+'.json').write_text(json.dumps(info,indent=2));row.update(saved=str(target.resolve()),sha256=sha,bytes=size);saved+=1;total+=size
                    emit('metadata-file-rescued','Preserved file data behind malformed filename',context=row)
                except Exception as e:caught(e,dict(number=number),site='metadata-rescue-file');row['error']=str(e)
                reports.append(row)
    finally:ctx.close()
    result=dict(malformed_name_records=len(reports),files_saved=saved,bytes_saved=total,reports=reports,scope='Read-only rescue of complete default data streams behind malformed FILE_NAME UTF-16. Original filesystem bytes stay unchanged; no missing bytes are synthesized.')
    (output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True);return result


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();rescue(**vars(a))
