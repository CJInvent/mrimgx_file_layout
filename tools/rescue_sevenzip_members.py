"""Export source-known COPY members of damaged 7z archives, with provenance."""
import argparse,collections,hashlib,json,pathlib,zlib
from rebuild_context import Context
from sevenzip_copy import MAGIC,copy_members
from rebuild_audit import caught,emit
from zip_directory import known


def member_parts(start,stop,holes):
    position=start
    for lo,hi,*_ in sorted(holes):
        if hi<=position:continue
        if lo>=stop:break
        if lo>position:yield position,min(lo,stop)
        position=max(position,hi)
    if position<stop:yield position,stop


def export_members(stream,size,holes,owner,folder,counts,maximum_total_bytes):
    members,proof=copy_members(stream,size,holes);folder.mkdir(parents=True)
    (folder/'original-metadata.json').write_text(json.dumps(dict(owner=owner,**proof),indent=2))
    for number,member in enumerate(members):
        name,crc,length,_,_=member['key'];parts=list(member_parts(member['start'],member['stop'],holes));complete=sum(hi-lo for lo,hi in parts)==length
        if not length:parts=[(member['start'],member['start'])]
        for index,(lo,hi) in enumerate(parts):
            if counts['exported_bytes']+hi-lo>maximum_total_bytes:
                emit('search-limit','7z COPY export byte budget reached',severity='warning',context=owner);return True
            path=folder/(str(number)+'-'+str(index)+'.bin');digest=hashlib.sha256();checksum=0;remaining=hi-lo;stream.seek(lo)
            with path.open('xb') as output:
                while remaining:
                    data=stream.read(min(remaining,1024**2))
                    if not data:raise EOFError('7z COPY source ended within a known member range')
                    output.write(data);digest.update(data);checksum=zlib.crc32(data,checksum);remaining-=len(data)
            valid=complete and crc is not None and checksum==crc
            meta=dict(schema_version=1,kind='7z-copy-member' if complete else '7z-copy-member-known-part',**owner,member_name=name,original_size=length,original_crc32=crc,decoded_crc32=checksum,complete_original_member=complete,valid=valid,decoded_bytes=hi-lo,logical_member_offset=lo-member['start'],source_file_offset=lo,sha256=digest.hexdigest(),source_member=member,original_metadata=str((folder/'original-metadata.json').resolve()),placement_status='unresolved',vhdx_insertion_authorized=False,scope='Exact contiguous known bytes in an original COPY member; archive membership does not prove a standalone historical filesystem path. Partial or CRC-failing members remain explicitly uncertain.')
            path.with_suffix('.bin.json').write_text(json.dumps(meta,indent=2));counts['exported_bytes']+=hi-lo;counts['valid_members' if valid else 'uncertain_members']+=1
    counts['unsupported_folders']+=len(proof['unsupported_folders'])
    return False


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-total-bytes',type=int,default=256*1024**3);a=ap.parse_args()
    if a.maximum_total_bytes<1:ap.error('export budget must be positive')
    a.output.mkdir();ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);counts=collections.Counter()
    try:
        with a.inventory.open() as inventory:
            for row in map(json.loads,inventory):
                typed=False
                try:
                    record=ctx.fs.mft.get(row['record'])
                    if record.header.Flags&2 or record.size()<32:continue
                    stream=record.open();holes=ctx.holes(record)
                    if not holes or not known(holes,0,6) or stream.read(6)!=MAGIC:continue
                    typed=True;counts['damaged_archives_examined']+=1
                    if export_members(stream,record.size(),holes,dict(archive_record=row['record'],archive_sequence=record.header.SequenceNumber,archive_path=row.get('path')),a.output/str(row['record']),counts,a.maximum_total_bytes):break
                except (OSError,EOFError,MemoryError):raise
                except Exception as error:
                    caught(error,dict(record=row['record']),expected=not typed,site='7z-copy-member-rescue')
                    if typed:counts['archive_errors']+=1
        (a.output/'summary.json').write_text(json.dumps(dict(counts=counts,scope='COPY-only source-known exports; unsupported compressed folders remain in the original evidence.'),indent=2));print(json.dumps(dict(counts=counts)),flush=True)
    finally:ctx.close()


if __name__=='__main__':main()
