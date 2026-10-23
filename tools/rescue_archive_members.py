"""Export members of damaged original archives, with per-member integrity logs.

Member names never become host paths. No extracted member authorizes a VHDX
placement. Unknown compressed bytes stop decoding, and partial/CRC-failing
outputs retain explicit uncertainty alongside their original metadata.
"""
import argparse,collections,hashlib,json,pathlib,zipfile,zlib
from rebuild_context import Context
from recover_indexed_donor_frames import archive_members,ARCHIVES
from rebuild_audit import emit,caught
from zip_local_members import local_members
from zip_directory import archive_nomination


def decode_member(stream,start,length,method,expected_size,expected_crc,holes,output,limit):
    end=start+length;known_end=min([end]+[max(start,lo) for lo,hi,*rest in holes if lo<end and hi>start])
    state=dict(valid=False,decoded_bytes=0,compressed_bytes_read=0,original_compressed_bytes=length,known_compressed_bytes=known_end-start,crc32=0,sha256=None,error=None)
    digest=hashlib.sha256();decoder=zlib.decompressobj(-15) if method==8 else None
    def write(data):
        if state['decoded_bytes']+len(data)>limit:raise ValueError('member output limit reached')
        output.write(data);digest.update(data);state['crc32']=zlib.crc32(data,state['crc32']);state['decoded_bytes']+=len(data)
    try:
        if method not in (0,8):raise ValueError('unsupported member compression method '+str(method))
        if expected_size>limit:raise ValueError('declared member size exceeds output limit')
        stream.seek(start)
        while state['compressed_bytes_read']<known_end-start:
            data=stream.read(min(65536,known_end-start-state['compressed_bytes_read']))
            if not data:raise ValueError('short compressed member read')
            state['compressed_bytes_read']+=len(data)
            if decoder is None:write(data)
            else:
                while data:
                    write(decoder.decompress(data,min(65536,limit-state['decoded_bytes']+1)));data=decoder.unconsumed_tail
        if known_end!=end:raise ValueError('compressed member intersects unresolved source bytes; decoded prefix only')
        if decoder is not None and (not decoder.eof or decoder.unused_data):raise ValueError('deflate boundary or end marker differs')
        if state['decoded_bytes']!=expected_size:raise ValueError('original member size differs')
        if state['crc32']!=expected_crc:raise ValueError('original member CRC32 differs')
        state['valid']=True
    except (ValueError,zlib.error) as error:state['error']=str(error)
    state['sha256']=digest.hexdigest();return state


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--maximum-member-bytes',type=int,default=16*1024**3);ap.add_argument('--maximum-total-bytes',type=int,default=256*1024**3)
    ap.add_argument('--maximum-local-scan-bytes',type=int,default=256*1024**2)
    a=ap.parse_args()
    if min(a.maximum_member_bytes,a.maximum_total_bytes,a.maximum_local_scan_bytes)<1:ap.error('output/scan limits must be positive')
    a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);counts=collections.Counter();stopped=False
    try:
        with (a.output/'member-audit.jsonl').open('x',encoding='utf-8') as audit,a.inventory.open() as inventory:
            for row in map(json.loads,inventory):
                try:
                    record=ctx.fs.mft.get(row['record']);nomination=archive_nomination(ctx,record,row.get('path') or '')
                except Exception as error:
                    caught(error,dict(record=row['record']),expected=True,site='archive-content-nomination');continue
                if not nomination:continue
                number=row['record'];counts['archives_examined']+=1;local=False;directory_error=None
                counts['nomination_'+nomination]+=1
                try:record=ctx.fs.mft.get(number);members=archive_members(ctx,record);holes=ctx.holes(record)
                except Exception as error:
                    caught(error,dict(record=number),expected=True,site='archive-member-directory');counts['unreadable_directories']+=1;directory_error=str(error);audit.write(json.dumps(dict(record=number,path=row.get('path'),error=directory_error,kind='archive-directory-error'))+'\n');audit.flush()
                    try:
                        record=ctx.fs.mft.get(number);holes=ctx.holes(record);members,scan=local_members(record.open(),record.size(),holes,a.maximum_local_scan_bytes);local=True
                        detail=dict(record=number,path=row.get('path'),kind='archive-local-header-scan',directory_error=directory_error,**scan);audit.write(json.dumps(detail)+'\n');audit.flush()
                        counts['local_header_scans']+=1;counts['local_header_nominations']+=len(members)
                        if scan['scan_bound_reached']:emit('search-limit','Archive local-header scan bound reached',severity='warning',context=detail)
                        for reason,n in scan['skipped'].items():emit('archive-local-header-skip',reason,severity='warning',context=dict(record=number,count=n))
                    except Exception as local_error:
                        caught(local_error,dict(record=number),site='archive-local-header-scan');counts['unreadable_local_headers']+=1;audit.write(json.dumps(dict(record=number,path=row.get('path'),error=str(local_error),kind='archive-local-header-error'))+'\n');audit.flush();continue
                if not local:
                    with zipfile.ZipFile(record.open()) as archive:
                        nominated=collections.Counter((m['key'][0],m['key'][1],m['key'][2],m['key'][3],m['key'][4]) for m in members)
                        for info in archive.infolist():
                            if info.is_dir():continue
                            key=(info.filename,info.CRC,info.file_size,info.compress_size,info.compress_type)
                            if nominated[key]:nominated[key]-=1;continue
                            issue=dict(record=number,path=row.get('path'),member_name=info.filename,kind='archive-member-unavailable',error='Encrypted member, missing local header or unsupported original bounds',original_crc32=info.CRC,original_size=info.file_size)
                            counts['unavailable_members']+=1;audit.write(json.dumps(issue)+'\n');audit.flush();emit('archive-member-unavailable',issue['error'],severity='warning',context=issue)
                # Source data is never executed. All output paths are generated IDs.
                for ordinal,member in enumerate(members):
                    if counts['exported_bytes']>=a.maximum_total_bytes:stopped=True;break
                    name,crc,size,compressed,method=member['key']
                    if name.endswith('/'):continue
                    folder=a.output/str(number);folder.mkdir(exist_ok=True)
                    target=folder/(str(ordinal)+'-'+hashlib.sha256(name.encode('utf-8',errors='surrogatepass')).hexdigest()[:20]+'.bin')
                    with target.open('xb') as output:result=decode_member(record.open(),member['start'],compressed,method,size,crc,holes,output,min(a.maximum_member_bytes,a.maximum_total_bytes-counts['exported_bytes']))
                    meta=dict(kind='original-archive-member' if result['valid'] else 'uncertain-archive-member-prefix',archive_record=number,archive_sequence=record.header.SequenceNumber,archive_path=row.get('path'),member_name=name,original_crc32=crc,original_size=size,compressed_start=member['start'],compressed_length=compressed,compression_method=method,filesystem_placement_unknown=True,vhdx_insertion_authorized=False,possible_locations=[dict(archive_record=number,archive_path=row.get('path'),member_name=name,placement_confirmed=False)],**result)
                    meta['original_member_directory_binding_proven']=not local
                    meta['archive_nomination']=nomination
                    if local:
                        meta.update(kind='local-archive-member-candidate' if result['valid'] else 'uncertain-local-archive-member-prefix',directory_error=directory_error,local_header_offset=member['local_header_offset'],local_header_bytes=member['local_header_bytes'],local_header_sha256=member['local_header_sha256'],scope='CRC/size and complete deflate boundary validate the local record only. Original active directory membership is unknown; this export never authorizes VHDX insertion.')
                        counts['local_header_valid_members' if result['valid'] else 'local_header_uncertain_members']+=1
                    target.with_suffix('.bin.json').write_text(json.dumps(meta,indent=2),encoding='utf-8');audit.write(json.dumps(dict(output=str(target.resolve()),**meta))+'\n');audit.flush()
                    counts['valid_members' if result['valid'] else 'incomplete_or_invalid_members']+=1;counts['exported_bytes']+=result['decoded_bytes']
                    if not result['valid']:emit('archive-member-integrity',result['error'],severity='warning',context=meta)
                if stopped:break
                print(json.dumps(dict(record=number,counts=dict(counts))),flush=True)
        if stopped:emit('search-limit','Archive member total export bound reached',severity='warning',context=dict(maximum_total_bytes=a.maximum_total_bytes))
        summary=dict(counts=dict(counts),total_output_bound_reached=stopped,limits=dict(maximum_member_bytes=a.maximum_member_bytes,maximum_total_bytes=a.maximum_total_bytes,maximum_local_scan_bytes=a.maximum_local_scan_bytes),scope='CRC-valid member records and uncertain decoded prefixes are separate external files with JSON metadata. Local-header-only records additionally retain unproven active directory membership. No member is inserted into the VHDX; source archive corruption and unsupported/encrypted members remain in preserved evidence. Only stored and raw-deflate member compression are decoded.')
        (a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
    finally:ctx.close()


if __name__=='__main__':main()
