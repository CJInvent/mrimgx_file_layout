"""Export unplaced content outside VHDX with JSON provenance and metadata.

No address is inferred from carving, export adjacency or a file signature.
Every residual frame is retained, even when a complete embedded file is carved.
"""
import argparse,collections,hashlib,io,json,pathlib,re,sqlite3,struct,zipfile,zlib
from contextlib import closing
from recover_png_crc_grid import validate_png
from pe_anchors import image_digest


def exclusive_write(path,data):
    with path.open('xb' if isinstance(data,bytes) else 'x') as stream:stream.write(data)


def carved_files(data,maximum=256*1024**2):
    for match in re.finditer(rb'\x89PNG\r\n\x1a\n|\xff\xd8\xff|\x1f\x8b\x08|PK\x03\x04|MZ|RIFF|%PDF-',data):
        start=match.start();chunk=data[start:];kind=match.group();validation=None;length=None;suffix=None
        try:
            if kind.startswith(b'\x89PNG'):
                pos=8
                while pos+12<=len(chunk):
                    n=struct.unpack_from('>I',chunk,pos)[0]
                    if n>maximum or pos+12+n>len(chunk):raise ValueError('PNG bounds')
                    typ=chunk[pos+4:pos+8];pos+=12+n
                    if typ==b'IEND':break
                validation=validate_png(chunk[:pos]);length=pos;suffix='png'
            elif kind.startswith(b'\xff\xd8'):
                from PIL import Image
                # EXIF can contain a complete nested JPEG thumbnail. Its EOI
                # must not truncate the outer image candidate.
                for ending in list(re.finditer(b'\xff\xd9',chunk))[:64]:
                    jpeg=chunk[:ending.end()]
                    try:
                        with Image.open(io.BytesIO(jpeg)) as image:
                            if image.format!='JPEG' or image.width*image.height>64*1024**2:continue
                            dimensions=image.size;image.verify()
                        with Image.open(io.BytesIO(jpeg)) as image:image.load()
                        length=len(jpeg);suffix='jpg';validation=dict(jpeg_decoded=True,dimensions=dimensions,original_digest_available=False,structural_validation_only=True);break
                    except Exception:continue
            elif kind.startswith(b'\x1f\x8b'):
                d=zlib.decompressobj(31);decoded=d.decompress(chunk,maximum+1)
                if len(decoded)>maximum or not d.eof:raise ValueError('gzip bound/truncation')
                length=len(chunk)-len(d.unused_data);suffix='gz';validation=dict(gzip_crc_and_size=True,decoded_bytes=len(decoded))
            elif kind.startswith(b'PK'):
                for end in re.finditer(b'PK\x05\x06',chunk):
                    if end.start()+22>len(chunk):continue
                    n=end.start()+22+struct.unpack_from('<H',chunk,end.start()+20)[0]
                    if n>len(chunk):continue
                    try:
                        with zipfile.ZipFile(io.BytesIO(chunk[:n])) as archive:
                            if sum(x.file_size for x in archive.infolist())>maximum or any(x.flag_bits&1 for x in archive.infolist()):continue
                            if archive.testzip() is not None:continue
                            validation=dict(all_member_crcs_valid=True,members=[dict(name=x.filename,bytes=x.file_size,crc32=x.CRC,date_time=x.date_time) for x in archive.infolist()]);length=n;suffix='zip';break
                    except Exception:continue
            elif kind==b'MZ':
                import pefile
                pe=pefile.PE(data=chunk,fast_load=True);cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];length=max([pe.OPTIONAL_HEADER.SizeOfHeaders,cert.VirtualAddress+cert.Size]+[s.PointerToRawData+s.SizeOfRawData for s in pe.sections])
                if not 0<length<=len(chunk):continue
                # Unsigned headers alone do not establish complete file size.
                validation=dict(embedded_image_digest=image_digest(chunk[:length]));suffix='exe'
            elif kind==b'RIFF' and chunk[8:12] in (b'WEBP',b'WAVE',b'AVI '):
                length=struct.unpack_from('<I',chunk,4)[0]+8
                if not 12<=length<=len(chunk):continue
                suffix={b'WEBP':'webp',b'WAVE':'wav',b'AVI ':'avi'}[chunk[8:12]];validation=dict(riff_declared_size=length,content_integrity_checked=False)
            elif kind==b'%PDF-':
                # Preserve bounded PDF candidates separately; never claim that
                # a repaired parser proves original cross-reference integrity.
                end=re.search(rb'startxref\s+(\d+)\s+%%EOF(?:\r\n|\r|\n)?',chunk)
                if end:
                    from recover_pdf_xrefs import classic_xrefs,stream_xrefs
                    pdf=chunk[:end.end()];offset=int(end.group(1))
                    refs=classic_xrefs(pdf) if pdf[offset:offset+4]==b'xref' else stream_xrefs(pdf)
                    if any(not re.match(str(number).encode()+rb'\s+'+str(generation).encode()+rb'\s+obj\b',pdf[position:position+64]) for (number,generation),position in refs.items()):raise ValueError('PDF object reference mismatch')
                    if refs:length=len(pdf);suffix='pdf';validation=dict(original_xref_parsed=True)
        except Exception:continue
        if suffix and length and length<=maximum:yield start,bytes(chunk[:length]),suffix,validation


def export(evidence,mappings,output):
    output.mkdir(exist_ok=False);fragments=output/'fragments';fragments.mkdir();files=output/'files';files.mkdir();accepted=json.loads(mappings.read_text());placed={fid for m in accepted for fid in m['frames']};mapped_hashes=collections.defaultdict(list)
    for m in accepted:mapped_hashes[m['sha256']].append(m['disk_offset'])
    db=sqlite3.connect((evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);counts=collections.Counter();seen_files={}
    with closing(db),(evidence/'orphan-decoded.bin').open('rb') as corpus,(output/'index.jsonl').open('x') as log:
        for fid,offset,length,source_offset,stored,sha in db.execute('SELECT id,export_offset,decoded_length,source_offset,stored_length,sha256 FROM frames ORDER BY id'):
            if fid in placed:continue
            corpus.seek(offset);data=corpus.read(length)
            if len(data)!=length or hashlib.sha256(data).hexdigest()!=sha:raise ValueError('evidence frame mismatch')
            name=f'frame-{fid:08d}-{sha[:16]}.bin';path=fragments/name;exclusive_write(path,data)
            records=[dict(decoded_offset=off,signature=sig,length=n,fixup_valid=bool(valid),record_number=number,details=json.loads(details) if details else None) for off,sig,n,valid,number,details in db.execute('SELECT decoded_offset,signature,length,fixup_valid,record_number,details FROM records WHERE frame=?',(fid,))]
            metadata=dict(schema_version=1,kind='unplaced-frame',placement_status='unresolved',vhdx_insertion_authorized=False,frame=fid,sha256=sha,bytes=length,source_offset=source_offset,encoded_bytes=stored,original_evidence_offset=offset,original_evidence=str(evidence.resolve()),possible_locations=[],content_also_at=mapped_hashes.get(sha,[]),recoverable_ntfs_records=records,note='Content equality does not prove this frame originally belonged at an equivalent location. No export adjacency implies disk order.')
            exclusive_write(path.with_suffix(path.suffix+'.json'),json.dumps(metadata,indent=2));log.write(json.dumps(dict(path=str(path.relative_to(output)),metadata=str(path.with_suffix(path.suffix+'.json').relative_to(output)),**metadata))+'\n');counts['unplaced_frames']+=1;counts['unplaced_bytes']+=length
            for start,content,suffix,validation in carved_files(data):
                digest=hashlib.sha256(content).hexdigest();key=(digest,suffix);provenance=dict(frame=fid,frame_offset=start,source_offset=source_offset,source_encoding='zstd-decoded-frame')
                if key in seen_files:
                    side=seen_files[key];old=json.loads(side.read_text());old['provenance'].append(provenance);side.write_text(json.dumps(old,indent=2));continue
                target=files/(digest+'.'+suffix);exclusive_write(target,content);side=target.with_suffix(target.suffix+'.json');seen_files[key]=side
                info=dict(schema_version=1,kind='carved-file',file_type=suffix,sha256=digest,bytes=len(content),placement_status='unresolved',original_filename=None,possible_locations=[],vhdx_insertion_authorized=False,validation=validation,provenance=[provenance],note='Internal file validation is distinct from a known original filename, filesystem address, or original whole-file digest.')
                exclusive_write(side,json.dumps(info,indent=2));counts['carved_files']+=1;counts['carved_file_bytes']+=len(content)
    summary=dict(counts=counts,scope='All unplaced decoded frames and bounded internally checked files are outside the VHDX. JSON sidecars retain known metadata, provenance and uncertainty. Original raw encoded failures and metadata remain in the unchanged evidence directory.');(output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);return summary


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('evidence','mappings','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();export(a.evidence,a.mappings,a.output)
