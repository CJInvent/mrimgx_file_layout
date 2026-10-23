"""Export unplaced content outside VHDX with JSON provenance and metadata.

No address is inferred from carving, export adjacency or a file signature.
Every residual frame is retained, even when a complete embedded file is carved.
"""
from rebuild_audit import caught as _audit_caught
import argparse,collections,hashlib,io,json,pathlib,re,sqlite3,struct,zipfile,zlib
from contextlib import closing
from recover_png_crc_grid import validate_png
from pe_anchors import image_digest
from recover_catalog_files import catalog_digest
from ntfs_compressed_fragments import compressed_units


def pe_catalog_hashes(path):
    hashes={}
    if path is None:return hashes
    algorithms={'1.3.14.3.2.26':'sha1','2.16.840.1.101.3.4.2.1':'sha256'}
    with path.open() as stream:
        for row in map(json.loads,stream):
            algorithm=algorithms.get(row.get('algorithm_oid'))
            if not algorithm or row.get('subject_oid')!='1.3.6.1.4.1.311.2.1.15' or not row.get('signature_hash_verified'):continue
            names=[a['text'] for a in row.get('attributes',[]) if a.get('tag','').casefold()=='file' and a.get('text')]
            key=(algorithm,row['digest'])
            if key not in hashes or (names and not hashes[key]['member_names']):hashes[key]=dict(algorithm=algorithm,digest=row['digest'],catalog_record=row['catalog_record'],catalog_sha256=row['catalog_sha256'],reference=row.get('reference'),member_names=names,signature_hash_verified=True,hash_kind='pe-excluding-checksum-security-certificate',historical_filename_binding_proven=False)
    return hashes


def catalog_filename(validation):
    names={pathlib.PureWindowsPath(n).name for n in validation.get('catalog_image_digest',{}).get('member_names',[]) if n}
    return next(iter(names)) if len(names)==1 else None


def exclusive_write(path,data):
    with path.open('xb' if isinstance(data,bytes) else 'x') as stream:stream.write(data)


def carved_files(data,maximum=256*1024**2,catalog_hashes=None):
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
                    except Exception as _audit_error:
                        _audit_caught(_audit_error, None, expected=True, site='rescue_unplaced_files.py:40')
                        continue
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
                    except Exception as _audit_error:
                        _audit_caught(_audit_error, None, expected=True, site='rescue_unplaced_files.py:55')
                        continue
            elif kind==b'MZ':
                import pefile
                pe=pefile.PE(data=chunk,fast_load=True);cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];length=max([pe.OPTIONAL_HEADER.SizeOfHeaders,cert.VirtualAddress+cert.Size]+[s.PointerToRawData+s.SizeOfRawData for s in pe.sections])
                if not 0<length<=len(chunk):continue
                # Unsigned headers alone do not establish complete file size.
                try:validation=dict(embedded_image_digest=image_digest(chunk[:length]))
                except Exception:
                    if not catalog_hashes:raise
                    proofs=[catalog_hashes[(alg,digest)] for alg in ('sha1','sha256') if (digest:=catalog_digest(chunk[:length],alg,'pe')) and (alg,digest) in catalog_hashes]
                    if not proofs:raise ValueError('unsigned PE has no matching surviving verified catalog member')
                    validation=dict(catalog_image_digest=proofs[-1],original_whole_file_digest_available=False,excluded_pe_fields_not_bound=True)
                suffix='exe';hint=catalog_filename(validation)
                if hint and re.fullmatch(r'\.[a-zA-Z0-9]{1,12}',pathlib.PureWindowsPath(hint).suffix):suffix=pathlib.PureWindowsPath(hint).suffix[1:].lower()
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
        except Exception as _audit_error:
            _audit_caught(_audit_error, None, expected=True, site='rescue_unplaced_files.py:76')
            continue
        if suffix and length and length<=maximum:yield start,bytes(chunk[:length]),suffix,validation


def export(evidence,mappings,output,catalog_members=None):
    output.mkdir(exist_ok=False);fragments=output/'fragments';fragments.mkdir();files=output/'files';files.mkdir();compressed=output/'compressed-fragments';compressed.mkdir();seen_units={};accepted=json.loads(mappings.read_text());placed={fid for m in accepted for fid in m['frames']};mapped_hashes=collections.defaultdict(list)
    for m in accepted:mapped_hashes[m['sha256']].append(m['disk_offset'])
    db=sqlite3.connect((evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);counts=collections.Counter();seen_files={};catalog_hashes=pe_catalog_hashes(catalog_members)
    with closing(db),(evidence/'orphan-decoded.bin').open('rb') as corpus,(output/'index.jsonl').open('x') as log:
        for fid,offset,length,source_offset,stored,sha in db.execute('SELECT id,export_offset,decoded_length,source_offset,stored_length,sha256 FROM frames ORDER BY id'):
            if fid in placed:continue
            corpus.seek(offset);data=corpus.read(length)
            if len(data)!=length or hashlib.sha256(data).hexdigest()!=sha:raise ValueError('evidence frame mismatch')
            name=f'frame-{fid:08d}-{sha[:16]}.bin';path=fragments/name;exclusive_write(path,data)
            records=[dict(decoded_offset=off,signature=sig,length=n,fixup_valid=bool(valid),record_number=number,details=json.loads(details) if details else None) for off,sig,n,valid,number,details in db.execute('SELECT decoded_offset,signature,length,fixup_valid,record_number,details FROM records WHERE frame=?',(fid,))]
            metadata=dict(schema_version=1,kind='unplaced-frame',placement_status='unresolved',vhdx_insertion_authorized=False,frame=fid,sha256=sha,bytes=length,source_offset=source_offset,encoded_bytes=stored,original_evidence_offset=offset,original_evidence=str(evidence.resolve()),possible_locations=[],content_also_at=mapped_hashes.get(sha,[]),recoverable_ntfs_records=records,note='Content equality does not prove this frame originally belonged at an equivalent location. No export adjacency implies disk order.')
            exclusive_write(path.with_suffix(path.suffix+'.json'),json.dumps(metadata,indent=2));log.write(json.dumps(dict(path=str(path.relative_to(output)),metadata=str(path.with_suffix(path.suffix+'.json').relative_to(output)),**metadata))+'\n');counts['unplaced_frames']+=1;counts['unplaced_bytes']+=length
            candidates=[(start,content,suffix,validation,dict(frame=fid,frame_offset=start,source_offset=source_offset,source_encoding='zstd-decoded-frame')) for start,content,suffix,validation in carved_files(data,catalog_hashes=catalog_hashes)]
            for start,consumed,decoded in compressed_units(data):
                digest=hashlib.sha256(decoded).hexdigest();witness=dict(frame=fid,frame_offset=start,source_offset=source_offset,source_encoding='ntfs-lznt1-within-zstd-frame',encoded_bytes=consumed,encoded_sha256=hashlib.sha256(data[start:start+consumed]).hexdigest())
                if digest in seen_units:
                    side=seen_units[digest];meta=json.loads(side.read_text());meta['provenance'].append(witness);side.write_text(json.dumps(meta,indent=2))
                else:
                    target=compressed/(digest+'.bin');exclusive_write(target,decoded);side=target.with_suffix('.bin.json');seen_units[digest]=side;exclusive_write(side,json.dumps(dict(schema_version=1,kind='uncertain-ntfs-compressed-unit-fragment',sha256=digest,bytes=len(decoded),placement_status='unresolved',vhdx_insertion_authorized=False,possible_locations=[],provenance=[witness],validation=dict(lznt1_chunk_sequences_valid=True,complete_chunks=16,chunk_decoded_bytes=4096,structural_validation_only=True,original_file_digest_available=False,original_unit_start_proven=False),note='A complete bounded compression-unit-shaped sequence is readable. Original file identity, logical offset and filesystem address are unproven; false positives remain possible.'),indent=2));counts['compressed_unit_fragments']+=1;counts['compressed_unit_decoded_bytes']+=len(decoded)
                for inner,content,suffix,validation in carved_files(decoded,catalog_hashes=catalog_hashes):candidates.append((inner,content,suffix,validation,dict(witness,decoded_unit_offset=inner)))
            for start,content,suffix,validation,provenance in candidates:
                digest=hashlib.sha256(content).hexdigest();key=(digest,suffix)
                if key in seen_files:
                    side=seen_files[key];old=json.loads(side.read_text());old['provenance'].append(provenance);side.write_text(json.dumps(old,indent=2));continue
                target=files/(digest+'.'+suffix);exclusive_write(target,content);side=target.with_suffix(target.suffix+'.json');seen_files[key]=side
                info=dict(schema_version=1,kind='carved-file',file_type=suffix,sha256=digest,bytes=len(content),placement_status='unresolved',original_filename=catalog_filename(validation),possible_locations=[],vhdx_insertion_authorized=False,validation=validation,provenance=[provenance],note='Internal file validation is distinct from a known original filename, filesystem address, or original whole-file digest.')
                exclusive_write(side,json.dumps(info,indent=2));counts['carved_files']+=1;counts['carved_file_bytes']+=len(content)
    summary=dict(counts=counts,scope='All unplaced decoded frames and bounded internally checked files are outside the VHDX. JSON sidecars retain known metadata, provenance and uncertainty. Original raw encoded failures and metadata remain in the unchanged evidence directory.');(output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);return summary


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('evidence','mappings','output'):ap.add_argument(name,type=pathlib.Path)
    ap.add_argument('--catalog-members',type=pathlib.Path,help='optional verified catalog-member inventory for unsigned PE candidates')
    a=ap.parse_args();export(a.evidence,a.mappings,a.output,a.catalog_members)
