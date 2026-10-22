"""Inventory unused encoded ranges and decode orphan frames without editing an image.

Requires a completed recovery manifest and its fingerprinted plan. 'Unaccounted'
means not incorporated into that export, not never physically read or hashed.
The source and VHDX are read-only. Output is a new forensic evidence directory.
"""
from rebuild_audit import caught as _audit_caught
import argparse
import collections
import hashlib
import json
import pathlib
import sqlite3
import struct
import time

import zstandard

from make_recovery_plan import make_plan, read_at


def merge_ranges(ranges):
    result = []
    for start, end in sorted(ranges):
        if result and start <= result[-1][1]:
            result[-1][1] = max(end, result[-1][1])
        else:
            result.append([start, end])
    return result


def complement(ranges, end):
    pos = 0
    for start, stop in ranges:
        if start > pos:
            yield pos, start
        pos = max(pos, stop)
    if pos < end:
        yield pos, end


def root_layout(source):
    size = source.stat().st_size
    with source.open('rb') as f:
        offset, magic = struct.unpack('<Q12s', read_at(f, size - 20, 20, size))
        if magic != b'MACRIUM_FILE':
            raise ValueError('footer magic')
        name, n, digest, flags = struct.unpack('<8sI16sB3x', read_at(f, offset, 32, size))
        raw = read_at(f, offset + 32, n, size)
        if name != b'$JSON   ' or flags & 4 or hashlib.md5(raw).digest() != digest:
            raise ValueError('root metadata validation')
        if flags & 2:
            raw = zstandard.ZstdDecompressor().decompress(raw, max_output_size=16 * 1024**2)
        return json.loads(raw)


def catalog(source, plan, manifest, out):
    checked = make_plan(source, plan)
    if checked != plan:
        raise ValueError('source/plan fingerprint mismatch')
    layout = root_layout(source)
    if layout['_header']['backup_type'] != 'full' or layout['_encryption'].get('enable'):
        raise ValueError('requires unencrypted full image')
    events = [json.loads(line) for line in manifest.open()]
    if events[-1].get('operation') != 'complete':
        raise ValueError('recovery manifest is incomplete')
    failed = {(e['partition'], e.get('reserved', False), e['block']) for e in events if e.get('status') == 'unrecoverable'}
    db = sqlite3.connect(out / 'catalog.sqlite')
    db.execute('CREATE TABLE entries(partition INTEGER, reserved INTEGER, block INTEGER, disk_offset INTEGER, decoded_length INTEGER, source_offset INTEGER, stored_length INTEGER, digest BLOB, incorporated INTEGER)')
    accounted = []
    metadata = layout['_header']['index_file_position']
    with source.open('rb') as f:
        for pi, (spec, p) in enumerate(zip(plan['partitions'], layout['disks'][0]['partitions'])):
            pending = []
            for reserved in (True, False):
                count = spec['reserved_count'] if reserved else spec['count']
                if not count:
                    continue
                offset = spec['reserved_offset'] if reserved else spec['entries_offset']
                raw = read_at(f, offset, count * 30, source.stat().st_size)
                stride = 4 * 1024**2 if reserved else p['_header']['block_size']
                origin = p['_geometry']['start'] + (p['_geometry'].get('boot_sector_offset',0) if reserved else p['_file_system'].get('lcn0_offset',0) - p['_file_system'].get('start',0))
                limit = origin + p['_file_system']['reserved_sectors_byte_length'] if reserved else p['_geometry']['start'] + p['_geometry']['length']
                for bi, (pos, digest, n, fn) in enumerate(struct.iter_unpack('<q16sIH', raw)):
                    dest = origin + bi * stride
                    if dest >= limit:
                        continue
                    override = None if reserved else spec.get('overrides', {}).get(str(bi))
                    incorporated = bool(n and not override and (pi, reserved, bi) not in failed)
                    if n or pos or digest != bytes(16):
                        pending.append((pi, int(reserved), bi, dest, min(stride, limit - dest), pos, n, digest, int(incorporated)))
                    if incorporated:
                        if fn or not 0 <= pos < pos + n <= metadata:
                            raise ValueError('incorporated entry has invalid bounds')
                        accounted.append((pos, pos + n))
                    if override and (pi, reserved, bi) not in failed:
                        a, n = override['source_offset'], override['stored_length']
                        if not 0 <= a < a + n <= metadata:
                            raise ValueError('override bounds')
                        accounted.append((a, a + n))
                    if len(pending) >= 10000:
                        db.executemany('INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?)', pending); pending.clear()
            db.executemany('INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?)', pending)
            db.commit(); print('cataloged partition', pi, flush=True)
    db.execute('CREATE INDEX entries_digest ON entries(digest)'); db.commit()
    covered = merge_ranges(accounted)
    gaps = list(complement(covered, metadata))
    with (out / 'source-coverage.jsonl').open('x') as log:
        for status, ranges in [('incorporated-encoded-data', covered), ('unaccounted-encoded-data', gaps), ('metadata-and-footer', [(metadata, source.stat().st_size)])]:
            for a, b in ranges:
                log.write(json.dumps(dict(status=status, source_offset=a, length=b-a)) + '\n')
    summary = dict(source_size=source.stat().st_size, data_region_end=metadata,
                   incorporated_encoded_bytes=sum(b-a for a,b in covered),
                   unaccounted_encoded_bytes=sum(b-a for a,b in gaps), unaccounted_ranges=len(gaps),
                   metadata_bytes=source.stat().st_size-metadata,
                   note='Physical read history is not inferred. Coverage means incorporated into completed export.')
    (out / 'coverage-summary.json').write_text(json.dumps(summary, indent=2))
    (out / 'layout.json').write_text(json.dumps(layout, indent=2))
    (out / 'input-plan.json').write_text(json.dumps(plan, indent=2))
    print(json.dumps(summary), flush=True)
    return db, gaps, metadata


def scan(source, out, db, gaps, metadata):
    db.execute('CREATE TABLE frames(id INTEGER PRIMARY KEY, source_offset INTEGER, stored_length INTEGER, export_offset INTEGER, decoded_length INTEGER, md5 BLOB, sha256 TEXT, frame_checksum INTEGER, digest_matches TEXT)')
    db.execute('CREATE TABLE records(frame INTEGER, decoded_offset INTEGER, signature TEXT, raw_export_offset INTEGER, length INTEGER, fixup_valid INTEGER, record_number INTEGER, details TEXT)')
    from dissect.ntfs.util import apply_fixup
    stats = collections.Counter(); last = time.monotonic(); frame_id = 0
    source_state = source.stat()
    with source.open('rb') as f, (out/'source-residual.bin').open('xb') as residual, (out/'source-residual-map.jsonl').open('x') as rmap, (out/'orphan-decoded.bin').open('xb') as decoded, (out/'ntfs-records.bin').open('xb') as records, (out/'frames.jsonl').open('x') as frames, (out/'decode-failures.jsonl').open('x') as failures:
        for gi, (start,end) in enumerate(gaps):
            # Keep exact encoded bytes, including invalid frames, padding and unknown structures.
            f.seek(start); remaining=end-start; raw_offset=residual.tell(); sha=hashlib.sha256()
            while remaining:
                chunk=f.read(min(8*1024**2,remaining))
                if not chunk: raise EOFError('source range short read')
                residual.write(chunk);sha.update(chunk);remaining-=len(chunk)
            rmap.write(json.dumps(dict(source_offset=start,length=end-start,export_offset=raw_offset,sha256=sha.hexdigest()))+'\n')
            # Search every byte of every unaccounted range, preserving source-order exports.
            scan_pos=start; frame_end=start
            while scan_pos<end:
                f.seek(scan_pos); window=min(8*1024**2,end-scan_pos)
                buf=f.read(min(window+5*1024**2,end-scan_pos)); off=max(0,frame_end-scan_pos)
                while off<window:
                    hit=buf.find(b'\x28\xb5\x2f\xfd',off)
                    if hit<0 or hit>=window:break
                    off=hit+4;stats['zstd_magic_candidates']+=1
                    try:
                        raw=buf[hit:hit+5*1024**2]
                        params=zstandard.get_frame_parameters(raw)
                        if params.content_size in (zstandard.CONTENTSIZE_UNKNOWN,zstandard.CONTENTSIZE_ERROR) or not 0<params.content_size<=4*1024**2:
                            stats['unsupported_declared_size']+=1;continue
                        dec=zstandard.ZstdDecompressor().decompressobj();data=dec.decompress(raw)
                        if not dec.eof or len(data)!=params.content_size:raise ValueError('incomplete frame')
                        n=len(raw)-len(dec.unused_data);frame_id+=1
                        padding=(-decoded.tell())%512
                        decoded.write(bytes(padding));export_offset=decoded.tell();decoded.write(data)
                        digest=hashlib.md5(data).digest()
                        match_count=db.execute('SELECT count(*) FROM entries WHERE digest=?',(digest,)).fetchone()[0]
                        # Keep common digests normalized: their complete matches
                        # are a lazy SQL join on entries.digest=frames.md5.
                        matches=[dict(partition=p,reserved=bool(r),block=b,disk_offset=d,decoded_length=l,incorporated=bool(i)) for p,r,b,d,l,i in db.execute('SELECT partition,reserved,block,disk_offset,decoded_length,incorporated FROM entries WHERE digest=? LIMIT 32',(digest,))] if match_count<=32 else []
                        item=dict(id=frame_id,source_offset=scan_pos+hit,stored_length=n,export_offset=export_offset,decoded_length=len(data),md5=digest.hex(),sha256=hashlib.sha256(data).hexdigest(),frame_checksum=bool(params.has_checksum),digest_match_count=match_count,digest_matches=matches,matches_via_sql=match_count>32)
                        db.execute('INSERT INTO frames VALUES (?,?,?,?,?,?,?,?,?)',(frame_id,scan_pos+hit,n,export_offset,len(data),digest,item['sha256'],int(params.has_checksum),json.dumps(matches)))
                        frames.write(json.dumps(item)+'\n');stats['decoded_frames']+=1;stats['decoded_bytes']+=len(data)
                        if match_count:stats['frames_matching_surviving_digest']+=1
                        for roff in range(0,len(data)-511,512):
                            sig=data[roff:roff+4]
                            if sig not in (b'FILE',b'INDX'):continue
                            length=1024 if sig==b'FILE' else 4096
                            rec=data[roff:roff+length]
                            if len(rec)!=length:continue
                            valid=False;number=None;details={}
                            try:
                                fixed=apply_fixup(rec);valid=True
                                if sig==b'FILE':
                                    number=struct.unpack_from('<I',fixed,44)[0]
                                    details=dict(sequence=struct.unpack_from('<H',fixed,16)[0],flags=struct.unpack_from('<H',fixed,22)[0],base_reference=struct.unpack_from('<Q',fixed,32)[0])
                                else:details=dict(vcn=struct.unpack_from('<Q',fixed,16)[0])
                            except Exception as ex:
                                _audit_caught(ex, None, expected=True, site='forensic_residuals.py:179')
                                details={'error':str(ex)}
                            record_offset=records.tell();records.write(rec)
                            db.execute('INSERT INTO records VALUES (?,?,?,?,?,?,?,?)',(frame_id,roff,sig.decode(),record_offset,length,int(valid),number,json.dumps(details)))
                            stats[sig.decode()+('_fixup_valid' if valid else '_fixup_failed')]+=1
                        off=hit+n;frame_end=scan_pos+off
                    except (zstandard.ZstdError,ValueError,OverflowError) as ex:
                        _audit_caught(ex, None, expected=True, site='forensic_residuals.py:184')
                        stats['decode_failures']+=1
                        failures.write(json.dumps(dict(source_offset=scan_pos+hit,range_start=start,range_end=end,error=str(ex)))+'\n')
                scan_pos+=window
            if time.monotonic()-last>5:
                db.commit();frames.flush();rmap.flush()
                print('range',gi+1,'/',len(gaps),'source',end,dict(stats),flush=True);last=time.monotonic()
        db.execute('CREATE INDEX frames_md5 ON frames(md5)');db.commit()
        f.seek(metadata)
        with (out/'source-metadata-tail.bin').open('xb') as dst:
            while chunk:=f.read(8*1024**2):dst.write(chunk)
        stats['residual_export_bytes']=residual.tell();stats['decoded_export_bytes']=decoded.tell();stats['ntfs_record_export_bytes']=records.tell()
    after=source.stat()
    if (source_state.st_size,source_state.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('source changed')
    stats['source_size_and_write_time_unchanged']=True
    (out/'scan-summary.json').write_text(json.dumps(stats,indent=2));print(json.dumps(stats,indent=2),flush=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=pathlib.Path);ap.add_argument('plan',type=pathlib.Path)
    ap.add_argument('manifest',type=pathlib.Path);ap.add_argument('output',type=pathlib.Path)
    args=ap.parse_args();args.output.mkdir(exist_ok=False)
    db,gaps,metadata=catalog(args.source,json.loads(args.plan.read_text()),args.manifest,args.output)
    scan(args.source,args.output,db,gaps,metadata)


if __name__=='__main__':main()
