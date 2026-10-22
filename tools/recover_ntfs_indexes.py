"""Map orphan Zstandard directory frames through independently readable NTFS MFT runlists.

Input: a fingerprinted recovery plan with a usable NTFS boot-block override if
needed. Output: a new plan; neither source bytes nor the input plan are changed.
All resulting overrides remain explicitly reconstructed/unverified.
Requires zstandard and dissect.ntfs. Do not infer mappings from frame order.
"""
from rebuild_audit import caught as _audit_caught
import argparse
import functools
import hashlib
import io
import json
import pathlib
import struct

import zstandard
from dissect.ntfs import NTFS
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.util import apply_fixup
from make_recovery_plan import read_at


class IndexedVolume(io.RawIOBase):
    def __init__(self, source, plan, partition):
        self.source = source
        self.f = source.open('rb')
        self.file_size = source.stat().st_size
        if self.file_size != plan['source_size']:
            raise ValueError('source length differs from plan')
        root, magic = struct.unpack('<Q12s', read_at(self.f, self.file_size - 20, 20, self.file_size))
        if magic != b'MACRIUM_FILE':
            raise ValueError('footer magic')
        name, n, digest, flags = struct.unpack('<8sI16sB3x', read_at(self.f, root, 32, self.file_size))
        if name != b'$JSON   ' or flags & 4:
            raise ValueError('unsupported root metadata')
        text = read_at(self.f, root + 32, n, self.file_size)
        if hashlib.md5(text).digest() != digest:
            raise ValueError('root stored digest')
        if flags & 2:
            text = zstandard.ZstdDecompressor().decompress(text, max_output_size=16 * 1024**2)
        if hashlib.md5(text).hexdigest() != plan['json_md5']:
            raise ValueError('root plan fingerprint')
        layout = json.loads(text)
        if layout['_encryption'].get('enable') or layout['_header']['backup_type'] != 'full':
            raise ValueError('requires unencrypted full image')
        p = layout['disks'][0]['partitions'][partition]
        if p['_file_system']['type'] != 'NTFS':
            raise ValueError('partition is not NTFS')
        self.size = p['_geometry']['length']
        self.block_size = p['_header']['block_size']
        self.metadata = layout['_header']['index_file_position']
        self.spec = plan['partitions'][partition]
        self.entries = read_at(self.f, self.spec['entries_offset'], self.spec['count'] * 30, self.file_size)
        if hashlib.md5(self.entries).hexdigest() != self.spec['entries_md5']:
            raise ValueError('entry array plan fingerprint')
        self.pos = 0

    @functools.lru_cache(maxsize=128)
    def block(self, number):
        if not 0 <= number < self.spec['count']:
            raise ValueError('block outside index')
        pos, digest, n, file_number = struct.unpack_from('<Q16sIH', self.entries, number * 30)
        override = self.spec.get('overrides', {}).get(str(number))
        if override:
            pos, n, file_number = override['source_offset'], override['stored_length'], 0
            digest = bytes.fromhex(override['decoded_md5'])
        if not n or file_number or n > self.block_size + 1024**2 or pos + n > self.metadata:
            raise ValueError(f'unavailable or invalid entry {number}')
        raw = read_at(self.f, pos, n, self.file_size)
        data = zstandard.ZstdDecompressor().decompress(raw, max_output_size=self.block_size)
        if len(data) > self.block_size or hashlib.md5(data).digest() != digest:
            raise ValueError(f'decoded digest/size {number}')
        return data

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, offset, whence=0):
        self.pos = offset if whence == 0 else self.pos + offset if whence == 1 else self.size + offset
        if not 0 <= self.pos <= self.size: raise ValueError('seek bounds')
        return self.pos

    def read(self, size=-1):
        if size < 0: raise ValueError('unbounded read')
        size = min(size, self.size - self.pos)
        out = bytearray()
        while size:
            number, offset = divmod(self.pos, self.block_size)
            b = self.block(number)
            n = min(size, len(b) - offset)
            if n <= 0: raise ValueError('short decoded block')
            out.extend(b[offset:offset + n]); self.pos += n; size -= n
        return bytes(out)


def recover(source, plan, partition, scan_start, scan_end):
    volume = IndexedVolume(source, plan, partition)
    ntfs = NTFS(volume)
    if ntfs.cluster_size != 4096 or ntfs._index_size != 4096:
        raise ValueError('this scanner currently requires 4096-byte clusters/index buffers')
    if not 0 <= scan_start < scan_end <= volume.metadata:
        raise ValueError('scan bounds')
    known = {struct.unpack_from('<Q', volume.entries, i * 30)[0]
             for i in range(volume.spec['count'])
             if struct.unpack_from('<I', volume.entries, i * 30 + 24)[0]}
    found, ambiguous = {}, set()

    def locate(parent, vcn):
        r = ntfs.mft.get(parent & ((1 << 48) - 1))
        if r.header.SequenceNumber != parent >> 48 or not r.is_dir() or not r.header.Flags & 1:
            raise ValueError('parent record does not corroborate candidate')
        for attr in r.attributes[ATTRIBUTE_TYPE_CODE.INDEX_ALLOCATION]:
            if attr.name != '$I30': continue
            logical = attr.header.lowest_vcn
            for lcn, count in attr.dataruns():
                if lcn is not None and logical <= vcn < logical + count:
                    return (lcn + vcn - logical) * 4096
                logical += count
        raise ValueError('VCN is outside parent runlist')

    with source.open('rb') as scan:
        for pos in range(scan_start, scan_end, 8 * 1024**2):
            scan.seek(pos)
            window = min(8 * 1024**2, scan_end - pos)
            buf = scan.read(window + volume.block_size + 1024**2)
            offset = 0
            while offset < window:
                offset = buf.find(b'\x28\xb5\x2f\xfd', offset)
                if offset < 0 or offset >= window: break
                source_offset = pos + offset
                offset += 4
                if source_offset in known: continue
                try:
                    raw = buf[offset - 4:offset - 4 + volume.block_size + 1024**2]
                    if zstandard.frame_content_size(raw) != volume.block_size: continue
                    decoder = zstandard.ZstdDecompressor().decompressobj()
                    data = decoder.decompress(raw)
                    if not decoder.eof: continue
                    stored_length = len(raw) - len(decoder.unused_data)
                    mappings, parents = [], []
                    for page in range(0, len(data) - 4095, 4096):
                        if data[page:page + 4] != b'INDX': continue
                        fixed = apply_fixup(data[page:page + 4096])
                        vcn = struct.unpack_from('<Q', fixed, 16)[0]
                        entry = 24 + struct.unpack_from('<I', fixed, 24)[0]
                        entry_len, key_len, flags = struct.unpack_from('<HHH', fixed, entry + 8)
                        if flags & 2 or key_len < 66 or entry + 16 + key_len > 4096: continue
                        parent = struct.unpack_from('<Q', fixed, entry + 16)[0]
                        base = locate(parent, vcn) - page
                        if base >= 0 and base % volume.block_size == 0:
                            mappings.append(base // volume.block_size)
                            parents.append(parent & ((1 << 48) - 1))
                    if not mappings or len(set(mappings)) != 1: continue
                    number = mappings[0]
                    if number >= volume.spec['count']: continue
                    old_pos, old_digest, old_n, _ = struct.unpack_from('<Q16sIH', volume.entries, number * 30)
                    digest = hashlib.md5(data).hexdigest()
                    if old_n and old_digest.hex() == digest: continue
                    if old_n and old_pos != source_offset: continue
                    key = str(number)
                    if key in ambiguous: continue
                    if key in found and found[key]['decoded_md5'] != digest:
                        del found[key]; ambiguous.add(key); continue
                    found[key] = dict(source_offset=source_offset, stored_length=stored_length,
                                      decoded_md5=digest, reason=(
                        f'Carved INDX: {len(mappings)} fixup-valid pages mapped through verified MFT '
                        f'parent runlists {sorted(set(parents))}; original index digest unavailable.'))
                except (ValueError, EOFError, OSError, struct.error, zstandard.ZstdError) as _audit_error:
                    _audit_caught(_audit_error, locals(), expected=False, site='recover_ntfs_indexes.py:169')
                    continue
            print(f'scanned={pos + window} reconstructed={len(found)} ambiguous={len(ambiguous)}', flush=True)
    plan['partitions'][partition].setdefault('overrides', {}).update(found)
    return plan


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=pathlib.Path)
    ap.add_argument('plan', type=pathlib.Path)
    ap.add_argument('output', type=pathlib.Path)
    ap.add_argument('--partition', type=int, required=True)
    ap.add_argument('--scan-start', type=int, default=0)
    ap.add_argument('--scan-end', type=int, required=True)
    args = ap.parse_args()
    if args.output.exists(): raise SystemExit('Output exists')
    result = recover(args.source, json.loads(args.plan.read_text()), args.partition, args.scan_start, args.scan_end)
    with args.output.open('x') as f: json.dump(result, f, indent=2)
