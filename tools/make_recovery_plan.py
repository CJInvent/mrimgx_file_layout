"""Create a fingerprinted recovery plan from independently established index offsets.

Does not repair or change the backup. Descriptor offsets are forensic inputs, not
automatically trusted. The converter checks all entry bounds and decoded hashes.
"""
import argparse
import hashlib
import json
import pathlib
import struct

import zstandard


def read_at(f, offset, size, file_size):
    if offset < 0 or size < 0 or size > 512 * 1024**2 or offset + size > file_size:
        raise ValueError("read outside file / excessive allocation")
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise IOError(f"short read at {offset}: requested {size}, actual {len(data)}")
    return data


def make_plan(source, descriptor):
    size = source.stat().st_size
    with source.open("rb") as f:
        root, magic = struct.unpack("<Q12s", read_at(f, size - 20, 20, size))
        if magic != b"MACRIUM_FILE":
            raise ValueError("footer magic")
        name, length, digest, flags = struct.unpack("<8sI16sB3x", read_at(f, root, 32, size))
        if name != b"$JSON   " or flags & 4:
            raise ValueError("Expected unencrypted JSON first at root")
        text = read_at(f, root + 32, length, size)
        if hashlib.md5(text).digest() != digest:
            raise ValueError("JSON stored hash failed")
        if flags & 2:
            text = zstandard.ZstdDecompressor().decompress(text, max_output_size=16 * 1024**2)
        layout = json.loads(text)
        parts = layout["disks"][0]["partitions"]
        if len(parts) != len(descriptor["partitions"]):
            raise ValueError("Partition count")
        plan = dict(imageid=layout["_header"]["imageid"], source_size=size,
                    json_md5=hashlib.md5(text).hexdigest(), partitions=[])
        for part, spec in zip(parts, descriptor["partitions"]):
            spec = dict(spec)
            spec["count"] = part["_header"]["block_count"]
            spec["entries_md5"] = hashlib.md5(
                read_at(f, spec["entries_offset"], spec["count"] * 30, size)).hexdigest()
            spec.setdefault("reserved_count", 0)
            spec.setdefault("reserved_offset", 0)
            if spec["reserved_count"]:
                spec["reserved_md5"] = hashlib.md5(
                    read_at(f, spec["reserved_offset"], spec["reserved_count"] * 30, size)).hexdigest()
            plan["partitions"].append(spec)
        return plan


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=pathlib.Path)
    ap.add_argument("descriptor", type=pathlib.Path)
    ap.add_argument("output", type=pathlib.Path)
    args = ap.parse_args()
    result = make_plan(args.source, json.loads(args.descriptor.read_text()))
    with args.output.open("x") as f:
        json.dump(result, f, indent=2)
