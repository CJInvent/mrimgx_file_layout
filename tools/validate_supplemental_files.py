"""Independently validate file-slice reconstructions and original-index repairs."""
import argparse,hashlib,json,pathlib,sqlite3
from rebuild_context import Context
from recover_duplicate_files import file_extents
from recover_catalog_files import catalog_digest
from placement_payload import payload
from windows_metadata import catalog_members
from component_manifest_hashes import OriginalManifestReader,verify_binding


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','baseline_manifest','evidence','mapping_directory','supplemental','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=None;requests=json.loads(a.supplemental.read_text());db=sqlite3.connect((a.evidence/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True);files={};catalogs={};results=[]
    original_manifest_reader=None
    with a.source.open('rb') as source:
        for m in requests:
            content=payload(source,m)
            for e in m['evidence']:
                if e['method']=='unique-original-index-md5-bit-repair':
                    entry=db.execute('SELECT source_offset,stored_length,digest,decoded_length FROM entries WHERE partition=? AND block=? AND disk_offset=?',(m['partition'],e['block'],m['disk_offset'])).fetchall()
                    if len(entry)!=1 or entry[0]!=(m['source_offset'],m['stored_length'],bytes.fromhex(e['original_md5']),m['length']) or hashlib.md5(content).hexdigest()!=e['original_md5']:raise ValueError('repair does not match original source index')
                    results.append(dict(kind='original-index-repair',disk_offset=m['disk_offset'],bytes=len(content),sha256=m['sha256'],valid=True));continue
                if e['method'] not in ('catalog-validated-file-slice','component-manifest-validated-file-slice','appx-signature-validated-file-slice'):raise ValueError('unsupported supplemental evidence')
                if ctx is None:ctx=Context(a.source,a.baseline,a.mft,a.baseline_manifest,a.evidence,a.mapping_directory)
                record=e['record']
                if record not in files:
                    rec=ctx.fs.mft.get(record)
                    if rec.size()!=e['file_size']:raise ValueError('file-slice MFT size differs')
                    files[record]=(bytearray(rec.open().read()),file_extents(rec,rec.size()),[])
                data,extents,proofs=files[record];copied=0
                for logical,physical,length in extents:
                    lo=max(m['disk_offset']-ctx.origin,physical);hi=min(m['disk_offset']-ctx.origin+m['length'],physical+length)
                    if hi>lo:data[logical+lo-physical:logical+hi-physical]=content[lo-(m['disk_offset']-ctx.origin):hi-(m['disk_offset']-ctx.origin)];copied+=hi-lo
                if copied!=len(content):raise ValueError('file slice extends outside its original file runlist')
                proofs.append(e)
    for number,(data,extents,proofs) in files.items():
        for e in proofs:
            if e['method']=='appx-signature-validated-file-slice':
                from appx_signature_hashes import verify_binding as verify_appx_binding
                if hashlib.new(e['algorithm'],data).hexdigest()!=e['expected_digest'] or hashlib.sha256(data).hexdigest()!=e['file_sha256_observed']:raise ValueError('supplemental Appx part file hash differs')
                if original_manifest_reader is None:original_manifest_reader=OriginalManifestReader(a.baseline,a.mft,ctx.layout,a.baseline_manifest)
                verify_appx_binding(original_manifest_reader,ctx.fs.mft.get(number),e['hash_source'],e['algorithm'],e['expected_digest'],ctx.fs);continue
            if e['method']=='component-manifest-validated-file-slice':
                if hashlib.new(e['algorithm'],data).hexdigest()!=e['expected_digest'] or hashlib.sha256(data).hexdigest()!=e['file_sha256_observed']:raise ValueError('supplemental component file hash differs')
                if original_manifest_reader is None:original_manifest_reader=OriginalManifestReader(a.baseline,a.mft,ctx.layout,a.baseline_manifest)
                verify_binding(original_manifest_reader,ctx.fs.mft.get(number),e['hash_source'],e['algorithm'],e['expected_digest'])
                continue
            if catalog_digest(data,e['algorithm'],e['hash_kind'])!=e['expected_digest']:raise ValueError('supplemental slices do not reconstruct complete original catalog digest')
            c=e['catalog'];key=(c['catalog_record'],c['catalog_sha256'])
            if key not in catalogs:
                rec,encoded=ctx.read_complete(c['catalog_record'],64*1024**2)
                if hashlib.sha256(encoded).hexdigest()!=c['catalog_sha256']:raise ValueError('catalog source content differs')
                path=a.output/(str(c['catalog_record'])+'.cat')
                with path.open('xb') as out:out.write(encoded)
                catalogs[key]=list(catalog_members(path))
            algorithm_oid={'sha1':'1.3.14.3.2.26','sha256':'2.16.840.1.101.3.4.2.1'}[e['algorithm']];subject_oid={'pe':'1.3.6.1.4.1.311.2.1.15','flat':'1.3.6.1.4.1.311.2.1.25'}[e['hash_kind']]
            if not any(member.get('digest')==e['expected_digest'] and member.get('algorithm_oid')==algorithm_oid and member.get('subject_oid')==subject_oid for member in catalogs[key]):raise ValueError('expected file digest absent from independently signature-checked source catalog')
        is_component=any(e['method']=='component-manifest-validated-file-slice' for e in proofs)
        is_appx=any(e['method']=='appx-signature-validated-file-slice' for e in proofs)
        results.append(dict(kind='appx-signature-file-slices' if is_appx else 'component-manifest-file-slices' if is_component else 'catalog-file-slices',record=number,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),original_appx_signature_rechecked=is_appx,original_appx_bindings=[e['hash_source'] for e in proofs if e['method']=='appx-signature-validated-file-slice'],original_manifest_rechecked=is_component,original_manifest_bindings=[e['hash_source'] for e in proofs if e['method']=='component-manifest-validated-file-slice'],catalog_signature_hash_rechecked=not is_component and not is_appx,valid=True))
    if original_manifest_reader is not None:original_manifest_reader.close()
    if ctx is not None:ctx.close()
    db.close()
    result=dict(valid=True,supplemental_destinations=len(requests),supplemental_bytes=sum(m['length'] for m in requests),validated_files_or_frames=results,scope='Only the validated source slices may be written. Other bytes in their enclosing frames retain unresolved placement status.');(a.output/'summary.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)


if __name__=='__main__':main()
