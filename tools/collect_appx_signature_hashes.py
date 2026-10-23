"""Dynamically discover original signature hashes for missing installed MSIX parts."""
import argparse,collections,hashlib,json,pathlib
from rebuild_context import Context
from component_manifest_hashes import OriginalManifestReader
from appx_signature_hashes import PARTS,package_path,signature_hashes
from rebuild_audit import caught


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('source','baseline','mft','inventory','manifest','evidence','mapping_directory','output'):ap.add_argument(name,type=pathlib.Path)
    a=ap.parse_args();a.output.mkdir(exist_ok=False);ctx=Context(a.source,a.baseline,a.mft,a.manifest,a.evidence,a.mapping_directory);reader=OriginalManifestReader(a.baseline,a.mft,ctx.layout,a.manifest);packages=set();targets=[];reports=[];counts=collections.Counter()
    with a.inventory.open() as stream:
        for row in map(json.loads,stream):
            parts=pathlib.PureWindowsPath(row.get('path') or '').parts
            if len(parts)>3 and [p.casefold() for p in parts[:2]]==['program files','windowsapps']:packages.add(str(pathlib.PureWindowsPath(*parts[:3])))
    for package in sorted(packages):
        try:
            signature_path=package+'\\AppxSignature.p7x';signature_source='original-baseline'
            try:
                signature=reader.fs.mft.get(signature_path);signature,data=reader.read(signature.segment,signature_path)
            except Exception as error:
                caught(error,dict(package=package),expected=True,site='appx-signature-baseline-fallback')
                signature=ctx.fs.mft.get(signature_path);signature,data=ctx.read_complete(signature.segment,4*1024**2);signature_source='source-backed-mapped-overlay'
            digests=signature_hashes(data);counts['verified_original_signatures']+=1
        except Exception as error:
            caught(error,dict(package=package),expected=True,site='appx-original-signature-probe');reports.append(dict(package=package,signature_rejected=str(error)));continue
        for part,name in PARTS.items():
            if part not in digests:continue
            path=package+'\\'+name
            try:
                package_path(path,part);record=ctx.fs.mft.get(path)
                if not ctx.holes(record) or not 0<record.size()<=4*1024**2:continue
                binding=dict(kind='original-appx-signature-file-hash',part=part,target_path=path,target_sequence=record.header.SequenceNumber,signature_record=signature.segment,signature_sequence=signature.header.SequenceNumber,signature_path=signature_path,signature_sha256=hashlib.sha256(data).hexdigest(),original_baseline_bytes_only=True,signature_cryptographically_verified=True,certificate_trust_asserted=False)
                binding['target_record']=record.segment
                binding['signature_source']=signature_source;binding['original_baseline_bytes_only']=signature_source=='original-baseline'
                targets.append(dict(record=record.segment,size=record.size(),algorithm='sha256',digest=digests[part],hash_source=binding))
            except Exception as error:caught(error,dict(package=package,part=part),expected=True,site='appx-original-part-probe');reports.append(dict(package=package,part=part,rejected=str(error)))
    (a.output/'hash-targets.json').write_text(json.dumps(targets,indent=2));(a.output/'reports.json').write_text(json.dumps(reports,indent=2));summary=dict(packages=len(packages),counts=counts,targets=len(targets),scope='Named installed-package part hashes from cryptographically verified, complete original signatures, read from baseline or source-backed mapped overlay as recorded per target. No certificate-chain trust assertion.');(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True);reader.close();ctx.close()


if __name__=='__main__':main()
