"""Merge independently validated additive mapping branches; reject byte conflicts."""
import argparse,json,pathlib


def combine(base,branches):
    originals={m['disk_offset']:m for m in base};result=dict(originals)
    for branch in branches:
        entries={m['disk_offset']:m for m in branch}
        if any(entries.get(offset)!=m for offset,m in originals.items()):raise ValueError('branch changed or removed original mappings')
        for offset,m in entries.items():
            if offset not in result:result[offset]=m;continue
            old=result[offset]
            if any(old[k]!=m[k] for k in ('partition','reserved','block','length','sha256')):raise ValueError('conflicting mapped bytes or geometry at '+str(offset))
    ordered=sorted(result.values(),key=lambda m:m['disk_offset'])
    if any(a['disk_offset']+a['length']>b['disk_offset'] for a,b in zip(ordered,ordered[1:])):raise ValueError('overlapping mapped ranges')
    return ordered


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('base',type=pathlib.Path);ap.add_argument('output',type=pathlib.Path);ap.add_argument('branches',nargs='+',type=pathlib.Path);a=ap.parse_args();a.output.mkdir(exist_ok=False)
    base=json.loads((a.base/'accepted-mappings.json').read_text());branches=[json.loads((b/'accepted-mappings.json').read_text()) for b in a.branches];branch_plans=[json.loads((b/'recovery-plan.json').read_text()) for b in a.branches];combined=combine(base,branches);plan=json.loads((a.base/'recovery-plan.json').read_text());known={m['disk_offset'] for m in base}
    for m in combined:
        if m['disk_offset'] in known:continue
        if m['reserved']:raise ValueError('reserved mapping plan merge unsupported')
        for p in branch_plans:
            override=p['partitions'][m['partition']].get('overrides',{}).get(str(m['block']))
            if override and override['source_offset']==m['source_offset']:
                plan['partitions'][m['partition']].setdefault('overrides',{})[str(m['block'])]=override;break
        else:raise ValueError('mapping lacks corresponding plan override')
    (a.output/'accepted-mappings.json').write_text(json.dumps(combined,indent=2));(a.output/'recovery-plan.json').write_text(json.dumps(plan,indent=2));summary=dict(accepted_destinations=len(combined),accepted_bytes=sum(m['length'] for m in combined),added_destinations=len(combined)-len(base));(a.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))


if __name__=='__main__':main()
