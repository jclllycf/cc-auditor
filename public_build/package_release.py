"""只打包已验收快照；ZIP 成员与逐文件摘要同时交付，禁止带入运行数据。"""
from __future__ import annotations
import argparse,json,zipfile,subprocess,sys,os,shutil
from pathlib import Path
from public_build.release_guard import audit_zip,sha,safe_name,reviewed_findings,exceptions,files

def archive(root,destination,prefix):
    members=list(files(root));manifest=[];policy=exceptions(root)
    for p in members:
        name=p.relative_to(root).as_posix();safe_name(name)
        if reviewed_findings(name,p.read_bytes(),policy):raise ValueError('private_content_rejected:'+name)
        manifest.append({'path':name,'sha256':sha(p.read_bytes()),'size':p.stat().st_size})
    with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in members:
            name=prefix+'/'+p.relative_to(root).as_posix();z.write(p,name)
    receipt=audit_zip(destination)
    return {**receipt,'file':destination.name,'files':manifest}

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--windows',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--upstream-dir',type=Path,required=True);a=p.parse_args()
    from public_build.release_guard import audit_tree
    from public_build.audit_frozen import audit
    audit_tree(a.source,json.loads((a.source/'public-manifest.json').read_text('utf-8')))
    audit(a.windows/'CC_Auditor.exe')
    env=dict(os.environ);env.pop('PYTHONPATH',None);env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONIOENCODING']='utf-8'
    calculated=subprocess.run([sys.executable,'-B','-c','from cc_auditor.toolkit.preflight_v3 import source_build; import json; print(json.dumps(source_build()))'],cwd=a.source,env=env,text=True,encoding='utf-8',capture_output=True,check=True)
    if json.loads(calculated.stdout)!=json.loads((a.windows/'_internal/v3-source-manifest.json').read_text('utf-8')):raise ValueError('public_source_and_frozen_runtime_mismatch')
    a.output.mkdir(parents=True,exist_ok=True)
    receipts=[archive(a.source,a.output/'CC_Auditor_3.6.0-beta.1_Source.zip','cc-auditor'),archive(a.windows,a.output/'CC_Auditor_3.6.0-beta.1_Windows_x64.zip','CC_Auditor')]
    for record in json.loads((a.source/'licenses/corresponding-source.json').read_text('utf-8')):
        safe_name(record['name']);path=a.upstream_dir/record['name']
        if sha(path.read_bytes())!=record['sha256']:raise ValueError('corresponding_source_hash_mismatch')
        target=a.output/record['name']
        if target.exists():raise FileExistsError('never_overwrite_upstream_asset')
        shutil.copyfile(path,target);receipts.append({'file':target.name,'sha256':record['sha256'],'size':target.stat().st_size,'origin':record['url']})
    (a.output/'SHA256SUMS.txt').write_text(''.join(x['sha256']+'  '+x['file']+'\n' for x in receipts),encoding='ascii')
    (a.output/'archive-manifests.json').write_text(json.dumps({'version':'3.6.0-beta.1','archives':receipts},ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps([{k:v for k,v in r.items() if k!='files'} for r in receipts],indent=2))
if __name__=='__main__':main()
