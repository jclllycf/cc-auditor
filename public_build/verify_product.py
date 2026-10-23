"""离线发行验收：真实 stdio 子进程、版本路由、合成 PDF；不触发环境采集。"""
from __future__ import annotations
import argparse,json,os,subprocess,sys,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def mcp(command):
    requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','clientInfo':{'name':'cc-release-smoke','version':'1'}}},
              {'jsonrpc':'2.0','method':'notifications/initialized'},
              {'jsonrpc':'2.0','id':2,'method':'tools/list'},
              {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'audit_capabilities','arguments':{}}},
              {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'legacy_approve','arguments':{'approved':True}}}]
    env=dict(os.environ);env.pop('PYTHONPATH',None);env['PYTHONIOENCODING']='utf-8'
    if os.name=='nt':env['PATH']=str(Path(env.get('SystemRoot','C:/Windows'))/'System32')
    with tempfile.TemporaryDirectory() as d:
        p=subprocess.run(command,input='\n'.join(json.dumps(r) for r in requests)+'\n',text=True,encoding='utf-8',capture_output=True,cwd=d,env=env,timeout=45)
    if p.returncode:raise RuntimeError('mcp_process_failed')
    responses=[json.loads(x) for x in p.stdout.splitlines()];byid={r['id']:r for r in responses}
    assert len(responses)==4
    assert byid[1]['result']['serverInfo']['version']=='3.6.0-beta.1'
    assert len(byid[2]['result']['tools'])==7
    cap=byid[3]['result']['structuredContent'];assert cap['active_anthropic_probing'] is False and cap['assessment_contract']=='3.5.health.region.1'
    assert byid[4]['result']['isError'] is True
    return {'stdio_process':'passed','tools':7,'version':cap['version'],'legacy_self_approval_rejected':True,'environment_scan_started':False}

def synthetic(destination):
    from tests_toolkit.test_v34_clean_preuse import clean_user
    from cc_auditor.toolkit.evidence_completion_v33 import attach
    from cc_auditor.toolkit.preflight_v3 import save
    r=clean_user();r['version']='3.6.0-beta.1';r['run_id']='0'*31+'6';r['synthetic']=True
    r['user_declarations']['api_execution_mode']='unknown'
    r['profiles'][0]['dynamic_result']['data']['independent_network']['dns']={'status':'failed','reason':'synthetic_missing_authoritative_receipt'}
    r['approval']['scopes'].append('independent_network')
    attach(r,r['program_context_v33'],attempts=[])
    assert r['model_version']=='3.5.health.region.1'
    assert all('risk_index' not in a for a in r['surface_assessments'].values())
    path=save(r,Path(destination))['json'];return path

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path);p.add_argument('--synthetic-dir',type=Path);a=p.parse_args()
    command=[str(a.exe.resolve()),'--mcp'] if a.exe else [sys.executable,str(ROOT/'preflight_entry_v3.py'),'--mcp']
    receipt={'mcp':mcp(command)}
    if a.synthetic_dir:
        source=synthetic(a.synthetic_dir)
        command=[str(a.exe.resolve()),'--pdf-from-report',source] if a.exe else [sys.executable,str(ROOT/'preflight_entry_v3.py'),'--pdf-from-report',source]
        env=dict(os.environ);env['PYTHONIOENCODING']='utf-8'
        if os.name=='nt':env['PATH']=str(Path(env.get('SystemRoot','C:/Windows'))/'System32')
        proc=subprocess.run(command,cwd=a.synthetic_dir,text=True,encoding='utf-8',capture_output=True,env=env,timeout=180)
        if proc.returncode:raise RuntimeError('offline_pdf_failed:'+proc.stderr[-1200:])
        receipt['synthetic_pdfs']=json.loads(proc.stdout)
        assert 2<=len(receipt['synthetic_pdfs'])<=3
    print(json.dumps(receipt,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
