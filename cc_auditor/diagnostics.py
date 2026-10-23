"""Bounded, metadata-only diagnostics; no credentials, packet capture or configuration writes."""
import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
import psutil
from . import collectors, storage
from .model import utc
from .tls_safety import verified_context

HOSTS = {'web':'claude.ai', 'api':'api.anthropic.com'}
FAILURES = {'none':'通过','dns_failed':'DNS 解析失败','family_unavailable':'DNS 未返回此地址族',
    'tcp_timeout':'TCP 连接超时','tcp_refused':'TCP 连接被拒绝','tcp_failed':'TCP 连接失败',
    'certificate_failed':'TLS 证书校验失败','tls_failed':'TLS 协商失败','timeout':'未在总时限内完成',
    'not_selected':'未选择','cancelled':'已取消','probe_failed':'探针失败'}

def route_probe(host, version):
    """Public preflight: legacy active probe disabled."""
    raise PermissionError("legacy_active_probe_disabled_in_public_preflight")

def routes():
    """Public preflight: legacy active probe disabled."""
    raise PermissionError("legacy_active_probe_disabled_in_public_preflight")

def inventory():
    """PID plus creation time identifies an instance; paths and unrelated process data never leave memory."""
    result={'status':'ok','captured_at_utc':utc(),'instances':[],'errors':[],'cli_located':False,'cli_version':None,
            'execution_host':'local_auditor','activity':'not_assessed','remote_execution':'not_assessed','events':'permission_required'}
    info=collectors.installation()['value'];result['cli_located']=info['cli_located'];result['cli_version']=info['binary_file_version']
    try:
        rows=list(psutil.process_iter(['name','ppid'],ad_value=None))
        parents={p.pid:p.info.get('ppid') for p in rows}
        candidates=[];paths={};created_at={}
        for cached in [p for p in rows if (p.info.get('name') or '').lower() in ('claude','claude.exe')][:64]:
            # process_iter caches Process objects; acquire a fresh handle and check identity after reads.
            try:
                p=psutil.Process(cached.pid)
                if p.name().lower() not in ('claude','claude.exe'):raise psutil.NoSuchProcess(p.pid)
                created_at[p.pid]=p.create_time();paths[p.pid]=p.exe();parents[p.pid]=p.ppid()
                if not p.is_running():raise psutil.NoSuchProcess(p.pid)
                candidates.append(p)
            except (psutil.Error,OSError):result['errors'].append('instance_unavailable')
        valid_ids={p.pid for p in candidates}
        desktops={pid for pid,path in paths.items() if pid in valid_ids and collectors.classify(path)=='desktop_shell_candidate'}
        for p in candidates:
            seen=set();parent=parents.get(p.pid);ancestor=False
            for _ in range(12):
                if parent in desktops and created_at.get(parent,float('inf'))<=created_at[p.pid]:ancestor=True;break
                if parent is None or parent in seen:break
                seen.add(parent);parent=parents.get(parent)
            try:
                created=created_at[p.pid]
                if not p.is_running():raise psutil.NoSuchProcess(p.pid)
                result['instances'].append({'pid':p.pid,'parent_pid':parents.get(p.pid),'created_epoch':created,
                    'lifetime_seconds':max(0,round(time.time()-created)), 'kind':collectors.classify(paths[p.pid],ancestor)})
            except (psutil.Error,OSError):result['errors'].append('instance_unavailable')
    except (psutil.Error,OSError):result['status']='error';result['errors'].append('query_failed')
    result['errors']=sorted(set(result['errors']));return result

def validate_inventory(x):
    if type(x) is not dict or set(x)!={'status','captured_at_utc','instances','errors','cli_located','cli_version','execution_host','activity','remote_execution','events'}:raise ValueError('invalid_inventory')
    storage.timestamp(x['captured_at_utc'])
    if x['status'] not in ('ok','error') or type(x['cli_located']) is not bool or x['execution_host']!='local_auditor' or x['activity']!='not_assessed' or x['remote_execution']!='not_assessed' or x['events']!='permission_required':raise ValueError('invalid_inventory')
    import re
    if x['cli_version'] is not None and (type(x['cli_version']) is not str or not re.fullmatch(r'\d+(?:\.\d+){1,3}',x['cli_version'])):raise ValueError('invalid_binary_version')
    if type(x['instances']) is not list or len(x['instances'])>64 or type(x['errors']) is not list or any(e not in ('path_unavailable','instance_unavailable','query_failed') for e in x['errors']):raise ValueError('invalid_inventory')
    for i in x['instances']:
        if type(i) is not dict or set(i)!={'pid','parent_pid','created_epoch','lifetime_seconds','kind'}:raise ValueError('invalid_instance')
        if type(i['pid']) is not int or i['pid']<=0 or (i['parent_pid'] is not None and (type(i['parent_pid']) is not int or i['parent_pid']<0)) or type(i['created_epoch']) not in (int,float) or i['created_epoch']<0 or type(i['lifetime_seconds']) is not int or i['lifetime_seconds']<0:raise ValueError('invalid_instance')
        if i['kind'] not in ('desktop_shell_candidate','embedded_engine_candidate','desktop_child_candidate','standalone_cli_candidate','unattributed_engine','unattributed_claude'):raise ValueError('invalid_instance_kind')
    return x

def validate_routes(x):
    if type(x) is not dict or set(x)!={'web_4','web_6','api_4','api_6'}:raise ValueError('invalid_routes')
    for r in x.values():
        if type(r) is not dict or set(r)!={'status','error','stage','address_count','mapped_count','tls','duration_ms'}:raise ValueError('invalid_route')
        if r['status'] not in ('ok','error') or r['error'] not in FAILURES or r['stage'] not in ('dns','tcp','tls','complete'):raise ValueError('invalid_route')
        if any(type(r[k]) is not int or not 0<=r[k]<=120000 for k in ('address_count','mapped_count','duration_ms')) or r['mapped_count']>r['address_count'] or r['tls'] not in ('','TLSv1.2','TLSv1.3'):raise ValueError('invalid_route')
        if (r['status']=='ok') != (r['stage']=='complete' and r['error']=='none' and bool(r['tls']) and r['address_count']>0):raise ValueError('invalid_route_success')
    return x
