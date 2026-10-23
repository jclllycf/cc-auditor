"""目标路径与通用测点严格分开，控制接口只读固定路径。"""
import http.client
import ipaddress
import json
from pathlib import Path
from .proxy_adapters import read_config,family,simulate_symbolic,capabilities
from .proxy_discovery import config_candidates
from .zero_contact_guard import utc_now

TARGETS=[dict(surface=s,host=h,process=p,port=443,network='tcp',process_path='') for s,h,p in (
    ('desktop','claude.ai','claude.exe'),('desktop_code','api.anthropic.com','claude.exe'),
    ('web','claude.ai','chrome.exe'),('web','claude.ai','msedge.exe'),('web','claude.ai','firefox.exe'),
    ('cli','api.anthropic.com',''),('api','api.anthropic.com',''))]

def _read_controller(endpoint,secret,path):
    # No arbitrary URL, port scanning, WebSocket stream, auth export, redirects or write methods.
    if path not in ('/version','/rules','/proxies','/connections','/configs','/providers/rules'):raise ValueError('controller_path')
    host,port=endpoint.rsplit(':',1);host=host.strip('[]')
    if host in ('0.0.0.0','::'):host='127.0.0.1'
    if not ipaddress.ip_address(host).is_loopback or not 0<int(port)<65536:raise ValueError('controller_not_loopback')
    conn=http.client.HTTPConnection(host,int(port),timeout=2)
    try:
        conn.request('GET',path,headers={'Authorization':'Bearer '+secret} if secret else {})
        response=conn.getresponse()
        if response.status!=200:raise ValueError('controller_unavailable')
        data=response.read(2*1024*1024+1)
        if len(data)>2*1024*1024:raise ValueError('controller_response_limit')
        return json.loads(data)
    finally:conn.close()

def inspect_routes(runtime,discovery,allow_existing=False):
    results=[];configs=[];connections=[];controllers=[]
    candidates=config_candidates(runtime)
    if not candidates:candidates=[(None,c) for c in sorted({p['family'] for p in discovery['software'] if p['family'] in ('mihomo','sing-box')})]
    for path,hint in candidates:
        try:
            config,partial=read_config(path) if path is not None else ({},False);core=family(config) if path is not None else hint
            if core=='unknown':continue
            alias=runtime.alias
            config_id='config-'+str(len(configs)+1)
            # Config existence is not evidence of activation; only a running core's explicit -f/-d is stronger.
            summary={'id':config_id,'kernel':core,'file_kind':path.suffix if path else 'runtime_only_no_config_file','parser_partial':partial,
                'activation':'candidate_unverified','capabilities':capabilities(core),'routes':[],'dns_strategy_present':bool(config.get('dns')),
                'tun_configured':bool((config.get('tun') or {}).get('enable')) if isinstance(config.get('tun'),dict) else False}
            for target in TARGETS:summary['routes'].append(simulate_symbolic(config,target,alias))
            # A launch command can identify the file loaded at process startup,
            # but a running core might subsequently reload different content.
            launch_owners=[]
            for proc in getattr(runtime,'processes',[]):
                item=proc['public'];pid=item['pid']
                if item.get('role')!='core' or item.get('running') is not True:continue
                if core!=item.get('family') and not (core=='xray' and item.get('family')=='v2fly'):continue
                for declared in runtime.launch.get(pid,{}).get('files',[]):
                    if path is not None and str(declared.resolve()).casefold()==str(path.resolve()).casefold():
                        launch_owners.append(pid)
            if len(launch_owners)==1:
                summary['activation']='running_core_launch_config'
                summary['activation_evidence']='pid_and_explicit_launch_argument_at_startup_not_live_content_equivalence'
                summary['running_core_count']=1
            endpoint=config.get('external-controller');pipe=config.get('external-controller-pipe')
            if core=='sing-box':endpoint=((config.get('experimental') or {}).get('clash_api') or {}).get('external_controller')
            if core in ('mihomo','sing-box') and any(p['family'] in ('mihomo','sing-box') for p in discovery['software']):
                try:
                    secret=config.get('secret','') if core=='mihomo' else ((config.get('experimental') or {}).get('clash_api') or {}).get('secret','')
                    kernels=[p for p in discovery['software'] if p['family']==core]
                    live_pids={p['public']['pid'] for p in runtime.processes if p['process'].is_running()}
                    kernels=[p for p in kernels if p['pid'] in live_pids]
                    from .controller_pipe_v3 import read as read_pipe,discover_names
                    candidates=[]
                    for p in kernels:
                        meta=runtime.launch.get(p['pid'],{})
                        if meta.get('ext-ctl-pipe'):candidates.append(('pipe',meta['ext-ctl-pipe'],meta.get('secret',secret),[p['pid']],'kernel_cli_override'))
                        if meta.get('ext-ctl'):candidates.append(('tcp',meta['ext-ctl'],meta.get('secret',secret),[p['pid']],'kernel_cli_override'))
                    if pipe:candidates.append(('pipe',str(pipe),str(secret),[p['pid'] for p in kernels],'candidate_config'))
                    if endpoint:candidates.append(('tcp',str(endpoint),str(secret),[p['pid'] for p in kernels],'candidate_config'))
                    for name in discover_names({p['family'] for p in kernels}):
                        candidates.append(('pipe',name,str(secret),[p['pid'] for p in kernels],'kernel_named_pipe_inventory'))
                    get=None;attempts=[];seen=set()
                    for transport,address,credential,pids,origin in candidates[:12]:
                        if (transport,address) in seen:continue
                        seen.add((transport,address))
                        try:
                            if transport=='pipe':probe=lambda path,a=address,c=credential,ids=pids:read_pipe(a,path,str(c),ids)
                            else:
                                port=int(address.rsplit(':',1)[1]);host=address.rsplit(':',1)[0].strip('[]')
                                if not any(l['port']==port and l['host'] in (host,'0.0.0.0','::') for p in kernels if p['pid'] in pids for l in p['listeners']):raise ValueError('listener_not_owned_by_kernel')
                                probe=lambda path,a=address,c=credential:_read_controller(a,str(c),path)
                            ver=probe('/version');get=probe
                            attempts.append({'transport':transport,'origin':origin,'status':'observed'})
                            break
                        except (OSError,ValueError,TypeError,http.client.HTTPException):attempts.append({'transport':transport,'origin':origin,'status':'unavailable_or_access_denied'})
                    if get is None:
                        controllers.append({'config_id':config_id,'status':'unavailable','attempts':attempts,'reason':'候选控制接口不存在、权限受限或未通过内核 PID/认证核验；未猜密钥。'})
                        raise ValueError('runtime_controller_not_bound')
                    # 本机内存中的控制器绑定，不进入报告；供同轮自动补证复用。
                    if not isinstance(getattr(runtime,'v33_controllers',None),dict):runtime.v33_controllers={}
                    binding=runtime.alias(str((transport,address,tuple(pids))))
                    controllers.append({'config_id':config_id,'status':'observed','kernel_version':str(ver.get('version',''))[:64],
                        'source':'runtime_endpoint_pid_checked','attempts':attempts,'candidate_file_equivalence':'not_proven',
                        'scope':'只读取当前内核接口；没有修改配置或节点'})
                    rules=get('/rules').get('rules',[])
                    rules=[r for r in rules if isinstance(r,dict) and (r.get('extra') or {}).get('disabled') is not True]
                    summary['runtime_rule_indices']='active_rules_order_not_disabled_original_indices'
                    # The API's ordered rule list avoids guessing partial YAML nodes / groups.
                    names={'Domain':'DOMAIN','DomainSuffix':'DOMAIN-SUFFIX','DomainKeyword':'DOMAIN-KEYWORD','ProcessName':'PROCESS-NAME','ProcessPath':'PROCESS-PATH','DstPort':'DST-PORT','Network':'NETWORK','RuleSet':'RULE-SET','GeoSite':'GEOSITE'}
                    runtime_settings=get('/configs');mode=runtime_settings.get('mode','unknown')
                    api_config={'rules':[','.join([names.get(r.get('type'),str(r.get('type','UNSUPPORTED'))),str(r.get('payload','')),str(r.get('proxy','UNKNOWN'))]) if r.get('type') not in ('Match','MATCH') else 'MATCH,'+str(r.get('proxy','UNKNOWN')) for r in rules],
                        'mode':mode,'_runtime_chain_fields_incomplete':True}
                    summary['runtime_mode']=str(mode)[:24]
                    live=get('/proxies').get('proxies',{})
                    if isinstance(live,dict):
                        api_config['proxy-groups']=[{'name':name,'_selected':node.get('now')} for name,node in live.items() if isinstance(node,dict) and node.get('all')]
                        api_config['proxies']=[{'name':name,'type':node.get('type','unknown')} for name,node in live.items() if isinstance(node,dict) and not node.get('all')]
                    if rules or str(mode).lower() in ('direct','global'):
                        summary['runtime_rules']=[simulate_symbolic(api_config,t,alias) for t in TARGETS];summary['activation']='controller_rules_observed'
                        runtime.v33_controllers[binding]={'get':get,'config':api_config,'core':core,'config_id':config_id,'binding':binding,'config_path':path,'kernel_pids':list(pids),'tun_enabled':(runtime_settings.get('tun') or {}).get('enable') is True}
                    if allow_existing:
                        if not isinstance(getattr(runtime,'v33_connection_snapshots',None),dict):runtime.v33_connection_snapshots={}
                        if binding not in runtime.v33_connection_snapshots:runtime.v33_connection_snapshots[binding]=get('/connections').get('connections',[])
                        raw=runtime.v33_connection_snapshots[binding]
                        for entry in raw[:1024]:
                            m=entry.get('metadata') or {};host=str(m.get('host','')).lower()
                            if host not in ('claude.ai','api.anthropic.com') and not host.endswith(('.claude.ai','.anthropic.com')):continue
                            proc=Path(str(m.get('processPath') or m.get('process',''))).name
                            if proc.lower() not in ('claude.exe','chrome.exe','msedge.exe','firefox.exe','node.exe'):proc='unattributed'
                            connections.append({'source':'existing_controller_connection','captured_at_utc':utc_now(),'config_id':config_id,
                                'process':proc,'host':host if host in ('claude.ai','api.anthropic.com') else '*.claude.ai' if host.endswith('.claude.ai') else '*.anthropic.com','port':m.get('destinationPort'),'rule_type':str(entry.get('rule',''))[:48],
                                'chain':[alias(x) for x in (entry.get('chains') or [])[:12]],'final_public_egress':None,
                                'attribution':'controller_metadata_not_independent_profile_or_os_socket_proof',
                                'limitations':'规则/链来自既有连接表；没有独立最终公网出口证明，不读取请求正文。'})
                except (OSError,ValueError,TypeError,KeyError,http.client.HTTPException):
                    if not any(c['config_id']==config_id for c in controllers):controllers.append({'config_id':config_id,'status':'unavailable','reason':'只读控制接口未得到有效结果'})
            configs.append(summary)
        except (OSError,ValueError,TypeError,KeyError):configs.append({'id':'config-'+str(len(configs)+1),'status':'unavailable','reason':'配置格式/权限/大小不满足安全读取条件'})
    return {'captured_at_utc':utc_now(),'configs':configs,'controllers':controllers,'existing_connections':connections,
        'generic_probe_egress_is_claude_egress':False,'final_public_egress':'unverified','scanner_target_contacts':0,'launch_inspection':[{"pid":pid,"status":state} for pid,state in runtime.launch_status.items()],
        'limitations':['静态模拟没有发送或解析 Claude 目标。','多份配置不表示同时生效；未经控制器核对的保持候选。','动态组/远程规则集/上下文缺失不能据兜底判断。']}
