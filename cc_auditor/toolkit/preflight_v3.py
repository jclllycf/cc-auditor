"""唯一使用前预检编排器；按授权采集证据，不创建三种模式或客户端监控平台。"""
from __future__ import annotations
import copy
import hashlib
import json
import time
import sys
from pathlib import Path
from .. import storage
from ..model import root_dir,canonical
from . import profiles_v3,proxy_discovery,route_correlation,network_v3
from .consent_v3 import BROKER
from .zero_contact_guard import utc_now

SCHEMA='cc-auditor-preflight/3';VERSION='3.6.0-beta.1';RULESET='2026-10-22.health-region.1'
STATE_ZH={'passed':'已测通过','fault':'已证实异常','reference':'参考证据','partial':'部分证据','unknown':'尚未检测','failed':'检测失败','unsupported':'当前不支持','permission':'未授权'}
RUNS={}

def prepare(scopes=None):
    profiles,private=profiles_v3.discover()
    manifest=BROKER.prepare(profiles,scopes)
    RUNS[manifest['scan_id']]={'manifest':manifest,'profiles':private}
    return manifest

def summarize(report):
    checks=report['checks'];observed=[c for c in checks if c['state'] in ('passed','fault','reference')]
    good=sum(c['state']=='passed' for c in checks);bad=sum(c['state']=='fault' for c in checks)
    issues={c['issue_id']:c for c in checks if c['state']=='fault' and c['points']>0}
    score=max(0,100-sum(c['points'] for c in issues.values()));cov=round(len(observed)/len(checks)*100,1) if checks else 0
    critical_unknown=any(c['id'].startswith('target_egress') and c['state']!='passed' for c in checks)
    summary={'observed':len(observed),'applicable':len(checks),'passed':good,'faults':bad,'reference':sum(c['state']=='reference' for c in checks),
        'unknown':sum(c['state'] not in ('passed','fault','reference') for c in checks),'coverage_percent':cov,
        'tested_pass_rate':round(good/(good+bad)*100,1) if good+bad else None,'measured_subset_score':score,
        'technical_score':score if cov>=60 and not critical_unknown else None,'points_deducted':sum(c['points'] for c in issues.values()),
        'deduplication':'同一 issue_id 只扣一次；未知、代理品牌、语言、Claude 进程数、通用出口国家扣 0 分。',
        'confidence':'有限' if cov<60 or critical_unknown else '中等','critical_path_unknown':critical_unknown,'conclusion':'已测项目存在明确技术问题，请先核对。' if bad else '已测项目未见明确技术阻碍，但关键路径仍有未验证项。',
        'policy_eligibility':'需要用户按真实所在地和主体资格自行核对；未从出口、语言、国籍或时区推断。',
        'account_enforcement':'服务端不可知；不是封禁概率。'}
    return summary

def make_report(scan_id,approval,local=None,topology=None,discovery=None,routes=None,profiles=None,probes=None,synthetic=False,independent=None,region=None,host_context=None):
    local=local or {};topology=topology or {};profiles=profiles or [];probes=probes or [];checks=[];now=utc_now()
    def add(id,layer,title,state,value,criterion,points=0,issue=None,source='local_observation',scope='all',reason=''):
        checks.append({'id':id,'layer':layer,'title':title,'state':state,'value':value,'criterion':criterion,'points':points if state=='fault' else 0,
            'issue_id':issue or id,'source':source,'scope':scope,'captured_at_utc':now,'reason':reason,'evidence_id':'E'+str(len(checks)+1).zfill(3),
            'next_step': '按对应环境与实际应用复核；本工具不自动改设置。' if state=='fault' else '在明确授权范围补充证据；未知不是已证实故障。' if state not in ('passed','reference') else '保留本次证据与适用范围。'})
    os=local.get('os_compatibility') or {};res=local.get('resources') or {};sec=local.get('security_and_certificates') or {};hosts=sec.get('hosts_file') or {}
    for key,title in [('desktop_compatible','桌面端 Windows 条件'),('cli_compatible','CLI Windows 条件')]:
        val=os.get(key);add('os_'+key,'L01',title,'passed' if val is True else 'fault' if val is False else 'permission' if not local else 'failed',val,'按版本化基础安装要求核对',15,scope='desktop' if key.startswith('desktop') else 'cli')
    for key,title in [('cli_ram_sufficient','CLI 内存'),('disk_sufficient','系统可用空间')]:
        val=res.get(key);add(key,'L01',title,'passed' if val is True else 'fault' if val is False else 'unknown',val,'内存≥4GB；安装前可用空间≥1GB 为工具参考门槛',10)
    tls=sec.get('insecure_tls_env_enabled')
    add('tls_bypass','L08','TLS 证书验证设置','fault' if tls is True else 'passed' if tls is False else 'unknown' if 'local_system' in approval['scopes'] else 'permission',tls,'检测器继承环境未关闭证书校验；不代表其他进程环境',35)
    add('api_override','L02','检测器继承环境中的 API 端点覆盖','reference' if type(sec.get('api_endpoint_override_present')) is bool else 'unknown' if 'local_system' in approval['scopes'] else 'permission',sec.get('api_endpoint_override_present'),'只记录变量是否存在；不能推定未来 API 客户端的环境')
    add('hosts_block','L08','hosts 目标域名映射','fault' if hosts.get('blocking_entries',0)>0 else 'passed' if hosts.get('status')=='observed' else 'unknown',hosts.get('blocking_entries'),'只读本机记录；不访问目标',30)
    add('root_store','L08','根证书与自定义 CA','reference' if sec.get('root_cert_count') is not None else 'unknown',{'count':sec.get('root_cert_count'),'custom_ca_present':bool(sec.get('custom_ca_env_vars_present'))},'证书数量/变量存在不证明截获或恶意')
    add('locale','L01','语言与时区','reference' if local.get('locale_and_time_reference') else 'unknown',local.get('locale_and_time_reference'),'仅环境事实，不推断物理位置')
    add('execution_host','L01','本次采集执行位置','reference' if local.get('vantage') else 'unknown',local.get('vantage'),'采集器在这台 Windows 执行；Agent 云端模型的位置不能当作设备所在地')
    flags=topology.get('query_flags') or {};proxy=topology.get('proxy_configuration') or {};tuns=topology.get('vpn_and_tun_topology') or {}
    for key,title,layer in [('proxy_registry_ok','系统代理配置','L02'),('adapters_ok','活动网卡/TUN','L03'),('routes_ok','IPv4/IPv6 路由','L03'),('dns_ok','活动网卡 DNS','L04')]:
        add(key,layer,title,'reference' if flags.get(key) else 'failed' if topology else 'permission',proxy if layer=='L02' else tuns if layer=='L03' else topology.get('dns_configuration'),'配置不是实际目标流量路径')
    add('pac_evaluation','L02','PAC 脚本实际决策','unknown' if proxy.get('pac_configured') else 'reference' if topology else 'permission',{'configured':proxy.get('pac_configured')},'不执行用户/远程脚本；无脚本结果不推定 DIRECT')
    software=(discovery or {}).get('software',[])
    add('proxy_inventory','L02','代理 GUI / 内核 / 安装与监听','reference' if discovery and discovery.get('status')=='observed' else 'partial' if discovery else 'permission',software,'名称/路径/版本为候选，监听≠生效，控制器/系统接管需关联')
    add('proxy_signatures','L02','代理二进制离线签名','reference' if software else 'unknown',[x.get('signature') for x in software],'仅缓存 WinVerifyTrust，不访问证书端点；有效签名也不证明官方发布者身份')
    instances=(local.get('cli_and_processes') or {}).get('running_claude_instances',[])
    add('claude_processes','L12','既有 Claude 进程事实（不扣分）','reference' if (local.get('cli_and_processes') or {}).get('inventory_status')=='ok' else 'unknown' if 'local_system' in approval['scopes'] else 'permission',{'count':len(instances),'instances':instances},'进程存在/数量不是账号风险，未启动/结束任何客户端')
    simulated=any(r.get('status')=='simulated' for c in (routes or {}).get('configs',[]) for r in c.get('runtime_rules',c.get('routes',[])))
    add('proxy_rules','L12','各应用 Claude 目标规则模拟','reference' if simulated else 'partial' if routes and routes.get('configs') else 'unknown',routes or {},'只做字符串/配置模拟；未知优先级规则不能跳过',source='configuration_simulation')
    add('existing_client','L12','可选既有客户端连接研究','reference' if routes and routes.get('existing_connections') else 'permission' if 'existing_connections' not in approval['scopes'] else 'unknown',(routes or {}).get('existing_connections',[]),'只用已有连接；没有记录不代表从未联网',source='existing_client_observation')
    for surface in ('desktop','web','cli','api'):
        add('target_egress_'+surface,'L05',surface+' 目标最终公网出口','unknown',None,'通用 IP 回显/节点名称/本地代理第一跳不能证明此出口',scope=surface)
    add('generic_probe','L05','中立探针自身出口','reference' if any(p.get('status')=='observed' for p in probes) else 'failed' if probes else 'permission',probes,'仅归属于检测器及这些测点；不跨场景填入 Claude 路径',source='third_party_receiver')
    for id,title,layer in [('dns_receiver','权威 DNS 接收端核验','L04'),('ipv6_bypass','IPv6 / UDP 实际旁路','L03'),('webrtc_stun','WebRTC 外部 STUN 出口','L10'),('browser_tls_fingerprint','日常浏览器 TLS/HTTP2/JA4','L07')]:
        browser_results=[(p.get('dynamic_result') or {}).get('data',{}).get('independent_network',{}) for p in profiles]
        kind={'dns_receiver':'dns','ipv6_bypass':'ipv6','webrtc_stun':'stun','browser_tls_fingerprint':'tls'}[id]
        values=[v[kind] for v in browser_results if kind in v]
        values+=[v for v in (independent or []) if v.get('kind')=={'dns_receiver':'system_authoritative_dns','webrtc_stun':'python_udp_stun'}.get(id)]
        state='reference' if any(v.get('status')=='observed' for v in values) else 'failed' if values else 'permission' if 'independent_network' not in approval['scopes'] else 'unknown'
        add(id,layer,title,state,values or None,'只说明独立测点所见路线；差异不是自动确认泄漏，不代表 Claude 出口',source='independent_receiver')
    for id,title,key in [('rdap','探针 IP 的 RDAP 注册归属','registry'),('bgp','探针 IP 的 BGP 前缀与 ASN','bgp'),('rpki','探针 IP 的 RPKI 参考','rpki_state'),('reputation','探针 IP 的供应商代理/声誉分类','vendor_labels')]:
        values=[p for p in probes if p.get('status')=='observed' and p.get(key)]
        add(id,'L06',title,'reference' if values else 'failed' if probes else 'permission',values,'仅对应本工具探针的 IP；供应商矛盾保留，注册国家不是地理位置，声誉不是封禁分',source='third_party_receiver')
    add('neutral_tls','L07','中立测点的 TLS 强校验','passed' if any(p.get('tls') for p in probes) else 'unknown',[p.get('tls') for p in probes if p.get('tls')],'只代表 Python 探针的兼容性，不代表 Claude 指纹')
    for p in profiles:
        key=p['profile_key'];static=p.get('static_profile_checked');dynamic=p.get('dynamic_profile_checked')
        add(key+'_static','L09',p['browser_name']+' / '+p['profile_alias']+' 静态诊断','reference' if static else 'failed' if 'browser_static' in approval['scopes'] else 'permission',{'version':p['version'],'preferences':p.get('network_preferences')},'真实现有目录的指定诊断键，不读登录内容',scope=key,reason=p.get('static_error',''))
        add(key+'_extensions','L11',p['profile_alias']+' 扩展能力','reference' if p.get('extension_count') is not None else 'unknown',{'count':p.get('extension_count'),'permissions':p.get('extension_capabilities')},'权限是能力，不等于扩展已注入 Claude',scope=key)
        add(key+'_dynamic','L10',p['profile_alias']+' 自有页运行','reference' if dynamic else 'permission' if 'browser_dynamic' not in approval['scopes'] else 'unknown',p.get('dynamic_result'), '必须收到本次 token 回调；目标 Profile 的验证强度另列',scope=key,reason=p.get('reason',''))
        add(key+'_identity','L09',p['profile_alias']+' Profile 归属核验','passed' if p.get('actual_profile_verified') else 'partial' if dynamic else 'unknown',p.get('profile_binding'),'用户确认和启动参数不等于不可伪造的 Profile 身份证明',scope=key)
        features=((p.get('dynamic_result') or {}).get('data') or {}).get('features',{})
        for f in ('cookies','websocket','webassembly','workers','canvas_2d'):
            v=features.get(f);add(key+'_'+f,'L10',p['profile_alias']+' '+f,'passed' if v is True else 'fault' if v is False else 'unknown',v,'只对本工具 origin 的 API 暴露/可用性负责；WebSocket 存在不等于远程握手成功',10,scope=key)
        add(key+'_cleanup','L10',p['profile_alias']+' 工具实验键清理','reference' if p.get('cleanup_status')=='reported_clean' else 'unknown',p.get('cleanup_status'),'只清理工具自己实验键；不删除历史或账号会话',scope=key)
    if host_context is not None:
        for key,title in (('cli','CLI 本机终端/运行时候选'),('api','API 本机运行时/宿主候选')):
            add(key+'_host_context','L01',title,'reference' if host_context.get(key) else 'permission' if 'local_system' not in approval['scopes'] else 'failed',host_context.get(key),'仅本机候选，不执行 Claude，不读取目标进程环境或 API key；远端/WSL/容器不由本机代测',source='local_runtime_metadata',scope=key)
    if region is not None:
        windows=region.get('windows',{})
        add('windows_region','L01','Windows 国家/地区与格式','reference' if windows.get('status')=='observed' else 'permission' if 'browser_region' not in approval['scopes'] else 'unknown',windows,'用户配置参考，不是物理定位，不计地区风险',source='windows_registry_allowlist')
        for d in region.get('devices',[]):
            add(d['device_key']+'_region','L09','浏览器设备层实验国家/版本/时间','reference' if d.get('status')=='observed' else 'unsupported' if d.get('status')=='not_supported' else 'failed',d,'设备 Local State，不是 per-Profile；Google 专属参考，普通网站不能直接读取；不计分',source='browser_local_state_allowlist',scope=d['device_key'])
        for p in region.get('profiles',[]):
            add(p['profile_key']+'_region','L09','日常 Profile 网页语言对照','reference' if p.get('status')=='observed' else 'failed',p,'Preferences 与本轮工具 origin 的 navigator/Accept-Language 分开记录；不推定 Claude 已收到',source='profile_preferences_and_tool_origin',scope=p['profile_key'])
    report={'schema':SCHEMA,'version':VERSION,'ruleset':RULESET,'run_id':scan_id,'created_at_utc':now,'synthetic':synthetic,'approval':approval,
        'checks':checks,'profiles':profiles,'proxy_discovery':discovery,'target_routes':routes,'generic_probe_egress':probes,
        'source_build':approval.get('source_build') or source_build(),
        'zero_contact':{'scope':'本工具采集器；不包含用户已有程序和 Agent 模型通信','scanner_anthropic_requests_sent':0,'basis':'目标模拟无网络；外部采集器只有固定中立域名；没有整机抓包证明'},
        'network_events':probes,'independent_network_events':independent or [],'consent_events':[{'event':'local_user_approved','at':approval.get('approved_at_utc'),'scopes':approval['scopes']}],
        'cleanup':{'temporary_servers':'closed_after_callbacks_or_timeout' if any(p.get('dynamic_result') for p in profiles) else 'not_started','existing_profile_settings_changed':False,'reports':'retained_by_user_choice','cloud_data_retractable':False}}
    if region is not None:report['browser_region_signals']=region
    if host_context is not None:report['host_context']=host_context
    if approval.get('user_declarations'):report['user_declarations']=approval['user_declarations']
    for check in checks:
        source=local if check['layer'] in ('L01','L08') or check['id']=='claude_processes' else topology if check['id'] in ('proxy_registry_ok','adapters_ok','routes_ok','dns_ok','pac_evaluation') else routes if check['id'] in ('proxy_rules','existing_client') else discovery if check['id'].startswith('proxy_') else None
        if source and source.get('captured_at_utc'):check['captured_at_utc']=source['captured_at_utc']
        for p in profiles:
            if check['scope']==p['profile_key'] and p.get('checked_at_utc'):check['captured_at_utc']=p['checked_at_utc']
    report['summary']=summarize(report)
    from .risk_v31 import assess
    report['risk_assessment']=assess(report)
    from .assess_v32 import assess as assess_v32
    report.update(assess_v32(report))
    return report

def run(scan_id):
    session=RUNS.get(scan_id)
    if not session:raise ValueError('先准备本轮预检')
    if session['manifest']['source_build']!=source_build():raise ValueError('source_changed_prepare_again')
    approval=BROKER.approve_and_consume(scan_id);local=None;topo=None;discovery=None;routes=None;runtime=None;probes=[];profiles=[];independent=[];host_context={'status':'permission'};region={'status':'permission'}
    private_options=BROKER.take_private_options(scan_id);program={'status':'permission'};program_private={}
    if approval['source_build']!=source_build():raise ValueError('source_changed_after_consent')
    errors=[]
    def guarded(name,operation,fallback):
        if BROKER.cancelled(scan_id):return fallback
        try:return operation()
        except Exception as error:
            errors.append({'collector':name,'error_class':type(error).__name__,'message':'此采集器未完成，其他获批检查继续；未算通过。'})
            return fallback
    if 'program_context' in approval['scopes']:
        from .program_context_v33 import collect as program_collect
        program,program_private=guarded('program_context',lambda:program_collect(approval['user_declarations'],private_options),({'status':'failed'},{}))
    private_options.clear()
    if 'local_system' in approval['scopes']:
        from .local_environment import inspect_local_environment,inspect_network_topology
        local=guarded('local_system',inspect_local_environment,{'collector_state':'failed'})
        topo=guarded('network_topology',inspect_network_topology,{'collector_state':'failed'})
        from .host_context_v32 import collect as host_collect
        host_context=guarded('host_context',host_collect,{'status':'failed'})
        processes=local.get('cli_and_processes') or {}
        processes['running_claude_instances']=guarded('claude_identity',lambda:proxy_discovery.claude_identity(processes.get('running_claude_instances',[])),processes.get('running_claude_instances',[]))
    if 'proxy_config' in approval['scopes'] or 'local_system' in approval['scopes']:
        discovery,runtime=guarded('proxy_discovery',proxy_discovery.discover,({'status':'failed','software':[]},None))
        discovery=proxy_discovery.correlate_system_proxy(discovery,topo)
        if 'proxy_config' in approval['scopes'] and runtime is not None:routes=guarded('proxy_rules',lambda:route_correlation.inspect_routes(runtime,discovery,'existing_connections' in approval['scopes']),{'collector_state':'failed'})
    for key,record in session['profiles'].items():
        p=guarded('profile_static_'+key,lambda:profiles_v3.static_profile(record),dict(record['public'])) if 'browser_static' in approval['scopes'] else dict(record['public'])
        if key in approval['profiles'] and 'browser_dynamic' in approval['scopes']:
            d=guarded('profile_dynamic_'+key,lambda:profiles_v3.dynamic_profile(record,independent_network='independent_network' in approval['scopes']),{'status':'failed','dynamic_profile_checked':False});p.update({k:v for k,v in d.items() if k not in record['public'] or k in ('dynamic_profile_checked','actual_profile_verified','write_tests_performed','rollback_status','cleanup_status')})
            p['dynamic_result']=d
        profiles.append(p)
    if 'browser_region' in approval['scopes']:
        from .region_v32 import collect as region_collect,attach_website
        region=guarded('browser_region',lambda:attach_website(region_collect(session['profiles']),profiles),{'status':'failed'})
    if 'neutral_network' in approval['scopes']:
        tun=(topo or {}).get('vpn_and_tun_topology') or {}
        probes=guarded('neutral_network',lambda:network_v3.checks(allow_fake=bool(tun.get('tun_owns_ipv4_default_route') or tun.get('tun_owns_ipv6_default_route'))),[{**network_v3._entry(h),'request_sent':None,'reason':'collector_failed'} for h,_ in network_v3.ENDPOINTS.values()])
    if 'independent_network' in approval['scopes']:
        from .deep_network_v31 import checks as deep_checks
        tun=(topo or {}).get('vpn_and_tun_topology') or {}
        independent=guarded('independent_network',lambda:deep_checks(bool(tun.get('tun_owns_ipv4_default_route') or tun.get('tun_owns_ipv6_default_route'))),[{'status':'failed','reason':'collector_failed'}])
    report=make_report(scan_id,approval,local,topo,discovery,routes,profiles,probes,independent=independent,region=region,host_context=host_context)
    from .evidence_completion_v33 import complete,attach
    report=guarded('evidence_completion',lambda:complete(report,topo,discovery,runtime,program,program_private,session['profiles'],lambda:BROKER.cancelled(scan_id)),report)
    if 'assessment_v33' not in report:attach(report,program,attempts=[{'source':'completion','surface':'all','status':'failed','reason':'completion_not_finished'}])
    report['collector_errors']=errors
    paths=save(report)
    from .pdf_report_renderer import build_pdf_reports
    pdfs=guarded('pdf_renderer',lambda:build_pdf_reports(paths['json']),{})
    from .plain_decisions_v35 import assess as display_assess
    view=display_assess(report)
    session['result']={'status':'cancelled' if BROKER.cancelled(scan_id) else 'completed' if pdfs and not errors else 'completed_with_limitations','run_id':scan_id,'summary_zh':view['headline'],'surface_assessments':{k:{x:a[x] for x in ('health_level','health_score','technical_environment_ready','recommend_now','reason','next_action')} for k,a in view['surface_assessments'].items()},'usage_scenarios':view['usage_scenarios'],'remaining_gap_count':len(report['remaining_gaps_v33']),'pdf_paths':pdfs,'evidence_path':paths['json'],'collector_errors':errors}
    return session['result']


def source_build():
    """本轮加载代码的可追溯摘要，不包含用户配置/路径。"""
    if getattr(sys,'frozen',False):return json.loads((Path(sys._MEIPASS)/'v3-source-manifest.json').read_text(encoding='utf-8'))
    digest=hashlib.sha256();files=[]
    base=Path(__file__).parent.parent
    for path in sorted([*base.glob('*.py'),*base.glob('toolkit/*.py'),*base.glob('toolkit/*.json'),*base.glob('_vendor/**/*.py'),*base.glob('_vendor_pdf/**/*.py'),*base.glob('_vendor_reportlab/**/*.py')]):
        name=path.relative_to(base).as_posix();digest.update(name.encode());digest.update(path.read_bytes());files.append(name)
    return {'toolkit_source_sha256':digest.hexdigest(),'files':len(files),'dependency':'bundled PyYAML 6.0.3 + pypdf 6.10.0 + ReportLab 4.4.10 + Pillow 13.0.0 + charset-normalizer 3.5.2 / psutil + PySide6','scope':'采集器及随附 Python 源文件；非操作系统或配置完整性证明'}

def save(report,directory=None):
    storage.bounded(report)
    if report['summary']!=summarize(report):raise ValueError('inconsistent_summary')
    target=storage.safe_dir(directory or root_dir()/'data/preflight_v3'/report['run_id']);path=target/'evidence.json'
    with path.open('x',encoding='utf-8') as f:json.dump({'report':report,'sha256':hashlib.sha256(canonical(report)).hexdigest()},f,ensure_ascii=False,indent=2,allow_nan=False)
    return {'json':str(path)}

def read(path):
    payload=storage.read_json(path);r=payload.get('report')
    if not isinstance(r,dict) or r.get('schema')!=SCHEMA or payload.get('sha256')!=hashlib.sha256(canonical(r)).hexdigest():raise ValueError('invalid_preflight_report')
    if r['summary']!=summarize(r):raise ValueError('inconsistent_summary')
    return r,payload['sha256']
