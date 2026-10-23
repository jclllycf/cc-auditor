"""同轮目标规则/中立视点关联；不访问、解析 Claude 域名，不导出配置和进程路径。"""
from pathlib import Path
import socket
from .proxy_adapters import simulate_symbolic
from .zero_contact_guard import utc_now

def _ips(rows,host,process):
    found=[]
    for row in rows[:2048]:
        m=row.get('metadata') or {}
        if m.get('host','').lower()==host and str(m.get('process','')).casefold()==process.casefold():
            value=m.get('destinationIP')
            if isinstance(value,str) and value not in found:found.append(value)
    return found[:4]

def _sim(config,target,rows,alias):
    # Pre-use verdict comes from all feasible static branches. Optional historical
    # IP records are development calibration and must never determine the verdict.
    result=simulate_symbolic(config,target,alias)
    ips=_ips(rows,target['host'],target['process'])
    if ips:
        observed=[simulate_symbolic(config,{**target,'destination_ip':ip},alias) for ip in ips]
        result['optional_development_calibration']={'samples':len(observed),'all_agree_with_preuse':all(v.get('configured_chain')==result.get('configured_chain') for v in observed)}
    return result

def refine(report,topology,discovery,runtime,private):
    scopes=report.get('approval',{}).get('scopes',[]);out={};controllers=getattr(runtime,'v33_controllers',{}) if runtime else {}
    snapshots=dict(getattr(runtime,'v33_connection_snapshots',{})) if runtime else {}
    refresh=[]
    if 'existing_connections' in scopes:
        for binding,ctl in list(controllers.items())[:4]:
            try:snapshots[binding]=ctl['get']('/connections').get('connections',[])[:2048];refresh.append({'source':binding,'status':'observed','snapshot':2})
            except Exception:refresh.append({'source':binding,'status':'failed','snapshot':2})
    program=report.get('program_context_v33') or {};tun=(topology or {}).get('vpn_and_tun_topology') or {};proxy=(topology or {}).get('proxy_configuration') or {}
    system_transport=program.get('desktop',{}).get('neutral_transport',{})
    # Future paths must not depend on which Claude/SDK binaries happen to be
    # installed on the developer machine. Unknown future process/path selectors
    # branch symbolically. System measurements stay labelled as host baselines.
    contexts=[('desktop','desktop','claude.exe','',system_transport),
              ('cli','cli','','',program.get('cli',{}).get('neutral_transport') or system_transport),
              ('api','api','','',program.get('api',{}).get('neutral_transport') or system_transport)]
    for p in report.get('profiles',[]):
        if p['profile_key'] not in report.get('approval',{}).get('profiles',[]):continue
        net=(((p.get('dynamic_result') or {}).get('data') or {}).get('independent_network') or {}).get('ipv4') or {}
        contexts.append(('web:'+p['profile_key'],'web',{'chrome':'chrome.exe','edge':'msedge.exe','firefox':'firefox.exe'}.get(p.get('browser_id'),''),'',net))
        if 'api' in report.get('user_declarations',{}).get('surfaces',[]) and (report.get('user_declarations',{}).get('plan_registration') or report.get('user_declarations',{}).get('plan_payment')):
            contexts.append(('console:'+p['profile_key'],'web_console',{'chrome':'chrome.exe','edge':'msedge.exe','firefox':'firefox.exe'}.get(p.get('browser_id'),''),'',net))
    markers=program.get('proxy_markers') or {};env_proxy=any(v.get(k) for v in (markers.get('collector',{}),markers.get('user',{}),markers.get('machine',{})) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'))
    for key,surface,process,process_path,neutral in contexts:
        base={'status':'unverified','minimum_verified':False,'captured_at_utc':utc_now(),'final_claude_public_egress':None,'anthropic_requests_sent':0,'reason':'尚未关联该入口的目标规则与实际中立测量视点','snapshot_refresh':refresh,'simulations':[]}
        out[key]=base
        # Offline route simulation remains available when external receivers are
        # declined. Probe permission controls only proof of the neutral path.
        if 'proxy_config' not in scopes:base['reason']='尚未授权本地代理规则读取';continue
        neutral_allowed='independent_network' in scopes
        if surface in ('cli','api') and not (program.get(surface,{}).get('host_bound') or program.get(surface,{}).get('preuse_host_bound')) and program.get(surface,{}).get('host_kind','windows') in ('wsl','container','remote'):
            base['reason']='未来计划使用的特殊宿主尚未指定；本机数据不能替代它';continue
        if surface in ('cli','api') and program.get(surface,{}).get('host_kind') in ('wsl','container','remote'):base['reason']='子系统/远端路径未有独立运行规则绑定；Windows TUN 不代替该宿主';continue
        is_browser=surface in ('web','web_console')
        browser=next((p for p in report.get('profiles',[]) if key in ('web:'+p['profile_key'],'console:'+p['profile_key'])),{})
        if is_browser:process_path=(private.get('browser_exes') or {}).get(browser.get('profile_key'),'')
        flags=program['profile_flags'].get(browser.get('profile_key'),{}) if 'profile_flags' in program else (program.get('browser_flags') or {}).get(browser.get('browser_id'),{})
        clean_flags=not is_browser or flags.get('status')=='observed' and flags.get('explicit_proxy_override_present') is False
        base['entry_conditions']={'pac_configured':proxy.get('pac_configured'),
            'wpad_auto_detect':proxy.get('wpad_auto_detect'),
            'browser_proxy_override_present':flags.get('explicit_proxy_override_present') if is_browser else None,
            'browser_proxy_extensions_present':browser.get('proxy_extension_count') if is_browser else None,
            'running_controller_count':len(controllers)}
        # A PAC/WPAD or per-profile override is a distinct unresolved entry
        # condition, never evidence that the system TUN/direct route was used.
        browser_proxy_extension=any(c.get('proxy_permission') is True for c in browser.get('extension_capabilities',[]))
        prefs=browser.get('network_preferences') or {}
        profile_proxy_mode=((prefs.get('proxy') or {}).get('diagnostic_values') or {}).get('mode')
        profile_override=(profile_proxy_mode not in (None,'system','direct') or prefs.get('network.proxy.type') not in (None,0,5))
        system_entry_clear=not proxy.get('system_proxy_enabled') and not proxy.get('pac_configured') and proxy.get('wpad_auto_detect') is False
        clean_flags=clean_flags and not browser_proxy_extension and not profile_override
        base['entry_conditions'].update(browser_proxy_extensions_present=browser_proxy_extension,
                                        profile_proxy_override_present=profile_override)
        if len(controllers)!=1:
            # 明确的默认直连基线也可用于首次使用者；不要求实际调用 Claude。
            direct=(not controllers and (discovery or {}).get('status')=='observed' and not (discovery or {}).get('software') and (topology or {}).get('query_flags',{}).get('routes_ok') and (topology or {}).get('query_flags',{}).get('adapters_ok') and (topology or {}).get('query_flags',{}).get('proxy_registry_ok') and system_entry_clear and not env_proxy and markers.get('winhttp',{}).get('status')=='observed' and markers['winhttp'].get('proxy_endpoint_marker_present') is False and tun.get('windows_vpn_connected_count')==0 and not tun.get('active_tunnel_families') and not tun.get('tun_owns_ipv4_default_route') and clean_flags and neutral_allowed and neutral.get('status')=='observed')
            if direct:base.update(status='passed',minimum_verified=True,proof_basis='direct_baseline_and_neutral',reason='未发现代理覆盖的默认本机路径与该视点中立 TLS 前置完成；不保证未来应用没有自行覆盖')
            else:
                candidates=[c for c in (report.get('target_routes') or {}).get('configs',[]) if c.get('activation')=='running_core_launch_config' and not c.get('parser_partial')]
                simulations=[x for cfg in candidates for x in cfg.get('routes',[]) if (x.get('target') or {}).get('surface')==surface and (not is_browser or (x.get('target') or {}).get('process')==process)]
                base['simulations']=simulations[:16]
                all_consistent=bool(simulations) and all(x.get('status')=='simulated' and x.get('symbolic_consistent') for x in simulations)
                if all_consistent and len(candidates)==1:
                    chains={tuple(x.get('configured_chain') or []) for x in simulations}
                    base.update(status='partial',symbolic_consistent=len(chains)==1,proof_basis='symbolic_running_launch_config',
                        reason='已解析唯一运行内核在启动时声明的配置文件；无法据此证明运行中配置未变、入口接管或中立同链')
                else:base['reason']='运行配置未能唯一绑定或分支出站不一致；保留规则差异和中立测量边界'
            continue
        binding,ctl=next(iter(controllers.items()));rows=snapshots.get(binding,[]);config=ctl['config'];alias=runtime.alias
        hosts=['claude.ai','api.anthropic.com'] if surface=='desktop' else ['claude.ai'] if surface=='web' else ['platform.claude.com'] if surface=='web_console' else ['api.anthropic.com']
        targets=[_sim(config,dict(surface=surface,host=h,process=process,process_path=process_path,port=443,network='tcp'),rows,alias) for h in hosts]
        api_probe_exe=((private.get('api') or {}).get('python_exe') or (private.get('api') or {}).get('node_exe') or '') if program.get('api',{}).get('host_bound') else ''
        neutral_process=process if is_browser else Path(api_probe_exe).name if surface=='api' and api_probe_exe else 'powershell.exe'
        import os
        neutral_path=process_path if is_browser else api_probe_exe if surface=='api' and api_probe_exe else str(Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe')
        n=_sim(config,dict(surface=surface,host='api4.ipify.org',process=neutral_process,process_path=neutral_path,port=443,network='tcp'),rows,alias)
        base['simulations']=targets+[n];base['controller_binding']=binding
        cores=[x for x in (discovery or {}).get('software',[]) if x.get('role')=='core' and x.get('running') is True]
        sole_core=(discovery or {}).get('status')=='observed' and len(cores)==1 and ctl.get('kernel_pids')==[cores[0]['pid']] and ctl.get('core')==cores[0].get('family')
        queried=(topology or {}).get('query_flags',{})
        tun_bound=sole_core and queried.get('routes_ok') is True and queried.get('adapters_ok') is True and queried.get('proxy_registry_ok') is True and ctl.get('tun_enabled') and tun.get('tun_owns_ipv4_default_route') and system_entry_clear and clean_flags and not env_proxy
        if any(t.get('symbolic_consistent') and t['status']=='simulated' and any(x in ('REJECT','REJECT-DROP') for x in t['configured_chain']) for t in targets):
            if tun_bound:base.update(status='verified_fault',fault_kind='runtime_reject',reason='已归因的默认 TUN 入口运行规则对本目标明确执行 REJECT')
            else:base.update(status='partial',reason='运行规则存在 REJECT，但入口尚未唯一归因；未伪称该客户端已被阻断')
            continue
        same=all(t.get('status')=='simulated' and t.get('symbolic_consistent') and t.get('configured_chain') and t['configured_chain']==n.get('configured_chain') and t.get('chain_state') in ('configured','runtime_upstream_not_observed') for t in targets) and n.get('status')=='simulated' and n.get('symbolic_consistent')
        if same and tun_bound and neutral_allowed and neutral.get('status')=='observed':
            base.update(status='passed',minimum_verified=True,proof_basis='runtime_rule_and_neutral_same_chain',reason='唯一内核的运行 TUN 与系统默认路由一致，目标/该视点中立端点规则选择同链；上游和 Claude 最终公网出口仍未实测',upstream_complete=all(t.get('chain_state')=='configured' for t in targets))
        else:base.update(status='partial',symbolic_consistent=all(t.get('symbolic_consistent') for t in targets),reason='已离线解析运行规则的可能分支；同链、入口归属或获准中立测量未全部满足' if neutral_allowed else '已离线解析规则；用户未批准独立网络接收端，因此不宣称同链测量或最终出口')
    console=[v for k,v in out.items() if k.startswith('console:') and (not report.get('user_declarations',{}).get('primary_profile') or k=='console:'+report['user_declarations']['primary_profile'])]
    if console:out['registration_console']={**next((v for v in console if not v['minimum_verified']),console[0]),'reason':'Console 浏览器前置：'+'；'.join(v['reason'] for v in console)}
    return out
