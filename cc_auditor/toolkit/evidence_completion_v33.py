"""有界补证、逐次尝试记录与最小人工清单。无授权不调用对应采集器。"""
import copy,time,shutil
from .zero_contact_guard import utc_now
from . import fixed_risk_v33 as model

def remaining_gaps(report,view=None):
    view=view or (model.assess_v35(report) if str(report.get('version','')).startswith(('3.5','3.6')) else model.assess(report));out=[];trace=report.get('evidence_completion_v33',{}).get('attempts',[])
    scopes=set(report.get('approval',{}).get('scopes',[]))
    for s in view['selected_surfaces']:
        for r in view['surface_assessments'][s]['ledger']:
            if r.get('evidence_lifecycle')!='preuse_environment' or not r['critical_minimum'] or r['state'] not in ('partial','unverified'):continue
            scope=('browser_dynamic' if s=='web' and r['key'] in ('profile','page','tls') else
                   'independent_network' if r['key'] in ('dns','ipv6') else
                   'proxy_config' if r['key']=='route' else 'program_context')
            # Explicitly declined probes are a coverage limitation, not a
            # mandatory remediation task or an excuse to request Claude setup.
            if scope not in scopes:continue
            relevant=[x for x in trace if x.get('surface') in (s,'all') or x.get('source')=='profile:'+view['surface_assessments'][s].get('profile_key','!')]
            out.append({'claim':s+'.'+r['key'],'title':model.SURFACES[s]+'：'+r['title'],'source_candidates':[x['source'] for x in relevant] or [scope],
                'required_capability':r['title'],'consent_scope':scope,'last_attempt':relevant[-1] if relevant else None,'retry_budget':0 if report.get('evidence_completion_v33',{}).get('finalized') else 1,
                'evidence_result':r['state'],'final_reason':r['problem'],'attempts':relevant,'priority':'高',
                'evidence_lifecycle':'preuse_environment',
                'minimum_action':('打开主要日常档案的普通空白页，下一轮仅勾选该档案；不需要登录 Claude。' if s=='web' and r['key'] in ('profile','page','tls') else '在现有授权范围排查本机配置或中立测点；无须安装 Claude、创建 API 项目或提供 Key。'),
                'value':'解除该入口的最低条件缺口，可能改变是否建议开始使用；不保证服务端接受。'})
    dec=model.declarations(report.get('user_declarations'));policy=model._policy(dec)
    missing_policy=[x for x in policy['issues'] if '未列入已核对' not in x]
    if missing_policy and 'native_declaration' in scopes and not view['model_version'].startswith('3.5'):
        out.append({'claim':'eligibility_declaration','title':'真实条件与资格自述','source_candidates':['native_user_declaration'],'required_capability':'本人真实所在地/主体资格声明','consent_scope':'native_declaration','last_attempt':None,'retry_budget':0,'evidence_result':'unverified','final_reason':'；'.join(missing_policy),'attempts':[], 'priority':'高','minimum_action':'在下一次授权卡补充缺少的真实地区/主体声明；无需提供身份文件。','value':'软件不能用语言、时区或出口代替本人真实资格。'})
    # Usage scenarios reuse the surface-specific environment evidence above.
    # Console account/billing setup, payment methods and verification outcomes
    # belong to future_setup or server_only; they must never be presented as
    # currently collectible critical scan evidence, nor duplicated per use case.
    return out

def attach(report,program=None,paths=None,attempts=None,finalized=True):
    if program is not None:
        report['program_context_v33']=program
        for key in ('desktop','cli','api','browser_flags'):
            report['checks'].append({'id':'v33_'+key+'_context' if key!='browser_flags' else 'v33_browser_flags','layer':'L01' if key!='browser_flags' else 'L07','title':'v3.3 '+key+' 限定上下文','state':'reference' if program.get('status')=='observed' else 'permission','value':program.get(key), 'criterion':'获准本机限定读取；不执行 Claude、SDK 或项目正文','points':0,'issue_id':'v33_'+key,'source':'approved_local_context','scope':key,'captured_at_utc':program.get('captured_at_utc',utc_now()),'reason':'','evidence_id':'E'+str(len(report['checks'])+1).zfill(3),'next_step':'保留来源；候选不自动当作绑定'})
            if key=='browser_flags':
                report['checks'][-1]['value']={'family_reference':program.get(key,{}),'profile_bound':program.get('profile_flags',{})}
                relevant=program.get('profile_flags',{}) if 'profile_flags' in program else program.get(key,{})
                if any(v.get('ignore_certificate_errors') is True for v in relevant.values()):report['checks'][-1].update(state='fault',points=35,reason='已绑定浏览器明确带有全局证书验证绕过参数；仅适用对应档案视点')
    if paths is not None:
        report['path_evidence_v33']=paths
        for key,path in paths.items():
            report['checks'].append({'id':'v33_path_'+key.replace(':','_'),'layer':'L12','title':'v3.3 路径关联 '+key,'state':'reference' if path.get('status')=='passed' else 'fault' if path.get('status')=='verified_fault' else 'partial','value':path,'criterion':'运行规则与已批准中立视点关联；不是 Claude 最终公网出口','points':0,'issue_id':'v33_path_'+key,'source':'runtime_rule_neutral_correlation','scope':key,'captured_at_utc':path.get('captured_at_utc',utc_now()),'reason':path['reason'],'evidence_id':'E'+str(len(report['checks'])+1).zfill(3),'next_step':'仅在已批准范围继续复核'})
    if attempts is not None:report['evidence_completion_v33']={'version':'3.4.preuse.loop.1','finalized':finalized,'budget_seconds':75,'per_source_retry_limit':1,'attempts':attempts,'cancelled':False}
    from .preflight_v3 import summarize
    report['summary']=summarize(report);view=model.assess_v35(report) if str(report.get('version','')).startswith(('3.5','3.6')) else model.assess(report)
    if str(report.get('model_version','')).startswith('3.2'):
        report['historical_assessment_v32']={k:report[k] for k in ('model_version','surface_assessments','usage_scenarios','headline') if k in report}
    report['assessment_v33']=view;report.update(view);report['remaining_gaps_v33']=remaining_gaps(report,view)
    return report

def complete(report,topology,discovery,runtime,program,private,records,cancelled=lambda:False):
    from . import program_context_v33 as pc,profiles_v3,route_refinement_v33
    scopes=report['approval']['scopes'];start=time.monotonic();attempts=[]
    report['program_context_v33']=program
    plan=remaining_gaps(report)
    if cancelled():
        attach(report,program,{},[{'source':'completion','surface':'all','status':'cancelled','reason':'user_revoked'}]);report['evidence_completion_v33']['cancelled']=True;return report
    def attempt(source,surface,scope,cost,operation):
        row={'source':source,'surface':surface,'consent_scope':scope,'started_at_utc':utc_now(),'attempt':1,'status':'not_attempted'}
        attempts.append(row)
        if scope not in scopes:row.update(status='permission',reason='scope_not_approved');return None
        if cancelled():row.update(status='cancelled',reason='user_revoked');return None
        if time.monotonic()-start+cost>75:row.update(status='budget_exhausted',reason='bounded_total_budget');return None
        try:
            result=operation();row.update(status=result.get('status','completed') if isinstance(result,dict) else 'completed',finished_at_utc=utc_now());return result
        except Exception as e:row.update(status='failed',reason='collector_unavailable',error_class=type(e).__name__);return None
    if 'program_context' in scopes:
        program['proxy_markers']=pc.proxy_markers()
        allow_fake=bool((topology or {}).get('vpn_and_tun_topology',{}).get('tun_owns_ipv4_default_route'))
        desktop=attempt('windows_system_tls','desktop','independent_network',12,lambda:pc.windows_transport(allow_fake))
        if desktop:
            program['desktop']['neutral_transport']=desktop
            # Windows CLI 的系统 TLS 前置，不声称原生 CLI 的业务请求已被运行。
            if program.get('cli',{}).get('host_bound') and program['cli'].get('host_kind')=='windows':program['cli']['neutral_transport']=copy.deepcopy(desktop)
        api_private=private.get('api') or {}
        if program.get('api',{}).get('host_bound'):
            exe=api_private.get('python_exe') or api_private.get('node_exe')
            result=attempt('selected_api_runtime_tls','api','independent_network',12,lambda:pc.python_transport(exe,allow_fake) if api_private.get('python_exe') else pc.node_transport(exe,allow_fake))
            if result:program['api']['neutral_transport']=result
        sub=private.get('cli_subsystem')
        if sub:
            result=attempt('selected_subsystem_tls','cli','independent_network',12,lambda:pc.python_transport('python3',False,sub['prefix']))
            if result:program['cli']['neutral_transport']=result
        api_sub=private.get('api_subsystem')
        if api_sub:
            result=attempt('selected_api_environment_tls','api','independent_network',12,lambda:pc.python_transport('python3',False,api_sub['prefix']))
            if result:program['api']['neutral_transport']=result
        if (topology or {}).get('vpn_and_tun_topology',{}).get('system_has_ipv6_default_route') is True:
            fake6=(topology or {}).get('vpn_and_tun_topology',{}).get('tun_owns_ipv6_default_route') is True
            v6=attempt('windows_system_tls_ipv6','desktop','independent_network',12,lambda:pc.windows_transport(fake6,6))
            if v6:
                program['desktop'].setdefault('neutral_transport',{})['ipv6']=v6
                if program.get('cli',{}).get('host_kind')=='windows' and program['cli'].get('host_bound'):program['cli'].setdefault('neutral_transport',{})['ipv6']=copy.deepcopy(v6)
            if program.get('api',{}).get('host_bound'):
                exe=api_private.get('python_exe') or api_private.get('node_exe')
                result=attempt('selected_api_runtime_ipv6','api','independent_network',12,lambda:pc.python_transport(exe,fake6,family=6) if api_private.get('python_exe') else pc.node_transport(exe,fake6,family=6))
                if result:program['api'].setdefault('neutral_transport',{})['ipv6']=result
    # 原始结果保留在历史轨迹，重试只针对本轮已批准的真实档案。
    for p in report.get('profiles',[]):
        key=p['profile_key'];net=((p.get('dynamic_result') or {}).get('data') or {}).get('independent_network') or {}
        required_network=('ipv4','dns','stun')+(('ipv6',) if (topology or {}).get('vpn_and_tun_topology',{}).get('system_has_ipv6_default_route') is True else ())
        needs=not p.get('dynamic_profile_checked') or 'independent_network' in scopes and any(net.get(k,{}).get('status')!='observed' for k in required_network)
        if key not in report['approval'].get('profiles',[]) or not needs:continue
        first=copy.deepcopy(p.get('dynamic_result'));p['v33_attempt_history']=[{'attempt':1,'result':first}]
        d=attempt('profile:'+key,'web','browser_dynamic',35,lambda r=records[key]:profiles_v3.dynamic_profile(r,timeout=30,independent_network='independent_network' in scopes))
        attempts[-1]['attempt']=2
        if d:
            p['v33_attempt_history'].append({'attempt':2,'result':copy.deepcopy(d)})
            if d.get('dynamic_profile_checked'):
                oldnet=((first or {}).get('data') or {}).get('independent_network') or {};newnet=(d.get('data') or {}).get('independent_network') or {}
                protocols=('ipv4','ipv6','stun','dns','tls');sources={k:2 for k in protocols if isinstance(newnet.get(k),dict)}
                for k in protocols:
                    v=oldnet.get(k)
                    if not isinstance(v,dict):continue
                    if v.get('status')=='observed' and newnet.get(k,{}).get('status')!='observed':newnet[k]=copy.deepcopy(v);sources[k]=1
                if newnet:d.setdefault('data',{})['independent_network']=newnet;d['independent_network_source_attempts']=sources
                p.update({k:v for k,v in d.items() if k not in records[key]['public'] or k in ('dynamic_profile_checked','actual_profile_verified','write_tests_performed','rollback_status','cleanup_status')});p['dynamic_result']=d
                # 重建该 Profile 的事实项，保留原始尝试，不让旧失败残留为当前状态。
                from .preflight_v3 import make_report
                fresh=make_report(report['run_id'],report['approval'],profiles=[p])
                updates={c['id']:c for c in fresh['checks'] if c['scope']==key}
                for c in report['checks']:
                    if c['id'] in updates:
                        new=updates[c['id']];c.update({k:v for k,v in new.items() if k!='evidence_id'})
    if any(e.get('status')!='observed' for e in report.get('independent_network_events',[])):
        from .deep_network_v31 import checks
        result=attempt('system_dns_stun_retry','all','independent_network',24,lambda:checks(bool((topology or {}).get('vpn_and_tun_topology',{}).get('tun_owns_ipv4_default_route'))))
        attempts[-1]['attempt']=2
        if result:
            report['independent_network_attempt_history_v33']=[copy.deepcopy(report['independent_network_events']),result]
            # 同类成功优先合并，失败不是已确认网络故障，历史仍在。
            old={e.get('kind'):e for e in report.get('independent_network_events',[])}
            for e in result:
                if e.get('status')=='observed' or old.get(e.get('kind'),{}).get('status')!='observed':old[e.get('kind')]=e
            report['independent_network_events']=list(old.values())
    bound=attempt('profile_bound_browser_flags','web','program_context',2,lambda:pc.bind_browser_flags(report.get('profiles',[])))
    if bound is not None:program['profile_flags']=bound
    if 'program_context' in scopes:private['browser_exes']={key:str(value['exe']) for key,value in records.items() if value.get('exe')}
    paths=attempt('runtime_path_refinement','all','proxy_config',9,lambda:route_refinement_v33.refine(report,topology,discovery,runtime,private)) or {}
    attach(report,program,paths,attempts)
    report['evidence_completion_v33'].update(cancelled=cancelled(),duration_ms=round((time.monotonic()-start)*1000))
    final={g['claim']:g for g in report['remaining_gaps_v33']}
    report['evidence_completion_v33']['plan']=[{**g,'evidence_result':final.get(g['claim'],{}).get('evidence_result','resolved_or_no_longer_applicable'),'final_reason':final.get(g['claim'],{}).get('final_reason','自动关联后不再属于本次计划的关键缺口')} for g in plan]
    return report
