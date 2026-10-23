"""确定的预检行动指数；只依赖证据，不估计账户结果概率。"""
from decimal import Decimal,ROUND_HALF_UP
from .assess_v32 import declarations as legacy_declarations,KNOWN_SUPPORTED,KNOWN_NOT_LISTED,POLICY_SOURCES

VERSION='3.4.preuse.4'
SURFACES={'desktop':'桌面端 Desktop','web':'网页端 Web','cli':'命令行 CLI','api':'程序接口 API'}
FACTORS={'passed':Decimal('0'),'verified_fault':Decimal('1'),'not_configured':Decimal('1'),'partial':Decimal('.25'),'unverified':Decimal('.55'),'not_applicable':Decimal('0')}
STATE_ZH={'passed':'已按判据完成','verified_fault':'确认技术故障','not_configured':'必需条件未配置','partial':'取得部分证据','unverified':'关键证据未取得','not_applicable':'本次不适用'}


def declarations(raw=None):
    raw=raw or {};out=legacy_declarations(raw)
    for key,default in (('plan_daily',True),('plan_registration',False),('plan_payment',False),('eligibility_confirmed',False),('console_billing_ready',False)):
        out[key]=raw.get(key) if type(raw.get(key)) is bool else default
    from .api_execution_v35 import MODES
    out['api_execution_mode']=raw.get('api_execution_mode') if raw.get('api_execution_mode') in MODES else 'unknown'
    return out


def assess_v35(report):
    """新技术健康契约；assess 保留为不可变历史风险模型的回放入口。"""
    from .health_v35 import assess as health_assess
    return health_assess(report)


def round_index(value):return int(Decimal(value).quantize(Decimal('1'),rounding=ROUND_HALF_UP))


def evaluate_ledger(rows):
    """独立账本算法；不适用归一化、同根因最大贡献、严重故障下限。"""
    assert sum(r['weight'] for r in rows)==100
    applicable=sum(r['weight'] for r in rows if r['state']!='not_applicable')
    causes={}
    for row in rows:
        weight=Decimal(row['weight'])*100/Decimal(applicable) if applicable and row['state']!='not_applicable' else Decimal(0)
        row['normalized_weight']=str(weight.quantize(Decimal('.000001')))
        contribution=weight*FACTORS[row['state']]
        row['contribution_before_dedup']=str(contribution.quantize(Decimal('.000001')))
        row['contribution']='0'
        # 缺证只在同一实际缺口才去重；不把 DNS/IPv6 等不同缺口混成一个。
        cause=row['root_cause']
        if cause not in causes or contribution>causes[cause][1]:causes[cause]=(row,contribution)
    for row,value in causes.values():row['contribution']=str(value.quantize(Decimal('.000001')))
    total=sum((Decimal(r['contribution']) for r in rows),Decimal(0));raw_score=round_index(total)
    severe=any(r['state']=='verified_fault' and r['critical_fault'] for r in rows)
    index=max(raw_score,75 if severe else 0);index=min(100,max(0,index))
    return {'risk_index':index,'raw_contribution_sum':str(total.quantize(Decimal('.000001'))),'critical_floor_adjustment':index-min(100,raw_score),
        'confirmed_fault_contribution':str(sum((Decimal(r['contribution']) for r in rows if r['state']=='verified_fault'),Decimal(0)).quantize(Decimal('.000001'))),
        'missing_condition_contribution':str(sum((Decimal(r['contribution']) for r in rows if r['state']=='not_configured'),Decimal(0)).quantize(Decimal('.000001'))),
        'evidence_gap_contribution':str(sum((Decimal(r['contribution']) for r in rows if r['state'] in ('partial','unverified')),Decimal(0)).quantize(Decimal('.000001'))),
        'applicable_weight':applicable,'critical_confirmed_fault':severe,'ledger':rows}


def _refs(by,ids):return list(dict.fromkeys(by[k]['evidence_id'] for k in ids if k in by))


def _policy(dec):
    country=dec['physical_country'];issues=[]
    if not country:issues.append('尚未声明真实物理所在地')
    elif country in KNOWN_NOT_LISTED:issues.append('声明地区未列入已核对的官方支持名单')
    elif country not in KNOWN_SUPPORTED and not dec['eligibility_confirmed']:issues.append('该地区未纳入本地快照，尚未声明已按当前官方政策核对')
    if dec['entity']=='unknown':issues.append('尚未声明个人或组织使用主体')
    if dec['entity']=='organization' and not dec['eligibility_confirmed']:issues.append('组织主体适用性尚未由用户核对声明')
    return {'eligible_for_preflight_advice':not issues,'issues':issues,'basis':'用户真实条件自述与本地政策参考，非账户或身份认证',
        'source':POLICY_SOURCES['consumer'],'snapshot_date':'2026-10-18','future_policy_not_applied':True}


def _state(check):
    return {'passed':'passed','fault':'verified_fault','reference':'partial','partial':'partial'}.get((check or {}).get('state'),'unverified')


def _route_state(report,surface,p=None):
    key='web:'+p['profile_key'] if p else surface
    path=(report.get('path_evidence_v33') or {}).get(key,{})
    if path.get('status')=='verified_fault' and path.get('fault_kind') in ('runtime_reject','route_mismatch','tls_verification_failure'):
        return 'verified_fault',path
    if path.get('status')=='passed' and path.get('minimum_verified') is True and path.get('proof_basis') in ('runtime_rule_and_neutral_same_chain','direct_baseline_and_neutral'):
        return 'passed',path
    routes=report.get('target_routes') or {};relevant=[]
    for cfg in routes.get('configs',[]):
        if cfg.get('activation')!='controller_rules_observed':continue
        for r in cfg.get('runtime_rules',[]):
            t=r.get('target') or {};s=t.get('surface','')
            if s==surface or surface=='desktop' and s=='desktop_code':
                if not p or t.get('process')=={'chrome':'chrome.exe','edge':'msedge.exe','firefox':'firefox.exe'}.get(p.get('browser_id')):relevant.append(r)
    if path.get('status')=='partial' or relevant:return 'partial',path
    return 'unverified',path


def assess_surface(report,surface,p=None):
    by={c['id']:c for c in report.get('checks',[])};rows=[];program=report.get('program_context_v33') or {};dec=declarations(report.get('user_declarations'));policy=_policy(dec)
    context=program.get(surface,{})
    def add(key,title,weight,state,ids=(),critical=False,positive='',problem='',action='',cause=None,critical_fault=False,scope=None):
        # Future installation is outside the pre-use environment scoring denominator.
        lifecycle='future_setup' if (surface,key) in (('desktop','availability'),('cli','availability'),('api','application'),('api','runtime')) else 'preuse_environment'
        if lifecycle=='future_setup':state='not_applicable';critical=False
        rows.append({'key':key,'rule_id':surface+'.'+key,'title':title,'weight':weight,'state':state,'critical_minimum':critical,
            'critical_fault':critical_fault,'root_cause':cause or surface+':'+key,'evidence_ids':_refs(by,ids),
            'positive':positive or title+'已有本范围证据','problem':problem or title+'尚未达到本次判据',
            'action':action or '由检测器在已批准范围自动复核；仍缺时见证据补足清单。','scope':scope or surface,
            'evidence_lifecycle':lifecycle})
    def checks(key,title,weight,ids,critical=False,positive='',problem=''):
        cs=[by.get(k) for k in ids];fault=next((c for c in cs if c and c['state']=='fault'),None)
        st='verified_fault' if fault else 'passed' if all(c and c['state']=='passed' for c in cs) else 'partial' if any(c and c['state'] in ('passed','reference','partial') for c in cs) else 'unverified'
        add(key,title,weight,st,ids,critical,positive,problem,cause=fault.get('issue_id') if fault else None,critical_fault=bool(fault and fault.get('points',0)>=30))
    route,path=_route_state(report,surface,p)
    remote=surface in ('cli','api') and context.get('host_kind',dec.get(surface+'_host')) in ('wsl','container','remote')
    host_observed=context.get('preuse_host_bound') is True or context.get('host_bound') is True
    remote_unobserved=remote and not host_observed
    net=(((p or {}).get('dynamic_result') or {}).get('data') or {}).get('independent_network',{})
    system_dns=any(x.get('kind')=='system_authoritative_dns' and x.get('status')=='observed' for x in report.get('independent_network_events',[]))
    def route_row(weight):
        add('route','目标规则与中立路径关联',weight,route,['v33_path_'+('web_'+p['profile_key'] if p else surface),'proxy_rules','existing_client'],True,
            '目标规则与中立测量路径已按本次判据关联',path.get('reason') or '当前目标规则/同程序路径尚未充分关联',
            '自动核对运行规则、离线分支与获准中立端点；无需 Claude 历史连接。',critical_fault=route=='verified_fault')
    def dns_row(weight):
        # A Windows DNS receiver is a valid *host baseline*, not an observation
        # from an as-yet-unselected API/CLI process, WSL instance or remote host.
        # Never upgrade an unbound application to a fully verified DNS path.
        if surface=='web':
            st='passed' if net.get('dns',{}).get('status')=='observed' else 'unverified'
        elif remote:
            st='passed' if context.get('neutral_dns',{}).get('status')=='observed' and host_observed else 'unverified'
        else:
            st='passed' if system_dns else 'unverified'
        add('dns','该浏览器 DNS 实测' if surface=='web' else '所选特殊环境 DNS 前置' if remote else '本机系统 DNS 前置参考',weight,st,[(p['profile_key']+'_dynamic') if p else 'dns_receiver'],surface=='web',
            '取得'+('该浏览器' if p else '使用前系统环境的')+'权威 DNS 参考', '当前视点接收端尚未取得结果；不证明未来应用路径存在故障', '自动按该视点重试获准 DNS 接收端；Windows 结果不能代替未绑定的特殊宿主。')
    def ipv6_row(weight):
        routecheck=by.get('routes_ok') or {};tun=routecheck.get('value') or {}
        absent=routecheck.get('state')=='reference' and tun.get('system_has_ipv6_default_route') is False
        v=net.get('ipv6',{}) if p else context.get('neutral_transport',{}).get('ipv6',{})
        if not p and not remote and not v:v=(program.get('desktop',{}).get('neutral_transport') or {}).get('ipv6',{})
        st='not_applicable' if absent and not remote else 'passed' if v.get('status')=='observed' else 'unverified'
        critical=not remote and routecheck.get('state')=='reference' and tun.get('system_has_ipv6_default_route') is True
        add('ipv6','IPv6 独立路径',weight,st,[p['profile_key']+'_dynamic'] if p else ['ipv6_bypass','routes_ok'],critical,'该视点 IPv6 测点已取得结果','存在 IPv6 默认路由，但该视点独立结果尚未取得；不是已确认泄漏' if critical else 'IPv6 结果尚未取得；不是已确认泄漏')
    if surface=='desktop':
        installed=context.get('installed');st='passed' if installed is True else 'not_configured' if installed is False and context.get('status')=='observed' else 'unverified'
        problem='已检查本机安装线索，未发现 Desktop' if st=='not_configured' else '本次来源没有可确认 Desktop 安装的证据'
        add('availability','Desktop 已安装且身份可识别',20,st,['v33_desktop_context'],True,'已发现 Desktop 安装/现有桌面实例','尚未发现本机 Desktop；或本轮未获准核对安装线索','按真实需要安装官方 Desktop；检测器已自动检查运行实例和固定安装位置。')
        rows[-1].update(problem=problem,action='先在已批准范围核对安装身份；未安装时按真实需要选择官方 Desktop。')
        checks('os','Windows 与可用空间',15,['os_desktop_compatible','disk_sufficient'],True,'Windows 与空间达到安装基础门槛')
        route_row(25);dns_row(10);ipv6_row(10)
        transport=context.get('neutral_transport',{})
        add('tls','桌面系统 TLS 基础',10,'verified_fault' if transport.get('certificate_fault') is True else 'passed' if transport.get('tls_verified') is True else 'partial' if by.get('neutral_tls',{}).get('state')=='passed' else 'unverified',['v33_desktop_context','neutral_tls'],True,
            '系统视点中立 HTTPS 验证已完成','系统中立 TLS 尚未完成，或有独立证书故障证据；不是 Desktop 握手',critical_fault=transport.get('certificate_fault') is True)
        checks('hosts','本机 hosts 阻断检查',10,['hosts_block'],True,'hosts 未见目标阻断')
    elif surface=='web':
        p=p or {};pk=p.get('profile_key','');dyn=p.get('dynamic_result') or {};data=dyn.get('data') or {};binding=p.get('profile_binding') or dyn.get('profile_binding')
        profile_ok=p.get('static_profile_checked') and p.get('dynamic_profile_checked') and binding=='user_attested_targeted_launch_browser_pid'
        add('profile','主要日常 Profile 已定向核对',15,'passed' if profile_ok else 'partial' if p.get('static_profile_checked') or p.get('dynamic_profile_checked') else 'unverified',[pk+'_static',pk+'_identity',pk+'_dynamic'],True,
            p.get('browser_name','浏览器')+' '+p.get('profile_alias','')+' 已取得用户确认、定向回调与 PID 证据','日常档案归属/回调未达到本次最低判据','自动重试已批准日常档案；只有未打开或候选冲突时才请用户选择。',scope=pk)
        checks('page','该档案必要页面能力',15,[pk+'_'+k for k in ('cookies','websocket','webassembly','workers','canvas_2d')],True,'主要档案工具页必要能力正常')
        route_row(25);dns_row(10);ipv6_row(10)
        add('stun','浏览器 UDP/STUN 视点',10,'passed' if net.get('stun',{}).get('status')=='observed' else 'unverified',[pk+'_dynamic'],False,'该档案取得 UDP/STUN 回显','该档案 UDP/STUN 仍待补齐；不自动判泄漏')
        flags=program['profile_flags'].get(pk,{}) if 'profile_flags' in program else (program.get('browser_flags') or {}).get(p.get('browser_id'),{})
        tls='verified_fault' if flags.get('ignore_certificate_errors') is True else 'passed' if net.get('ipv4',{}).get('status')=='observed' and flags.get('status')=='observed' else 'partial' if net.get('ipv4',{}).get('status')=='observed' else 'unverified'
        add('tls','该浏览器 HTTPS 与验证开关',10,tls,[pk+'_dynamic','v33_browser_flags'],True,'该浏览器 HTTPS 成功且未见证书绕过启动标记','浏览器 TLS 判据未齐备，或发现明确证书绕过标记','自动核对浏览器已运行参数中的限定开关，并重试获准 HTTPS 测点。',critical_fault=tls=='verified_fault')
        add('extensions','限定扩展权限盘点',5,'passed' if p.get('extension_count') is not None else 'unverified',[pk+'_extensions'],False,'已盘点该档案扩展能力；不推定已注入 Claude','扩展权限盘点未完成')
    elif surface=='cli':
        installed=context.get('installed');st='passed' if installed is True else 'not_configured' if installed is False and context.get('status')=='observed' else 'unverified'
        add('availability','CLI 存在且分类明确',20,st,['v33_cli_context'],True,'实际执行视点发现 CLI 文件；未运行 Claude','CLI 未配置或执行位置还不能确定','自动检查本机安装线索、已运行 WSL/容器；多候选时只需指定一个宿主。')
        rows[-1]['problem']='已检查指定宿主，未发现 CLI 安装' if st=='not_configured' else '本次来源没有可确认 CLI 安装与执行位置的证据'
        local_host=context.get('host_kind','windows') in ('windows','unknown')
        add('host','可用终端宿主环境',15,'passed' if host_observed or local_host and context.get('shell_ready') is True else 'partial' if context.get('candidate_count',0)>0 else 'unverified',['v33_cli_context'],not local_host,'所选终端环境可供以后安装 CLI','所选特殊环境尚未取得独立基础资料；不要求先安装 Claude')
        route_row(25)
        own=context.get('neutral_transport') if not remote or host_observed else None
        baseline=(program.get('desktop',{}).get('neutral_transport') or {}) if local_host else {}
        t=own or baseline
        bound=bool(own and host_observed)
        tls='verified_fault' if (bound or local_host) and t.get('certificate_fault') is True else 'passed' if (bound or local_host) and t.get('tls_verified') is True else 'unverified'
        add('tls','已绑定终端宿主 TLS 前置' if bound else '所选特殊环境 TLS 前置' if remote else 'Windows 系统 TLS 使用前基础',15,tls,['v33_cli_context','neutral_tls'],True,'本次宿主环境的中立 TLS 已验证；未来 CLI 业务请求未测试','本次宿主系统 TLS 前置未完成；不要求先安装 CLI',critical_fault=tls=='verified_fault')
        dns_row(10);ipv6_row(5)
        add('shell','系统终端基础能力',10,'passed' if context.get('shell_ready') is True else 'not_configured' if context.get('shell_ready') is False else 'unverified',['v33_cli_context'],True,'Windows Shell 可供后续安装','操作系统未发现可用终端')
    else:
        configured=context.get('configured');st='passed' if configured is True else 'not_configured' if configured is False and context.get('status')=='observed' else 'unverified'
        add('application','指定 API 应用与客户端',25,st,['v33_api_context'],True,'指定目录内 API 客户端安装元数据已核对','API 应用未指定或未配置；未借用检测器 Python','仅在已批准的项目目录自动定位 SDK/客户端元数据；无目标时需选择实际应用目录。')
        rows[-1]['problem']='未选择实际 API 应用，或所选目录没有已安装 SDK' if st=='not_configured' else '本次来源没有实际 API 应用与运行时绑定证据'
        local_observed=context.get('status')=='observed' or by.get('os_desktop_compatible',{}).get('state') in ('passed','fault')
        add('host','计划使用的系统环境',15,'passed' if host_observed or not remote and local_observed else 'unverified',['v33_api_context','os_desktop_compatible'],True,'已取得所选系统环境基础资料；无需先创建 SDK 项目','所选特殊环境尚未取得独立基础资料；不要求先创建 API 项目')
        route_row(25)
        own=context.get('neutral_transport') if not remote or host_observed else None
        baseline=(program.get('desktop',{}).get('neutral_transport') or {}) if not remote else {}
        t=own or baseline
        # A verified host transport remains evidence even before an API SDK
        # exists; its meaning is host TLS readiness, never an SDK handshake.
        bound=bool(own and host_observed)
        tls='verified_fault' if (bound or not remote) and t.get('certificate_fault') is True else 'passed' if (bound or not remote) and t.get('tls_verified') is True else 'unverified'
        add('tls','已绑定候选宿主 TLS 前置' if bound else '所选特殊环境 TLS 前置' if remote else 'Windows 系统 TLS 使用前基础',15,tls,['v33_api_context','neutral_tls'],True,'本次宿主环境的中立 TLS 已验证；未来 SDK 业务请求未测试','本次宿主系统 TLS 前置未完成；未来 SDK 或项目不是本次缺证',critical_fault=tls=='verified_fault')
        dns_row(10);ipv6_row(10)
    evaluation=evaluate_ledger(rows)
    critical_missing=[r for r in rows if r['critical_minimum'] and r['state'] in ('partial','unverified')]
    blocking=[r for r in rows if r['state'] in ('verified_fault','not_configured') and r['critical_minimum']]
    # Missing pre-use evidence increases the engineering attention index but
    # does not automatically mean an installation cannot be started.
    environment_ready=evaluation['risk_index']<50 and not blocking and not remote_unobserved
    yes=environment_ready and policy['eligible_for_preflight_advice']
    decision_basis=('confirmed_environment_fault' if blocking else 'policy_condition' if not policy['eligible_for_preflight_advice'] else 'selected_environment_unobserved' if remote_unobserved else 'attention_threshold' if not environment_ready else 'ready_with_followups' if critical_missing else 'ready')
    issues=blocking+critical_missing
    reason=('现有环境适合开始合法安装或配置准备；待确认项目需在实际使用前复核' if yes else (blocking[0]['problem'] if blocking else policy['issues'][0] if policy['issues'] else '所选特殊环境尚未取得独立基础资料；未把缺测当故障' if remote_unobserved else '当前环境仍有需优先检查的证据缺口'))
    good=[r for r in rows if r['state']=='passed']
    index=evaluation['risk_index'];level='低关注' if index<25 else '中等关注' if index<50 else '高关注' if index<75 else '严重关注'
    installed=context.get('installed') if surface in ('desktop','cli') else context.get('configured') if surface=='api' else True
    install_state='not_required' if surface=='web' else 'installed' if installed is True else 'not_installed' if installed is False else 'unknown'
    # An installed binary or an SDK manifest is never proof of authenticated
    # Claude service operation. This preflight deliberately sends no request.
    operational=False
    configuration_state=('not_required' if surface=='web' else
                         'not_configured' if installed is False else
                         'installed_unverified' if installed is True else 'unknown')
    route_level=(path.get('proof_basis') or ('symbolic_rule_constrained' if path.get('symbolic_consistent') else 'proxy_config' if path.get('simulations') else 'unverified'))
    return {**evaluation,'surface':surface,'risk_level':level,'recommend_use':yes,'recommend_now':'是' if yes else '否','reason':reason,
        'preuse_environment_risk_index':index,'ready_to_begin_setup':yes,'installation_state':install_state,
        'environment_ready':environment_ready,'policy_ready':policy['eligible_for_preflight_advice'],'decision_basis':decision_basis,
        'configuration_state':configuration_state,'already_operational':operational,
        'operational_verification':'not_tested_zero_anthropic_contact',
        'route_evidence_level':route_level,
        'positive_factors':[{'text':r['positive'],'evidence_ids':r['evidence_ids']} for r in good],
        'obstacles':[{'text':r['problem'],'state':r['state'],'evidence_ids':r['evidence_ids'],'action':r['action'],'key':r['key']} for r in issues],
        'critical_missing_keys':[r['key'] for r in critical_missing],'minimum_technical_ready':environment_ready,
        'next_action':blocking[0]['action'] if blocking else '按本人真实条件核对支持地区和主体资格；技术预检不保证服务端接受。' if not yes else '可开始合法安装或配置；待验证项在实际使用前继续核查。',
        'policy':policy,'evidence_ids':list(dict.fromkeys(e for r in rows for e in r['evidence_ids']))}


def assess(report):
    dec=declarations(report.get('user_declarations'));surfaces={s:assess_surface(report,s) for s in ('desktop','cli','api')};ps=[]
    for p in report.get('profiles',[]):
        a=assess_surface(report,'web',p);a.update(profile_key=p['profile_key'],browser_name=p['browser_name'],profile_alias=p['profile_alias']);ps.append(a)
    chosen=[p for p in ps if p['profile_key']==dec['primary_profile']]
    rule='用户指定的主要日常档案'
    if not chosen:
        chosen=[p for p in ps if p['profile_key'] in report.get('approval',{}).get('profiles',[])] or ps;rule='未指定主档案：按本轮已选档案中最需处理者，未选浏览器不连带影响'
    main=max(chosen,key=lambda a:(not a['recommend_use'],a['risk_index'])) if chosen else assess_surface(report,'web')
    surfaces['web']={**main,'profiles':ps,'aggregation':rule,'selected_profile_keys':[p['profile_key'] for p in chosen]}
    surfaces={s:surfaces[s] for s in SURFACES};active=[surfaces[s] for s in dec['surfaces']]
    overall=bool(active) and all(a['recommend_use'] for a in active)
    scenarios=usage_scenarios(surfaces,dec,report)
    return {'model_version':VERSION,'surface_assessments':surfaces,'usage_scenarios':scenarios,'selected_surfaces':dec['surfaces'],
        'selection_source':dec['provenance'],'recommend_now':overall,'ready_to_begin_setup':overall,'headline':'所选入口的环境适合开始准备安装及使用 Claude' if overall else '本次暂不建议开始使用准备：请先核对真实资格' if all(a['environment_ready'] for a in active) else '所选入口的使用前环境仍需处理重点问题',
        'decision_reason':next((a['reason'] for a in active if not a['recommend_use']),'所选入口满足本次预检最低技术条件与声明资格'),
        'disclaimer':'确定指数是 CC Auditor 的预检行动指标，不是 Anthropic 封禁概率、服务端验证或支付成功率。'}


def usage_scenarios(surfaces,dec,report):
    policy=_policy(dec);active=[surfaces[s] for s in dec['surfaces']];daily_yes=dec['plan_daily'] and all(s['recommend_use'] for s in active)
    daily={'recommend_now':daily_yes,'recommend_text':'是' if daily_yes else '否','reason':'所选入口达到本次最低技术与声明资格条件' if daily_yes else next((s['reason'] for s in active if not s['recommend_use']),'日常使用不在本次计划'),
        'satisfied':[p['text'] for s in active for p in s['positive_factors']][:6],'obstacles':[o['text'] for s in active for o in s['obstacles']]+policy['issues'],'planned':dec['plan_daily']}
    web_ready=surfaces['web']['minimum_technical_ready'];registration=[]
    browser_base=all(not r['critical_minimum'] or r['state']=='passed' or r['key']=='route' for r in surfaces['web']['ledger'])
    for key,title in (('consumer','Claude.ai 消费者注册'),('console','Console/API 注册')):
        if key=='console' and 'api' not in dec['surfaces']:continue
        if key=='consumer' and set(dec['surfaces'])=={'api'}:continue
        console_path=(report.get('path_evidence_v33') or {}).get('registration_console',{})
        technical=web_ready if key=='consumer' else browser_base and console_path.get('minimum_verified') is True
        obstacles=list(policy['issues'])+([] if technical else ['注册入口的浏览器/目标网络前置还未达到判据'])
        yes=dec['plan_registration'] and not obstacles
        registration.append({'id':key,'title':title,'recommend_now':yes,'recommend_text':'是' if yes else '否','reason':'技术前置与用户声明资格支持尝试，不保证验证码或账号验证通过' if yes else '；'.join(obstacles) or '注册不在本次计划','satisfied':['浏览器注册环境已完成最低检查'] if technical else [],'obstacles':obstacles})
    payment=[]
    base=list(policy['issues'])
    for key,label in (('payment_method','付款类别'),('issuer_country','发行国家/地区'),('billing_country','账单国家/地区')):
        if not dec.get(key) or dec.get(key)=='unknown':base.append('未声明'+label)
    if dec['payment_method'] not in ('credit','debit','unknown'):base.append('所述方式不属于网页自助信用卡/借记卡范围')
    if dec['issuer_country'] and dec['billing_country'] and dec['issuer_country']!=dec['billing_country']:base.append('自述发行地区与账单地区不一致')
    if dec['issuer_country'] in KNOWN_NOT_LISTED or dec['billing_country'] in KNOWN_NOT_LISTED:base.append('声明付款地区未列入已核对支持名单')
    if dec['billing_matches_bank']!='yes':base.append('尚未确认账单资料与银行记录一致')
    if dec['three_ds']!='yes':base.append('尚未确认可以完成交易可能要求的 3DS')
    for key,title in (('subscription','Claude 网页订阅'),('api_billing','Console/API 预付计费')):
        if key=='api_billing' and 'api' not in dec['surfaces']:continue
        if key=='subscription' and set(dec['surfaces'])=={'api'}:continue
        technical=web_ready if key=='subscription' else browser_base and (report.get('path_evidence_v33') or {}).get('registration_console',{}).get('minimum_verified') is True
        issues=base+([] if technical else ['付款入口浏览器网络前置还未完成'])
        if key=='api_billing' and not dec['console_billing_ready']:issues.append('尚未声明拥有 Console 计费权限并将自行核对预付条件')
        yes=dec['plan_payment'] and not issues
        payment.append({'id':key,'title':title,'recommend_now':yes,'recommend_text':'是' if yes else '否','reason':'技术前置与自述付款条件支持尝试；银行、3DS 与实际扣款仍由服务决定' if yes else '；'.join(issues) or '支付不在本次计划','satisfied':['已自述信用卡/借记卡、账单一致性与 3DS 能力'] if not base else [],'obstacles':issues})
    def group(items,planned):
        yes=planned and all(i['recommend_now'] for i in items)
        return {'recommend_now':yes,'recommend_text':'是' if yes else '否','reason':'所列子情境均支持按真实条件尝试' if yes else next((i['reason'] for i in items if not i['recommend_now']),'不在本次计划'),'sub_scenarios':items,'planned':planned}
    return {'daily_use':daily,'registration':group(registration,dec['plan_registration']),'payment':group(payment,dec['plan_payment'])}
