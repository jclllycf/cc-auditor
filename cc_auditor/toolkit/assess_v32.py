"""四端独立证据账本；区间是工程关注预算，不是概率或统计置信区间。"""
from __future__ import annotations
import math

VERSION='3.2.surface.1'
SURFACES={'desktop':'桌面端 Desktop','web':'网页端 Web','cli':'命令行 CLI','api':'程序接口 API'}
LABELS={'green':'低关注','amber':'中等关注','red':'高关注'}
HOSTS={'unknown':'宿主未指定','windows':'本机 Windows 终端','python':'本机 Python 应用（具体应用未绑定）','node':'本机 Node 应用（具体应用未绑定）','wsl':'WSL','container':'容器','remote':'远程服务器'}
POLICY_DATE='2026-10-18'
POLICY_SOURCES={
 'consumer':'https://support.claude.com/en/articles/8461763-where-can-i-access-claude',
 'api':'https://platform.claude.com/docs/en/api/supported-regions',
 'billing':'https://support.claude.com/en/articles/9402418-why-was-my-card-declined',
 'subscription':'https://support.claude.com/en/articles/8325618-paid-plan-billing-faqs',
 'credits':'https://support.claude.com/en/articles/8977456-how-do-i-pay-for-my-claude-api-usage'}
# 仅明确核对过的常见声明项；其余返回需人工核对，不把未纳入快照误判为不支持。
KNOWN_SUPPORTED={'US','CA','GB','JP','SG','AU','NZ','DE','FR','KR','TW','IN','MY','TH','VN','PH','ID','AE','NL','CH','SE','IE','IT','ES','BR','MX'}
KNOWN_NOT_LISTED={'CN','HK','MO','RU','IR','KP','SY','CU','BY'}


def declarations(raw=None):
    """只保留枚举/地区代码，调用者不能夹带凭据或任意私人文字。"""
    raw=raw or {};out={}
    surfaces=raw.get('surfaces',['desktop','web'])
    out['surfaces']=[s for s in SURFACES if s in surfaces] if isinstance(surfaces,list) else ['desktop','web']
    if not out['surfaces']:out['surfaces']=['desktop','web']
    for key,choices in {'cli_host':('unknown','windows','wsl','container','remote'),
                         'api_host':('unknown','python','node','wsl','container','remote'),
                         'entity':('unknown','individual','organization'),
                         'payment_method':('unknown','credit','debit','paypal','other'),
                         'billing_matches_bank':('unknown','yes','no'),
                         'three_ds':('unknown','yes','no')}.items():
        out[key]=raw.get(key) if raw.get(key) in choices else 'unknown'
    import re
    for key in ('physical_country','issuer_country','billing_country'):
        val=raw.get(key,'');out[key]=val.upper() if isinstance(val,str) and re.fullmatch('[A-Za-z]{2}',val) else ''
    primary=raw.get('primary_profile','');out['primary_profile']=primary if isinstance(primary,str) and re.fullmatch('[a-z0-9-]{1,70}',primary) else ''
    out['provenance']='native_user_declaration' if raw else 'not_provided'
    return out


def _refs(checks,ids):return list(dict.fromkeys(checks[k]['evidence_id'] for k in ids if k in checks))


def _model(surface,rows):
    assert sum(r['weight'] for r in rows)==100
    issues=set();lower=0;unknown=0;covered=0;faults=[];good=[];gaps=[]
    for row in rows:
        row['confirmed_contribution']=0
        if row['state']=='fault':
            if row['issue_id'] not in issues:
                issues.add(row['issue_id']);row['confirmed_contribution']=row['weight'];lower+=row['weight'];faults.append(row)
        else:unknown+=row['weight']*(1-row['support'])
        row['unresolved_contribution']=round(row['weight']*(1-row['support']),2) if row['state']!='fault' else 0
        covered+=row['weight']*row['support']
        if row['support']==1 and row['state']!='fault':good.append(row)
        if row['support']<1 and row['state']!='fault':gaps.append(row)
    upper=min(100,math.ceil(lower+unknown));lower=math.floor(lower)
    critical=[r for r in gaps if r['critical']]
    high=any(r['confirmed_contribution']>=20 or r.get('serious_fault') for r in faults) or lower>=35
    level='red' if high else 'amber' if faults or critical or upper>20 else 'green'
    confidence='高' if not critical and covered>=85 else '中' if covered>=50 else '低'
    risk=gaps+faults
    priorities=sorted(risk,key=lambda r:(r['state']=='fault',r['critical'],r['unresolved_contribution']+r['confirmed_contribution']),reverse=True)
    return {'surface':surface,'model_version':VERSION,'engineering_risk_level':LABELS[level],'risk_level':level,
        'risk_index_lower':lower,'risk_index_upper':upper,'risk_index':lower if lower==upper and not critical else [lower,upper],
        'confidence':confidence,'coverage':round(covered,1),'coverage_meaning':'本入口证据权重覆盖；与全报告事实项覆盖率不同',
        'measured_health':'未确认本入口技术故障' if not faults else '发现 '+str(len(faults))+' 类确认故障',
        'confirmed_faults':[r['title'] for r in faults], 'critical_unknowns':[r['title'] for r in critical],
        'critical_missing':[r['title'] for r in critical], 'top_positive_factors':[r['positive'] for r in good],
        'top_positive_evidence':[{'text':r['positive'],'evidence_ids':r['evidence_ids']} for r in good],
        'top_risks':[r['detail'] for r in priorities],
        'top_risk_evidence':[{'text':r['detail'],'confirmed_fault':r['state']=='fault','evidence_ids':r['evidence_ids']} for r in priorities],
        'next_action':priorities[0]['action'] if priorities else '保留结果；环境改变后再检查，使用资格另行核对。',
        'evidence_ids':list(dict.fromkeys(e for r in rows for e in r['evidence_ids'])), 'ledger':rows,
        'index_meaning':'0–100 工程关注预算：下界=确认故障权重；上界=下界+未确认权重。不是概率，未经账户结果校准。'}


def assess_surface(report,surface,profile=None):
    by={c['id']:c for c in report.get('checks',[])};rows=[];dec=declarations(report.get('user_declarations'))
    routes=report.get('target_routes') or {};configs=routes.get('configs',[])
    def row(key,title,weight,ids=(),support=None,critical=False,positive='',detail='',action='',fault_allowed=True):
        cs=[by[k] for k in ids if k in by];fault=next((c for c in cs if c['state']=='fault'),None) if fault_allowed else None
        if support is None:support=1 if cs and all(c['state'] in ('passed','reference') for c in cs) else 0
        rows.append({'key':key,'title':title,'weight':weight,'state':'fault' if fault else 'observed' if support==1 else 'partial' if support else 'unknown',
            'support':1 if fault else support,'critical':critical,'issue_id':fault.get('issue_id',key) if fault else key,
            'serious_fault':bool(fault and (fault.get('points',0)>=30 or fault.get('severity') in ('high','critical'))),
            'evidence_ids':_refs(by,ids),'positive':positive or title+'已核对','detail':detail or title+'仍有关键证据缺口',
            'action':action or '按技术版所列证据范围补检；不改变身份、地区或原有设置。'})
    host=dec.get(surface+'_host','unknown');remote=host in ('remote','wsl','container')
    bound=any(c.get('activation')=='controller_rules_observed' for c in configs)
    relevant=[]
    for cfg in configs:
        if cfg.get('activation')!='controller_rules_observed':continue
        for r in cfg.get('runtime_rules',[]):
            t=r.get('target',{});s=t.get('surface','')
            if s==surface or (surface=='desktop' and s.startswith('desktop')) or (surface=='web' and s.startswith('web')):
                if not profile or t.get('process') in ({'chrome':'chrome.exe','edge':'msedge.exe','firefox':'firefox.exe'}.get(profile.get('browser_id')),None):relevant.append(r)
    target=by.get('target_egress_'+surface,{})
    row('target','Claude 目标最终出口',30 if surface!='api' else 35,['target_egress_'+surface],support=1 if target.get('state')=='passed' and not remote else 0,critical=True,
        positive='该入口目标出口已有独立证据',detail='该入口最后公网出口未证实；普通查 IP 不能替代',action='关联该入口已运行客户端的被动连接与最终出口证据；不为补分主动访问 Claude。',fault_allowed=not remote)
    rule_support=1 if relevant and all(r.get('status')=='simulated' and r.get('chain_state')=='configured' for r in relevant) else .25 if bound else 0
    # 仅提升浏览器族的部分支持，快照不能独立确定 Profile，也不证明最后出口。
    process={'chrome':'chrome.exe','edge':'msedge.exe','firefox':'firefox.exe'}.get((profile or {}).get('browser_id'))
    browser_snapshot=surface=='web' and process and any(c.get('process')==process and c.get('rule_type') and c.get('host') in ('*.claude.ai','claude.ai','api.anthropic.com') for c in routes.get('existing_connections',[]))
    if browser_snapshot:rule_support=max(rule_support,.5)
    if remote or surface=='api' and host=='unknown':rule_support=0
    row('rules','运行规则与应用绑定',20 if surface=='desktop' else 15,['proxy_rules','existing_client'],support=rule_support,critical=True,positive='本入口运行规则和链已核对',detail='已有该浏览器族真实目标快照；未独立绑定 Profile/最终出口' if browser_snapshot else '内核已绑定，但目标规则仍受 IP/进程上下文缺口限制' if bound and not remote else '目标宿主或实际应用规则未绑定',action='补充实际进程/目标规则上下文，保留不能确定的早期匹配规则。',fault_allowed=False)
    if surface=='desktop':
        row('foundation','Windows 与安装空间',20,['os_desktop_compatible','disk_sufficient'],positive='Windows 与可用空间满足本工具基础门槛',detail='桌面端 Windows 或空间条件需要处理')
        row('hosts','本机 hosts 与根证书线索',10,['hosts_block','root_store'],positive='hosts 未见目标阻断，根证书参考已记录',detail='本机 hosts/根证书检查未齐备')
        row('dns','系统权威 DNS 参考',10,['dns_receiver'],support=1 if any(x.get('kind')=='system_authoritative_dns' and x.get('status')=='observed' for x in report.get('independent_network_events',[])) else 0,positive='取得系统权威 DNS 接收端记录',detail='缺系统 DNS 实测；不是已确认泄漏',fault_allowed=False)
        row('dual_stack','桌面应用 IPv6/TLS 实际路径',10,support=0,critical=True,detail='独立探针不能证明 Desktop 的 IPv6/TLS 路径',action='在一次授权内关联桌面进程的既有连接；无法归因时保留缺口。')
    elif surface=='web':
        p=profile or {};key=p.get('profile_key','');data=(p.get('dynamic_result') or {}).get('data',{});net=data.get('independent_network',{})
        feature_ids=[key+'_'+k for k in ('cookies','websocket','webassembly','workers','canvas_2d')]
        row('page','真实档案页面能力',15,feature_ids,support=1 if p.get('dynamic_profile_checked') and all(by.get(i,{}).get('state')=='passed' for i in feature_ids) else 0,positive=p.get('browser_name','浏览器')+' '+p.get('profile_alias','')+' 已完成工具页能力实测',detail='所选档案尚未取得完整页面能力结果',action='手动打开此日常档案，再通过一次授权运行本工具页面。')
        row('profile','档案归属与静态设置',10,[key+'_static',key+'_identity'],support=1 if p.get('actual_profile_verified') and p.get('static_profile_checked') else .5 if p.get('static_profile_checked') and p.get('dynamic_profile_checked') else .25 if p.get('static_profile_checked') else 0,critical=True,detail='档案由用户确认并定向打开，仍缺独立身份核验',action='核对本轮已选档案及浏览器 PID；不能将其他档案的结果合并为通过。',fault_allowed=False)
        for kind,title,weight in (('dns','浏览器权威 DNS',8),('ipv6','浏览器 IPv6',8),('stun','浏览器 UDP/STUN',7),('tls','浏览器 TLS/HTTP',7)):
            row(kind,title,weight,[key+'_dynamic'],support=1 if net.get(kind,{}).get('status')=='observed' else 0,positive=title+'取得独立接收端结果',detail=title+'未取得有效结果；未据此确认泄漏',action='在该日常档案重新授权补测此独立接收端，核对失败原因与预期路径。',fault_allowed=False)
    elif surface=='cli':
        foundation_ids=['os_cli_compatible','cli_ram_sufficient','disk_sufficient']
        row('foundation','本机 CLI 安装前置',15,foundation_ids,support=None if host=='windows' else .25 if not remote and all(by.get(k,{}).get('state')=='passed' for k in foundation_ids) else 0,positive='本机 Windows、内存和空间满足 CLI 基础门槛',detail='宿主未指定；本机前置不证明 WSL/远端条件',fault_allowed=host=='windows')
        cli=report.get('host_context',{}).get('cli',{})
        row('shell','终端与 CLI 存在性',10,['cli_host_context'],support=.5 if host=='windows' and cli.get('shell_available') else 0,detail='需确认所用终端及其环境；未安装 CLI 本身不扣分',action='在授权卡指定本机/WSL/容器/远程；本工具不会运行 Claude 或读取凭据。',fault_allowed=False)
        row('tls','终端环境证书验证',10,['tls_bypass'],support=.25 if host=='windows' else 0,detail='检测器环境不等于目标终端环境，尚未独立绑定',fault_allowed=False)
        row('dns','终端 DNS/双栈路径',20,['dns_receiver','ipv6_bypass'],support=.25 if host=='windows' and by.get('dns_receiver',{}).get('state')=='reference' else 0,critical=True,detail='系统 DNS 参考不等于该终端所有网络路线',action='在实际执行宿主补齐 DNS/IPv6 证据，远端需在远端执行预检。',fault_allowed=False)
    else:
        ctx=report.get('host_context',{}).get('api',{})
        row('host','API 应用和运行时',25,['api_host_context'],support=.25 if host in ('python','node') and ctx.get(host+'_candidate_found') else 0,critical=True,detail=HOSTS.get(host,HOSTS['unknown'])+'；未绑定具体应用',action='明确 API 的实际应用、运行时与宿主；远端需要在远端单独授权采集。',fault_allowed=False)
        row('tls','API 应用代理/CA 环境',15,['api_override','tls_bypass','root_store'],support=0,critical=True,detail='未读取目标 API 进程环境/密钥，不能继承检测器的 TLS 结论',action='在实际应用宿主核对非秘密代理和 CA 配置；不读取 API key。',fault_allowed=False)
        row('dns','API 应用 DNS/双栈',10,['dns_receiver','ipv6_bypass'],support=.25 if host in ('python','node') and by.get('dns_receiver',{}).get('state')=='reference' else 0,detail='本机探针网络不能代替 API 应用路径',fault_allowed=False)
    result=_model(surface,rows)
    result['execution_boundary']=HOSTS.get(host) if surface in ('cli','api') else '本机 Windows' if surface=='desktop' else '该日常浏览器档案'
    result['primary_gap']=result['confirmed_faults'][0] if result['confirmed_faults'] else ('实际终端宿主未指定' if surface=='cli' and host=='unknown' else '实际 API 应用宿主未指定' if surface=='api' and host=='unknown' else '远端/容器执行位置未覆盖' if remote else '浏览器 DNS / IPv6 / TLS 结果不全' if surface=='web' and any(r['key'] in ('dns','ipv6','tls') and r['support']==0 for r in rows) else result['critical_missing'][0] if result['critical_missing'] else '关键技术证据已齐备')
    if surface in ('cli','api') and (host=='unknown' or remote):result['next_action']='先在授权卡指定实际执行位置；远端、WSL、容器需在对应宿主独立授权采集。'
    return result


def assess(report):
    dec=declarations(report.get('user_declarations'));surfaces={s:assess_surface(report,s) for s in ('desktop','cli','api')}
    ps=[]
    for p in report.get('profiles',[]):
        m=assess_surface(report,'web',p);m.update(profile_key=p['profile_key'],browser_name=p['browser_name'],profile_alias=p['profile_alias'],dynamic_selected=p['profile_key'] in report.get('approval',{}).get('profiles',[]));ps.append(m)
    selected=[p for p in ps if p['profile_key']==dec['primary_profile']]
    policy='用户指定主要档案'
    if not selected:
        selected=[p for p in ps if p['dynamic_selected']] or ps;policy='未指定主档案，采用本轮所选档案中最需关注者' if selected else '未发现可评估的日常档案'
    web=max(selected,key=lambda p:(p['risk_level']=='red',p['risk_index_upper'])) if selected else assess_surface(report,'web')
    surfaces['web']={**web,'profiles':ps,'aggregation':policy,'selected_profile_keys':[p['profile_key'] for p in selected]}
    active=[surfaces[s] for s in dec['surfaces']]
    overall='red' if any(s['risk_level']=='red' for s in active) else 'amber' if any(s['risk_level']=='amber' for s in active) else 'green'
    scenarios=usage_scenarios(surfaces,dec)
    return {'model_version':VERSION,'surface_assessments':{s:surfaces[s] for s in SURFACES},'usage_scenarios':scenarios,
        'overall_action_level':overall,'selected_surfaces':dec['surfaces'],'selection_source':dec['provenance'],
        'headline':'先处理所选入口的确认故障' if overall=='red' else ('已测基础可用，先补齐所选入口的网络证据' if any(a['top_positive_factors'] for a in active) else '本轮证据有限，先核对所选入口') if overall=='amber' else '所选入口主要技术条件已核对',
        'disclaimer':'工程区间反映确认故障和证据缺口，不是封禁概率，也不保证注册、支付或账号可用。',
        'policy_snapshot':{'checked_at':POLICY_DATE,'sources':POLICY_SOURCES,'limitation':'地区代码快照仅覆盖部分已核对地区；未来生效政策不提前适用；主体/银行/服务端决定需实际核对。'}}


def _region(code):
    return '未声明' if not code else '列入已核对支持地区' if code in KNOWN_SUPPORTED else '未列入已核对官方支持名单' if code in KNOWN_NOT_LISTED else '未纳入本地政策快照，需人工核对'


def usage_scenarios(surfaces,dec):
    active=[surfaces[s] for s in dec['surfaces']];faults=[x for s in active for x in s['confirmed_faults']]
    positives=list(dict.fromkeys(x for s in active for x in s['top_positive_factors']))
    missing=list(dict.fromkeys(x for s in active for x in s['critical_missing']))
    daily={'feasibility_level':'有具体障碍需修复' if faults else '必要证据尚缺' if missing else '可尝试',
        'summary':'所选入口未确认技术故障；网络关键缺口需补测' if not faults and missing else '先处理所选入口的具体技术故障' if faults else '技术上可尝试，资格与实际服务另行确认',
        'positive_factors':positives,'confirmed_blockers':faults,'unknowns':missing+['真实使用资格、登录和服务端决定'],
        'next_action':'优先补测 '+ '、'.join(dec['surfaces'])+' 的目标路径；未选入口不阻止当前选择。',
        'evidence_ids':list(dict.fromkeys(e for s in active for e in s['evidence_ids']))}
    reg=[]
    for key,title in (('consumer','Claude.ai 消费者注册'),('api','Console/API 注册')):
        country=dec['physical_country'];known=country in KNOWN_SUPPORTED
        reg.append({'id':key,'title':title,'declared_physical_country':country or None,'region_lookup':_region(country),
            'feasibility_level':'受真实资格条件约束','positive_factors':['用户声明地区列入本地已核对名单'] if known else [],
            'confirmed_blockers':[],'declared_conditions_to_resolve':['声明地区未列入已核对官方名单'] if country in KNOWN_NOT_LISTED else [],
            'unknowns':['真实所在地未声明'] if not country else ['声明未经独立核验；主体资格、账号验证与当期政策仍需核对'],
            'next_action':'按本人真实所在地与主体条件核对官方当前规则；不使用设备语言、Chrome 内部地区或出口代替。','source':POLICY_SOURCES[key]})
    payment=[]
    method=dec['payment_method'];issuer=dec['issuer_country'];billing=dec['billing_country']
    declared_problems=[]
    if method in ('paypal','other'):declared_problems.append('所述方式不属于网页自助信用卡/借记卡范围')
    if issuer and billing and issuer!=billing:declared_problems.append('自述发卡地区与账单地区不一致，需核对')
    if dec['billing_matches_bank']=='no':declared_problems.append('自述账单资料与银行记录不一致')
    if dec['three_ds']=='no':declared_problems.append('自述不能完成 3DS；仅当交易要求验证时可能形成障碍')
    if issuer in KNOWN_NOT_LISTED or billing in KNOWN_NOT_LISTED:declared_problems.append('声明地区未列入已核对支持名单，账单适用性需复核')
    for key,title in (('subscription','Claude 网页订阅'),('credits','Console/API 预付计费')):
        payment.append({'id':key,'title':title,'feasibility_level':'受真实资格条件约束',
            'positive_factors':['自述使用信用卡/借记卡（未核验）'] if method in ('credit','debit') else [],
            'confirmed_blockers':[],'declared_conditions_to_resolve':declared_problems,
            'unknowns':(['付款类别未声明'] if method=='unknown' else [])+(['发卡/账单地区未完整声明'] if not issuer or not billing else [])+['当前账单资格、银行授权、可能的 3DS；未进入结算或扣款']+(['Console 计费权限、余额、预付/合同方式'] if key=='credits' else []),
            'next_action':'仅核对真实付款资料、发卡行及官方当期账单规则；不从单个 TLS 探针保证支付成功。','source':POLICY_SOURCES[key]})
    return {'daily_use':daily,'registration':{'feasibility_level':'受真实资格条件约束','summary':'技术准备部分完成；真实注册资格仍需核对','sub_scenarios':reg,'next_action':'自愿声明真实所在地与主体类别，再按入口核对当期规则。'},
        'payment':{'feasibility_level':'受真实资格条件约束','summary':'支付条件需核对；没有进行结算或扣款','sub_scenarios':payment,'next_action':'核对真实付款类别、发卡地区、账单一致性及银行验证。'}}
