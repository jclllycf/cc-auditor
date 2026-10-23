"""把同一账本译成普通用户可执行的决定；不采集、不改分、不推断服务端。"""
import copy
from .fixed_risk_v33 import assess as technical_assess,SURFACES

def _path(report,s,a):
    key='web:'+a.get('profile_key','') if s=='web' else s
    return (report.get('path_evidence_v33') or {}).get(key,{})

def route_reason(path):
    unresolved=[x for x in path.get('simulations',[]) if x.get('status')!='simulated']
    if unresolved:
        x=unresolved[0];n=x.get('rule_index');position='第'+str(n+1)+'条' if type(n) is int else '前置';kind=str(x.get('rule_type','')).upper()
        if kind in ('IP-CIDR','IP-CIDR6','IPCIDR','IPCIDR6'):return position+'存在未知目的 IP 条件；离线规则分支尚未收敛，无需先访问 Claude'
        if kind in ('RULE-SET','GEOIP','GEOSITE'):return position+'依赖本地未能核验的规则集；可比较离线命中/未命中分支'
        if kind.startswith('PROCESS'):return position+'存在进程条件；首次使用可按未来执行程序静态推断，无法确认的分支继续保留'
        return position+'代理规则缺少匹配依据，不能当作已确认直连或代理'
    return path.get('reason') or '尚未取得该入口的代理路径依据'

def assess(report):
    view=technical_assess(report)
    for s,a in view['surface_assessments'].items():
        a['technical_reason']=a['reason'];missing=a['critical_missing_keys'];blocking=[r for r in a['ledger'] if r['critical_minimum'] and r['state'] in ('verified_fault','not_configured')]
        if blocking:
            key=blocking[0]['key']
            if key=='tls':a['reason']='已确认该视点存在证书验证问题';a['next_action']='先查明证书异常，再复检；工具不会自动改设置。'
            elif key=='route':a['reason']='当前生效的代理规则明确拒绝该入口目标';a['next_action']='请按真实使用需求核对这条拒绝规则；检测器不会自动修改代理。'
        elif not a['policy']['eligible_for_preflight_advice']:
            # A missing/negative self-declared policy condition takes precedence
            # over advisory route gaps in the *action* decision. Keep the route
            # rows intact as separate technical evidence and next checks.
            a['reason']='；'.join(a['policy']['issues'])
            a['next_action']='请按真实所在地、使用主体和当前官方政策核对资格；系统语言、代理或 IP 不能代替真实资格。'
        elif a['decision_basis']=='selected_environment_unobserved':
            a['reason']=a['technical_reason']
            a['next_action']='先核对计划使用的 WSL、容器或远端环境是否可供只读预检；无需先安装 Claude 或 SDK。'
        elif s=='web' and any(k in missing for k in ('profile','page')):
            a['reason']='日常浏览器档案或必要网页能力还未完成核验';a['next_action']='打开本人的日常档案空白页；下一轮只勾选该档案，无需登录 Claude。'
        elif 'route' in missing:
            a['reason']=route_reason(_path(report,s,a));a['next_action']='先复核实际生效的代理配置与离线分支；可选中立测点需用户授权，无须安装或运行 Claude。'
        elif missing:
            r=next(r for r in a['ledger'] if r['key']==missing[0]);a['reason']=r['problem']
        elif not a['recommend_use']:a['next_action']='按本人真实所在地、主体及用途核对资格；修改语言或时区不能代替真实条件。'
    active=[view['surface_assessments'][s] for s in view['selected_surfaces']]
    view['decision_reason']=next((a['reason'] for a in active if not a['recommend_use']),view['decision_reason']);view['explanation_version']='3.4.preuse.plain.2'
    daily=view['usage_scenarios']['daily_use']
    if daily['planned'] and not daily['recommend_now']:daily['reason']=view['decision_reason']
    return view

def checklist(report,gaps,view):
    out=copy.deepcopy(gaps)
    for g in out:
        parts=g['claim'].split('.');s=parts[0];key=parts[-1]
        if s in SURFACES and key=='route':
            path=_path(report,s,view['surface_assessments'][s]);reasons=list(dict.fromkeys(route_reason({'simulations':[x]}) for x in path.get('simulations',[]) if x.get('status')!='simulated'))
            g['final_reason']='；'.join(reasons) or route_reason(path);g['minimum_action']='只核验本机实际运行内核、已批准的配置与离线规则分支；必要时补做中立测点，不需要 Claude 历史连接。'
        if s in SURFACES and key=='host':
            g['minimum_action']='核对计划使用的 WSL、容器或远端环境；未来安装客户端或创建 SDK 项目不属于此次缺证。'
        if s=='web' and key in ('dns','ipv6','stun'):
            profile=next((p for p in report.get('profiles',[]) if p['profile_key']==view['surface_assessments']['web'].get('profile_key')),{});net=(((profile.get('dynamic_result') or {}).get('data') or {}).get('independent_network') or {})
            reason=net.get(key,{}).get('reason')
            if key=='dns' and reason=='websocket_unavailable':g['final_reason']='浏览器连接 DNS 测试接收端未成功，不能据此判断浏览器 DNS 或泄漏。'
            elif key=='dns' and reason=='receiver_open_no_authoritative_event':g['final_reason']='浏览器已连接 DNS 接收端，但没有收到权威查询回执；系统 DNS 结果不能替代它。'
            g['minimum_action']='保持同一个日常浏览器档案；先完成代理规则问题，再由工具针对失败测点复检。无需手动运行网络命令；失败不等于已确认泄漏。'
    return out

def actions(report,view,gaps):
    active=[view['surface_assessments'][s] for s in view['selected_surfaces']];out=[]
    if any('route' in a['critical_missing_keys'] for a in active):out.append('优先核对当前代理规则分支与应用接管方式；不需要事先打开 Claude。')
    web=view['surface_assessments']['web']
    if any(k in web['critical_missing_keys'] for k in ('dns','ipv6','profile','page')):out.append('先保留日常浏览器与网络原设置；代理路径明确后，再由工具补测浏览器 DNS / IPv6。')
    future=[s for s in ('desktop','cli','api') if s in view['selected_surfaces'] and view['surface_assessments'][s]['installation_state'] in ('not_installed','unknown')]
    if future:out.append('当前环境评估与未来安装分开；符合真实资格后，再按需要准备 '+ '、'.join(s.upper() for s in future)+'。')
    if any(not a['policy']['eligible_for_preflight_advice'] for a in active):out.append('补齐必要的真实资格声明；已知不符合的条件不能靠更改电脑设置解决。')
    if not out:out.append('当前所选入口符合本次使用前准备条件；未来安装、登录及服务端结果仍需自行确认。')
    out+=['注册验证和银行交易由真实服务确认；检测器不会登录或扣款。','保留本轮报告，网络、代理或日常档案改变后再复检。']
    return out[:3]
