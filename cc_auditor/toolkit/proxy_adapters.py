"""保守的本地配置模拟。绝不解析目标域名 DNS，不执行脚本或下载规则集。"""
from __future__ import annotations
import json
import re
from pathlib import Path

def read_config(path):
    from ..storage import no_reparse
    p=Path(path);no_reparse(p)
    if not p.is_file() or p.stat().st_size>2*1024*1024:raise ValueError('configuration_size_or_type')
    text=p.read_text(encoding='utf-8-sig')
    if p.suffix.lower()=='.json':return json.loads(text),False
    # Bundled fixed mature parser; never installs anything or evaluates YAML constructors.
    try:
        from .safe_yaml_v3 import load
        return load(text),False
    except ImportError:pass
    # Deliberately restricted fallback: simple root scalars and scalar rule lists only.
    out={};section=None;partial=False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        if re.match(r'^[A-Za-z][\w-]*:',line):
            k,v=line.split(':',1);section=k
            v=v.strip()
            if v and not v.startswith('#'):out[k]=v.strip('"\'')
            elif k=='rules':out[k]=[]
            else:partial=True
        elif section=='rules' and re.match(r'^\s*-\s+[^\[{&*!]',line):
            value=re.sub(r'\s+#.*$','',line.lstrip()[1:].strip()).strip('"\'')
            out['rules'].append(value)
        elif section=='rules':partial=True;out.setdefault('rules',[]).append('UNSUPPORTED,unknown,UNKNOWN')
        else:partial=True
    out['_restricted_yaml']=True
    return out,partial

def family(config):
    if 'routing' in config:return 'xray'
    if 'route' in config:return 'sing-box'
    if 'rules' in config or 'proxy-groups' in config or 'mixed-port' in config:return 'mihomo'
    if 'server' in config or 'configs' in config:return 'shadowsocks'
    return 'unknown'

def _values(value):return value if isinstance(value,list) else [value]
def _or(states):return True if True in states else None if None in states else False
def _and(states):return False if False in states else None if None in states else True
def _suffix(host,value):return host==value.lstrip('.').lower() or host.endswith('.'+value.lstrip('.').lower())

def _domain(values,host,xray=False,kind='domain'):
    results=[]
    for raw in _values(values):
        if not isinstance(raw,str):results.append(None);continue
        if xray:
            if raw.startswith('full:'):results.append(host==raw[5:].lower())
            elif raw.startswith('domain:'):results.append(_suffix(host,raw[7:]))
            elif raw.startswith(('geosite:','ext:','regexp:')):results.append(None)
            else:results.append(raw.lower() in host) # Xray unprefixed strings use substring semantics.
        elif kind=='domain':results.append(host==raw.lower())
        elif kind=='domain_suffix':results.append(_suffix(host,raw))
        elif kind=='domain_keyword':results.append(raw.lower() in host)
        else:results.append(None)
    return _or(results)

def _json_rule(rule,target,core):
    if not isinstance(rule,dict):return None
    if rule.get('type')=='logical':
        states=[_json_rule(r,target,core) for r in rule.get('rules',[])]
        value=_and(states) if rule.get('mode')=='and' else _or(states) if rule.get('mode')=='or' else None
        return not value if rule.get('invert') and value is not None else value
    states=[]
    ignored={'type','outbound','outboundTag','balancerTag','ruleTag','action'}
    for k,v in rule.items():
        if k in ignored:continue
        if k in ('domain','domain_suffix','domain_keyword'):states.append(_domain(v,target['host'],core=='xray',k))
        elif k in ('process_name','process'):
            states.append(target['process'].casefold() in [str(x).casefold() for x in _values(v)] if target.get('process') else None)
        elif k in ('process_path','processPath'):states.append(target.get('process_path','').casefold() in [str(x).casefold() for x in _values(v)] if target.get('process_path') else None)
        elif k=='network':states.append(target['network'] in _values(v) if isinstance(v,list) else target['network'] in str(v).split(','))
        elif k in ('port',):
            ports=[str(x) for x in _values(v)];states.append(str(target['port']) in ports if all(x.isdigit() for x in ports) else None)
        elif k=='invert':continue
        else:states.append(None) # IP, remote rule sets, inbound/source context, regex and unsupported selectors.
    value=_and(states)
    return not value if rule.get('invert') and value is not None else value

def _clash_rule(rule,target):
    parts=[x.strip() for x in str(rule).split(',')];kind=parts[0].upper()
    if kind in ('MATCH','FINAL'):return True,parts[1] if len(parts)>1 else None,kind
    if len(parts)<3:return None,None,'invalid'
    value=parts[1];policy=parts[2]
    if kind in ('IP-CIDR','IP-CIDR6','IPCIDR','IPCIDR6'):
        import ipaddress
        try:
            address=ipaddress.ip_address(target.get('destination_ip',''));network=ipaddress.ip_network(value,strict=False)
            fake=address in ipaddress.ip_network('198.18.0.0/15') if address.version==4 else any(address in ipaddress.ip_network(n) for n in ('fdfe:dcba:9876::/48','2001:2::/48'))
            return (None if fake else address.version==network.version and address in network),policy,kind
        except ValueError:return None,policy,kind
    match={'DOMAIN':lambda:target['host']==value.lower(),'DOMAIN-SUFFIX':lambda:_suffix(target['host'],value),
        'DOMAIN-KEYWORD':lambda:value.lower() in target['host'],
        'PROCESS-NAME':lambda:target['process'].casefold()==value.casefold() if target.get('process') else None,
        'PROCESS-PATH':lambda:target['process_path'].casefold()==value.casefold() if target.get('process_path') else None,
        'DST-PORT':lambda:str(target['port'])==value,'NETWORK':lambda:target['network'].casefold()==value.casefold()}.get(kind)
    return match() if match else None,policy,kind

def chain(config,core,tag,alias):
    """Only configured hops; a select/url-test group is unknown without runtime selection."""
    nodes={}
    for node in config.get('outbounds',[]) if core!='mihomo' else config.get('proxies',[]):
        if isinstance(node,dict):nodes[node.get('tag',node.get('name'))]=node
    groups={x.get('name'):x for x in config.get('proxy-groups',[]) if isinstance(x,dict)}
    seen=set();hops=[]
    while tag and len(hops)<64:
        if tag in seen:return hops,'cycle'
        seen.add(tag)
        upper=str(tag).upper()
        # Only Mihomo reserves these policy names. Xray/sing-box allow user
        # outbound tags named "DIRECT" or "direct"; do not bypass their hops.
        # sing-box reject is a synthetic action, never a configured node.
        if (core=='mihomo' and upper in ('DIRECT','REJECT','REJECT-DROP','PASS','PASS-RULE')) or (core=='sing-box' and upper=='REJECT' and tag not in nodes):
            hops.append('REJECT' if upper=='BLOCK' else upper);return hops,'configured'
        hops.append(alias(str(tag)))
        if tag in groups:
            if groups[tag].get('_selected'):tag=groups[tag]['_selected'];continue
            return hops,'runtime_selection_unknown'
        node=nodes.get(tag)
        if not node:return hops,'unresolved_tag'
        kind=node.get('type',node.get('protocol','unknown'))
        if core=='xray' and kind=='blackhole' or core=='sing-box' and kind=='block':
            hops.append('REJECT');return hops,'configured'
        if kind in ('selector','urltest','url-test','load-balance','rematch','fallback'):
            return hops,'runtime_selection_unknown'
        nxt=node.get('detour') or node.get('dialer-proxy') or (node.get('proxySettings') or {}).get('tag')
        if not nxt:return hops,'runtime_upstream_not_observed' if config.get('_runtime_chain_fields_incomplete') else 'configured'
        tag=nxt
    return hops,'hop_budget_exhausted' if tag else 'unknown'

def _policy(rule,core):
    """Return only a terminal forwarding choice; unknown actions must fail closed."""
    if not isinstance(rule,dict):return None
    if core=='xray':
        # balancerTag is resolved by runtime strategy, never by the static list.
        return None if rule.get('balancerTag') else rule.get('outboundTag')
    action=rule.get('action','route')
    if action in ('reject','reject-dns'):return 'REJECT'
    if action=='route':return rule.get('outbound')
    # DNS actions, sniff and resolve have version-specific continuation semantics.
    return None

def simulate(config,target,alias=lambda x:x):
    core=family(config);rows=config.get('rules',[]) if core=='mihomo' else (config.get('routing') or {}).get('rules',[]) if core=='xray' else (config.get('route') or {}).get('rules',[])
    base={'source':'configuration_simulation','kernel':core,'target':{k:target[k] for k in ('surface','host','process','port','network')},
          'status':'unverified','rule_index':None,'rule_type':None,'configured_chain':[],'chain_state':'unknown','final_public_egress':None,
          'actual_client_connection_verified':False,'reason':'没有足够规则证据；未联系目标。'}
    if core not in ('mihomo','xray','sing-box'):return base
    if core=='mihomo' and str(config.get('mode','rule')).lower()!='rule':
        mode=str(config.get('mode')).lower()
        if mode in ('direct','global'):
            hops,state=chain(config,core,'DIRECT' if mode=='direct' else 'GLOBAL',alias)
            base.update(status='simulated',rule_type='kernel_'+mode+'_mode',configured_chain=hops,chain_state=state,reason='按已给出的内核模式推断；仍非客户端真实连接或最终出口。')
        else:base['reason']='内核模式不支持；不套用静态 rules。'
        return base
    for idx,row in enumerate(rows):
        if core=='mihomo':matched,policy,typ=_clash_rule(row,target)
        else:
            matched=_json_rule(row,target,core);policy=_policy(row,core);typ='field' if core=='xray' else row.get('action','route') if isinstance(row,dict) else 'unknown'
        if matched is False:continue
        if matched is None:base.update(rule_index=idx,rule_type=typ,reason='更高优先级规则依赖缺失的 IP/进程/规则集/动态状态；不能跳过后宣称兜底命中。');return base
        if not policy:base.update(rule_index=idx,rule_type=typ,reason='规则动作/负载均衡不是已确定出站，需版本或运行状态。');return base
        hops,state=chain(config,core,policy,alias)
        if core=='mihomo' and hops and hops[-1] in ('PASS','PASS-RULE'):continue
        base.update(status='simulated',rule_index=idx,rule_type=typ,configured_chain=hops,chain_state=state,
                    reason='仅配置推断，不等于客户端已走该链或最终公网出口。')
        return base
    policy=((config.get('outbounds') or [{}])[0].get('tag') if core=='xray' else (config.get('route') or {}).get('final'))
    if policy:
        hops,state=chain(config,core,policy,alias);base.update(status='simulated',rule_type='default_outbound',configured_chain=hops,chain_state=state)
    return base

def simulate_symbolic(config,target,alias=lambda x:x,max_branches=64):
    """Enumerate both outcomes of unknown selectors, preserving first-match order.

    No DNS lookup, rule download or Anthropic connection is performed. A
    single route is inferred only when *every* feasible branch selects the
    same configured chain. The branch cap fails closed to 'unverified'.
    """
    core=family(config)
    baseline=simulate(config,target,alias)
    if core not in ('mihomo','xray','sing-box'):
        return {**baseline,'branch_count':0,'symbolic_consistent':False}
    if core=='mihomo' and str(config.get('mode','rule')).lower()!='rule':
        return {**baseline,'branch_count':1,'symbolic_consistent':baseline.get('chain_state')=='configured'}
    rules=config.get('rules',[]) if core=='mihomo' else (config.get('routing') or {}).get('rules',[]) if core=='xray' else (config.get('route') or {}).get('rules',[])
    default=((config.get('outbounds') or [{}])[0].get('tag') if core=='xray' else (config.get('route') or {}).get('final'))
    # First-match routing has at most one continuing miss branch at a time.
    # Iteration is bounded even for hostile files with thousands of unknown rules.
    endings=[];unknown_types=set();continuing=True;unknown_seen=False
    budget=min(len(rules),4096)
    for idx,row in enumerate(rules[:budget]):
        if not continuing:break
        if core=='mihomo':match,policy,kind=_clash_rule(row,target)
        else:
            match=_json_rule(row,target,core);policy=_policy(row,core)
            kind='field' if core=='xray' else row.get('action','route') if isinstance(row,dict) else 'unknown'
        if match is False:continue
        if policy:
            hops,state=chain(config,core,policy,alias)
            # PASS resumes matching after this rule. A matched PASS branch
            # and a missed branch both continue, so neither is an ending.
            if core=='mihomo' and hops and hops[-1] in ('PASS','PASS-RULE'):
                if match is None:unknown_types.add(str(kind));unknown_seen=True
                continue
            endings.append((tuple(hops) if state in ('configured','runtime_upstream_not_observed') else None,state))
        else:endings.append((None,'unresolved_action'))
        if match is True:continuing=False
        else:unknown_types.add(str(kind));unknown_seen=True
        if len(endings)>max_branches:break
    exhausted=len(endings)>max_branches or continuing and len(rules)>budget
    if continuing and not exhausted:
        if default:
            hops,state=chain(config,core,default,alias)
            endings.append((tuple(hops) if state in ('configured','runtime_upstream_not_observed') else None,state))
        else:endings.append((None,'missing_default'))
    if exhausted or not endings or len(endings)>max_branches:
        return {**baseline,'reason':'符号规则分支超过安全上限或不完整；无法确认目标选路','branch_count':len(endings),'symbolic_consistent':False,'branch_budget_exhausted':True}
    valid=[e[0] for e in endings];consistent=all(c is not None and c==valid[0] for c in valid)
    resolved=consistent and all(state=='configured' for _,state in endings)
    result={**baseline,'symbolic_consistent':consistent,'branch_count':len(endings),
            'unknown_rule_types':sorted(unknown_types),'branch_chains':[list(c) if c else None for c in dict.fromkeys(valid)][:12],
            'outbound_config_resolved':resolved,'rule_branches_converge':consistent,
            'dynamic_selection_unresolved':any(s=='runtime_selection_unknown' for _,s in endings),
            'upstream_config_complete':resolved,'application_entry_verified':False,'neutral_probe_same_path_verified':False}
    if consistent:
        result.update(status='simulated',configured_chain=list(valid[0]),chain_state='configured' if resolved else 'runtime_upstream_not_observed',
                      rule_type='symbolic_all_branches_agree' if unknown_seen else baseline.get('rule_type'),
                      reason='全部可能规则分支选择同一配置链；尚未确认入口接管、动态上游可用性或公网出口')
    else:result.update(status='unverified',reason='前置未知规则、动态选择或缺少默认出口导致潜在不同路径；未推断实际出口')
    return result

def capabilities(core):
    return {'kernel':core,'static_rules':core in ('mihomo','xray','sing-box'),
        'read_only_connections_api':core=='mihomo','optional_clash_api_if_configured':core=='sing-box',
        'runtime_rule_hit':'controller_if_supported' if core=='mihomo' else 'not_assumed',
        'limitations':'功能依实际版本和配置；不假定 GUI 名就是内核，不执行候选程序。'}
