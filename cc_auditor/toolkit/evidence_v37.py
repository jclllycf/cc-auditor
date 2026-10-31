"""Offline, scoped evidence interpretation. No collectors, system writes or scores.

The legacy preflight/3 envelope and health/region scoring contract remain intact.
This additive contract records what was measured and what is still unknown.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import re

from ..model import canonical
from .address_semantics import classify_ice_candidate

CONTRACT = '3.7.evidence.1'
MAX_RECORDS = 512
STATE_MAP = {'passed': 'pass_scoped', 'fault': 'confirmed_fault', 'permission': 'blocked_by_policy',
             'unknown': 'not_run', 'not_tested': 'not_run', 'not_supported': 'unsupported',
    'timeout': 'failed', 'observed': 'reference', 'completed_without_public_mapping': 'reference'}
TERMINAL = {'not_run', 'blocked_by_policy', 'failed', 'unsupported', 'unavailable', 'expired', 'inconclusive'}
STATE_ZH = {'pass_scoped': '本项范围内通过', 'confirmed_fault': '确认的技术故障',
            'confirmed_mismatch': '确认与预期不符', 'reference': '环境参考特征',
            'needs_attribution': '仍需归因', 'partial': '部分证据', 'not_run': '尚未检测',
            'blocked_by_policy': '未授权或策略阻止', 'failed': '检测失败',
            'unsupported': '当前不支持', 'unavailable': '暂不可用', 'expired': '证据过期',
            'inconclusive': '尚不能判断'}
DIRECT_KINDS = {'observed_runtime', 'observed_receiver'}


def utc(value):
    if not isinstance(value, str):
        raise ValueError('missing_utc')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timezone_required')
    return parsed.astimezone(timezone.utc)


def alias(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9:_-]{1,120}', value) else 'unbound'


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _timestamp(value):
    try:
        return utc(value).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _direct(record):
    return record.get('source_kind') in DIRECT_KINDS or (record.get('synthetic') is True and record.get('source_kind') == 'synthetic')


def interpret(record, as_of, max_age_seconds=900):
    """Evaluate one scoped sample; failures/unknowns never become successes.

    Callers supply an explicit assessment clock. Offline report interpretation
    uses the original run time, not an invented new measurement time.
    """
    if not isinstance(record, dict) or len(canonical(record)) > 256 * 1024:
        raise ValueError('invalid_evidence_record')
    scope = record.get('scope') if isinstance(record.get('scope'), dict) else {}
    out = {'id': alias(record.get('id')), 'kind': alias(record.get('kind')),
           'scope': {k: alias(scope.get(k)) for k in ('device_session', 'profile_binding', 'profile_key', 'app_alias', 'space_alias', 'transport', 'target_class')},
           'source_kind': record.get('source_kind') if record.get('source_kind') in DIRECT_KINDS | {'observed_config', 'user_supplied', 'synthetic', 'inferred', 'official_documented'} else 'inferred',
           'measurement_mode': record.get('measurement_mode') if record.get('measurement_mode') in ('raw_observed', 'instrumented', 'inferred', 'unverified') else 'unverified',
           'vantage': alias(record.get('vantage')), 'receiver_id': alias(record.get('receiver_id')),
           'policy_snapshot_id':alias(record.get('policy_snapshot_id')),
           'software_version':record.get('software_version') if isinstance(record.get('software_version'),str) and re.fullmatch(r'[A-Za-z0-9 ._+()-]{1,80}',record['software_version']) else None,
           'failure_stage':record.get('failure_stage') if record.get('failure_stage') in ('dns','tcp','tls','http','dom','ice','authorization','collector') else 'unknown',
           'captured_at_utc': _timestamp(record.get('captured_at_utc')), 'evidence_sha256': digest(record),
           'source_record_sha256':record.get('source_record_sha256') if re.fullmatch('[0-9a-f]{64}',str(record.get('source_record_sha256',''))) else None,
           'runtime_sha256': record.get('runtime_sha256') if re.fullmatch('[0-9a-f]{64}', str(record.get('runtime_sha256', ''))) else None,
           'synthetic': record.get('synthetic') is True, 'state': 'inconclusive',
           'source_evidence_id':alias(record.get('source_evidence_id')),
           'classification': 'missing_provenance', 'root_cause_confirmed': False,
           'affects_health_score': False, 'side_effects': [], 'details': {}}

    def done(state, classification, note, **details):
        out.update(state=state, classification=classification, explanation_zh=note, details=details)
        return out

    state = STATE_MAP.get(record.get('state'), record.get('state'))
    if record.get('authorized') is not True:
        return done('blocked_by_policy', 'not_authorized', '本项没有有效授权，不继承其他范围的结果。')
    if state in TERMINAL:
        return done(state, 'probe_failed' if state == 'failed' else state, '保留本项失败、缺测或权限状态；没有把它换算成通过或风险百分比。')
    if state not in {'pass_scoped', 'confirmed_fault', 'reference', 'partial'}:
        return done('inconclusive', 'unknown_state', '来源状态未被当前契约识别。')
    try:
        age = (utc(as_of) - utc(record.get('captured_at_utc'))).total_seconds()
    except (ValueError, TypeError, OverflowError):
        return done('inconclusive', 'timestamp_missing_or_invalid', '缺少带时区的采样时间。')
    if age < -30:
        return done('inconclusive', 'future_timestamp', '样本时间晚于本轮，不能混入本轮结论。')
    if age > max_age_seconds:
        return done('expired', 'stale', '样本已超出本轮时间窗，不当成当前运行态。')
    if record.get('execution_origin') in ('cloud', 'remote', 'container'):
        return done('inconclusive', 'wrong_vantage', '该测量发生在另一个执行环境，不能代替用户本机。')
    if record.get('execution_origin') != 'local_windows' and not (record.get('synthetic') is True and record.get('execution_origin') == 'synthetic'):
        return done('inconclusive', 'execution_origin_unbound', '执行位置未获得足够归属证据，不能作为用户本机通过。')
    if out['scope']['device_session'] == 'unbound' or out['vantage'] == 'unbound':
        return done('inconclusive', 'scope_unbound', '设备或观察视点缺少绑定，保留原始证据但不确认本机通过。')
    if out['measurement_mode'] != 'raw_observed':
        return done('inconclusive', 'instrumented_measurement' if out['measurement_mode'] == 'instrumented' else 'unverified_measurement', '受干预、推断或未验证的数据不能冒充日常环境的原始实测。')
    if not _direct(record):
        return done('reference', 'indirect_evidence', '静态配置、用户转述与推断仅作参考；不等于运行态或接收端实测。')
    data = record.get('data') if isinstance(record.get('data'), dict) else {}
    kind = record.get('kind')
    if kind == 'dns':
        role = data.get('dns_role', 'business')
        if role in ('bootstrap', 'direct'):
            return done('reference', 'separate_dns_role', '节点 bootstrap、国内直连与业务解析分开记录，不相互代替。')
        observed = set(data.get('observed_resolver_regions') or [])
        expected = set(data.get('expected_resolver_regions') or [])
        if not data.get('authoritative_receipt'):
            return done('inconclusive', 'missing_authoritative_receipt', '没有权威接收回执，不能判定 DNS 泄漏或通过。')
        if data.get('conflicting_receivers'):
            return done('needs_attribution', 'receiver_disagreement', '接收站结论冲突；保留时间和测量范围，继续归因。')
        if not expected or not observed or not data.get('policy_bound'):
            return done('needs_attribution', 'dns_policy_unbound', 'DNS 出口已采样，但缺少当前解析意图或路径归属。')
        mismatch = not observed.issubset(expected)
        return done('confirmed_mismatch' if mismatch else 'pass_scoped', 'dns_policy_mismatch' if mismatch else 'dns_policy_matches',
                    '本项解析样本与当前明确策略不符；尚不证明唯一根因。' if mismatch else '本接收端、本 Profile、本时段的解析样本符合当前明确策略。')
    if kind == 'route':
        if data.get('resolution_rule_without_no_resolve') and not data.get('runtime_match'):
            return done('reference', 'potential_extra_resolution', '静态 IP/ASN 规则可能额外解析，尚未观察到因此泄漏。')
        if not data.get('policy_bound') or not data.get('expected_route'):
            return done('needs_attribution', 'route_intent_unbound', '缺少当前分流意图，不能按组名或国家标签判断错误。')
        actual = data.get('observed_route')
        if not data.get('runtime_match') or not actual:
            return done('needs_attribution', 'runtime_match_missing', '规则模拟不等于实际流量命中。')
        mismatch = actual != data['expected_route']
        return done('confirmed_mismatch' if mismatch else 'pass_scoped', 'runtime_route_mismatch' if mismatch else 'runtime_route_matches',
                    '运行态命中与当前业务分流意图不符。' if mismatch else '本次运行态命中符合当前业务分流意图；未推断最终公网出口。')
    if kind == 'ice':
        candidates = data.get('candidates')
        if not isinstance(candidates, list):
            return done('inconclusive', 'candidate_receipt_missing', '没有候选完成回执，不能把空白页面当成没有候选。')
        classified = [classify_ice_candidate(c.get('address'), c.get('type')) for c in candidates[:32] if isinstance(c, dict)]
        # Keep classifications, not the literal IPs, in agent-facing diagnostics.
        out['details']['candidate_categories'] = [c['category'] for c in classified]
        if any(c['category'] == 'invalid' for c in classified) or len(classified) != len(candidates) or len(candidates) > 32:
            return done('inconclusive', 'invalid_ice_candidate', '候选包含无法解释的数据或超限，不能算通过。')
        public = sum(c['public_unicast_candidate'] for c in classified)
        if not data.get('gathering_complete'):
            return done('partial', 'ice_gathering_incomplete', 'ICE 收集尚未完成；已有候选仅为部分样本。', public_candidate_count=public)
        if public:
            return done('reference', 'public_ice_sample', '观察到公网候选；是否非预期仍需当前策略与协议路径对照。', public_candidate_count=public)
        if data.get('udp_blocking_observed'):
            out['side_effects'] = ['可能影响 WebRTC 音视频；原生 UDP 和 HTTP/3 未因此验证。']
            return done('pass_scoped', 'pass_scoped_under_blocking', '在当前明确阻断条件下未观察到公网 ICE；范围仅限本次浏览器测量。')
        return done('reference', 'no_public_ice_in_sample', '本次完整候选中没有确认的公网地址；未因此验证其他应用或全部 UDP。', candidate_categories=[c['category'] for c in classified])
    if kind == 'ipv6':
        if data.get('resolver_ipv6') and not data.get('terminal_ipv6_observed'):
            return done('reference', 'not_public_terminal_ipv6', '递归解析器使用 IPv6，不证明终端存在公网 IPv6 连接。')
        return done('reference', 'ipv6_sample_only', 'IPv6 的可用性、地址族及暴露范围分别解释，不用超时证明安全。')
    if kind == 'external_score':
        if data.get('probe_error'):
            return done('failed', 'probe_failed', '第三方页面测试失败；分数保持空缺。')
        return done('reference', 'third_party_request_score', '仅为第三方该次请求的参考分数，不进入 CC 健康分、设备入侵概率或账号封禁预测。')
    if kind == 'fingerprint':
        return done('reference', 'browser_capability_reference', '语言、字体、Emoji、Canvas、WebGL 和内存档位是环境线索，不能据此判断国籍、所在地或违规。')
    if kind == 'failure_state':
        if data.get('fault_test_receipt') and data.get('independent_block_observed') and data.get('scenario'):
            return done('pass_scoped', 'fault_case_observed', '仅该故障场景有独立阻断回执；不外推其他空间、进程或故障。')
        return done('partial', 'configured_unproven_fault' if data.get('configured_protection') else 'not_verified', '无 DIRECT、strict-route 或 lockdown 配置不等于已验收系统级 Kill Switch。')
    if kind == 'redundancy':
        domains = data.get('failure_domain_aliases') or []
        return done('reference', 'single_failure_domain' if domains and len(set(domains)) == 1 else 'failure_domain_independence_unverified', '协议数量不等于独立服务器、入口、运营商或故障域数量。')
    if kind == 'endpoint':
        return done('inconclusive', 'endpoint_unverified', '代理与直连都失败时，端点可用性未验证；不能归咎特定节点或判定无泄漏。')
    if kind == 'destination':
        return done('blocked_by_policy', 'destination_policy_violation', '发现未授权目的地，停止此项；本解释器不会加载网页或发起请求。') if data.get('unapproved_subrequest') is True else done('inconclusive','destination_policy_unbound','缺少目的地审批和依赖审查，不主动加载检测网站。')
    if kind == 'policy':
        return done('reference', 'eligibility_separate', '政策资格由真实声明和当前官方政策核对，不混入技术评分。')
    return done(state, 'legacy_check_snapshot', '保留原始检查结果及范围；确认故障不等于唯一根因已证实。')


def collect_records(report):
    """Project existing approved results only. No new I/O and no raw config copy."""
    context = report.get('diagnostic_context_v37') or {}
    device = context.get('device_session', 'unbound')
    synthetic = report.get('synthetic') is True
    now = report.get('created_at_utc')
    records = []

    def add(identifier, kind, state, scope, source, data=None, captured=None, **extra):
        records.append({'id': identifier, 'kind': kind, 'state': state, 'scope': {'device_session': device, **scope},
                        'policy_snapshot_id':context.get('policy_snapshot_id'),
                        'source_kind': 'synthetic' if synthetic else source, 'synthetic': synthetic,
                        'measurement_mode': 'raw_observed', 'execution_origin': context.get('execution_origin', 'unknown'),
                        'vantage': extra.pop('vantage', 'local_collector'), 'authorized': True,
                        'captured_at_utc': captured or now, 'data': data or {}, **extra})

    profile_map={p.get('profile_key'):p for p in report.get('profiles',[]) if isinstance(p,dict)}
    for c in report.get('checks', [])[:256]:
        source = 'observed_config' if c.get('source') in ('configuration_simulation','profile_preferences_and_tool_origin') or c.get('id') in ('proxy_rules', 'proxy_inventory', 'proxy_signatures', 'pac_evaluation', 'root_store', 'locale') else 'observed_receiver' if c.get('source') in ('third_party_receiver','independent_receiver') else 'observed_runtime'
        check_scope={'app_alias':alias(c.get('scope'))}
        profile_key=str(c.get('scope','')).removeprefix('web:')
        profile=profile_map.get(profile_key)
        static=bool(profile and str(c.get('id','')).endswith(('_static','_extensions','_region')))
        if profile:
            check_scope.update(app_alias='browser',profile_key=profile_key,profile_binding=profile.get('profile_session_binding','unbound'))
            if static:source='observed_config'
        # Aggregated browser receiver checks are references, not profile-scoped passes.
        add(c.get('id', 'unbound'), 'check', c.get('state'), check_scope, source,
            {'legacy_check_id': alias(c.get('id'))}, captured=c.get('captured_at_utc') or 'timestamp_unavailable',source_evidence_id=c.get('evidence_id'),source_record_sha256=digest(c))
        if profile:
            records[-1]['software_version']=profile.get('version')
            records[-1]['vantage']='profile_preferences' if static else 'browser_tool_origin'
            records[-1]['authorized']=('browser_static' in (report.get('approval') or {}).get('scopes',[])) if static else (profile_key in (report.get('approval') or {}).get('profiles',[]) and 'browser_dynamic' in (report.get('approval') or {}).get('scopes',[]))
            if not static and (profile.get('dynamic_result') or {}).get('profile_binding')!='user_attested_targeted_launch_browser_pid':records[-1]['measurement_mode']='unverified'
        elif source=='observed_receiver':records[-1]['vantage']='independent_receiver'
    for p in report.get('profiles', [])[:24]:
        key = p.get('profile_key', 'unbound')
        scope = {'profile_key': key, 'profile_binding': p.get('profile_session_binding', 'unbound'), 'app_alias': 'browser'}
        dynamic = p.get('dynamic_result') or {}
        net = (dynamic.get('data') or {}).get('independent_network') or {}
        authorized = key in (report.get('approval') or {}).get('profiles', [])
        if not net:
            add(key + ':dynamic', 'check', 'not_run' if authorized else 'permission', scope, 'observed_runtime')
        for protocol in ('ipv4', 'ipv6', 'dns', 'stun', 'tls'):
            value = net.get(protocol)
            if not isinstance(value, dict):
                continue
            data = {}
            kind = {'stun': 'ice', 'dns': 'dns', 'ipv6': 'ipv6'}.get(protocol, 'check')
            if protocol == 'dns':
                data['authoritative_receipt'] = value.get('status') == 'observed' and bool(value.get('resolver_ips'))
            if protocol == 'stun':
                if isinstance(value.get('candidates'),list):
                    data = {'candidates': value['candidates'], 'gathering_complete': value.get('gathering_complete') is True}
                elif value.get('mapped_ip'):
                    data = {'candidates': [{'address': value['mapped_ip'], 'type': 'srflx'}], 'gathering_complete': False}
            sample=dynamic
            source_attempt=(dynamic.get('independent_network_source_attempts') or {}).get(protocol)
            if source_attempt is not None:
                history=next((h.get('result') for h in p.get('v33_attempt_history',[]) if h.get('attempt')==source_attempt),None)
                if isinstance(history,dict):sample=history
            add(key + ':' + protocol, kind, value.get('status', 'not_run'), {**scope, 'transport': protocol, 'target_class': 'neutral_receiver'},
                'observed_receiver', data, captured=sample.get('checked_at_utc') or (p.get('checked_at_utc') if source_attempt is None else 'timestamp_unavailable'),
                vantage='browser_tool_origin', receiver_id={'dns': 'dnscheck_tools', 'stun': 'cloudflare_stun', 'ipv4': 'ipify_v4', 'ipv6': 'ipify_v6', 'tls': 'peet_tls'}[protocol])
            records[-1]['software_version']=p.get('version')
            records[-1]['source_record_sha256']=digest(value)
            records[-1]['authorized'] = authorized and 'independent_network' in (report.get('approval') or {}).get('scopes', [])
            if sample.get('profile_binding') != 'user_attested_targeted_launch_browser_pid':
                records[-1]['measurement_mode'] = 'unverified'
    # Optional normalized evidence from future supported collectors; never arbitrary URLs/scripts.
    extras = report.get('diagnostic_observations_v37') or []
    if not isinstance(extras, list) or len(records) + len(extras) > MAX_RECORDS:
        raise ValueError('evidence_record_limit')
    records.extend(extras)
    return records


def analyze(report):
    records = collect_records(report)
    observations = [interpret(r, report.get('created_at_utc')) for r in records]
    for row in observations:
        if row['synthetic'] != (report.get('synthetic') is True):
            row.update(state='inconclusive',classification='mixed_synthetic_origin',explanation_zh='合成与真实证据混合，不能用示例数据确认本机结果。')
        actions={
            'dns_policy_mismatch':'审阅本项生效 DNS 与当前业务意图的差异，保留同 Profile 接收回执，再准备最小修复预案。',
            'runtime_route_mismatch':'核对该次内核命中的规则索引、规则集版本和预期组，仅审阅相关规则差异。',
            'dns_policy_unbound':'核对该 Profile 的当前 DNS 意图和权威回执，不用 HTTP 出口代替解析路径。',
            'missing_authoritative_receipt':'在已批准接收端重新取得本 Profile 的新鲜 DNS 回执；缺回执不判泄漏。',
            'receiver_disagreement':'对齐接收器与样本时间窗，再用独立回执核查分歧。',
            'configured_unproven_fault':'先审阅逐项故障验证与离线恢复方案；本轮不自动停内核或修改防火墙。',
            'wrong_vantage':'先连接并确认实际用户设备；保留云端样本作为独立视点。',
            'scope_unbound':'先补设备或 Profile 归属依据，再判断是否能对应当前电脑。',
            'instrumented_measurement':'在同一日常 Profile 的原始环境重新取样，受干预样本单独保存。',
            'stale':'在相同授权和测点下重新采样，旧样本继续保留原始时间。',
        }
        row['next_action_zh']=actions.get(row['classification'],
            '重新测量该 Profile 的第三方项目；错误排除前保持无分数。' if row['kind']=='external_score' and row['state']=='failed' else
            '仅在本人选择并授权该 Profile 后独立补测，不继承其他档案结果。' if row['scope']['profile_key']!='unbound' and row['state'] in ('not_run','blocked_by_policy') else
            '按此项原始检查判据核对故障，尚未证明唯一根因。' if row['state']=='confirmed_fault' else
            '保留本项状态和原始来源；仅在对应范围内补足可取得的证据。')
    confirmed = [r for r in observations if r['state'] in ('confirmed_fault', 'confirmed_mismatch')]
    features = [r for r in observations if r['state'] in ('reference', 'pass_scoped')]
    gaps = [r for r in observations if r not in confirmed and r not in features]
    from .coverage_v37 import summary as coverage_summary
    return {'capability_coverage_v37':coverage_summary(report), 'contract': CONTRACT, 'source_run_id': report.get('run_id'), 'source_created_at_utc': report.get('created_at_utc'),
            'source_snapshot_sha256': digest({k: v for k, v in report.items() if k != 'diagnostics_v37'}),
            'interpretation_clock': 'original_run_snapshot_not_current_measurement', 'synthetic': report.get('synthetic') is True,
            'observations': observations, 'confirmed': confirmed, 'features': features, 'gaps': gaps,
            'effective_policies': [c['effective_policy_v37'] for c in (report.get('target_routes') or {}).get('configs', []) if 'effective_policy_v37' in c],
            'counts': dict(Counter(r['state'] for r in observations)),
            'priority_findings': sorted(confirmed+gaps,key=lambda r:(0 if r in confirmed else 1 if r['kind'] in ('dns','route','ice','external_score','failure_state') else 3 if r['id'].startswith('target_egress') else 2))[:5],
            'health_contract_unchanged': '3.5.health.region.1', 'automatic_remediation_enabled': False,
            'scope_note_zh': '只解释原始保存的采样时段；同一机器的其他 Profile、容器、原生应用和未来服务请求不继承本项结果。'}


def compact(diagnostic, limit=10):
    """Bounded model-facing view: no addresses, config values or personal paths."""
    selected = (diagnostic['confirmed'] + diagnostic['gaps'] + diagnostic['features'])[:limit]
    keys = ('id', 'kind', 'state', 'classification', 'scope', 'source_kind', 'measurement_mode', 'vantage',
            'captured_at_utc', 'evidence_sha256', 'explanation_zh', 'root_cause_confirmed', 'side_effects','failure_stage','next_action_zh')
    return {'contract': CONTRACT, 'source_run_id': diagnostic['source_run_id'], 'counts': diagnostic['counts'],
            'returned': len(selected), 'total': len(diagnostic['observations']),
            'browser_detail_attempts':diagnostic['capability_coverage_v37']['browser_detail_attempts'],
            'observations': [{k: r[k] for k in keys} for r in selected],
            'automatic_remediation_enabled': False, 'scope_note_zh': diagnostic['scope_note_zh']}
