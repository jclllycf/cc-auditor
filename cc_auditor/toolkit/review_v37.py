"""Read-only remediation previews and strict snapshot comparison; no executor."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .evidence_v37 import analyze, digest, utc, STATE_ZH

_PLANS = {
    'dns_policy_mismatch': ('dns_policy_review', '核对业务 DNS、节点 bootstrap、浏览器 DoH 与生效覆写，形成最小候选差异。', 'strict-route 可能影响局域网和虚拟网卡；切换 DNS 可能中断解析。'),
    'runtime_route_mismatch': ('route_rule_review', '核对实际命中的规则索引、规则集版本与当前业务意图，仅审阅相关规则候选差异。', '规则顺序变化可能影响同域名的其他业务。'),
    'legacy_check_snapshot': ('technical_fault_review', '按原检查判据核对当前故障，先取得作用域明确的直接证据，再准备受支持项的最小差异。', '具体副作用必须在可执行差异确定后单独列明。'),
}


def remediation_plan(diagnostic):
    """Human-reviewable proposals only. No command strings or arbitrary action API."""
    proposals = []
    seen = set()
    for row in diagnostic['confirmed']:
        template = _PLANS.get(row['classification'])
        if not template:
            continue
        operation, preview, side_effect = template
        # A shared legacy fault can repeat; never deduplicate across profiles/spaces.
        identity = (operation, digest(row['scope']), row['id'])
        if identity in seen:
            continue
        seen.add(identity)
        proposals.append({'id': 'proposal-' + str(len(proposals) + 1), 'status': 'review_only',
                          'operation': operation, 'evidence_ids': [row['id']], 'scope': row['scope'],
                          'problem_zh': row['explanation_zh'], 'root_cause': 'not_yet_proven',
                          'change_preview_zh': preview, 'side_effects_zh': [side_effect],
                          'preconditions': ['native_secondary_approval', 'supported_fixed_operation', 'private_backup_verified',
                                            'expected_current_hash_matches', 'profile_not_locked', 'offline_recovery_available'],
                          'expected_runtime_sha256': row.get('runtime_sha256'),
                          'verification_zh': '同设备、同日常 Profile、同分流意图、同接收器与协议重测；失败和未知保留。',
                          'rollback_zh': '先验证备份摘要；遇后续修改或恢复冲突时拒绝覆盖，报告恢复失败并保留证据。',
                          'executable': False})
    return {'contract': '3.7.remediation-preview.1', 'source_run_id': diagnostic['source_run_id'],
            'automatic_execution': False, 'executor_implemented': False, 'proposals': proposals,
            'unresolved_count': len(diagnostic['gaps']),
            'note_zh': '这是修复预案，不是系统变更许可或已完成修复；环境特征与缺测不会生成刷分修改。'}


def compare(before, after):
    """Compare saved snapshots only when their measurement conditions are bound.

    Session bindings deliberately expire at collector restart. A profile number
    or equal display name cannot establish the same device/profile across runs.
    """
    left, right = analyze(before), analyze(after)
    result = {'contract': '3.7.comparison.1', 'before_run_id': before.get('run_id'), 'after_run_id': after.get('run_id'),
              'before_at_utc': before.get('created_at_utc'), 'after_at_utc': after.get('created_at_utc'),
              'status': 'not_comparable', 'reasons': [], 'rows': [], 'health_score_delta': None,
              'repair_proven': False, 'causal_attribution': 'not_established',
              'note_zh': '状态变化只描述可比样本；不按分数差断言修复或唯一因果。'}
    a, b = before.get('diagnostic_context_v37') or {}, after.get('diagnostic_context_v37') or {}
    for field in ('device_session', 'execution_origin'):
        if not a.get(field) or a.get(field) != b.get(field) or a.get(field) == 'unbound':
            result['reasons'].append(field + '_unbound_or_changed')
    if before.get('synthetic') is not after.get('synthetic'):
        result['reasons'].append('synthetic_and_real_not_comparable')
    if not before.get('version') or before.get('version') != after.get('version'):
        result['reasons'].append('collector_version_unbound_or_changed')
    if a.get('execution_origin') not in ('local_windows', 'synthetic'):
        result['reasons'].append('wrong_vantage')
    if sorted((before.get('approval') or {}).get('scopes', [])) != sorted((after.get('approval') or {}).get('scopes', [])):
        result['reasons'].append('authorization_scope_changed')
    try:
        if utc(after.get('created_at_utc')) <= utc(before.get('created_at_utc')):
            result['reasons'].append('not_a_later_snapshot')
    except (ValueError, TypeError, OverflowError):
        result['reasons'].append('invalid_snapshot_time')
    if result['reasons']:
        return result

    def key(row):
        return row['id'], row['kind'], row['scope']['profile_key'], row['scope']['app_alias'], row['scope']['space_alias']

    old = {key(r): r for r in left['observations']}
    new = {key(r): r for r in right['observations']}
    if len(old)!=len(left['observations']) or len(new)!=len(right['observations']):
        result['reasons'].append('ambiguous_duplicate_samples');return result
    for identity in sorted(set(old) | set(new)):
        x, y = old.get(identity), new.get(identity)
        reasons = []
        if x is None or y is None:
            reasons.append('sample_missing_in_one_snapshot')
        else:
            if x['measurement_mode'] != 'raw_observed' or y['measurement_mode'] != 'raw_observed':
                reasons.append('instrumented_or_unverified')
            if x['state'] in ('not_run', 'failed', 'expired', 'blocked_by_policy', 'unsupported', 'unavailable', 'inconclusive') or y['state'] in ('not_run', 'failed', 'expired', 'blocked_by_policy', 'unsupported', 'unavailable', 'inconclusive'):
                reasons.append('measurement_not_complete')
            if x['scope']['profile_key'] != 'unbound':
                if x['scope']['profile_binding'] == 'unbound' or x['scope']['profile_binding'] != y['scope']['profile_binding']:
                    reasons.append('daily_profile_binding_changed_or_missing')
            for field in ('vantage', 'receiver_id', 'source_kind','policy_snapshot_id','software_version'):
                if x[field] != y[field]:
                    reasons.append(field + '_changed')
            for field in ('transport', 'target_class'):
                if x['scope'][field] != y['scope'][field]:
                    reasons.append(field + '_changed')
            if x['scope']['profile_key']!='unbound' and not x['software_version']:reasons.append('browser_version_unbound')
            if x['kind'] in ('dns', 'route', 'ice', 'ipv6', 'external_score') or x['scope']['target_class']=='neutral_receiver':
                if x['policy_snapshot_id']=='unbound' or y['policy_snapshot_id']=='unbound':reasons.append('sample_policy_unbound')
                for field in ('network_context_id', 'policy_snapshot_id'):
                    if not a.get(field) or a.get(field) != b.get(field):
                        reasons.append(field + '_unbound_or_changed')
        result['rows'].append({'id': identity[0], 'kind': identity[1], 'status': 'not_comparable' if reasons else 'comparable',
                               'before': x['state'] if x else 'not_run', 'after': y['state'] if y else 'not_run',
                               'classification_before': x['classification'] if x else None,
                               'classification_after': y['classification'] if y else None,
                               'configuration_changed': x['runtime_sha256'] != y['runtime_sha256'] if x and y and x['runtime_sha256'] and y['runtime_sha256'] else None,
                               'raw_observation_changed':x['source_record_sha256']!=y['source_record_sha256'] if x and y and x['source_record_sha256'] and y['source_record_sha256'] else None,
                               'reasons': reasons})
    complete = sum(r['status'] == 'comparable' for r in result['rows'])
    result['status'] = 'comparable' if complete and complete == len(result['rows']) else 'partially_comparable' if complete else 'not_comparable'
    return result


def report_section(diagnostic):
    """HTML subset shared by the offline dashboard and existing PDF renderer."""
    e = html.escape
    out = ['<h2>证据诊断：故障、环境特征与缺失证据</h2>',
           '<p>' + e(diagnostic['scope_note_zh']) + '</p>']
    out.append('<h3>本轮优先事项</h3>')
    for r in diagnostic['priority_findings']:
        out.append('<p><b>'+e(r['id'])+'</b> · '+e(STATE_ZH[r['state']])+'<br>'+e(r['next_action_zh'])+'</p>')
    for title, rows in (('确认的技术故障', diagnostic['confirmed']), ('值得注意的环境特征', diagnostic['features']), ('暂未取得的证据', diagnostic['gaps'])):
        out.append('<h3>' + title + ' · ' + str(len(rows)) + '</h3>')
        if not rows:
            out.append('<p>本组没有记录；不代表其他范围已通过。</p>')
        for r in rows:
            out.append('<p><b>' + e(r['id']) + ' · ' + e(STATE_ZH[r['state']]) + '</b><br>' +
                       e(r['explanation_zh']) + '<br>视点 ' + e(r['vantage']) + ' / ' + e(r['scope']['profile_key']) +
                       '；来源 ' + e(r['source_kind']) + '；测量态 ' + e(r['measurement_mode']) +
                       '<br>时间 ' + e(str(r['captured_at_utc'])) + '；证据 ' + r['evidence_sha256'][:16] + '</p>')
    coverage=diagnostic['capability_coverage_v37']
    out.append('<h2>检测能力覆盖与本轮采样状态</h2><p>'+e(coverage['measurement_note_zh'])+'</p>')
    out.append('<table><tr><th>能力</th><th>实现范围</th><th>边界</th></tr>')
    labels={'bounded_observation':'已实现（限定观察）','partial':'部分覆盖','not_implemented':'待实现',
            'excluded_zero_contact':'默认不测（零接触）','not_inferred':'不作推断','server_private':'站点私有数据'}
    for row in coverage['groups']:
        out.append('<tr><td>'+e(row['title_zh'])+'</td><td>'+e(labels[row['implementation']])+'</td><td>'+e(row['boundary_zh'])+'</td></tr>')
    out.append('</table><pre>'+e(json.dumps(coverage['browser_detail_attempts'],ensure_ascii=False,indent=2))+'</pre>')
    plan = remediation_plan(diagnostic)
    if diagnostic.get('effective_policies'):
        out.append('<h2>源配置与运行态的已知差异</h2><pre>' + e(json.dumps(diagnostic['effective_policies'], ensure_ascii=False, indent=2)) + '</pre>')
    out.append('<h2>修复预案与回滚条件</h2><p>' + e(plan['note_zh']) + '</p>')
    for p in plan['proposals']:
        out.append('<h3>' + e(p['id']) + '</h3><p>' + e(p['change_preview_zh']) + '<br>副作用：' + e('；'.join(p['side_effects_zh'])) +
                   '<br>验证：' + e(p['verification_zh']) + '<br>回滚：' + e(p['rollback_zh']) + '</p>')
    return ''.join(out)


def export_review(report_path, before_path=None):
    from .preflight_v3 import read
    from ..storage import no_reparse
    report, source_sha = read(report_path)
    diagnostic = analyze(report)
    comparison = compare(read(before_path)[0], report) if before_path else None
    # Stable revision-specific names; existing reviews are never overwritten.
    payload = {'source_sha256': source_sha, 'diagnostics': diagnostic, 'plan': remediation_plan(diagnostic), 'comparison': comparison}
    name = 'review-v37-' + digest(payload)[:16]
    directory = Path(report_path).parent
    paths = {'html': directory / (name + '.html'), 'json': directory / (name + '.json')}
    for p in paths.values():
        no_reparse(p)
    body = ('<p class="eyebrow">CC AUDITOR / EVIDENCE REVIEW</p><h1>当前证据能说明什么</h1><p>' +
            ('合成演示，不是本机实测。' if report.get('synthetic') else '原始时段的离线解释，没有新增网络测量。') +
            '</p><p>运行 ' + html.escape(str(report.get('run_id'))) + ' · ' + html.escape(str(report.get('created_at_utc'))) +
            '<br>来源 SHA-256 ' + source_sha + '</p>' + report_section(diagnostic))
    if comparison:
        body += '<h2>前后证据对比</h2><p>' + html.escape(comparison['status']) + '；不能据此声称已修复。</p><pre>' + html.escape(json.dumps(comparison, ensure_ascii=False, indent=2)) + '</pre>'
    document = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>CC Auditor 证据诊断</title><style>body{margin:0;background:#f4f3ef;color:#183637;font:16px/1.8 system-ui,sans-serif}main{max-width:900px;margin:36px auto;padding:36px;background:white;border:1px solid #d8e2df;border-radius:16px}h1{font-size:32px}h2{margin-top:40px;border-top:1px solid #d8e2df;padding-top:24px}h3{color:#28695e}p{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}.eyebrow{letter-spacing:.12em;color:#53756e;font-size:12px}@media(max-width:650px){main{margin:0;padding:20px;border:0;border-radius:0}h1{font-size:26px}}</style><main>' + body + '</main></html>'
    contents = {'html': document, 'json': json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False)}
    for kind,path in paths.items():
        if path.exists() and path.read_text('utf-8') != contents[kind]:
            raise FileExistsError('preserve_existing_review')
    for kind, path in paths.items():
        if not path.exists():
            with path.open('x', encoding='utf-8') as stream:
                stream.write(contents[kind])
    return {kind: str(path) for kind, path in paths.items()}
