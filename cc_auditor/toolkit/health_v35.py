"""正向技术健康契约。资格、安装、地区线索不参与技术扣分。"""
import copy
from decimal import Decimal
from . import fixed_risk_v33 as legacy
from .api_execution_v35 import classify

VERSION = '3.5.health.region.1'
GAP_CAP = Decimal(20)
FACTORS = {'passed': Decimal(0), 'verified_fault': Decimal(1),
           'not_configured': Decimal(1), 'partial': Decimal('.15'),
           'unverified': Decimal('.35'), 'not_applicable': Decimal(0)}


def grade(score):
    return '未评分' if score is None else '优良' if score >= 85 else '良好' if score >= 70 else '需关注' if score >= 50 else '需优先整改'


def evaluate(rows):
    rows = copy.deepcopy(rows)
    applicable = sum(r['weight'] for r in rows if r['state'] != 'not_applicable')
    roots = {}
    for r in rows:
        for key in ('contribution', 'contribution_before_dedup'):
            r.pop(key, None)
        weight = Decimal(r['weight']) * 100 / Decimal(applicable) if applicable and r['state'] != 'not_applicable' else Decimal(0)
        amount = weight * FACTORS[r['state']]
        category = ('confirmed_fault' if r['state'] == 'verified_fault' else
                    'compatibility_issue' if r['state'] == 'not_configured' else 'measurement_gap')
        r.update(normalized_weight=str(weight.quantize(Decimal('.000001'))), penalty_category=category,
                 penalty_before_dedup=str(amount.quantize(Decimal('.000001'))), penalty='0')
        key = r['root_cause']
        if key not in roots or amount > roots[key][1]: roots[key] = (r, amount)
    sums = {'confirmed_fault': Decimal(0), 'compatibility_issue': Decimal(0), 'measurement_gap': Decimal(0)}
    for r, amount in roots.values(): sums[r['penalty_category']] += amount
    gap_raw = sums['measurement_gap']; factor = min(Decimal(1), GAP_CAP / gap_raw) if gap_raw else Decimal(1)
    for r, amount in roots.values():
        final = amount * factor if r['penalty_category'] == 'measurement_gap' else amount
        r['penalty'] = str(final.quantize(Decimal('.000001')))
    total = sums['confirmed_fault'] + sums['compatibility_issue'] + min(GAP_CAP, gap_raw)
    score = max(0, min(100, 100 - legacy.round_index(total)))
    severe = any(r['state'] == 'verified_fault' and r['critical_fault'] for r in rows)
    ceiling_adjustment = max(0, score - 25) if severe else 0
    score -= ceiling_adjustment
    return {'health_score': score if applicable else None, 'health_level': grade(score if applicable else None),
            'ledger': rows, 'applicable_weight': applicable, 'critical_confirmed_fault': severe,
            'penalties': {**{k: str(v.quantize(Decimal('.000001'))) for k, v in sums.items()},
                          'measurement_gap_after_cap': str(min(GAP_CAP, gap_raw)),
                          'measurement_gap_cap': str(GAP_CAP), 'critical_ceiling_adjustment': ceiling_adjustment},
            'coverage': {'passed': sum(r['state'] == 'passed' for r in rows),
                         'applicable': sum(r['state'] != 'not_applicable' for r in rows),
                         'confirmed_faults': sum(r['state'] == 'verified_fault' for r in rows),
                         'gaps': sum(r['state'] in ('partial', 'unverified') for r in rows)}}


def _surface(old):
    out = {k: copy.deepcopy(v) for k, v in old.items() if k not in (
        'risk_index', 'risk_level', 'preuse_environment_risk_index', 'raw_contribution_sum',
        'confirmed_fault_contribution', 'missing_condition_contribution', 'evidence_gap_contribution',
        'critical_floor_adjustment', 'profiles')}
    out.update(evaluate(old['ledger']))
    out['legacy_risk_index'] = old['risk_index']
    out['raw_environment_defect_index'] = {'contract': '3.4.preuse.4', 'value': old['risk_index'],
                                          'meaning': '历史内部对照；不是 v3.5 健康分'}
    blockers = [r for r in out['ledger'] if r['critical_minimum'] and r['state'] in ('verified_fault', 'not_configured')]
    missing = [r for r in out['ledger'] if r['critical_minimum'] and r['state'] in ('partial','unverified')]
    out['critical_missing_keys'] = [r['key'] for r in missing]
    out['positive_factors'] = [{'text':r['positive'],'evidence_ids':r['evidence_ids']} for r in out['ledger'] if r['state']=='passed']
    out['obstacles'] = [{'text':r['problem'],'state':r['state'],'evidence_ids':r['evidence_ids'],'action':r['action'],'key':r['key']} for r in blockers+missing]
    basics = [r for r in out['ledger'] if r['key'] in ('os', 'profile', 'page', 'shell', 'host') and r['state'] != 'not_applicable']
    minimum = bool(basics) and all(r['state'] == 'passed' for r in basics)
    ready = minimum and not blockers and out['health_score'] is not None and out['health_score'] >= 50
    out.update(technical_environment_ready=ready, environment_ready=ready, ready_to_begin_setup=ready,
               minimum_technical_ready=ready, recommend_use=ready, recommend_now='是' if ready else '暂缓',
               confirmed_blockers=[r['key'] for r in blockers],
               decision_basis='confirmed_technical_blocker' if blockers else 'minimum_environment_not_observed' if not minimum else 'ready_with_followups' if out['critical_missing_keys'] else 'ready',
               reason=blockers[0]['problem'] if blockers else '当前系统或日常浏览器基础尚未完成核验' if not minimum else '已测基础适合开始安装或配置；目标路径待确认项继续核对',
               next_action=blockers[0]['action'] if blockers else '在原授权范围复核当前缺口；无需先安装或登录 Claude。' if not ready else '可开始技术准备；注册和支付资格请另行核对。')
    return out


def assess(report):
    old = legacy.assess(report)
    # Windows hosts mappings apply before any future client is installed.
    # Add this shared environment fact to clients whose old ledger omitted it.
    hosts = next((r for r in report.get('checks', []) if r['id'] == 'hosts_block'), None)
    for s, a in old['surface_assessments'].items():
        if not hosts or s == 'desktop': continue
        context = (report.get('program_context_v33') or {}).get(s) or {}
        if s in ('cli', 'api') and context.get('host_kind') in ('wsl', 'container', 'remote'): continue
        targets = [a] + (a.get('profiles', []) if s == 'web' else []); seen = set()
        for target in targets:
            rows = target['ledger']
            if id(rows) in seen: continue
            seen.add(id(rows))
            route = next(row for row in rows if row['key'] == 'route'); route['weight'] -= 5
            rows.append({'key':'hosts','rule_id':s+'.hosts','title':'本机 hosts 目标映射',
                'weight':5,'state':'verified_fault' if hosts['state']=='fault' else 'passed' if hosts['state']=='passed' else 'unverified',
                'critical_minimum':True,'critical_fault':hosts['state']=='fault','root_cause':'windows_hosts_block',
                'evidence_ids':[hosts['evidence_id']],'positive':'本机 hosts 未见目标阻断',
                'problem':'本机 hosts 存在目标阻断映射' if hosts['state']=='fault' else '本机 hosts 尚未核对',
                'action':'核对已证实的本机 hosts 目标映射；工具不会自动修改。',
                'scope':s,'evidence_lifecycle':'preuse_environment'})
    surfaces = {k: _surface(v) for k, v in old['surface_assessments'].items()}
    surfaces['web']['profiles'] = [_surface(p) for p in old['surface_assessments']['web'].get('profiles', [])]
    execution = classify(report); api = surfaces['api']
    api.update(execution)
    # API result is never inferred from a software brand or an unmeasured cloud host.
    api['local_client_readiness'] = {'health_score': surfaces['desktop']['health_score'],
                                    'technical_environment_ready': surfaces['desktop']['technical_environment_ready'],
                                    'scope': 'windows_system_baseline_not_agent_or_api_connection',
                                    'ledger': copy.deepcopy(surfaces['desktop']['ledger'])}
    if not execution['applicable'] or not execution['local_path_candidate']:
        for row in api['ledger']:
            row.update(state='not_applicable', evidence_lifecycle='outside_local_measurement', critical_minimum=False)
        api.update(evaluate(api['ledger']))
        api.update(technical_environment_ready=None, environment_ready=None, ready_to_begin_setup=None,
                   minimum_technical_ready=None, recommend_use=None, recommend_now='不适用' if not execution['applicable'] else '仅评本机接入',
                   critical_missing_keys=[], obstacles=[], confirmed_blockers=[],
                   reason=execution['boundary'], next_action='确认实际请求执行者与提供商；本机预检不要求 SDK、密钥或云端私人资料。',
                   decision_basis='not_applicable' if not execution['applicable'] else 'execution_scope_unobserved')
    dec = legacy.declarations(report.get('user_declarations'))
    active = [surfaces[s] for s in dec['surfaces'] if s != 'api' or execution['applicable']]
    assessable = [s for s in active if s['technical_environment_ready'] is not None]
    ready = bool(assessable) and all(s['technical_environment_ready'] for s in assessable)
    if not assessable and execution['applicable'] and execution['selected']:
        ready = api['local_client_readiness']['technical_environment_ready']
    policy = legacy._policy(dec)
    eligibility = {'registration': 'needs_user_confirmation', 'payment': 'needs_user_confirmation',
                   'basis': '本人声明与历史政策快照；本轮未联网核对最新资格政策',
                   'self_declared_physical_country': dec['physical_country'] or None,
                   'declared_issues': policy['issues'], 'snapshot_date': policy['snapshot_date'],
                   'affects_technical_score': False, 'live_policy_verified': False}
    # Explicit eligibility claims remain visible, without presenting stale policy as verified-current.
    scenarios = copy.deepcopy(old['usage_scenarios'])
    daily = scenarios['daily_use']; daily.update(recommend_now=bool(dec['plan_daily'] and ready),
        recommend_text='可开始技术准备' if ready else '先处理技术问题',
        reason='技术环境与真实资格分别判断；实际登录和模型服务未测试',
        obstacles=[o['text'] for a in assessable for o in a['obstacles']])
    for key in ('registration', 'payment'):
        scenarios[key].update(recommend_now=False, recommend_text='需本人核对' if scenarios[key]['planned'] else '未计划',
                              eligibility_status='needs_user_confirmation',
                              reason='请核对当前真实资格及服务条件；技术健康分不代替资格或银行结果' if scenarios[key]['planned'] else '本次未计划，不影响环境分')
        for item in scenarios[key]['sub_scenarios']:
            item.update(recommend_now=False, recommend_text='需本人核对', policy_live_verified=False)
    from .region_observability_v35 import synthesize
    location = synthesize(report)
    for s, a in surfaces.items(): a['observed_egress'] = location['surface_region_summaries'][s]
    return {'model_version': VERSION, 'surface_assessments': surfaces,
            'usage_scenarios': scenarios, 'eligibility': eligibility,
            'location_observability': location, 'selected_surfaces': dec['surfaces'],
            'selection_source': dec['provenance'], 'recommend_now': ready, 'ready_to_begin_setup': ready,
            'technical_environment_ready': ready, 'unmeasured_execution_surfaces': ['api'] if execution['applicable'] and not execution['local_path_candidate'] else [],
            'headline': ('本机接入基础适合准备；API 实际执行链路超出本轮测量' if ready and not assessable else
                         '已测入口适合开始技术准备' if ready else
                         '本次没有适用的 Claude 入口' if not active else '先完成必要环境核验或处理已确认技术阻断'),
            'decision_reason': next((a['reason'] for a in assessable if not a['technical_environment_ready']), '已测本机基础支持技术准备；未测远端链路单列'),
            'disclaimer': '环境健康分越高越好；只评价可测技术环境，不是 Anthropic 封禁概率或真实服务承诺。'}
