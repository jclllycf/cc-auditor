"""可解释的工程行动等级；只读事实，绝不估计账号处罚概率。"""
from __future__ import annotations

VERSION = '3.1.action.1'
LEVELS = {'green': ('低关注', '所测技术基本正常'), 'amber': ('中等关注', '建议重点补检'), 'red': ('高关注', '先处理已确认问题')}


def assess(report):
    checks = report.get('checks', [])
    byid = {c['id']: c for c in checks}
    faults = [c for c in checks if c['state'] == 'fault']
    serious = [c for c in faults if c.get('points', 0) >= 30 or c.get('severity') in ('high', 'critical')]
    profiles = report.get('profiles') or []
    routes = report.get('target_routes') or {}
    bound = any(c.get('activation') == 'controller_rules_observed' for c in routes.get('configs', []))
    gaps = []

    def gap(key, title, detail, action, ids):
        gaps.append({'id': key, 'title': title, 'detail': detail, 'action': action,
                     'evidence_ids': [byid[x]['evidence_id'] for x in ids if x in byid], 'confirmed_fault': False})

    if not bound:
        gap('runtime_binding', '还没核对正在生效的代理规则',
            '已找到的配置文件，不一定是当前代理内核正在使用的那一份。',
            '读取已运行内核的只读控制接口，核对实际规则、代理组和链式转发；权限受限时说明具体缺口。', ['proxy_rules', 'proxy_inventory'])
    targets = [c for c in checks if c['id'].startswith('target_egress_')]
    if not targets or any(c['state'] != 'passed' for c in targets):
        gap('application_paths', 'Claude 各入口的最终出口还没证实',
            '桌面端、网页、命令行与 API 可能走不同路线；普通查 IP 结果不能代替它们。',
            '按每个入口关联运行规则与现有连接，分别标明已证实的转发链和仍缺少的最后出口证据。', [c['id'] for c in targets])
    for key, title, detail in (
        ('dns_receiver', 'DNS 实际去向需要核对', '网卡里写的 DNS 地址，不能证明查询最终由谁处理。'),
        ('ipv6_bypass', 'IPv6 旁路还需实测', '有 IPv6 默认路由，不等于 IPv6 流量已按预期经过代理。'),
        ('webrtc_stun', '浏览器语音/视频通道还需实测', 'WebRTC 可能使用独立 UDP 路线；本地 API 可用不等于公网路径已检查。')):
        c = byid.get(key)
        if not c or c['state'] not in ('passed', 'reference'):
            gap(key, title, detail, '在本机授权卡允许后，使用独立中立接收端补测；未取得结果保持待补检。', [key])
    incomplete = [p for p in profiles if not p.get('dynamic_profile_checked')]
    if incomplete or not profiles:
        label = '、'.join(dict.fromkeys(p['browser_name'] for p in incomplete)) or '日常浏览器'
        gap('daily_profiles', label + ' 还没完成页面实测',
            '静态设置检查无法替代在用户日常浏览器档案中运行测试页。',
            '先手动打开所选日常档案的普通空白页；重新授权后只打开本工具测试页，保持到显示完成。',
            [p['profile_key'] + '_dynamic' for p in incomplete])
    good = sum(c['state'] == 'passed' for c in checks)
    reference = sum(c['state'] == 'reference' for c in checks)
    unknown = len(checks) - good - len(faults) - reference
    coverage = round((good + reference + len(faults)) / len(checks) * 100, 1) if checks else 0
    level = 'red' if serious else 'amber' if faults or gaps or coverage < 80 else 'green'
    label, action = LEVELS[level]
    basis = ([{'id': c['id'], 'evidence_id': c['evidence_id'], 'title': c['title']} for c in serious] if serious else
             [{'id': g['id'], 'title': g['title'], 'evidence_ids': g['evidence_ids']} for g in gaps])
    windows = [byid.get(k) for k in ('os_desktop_compatible', 'os_cli_compatible', 'cli_ram_sufficient', 'disk_sufficient')]
    windows_ok = all(c and c['state'] == 'passed' for c in windows)
    headline = ('发现需要先处理的技术问题。' if serious else
                '电脑基础正常，Claude 专用网络还需核实。' if windows_ok and gaps else
                '本轮检查已完成，还有关键项目需要补检。' if level == 'amber' else '主要技术检查正常，保留本轮结果。')
    actions = []
    if faults:
        actions.append({'title': '先处理已确认的技术问题', 'detail': '、'.join(c['title'][:18] for c in faults[:2]) + '；只修复具体异常，不改身份或地区。'})
    for keys in (('runtime_binding', 'application_paths'), ('daily_profiles',), ('dns_receiver', 'ipv6_bypass', 'webrtc_stun')):
        candidates = [g for g in gaps if g['id'] in keys]
        if candidates:
            first = candidates[0]
            title='核实 Claude 专用代理路线' if 'runtime_binding' in keys else first['title']
            detail=first['action']
            if 'daily_profiles' in keys:
                names='、'.join(dict.fromkeys(p['browser_name'].replace('Google ','').replace('Microsoft ','') for p in incomplete[:2])) or '日常浏览器'
                title='补测 '+names+' 的日常档案'
            if 'dns_receiver' in keys:
                title='补做 DNS / IPv6 / WebRTC 独立测试'
                detail='允许后分别查看解析器、IPv6 和语音通道的真实出口；与预期不符时再判断具体异常。'
            actions.append({'title':title,'detail':detail})
    while len(actions) < 3:
        actions.append({'title': ['保留这次检查结果', '环境变化后再检查', '按真实条件核对使用资格'][len(actions)],
                        'detail': '本报告只解释本次技术观察；不能预测服务端决定或替代真实使用资格。'})
    return {'version': VERSION, 'action_level': level, 'label': label, 'action': action, 'headline': headline,
            'confirmed_fault_count': len(faults), 'critical_gap_count': len(gaps), 'critical_gaps': gaps,
            'completeness': {'total': len(checks), 'passed': good, 'fault': len(faults), 'reference': reference,
                             'needs_verification': unknown, 'observed': good + len(faults) + reference, 'percent': coverage},
            'observed_health': '已执行检查未确认技术故障' if not faults else '已确认具体技术异常',
            'confidence': '关键证据充分' if level == 'green' else '初步判断，见补检项', 'basis': basis,
            'actions': actions[:3], 'windows_ok': windows_ok, 'runtime_bound': bound,
            'disclaimer': '工程风险关注等级，不是 Anthropic 封禁概率，也不保证账号可用。'}
