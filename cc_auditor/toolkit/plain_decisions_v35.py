"""健康分同源解释；不再次收集数据或修改评分。"""
from .health_v35 import assess as technical_assess
from .plain_decisions_v33 import checklist, route_reason


def assess(report):
    view = technical_assess(report)
    for surface, a in view['surface_assessments'].items():
        if surface == 'api' and a['health_score'] is None: continue
        if a['confirmed_blockers']: continue
        if a['technical_environment_ready']:
            a['reason'] = '已测基础适合开始技术准备' + ('；仍有路径或测点待核对' if a['critical_missing_keys'] else '')
        elif surface == 'web':
            a['reason'] = '日常浏览器档案或必要页面能力尚未完成核验'
        else:
            a['reason'] = '所选执行环境基础尚未完成核验；没有把缺测当故障'
    view['explanation_version'] = '3.5.health.plain.1'
    return view


def actions(report, view, gaps):
    selected = [view['surface_assessments'][s] for s in view['selected_surfaces']]
    out = []
    for a in selected:
        if a['confirmed_blockers']: out.append(a['next_action'])
    if any('route' in a['critical_missing_keys'] for a in selected):
        out.append('由工具核对实际代理入口和离线规则分支；无需先访问 Claude。')
    if gaps:
        out.append('按补证清单优先复核当前缺口；测点失败不等于网络故障。')
    if 'api' in view['unmeasured_execution_surfaces']:
        out.append('先确认 API 由本机、云端平台还是网关发送；本机出口不代表云端。')
    out.append('可以先做技术准备；注册和付款前另行核对真实资格与服务条件。')
    return list(dict.fromkeys(out))[:3]
