"""同一证据生成正向健康报告；历史 PDF 与 JSON 完整保留。"""
import hashlib
import json
import secrets
import sys
from io import BytesIO
from pathlib import Path
from .plain_decisions_v35 import assess, checklist
from .evidence_completion_v33 import remaining_gaps
from .fixed_risk_v33 import SURFACES, STATE_ZH
from .pdf_v31 import e

VERSION = '3.5.health.pdf.1'


def technical_html(report, digest, view, gaps):
    from .pdf_report_renderer import fact_table
    from .pdf_v31 import LAYERS, STATE, describe, brief_value
    out = ['<h1>CC Auditor 3.5 首次使用前完整技术报告</h1><p>' + e(view['headline']) + '<br>' + e(view['disclaimer']) + '</p>',
           '<p>来源运行 ' + e(report['run_id']) + '<br>原始采集版本 ' + e(report['version']) + '；原始时间 ' + e(report['created_at_utc']) + '<br>证据 SHA-256 ' + digest + '<br>模型 ' + e(view['model_version']) + '</p>',
           '<h2>健康分公式与技术行动门槛</h2><p>四端独立计算。适用原始权重归一化为 100，不适用项移出分母。已测通过系数 0，确认故障与必要兼容条件未配置系数 1，部分证据系数 0.15，未取得证据系数 0.35。同一根因保留最高贡献；所有测量缺口合计最多扣 20，按比例缩放回每条账本。十进制 HALF_UP 四舍五入。健康分 = clamp(100 − 确认故障 − 兼容问题 − 有界测量缺口, 0, 100)。确认关键严重阻断时健康分最高 25；下调另列。85–100 优良，70–84 良好，50–69 需关注，0–49 需优先整改。</p>',
           '<p>技术准备要求：有可评估的系统/真实 Profile 基础、必要基础项已通过、没有确认关键阻断、健康分至少 50。全部缺测不会因缺口上限得到“可开始”。缺少 Claude、SDK、账号、历史连接、所在地自述不扣分。未知远端 API 不打整条路径分数；本机接入基础另列。真实资格、覆盖度、实际业务结果独立。</p>']
    if report.get('synthetic'):out.insert(0,'<h2>合成示例，不是本机实测</h2>')
    for s, a in view['surface_assessments'].items():
        score = '未评分' if a['health_score'] is None else str(a['health_score']) + '/100'
        out.append('<h2 class="page">' + e(SURFACES[s]) + '：环境健康分 ' + score + ' · ' + e(a['health_level']) + '</h2><p>适合开始准备：' + e(a['recommend_now']) + '<br>' + e(a['reason']) + '<br>下一步：' + e(a['next_action']) + '<br>实际服务：预检未测试；安装状态 ' + e(a['installation_state']) + '</p>')
        out.append('<h3>扣分账本与覆盖</h3><pre>' + e(json.dumps({'penalties':a['penalties'], 'coverage':a['coverage'], 'confirmed_blockers':a['confirmed_blockers']}, ensure_ascii=False, indent=2)) + '</pre>')
        out.append('<table><tr><th>规则 / 原始权重</th><th>状态 / 归一权重</th><th>扣分 / 证据</th></tr>')
        for row in a['ledger']:
            out.append('<tr><td>' + e(row['rule_id'] + ' · ' + row['title']) + '<br>' + str(row['weight']) + '</td><td>' + STATE_ZH[row['state']] + '<br>' + row['normalized_weight'] + '</td><td>' + row['penalty'] + '<br>' + e('、'.join(row['evidence_ids']) or '无本项证据') + '</td></tr>')
        out.append('</table>')
        for row in a['ledger']:
            out.append('<h3>' + e(row['title']) + '</h3><p>' + e(row['positive'] if row['state']=='passed' else row['problem']) + '<br>根因 ' + e(row['root_cause']) + '；类别 ' + e(row['penalty_category']) + '；去重前 ' + row['penalty_before_dedup'] + '<br>生命周期 ' + e(row['evidence_lifecycle']) + '<br>行动 ' + e(row['action']) + '</p>')
        if s == 'api':
            out.append('<h3>API 执行位置与本机接入边界</h3><pre>' + e(json.dumps({k:a[k] for k in ('execution_mode','actual_request_origin','classification_source','remote_api_path_observed','local_client_readiness','boundary')}, ensure_ascii=False, indent=2)) + '</pre>')
        if s == 'web':
            for p in a['profiles']:
                out.append('<h3>' + e(p['browser_name']+' / '+p['profile_alias']) + '</h3><pre>' + e(json.dumps({k:p[k] for k in ('health_score','technical_environment_ready','coverage','ledger')}, ensure_ascii=False, indent=2)) + '</pre>')
    for title, value in (('地区可观测画像与物理定位边界', view['location_observability']),
                         ('真实资格与三类行动', {'eligibility':view['eligibility'],'scenarios':view['usage_scenarios']}),
                         ('完整自动补证轨迹', report.get('evidence_completion_v33', {'status':'原始来源未记录；离线未新增测量'})),
                         ('当前证据补足事项', gaps), ('应用宿主限定证据', report.get('program_context_v33', {})),
                         ('规则路径关联', report.get('path_evidence_v33', {}))):
        out.append('<h2 class="page">' + title + '</h2><pre>' + e(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre>')
    out.append('<h2 class="page">Windows 与代理当前事实</h2>' + fact_table(report))
    out.append('<h2 class="page">原始全部检测证据</h2><p>原始 points 是旧采集器字段，不是 v3.5 健康扣分。四端有效公式和账本见前文。确认故障、未测、失败、参考和权限状态完整保留。</p>')
    for layer, title in LAYERS.items():
        out.append('<h2>' + e(layer+' · '+title) + '</h2>')
        for item in (x for x in report['checks'] if x.get('layer') == layer):
            explanation, follow = describe(item)
            out.append('<h3>' + e(item['evidence_id']+' · '+item['title']) + '</h3><p>' + e(explanation) + '<br>状态 ' + e(STATE.get(item['state'],item['state'])) + '；视点 ' + e(item.get('scope','')) + '<br>判据 ' + e(item.get('criterion','')) + '<br>说明 ' + e(item.get('reason','')) + '<br>下一步 ' + e(follow) + '<br>来源 '+e(item.get('source',''))+'；时间 '+e(item.get('captured_at_utc',''))+'</p><p>' + e(brief_value(item)) + '</p>')
    for title, value in (('代理规则与配置激活',report.get('target_routes',{})),('全部日常档案',report.get('profiles',[])),('中立测点',report.get('network_events',[])+report.get('independent_network_events',[])),('零接触与清理',{'zero_contact':report.get('zero_contact'), 'cleanup':report.get('cleanup')})):
        out.append('<h2 class="page">' + title + '</h2><pre>' + e(json.dumps(value,ensure_ascii=False,indent=2)) + '</pre>')
    return ''.join(out)


def validate(path, kind, run_id=None, digest=None, assessment_sha=None):
    from .pdf_report_renderer import pdf_backend
    import re
    Reader, _ = pdf_backend(); reader=Reader(str(path),strict=True)
    text=''.join(p.extract_text() or '' for p in reader.pages); compact=re.sub(r'\s+','',text)
    required = {'简明报告':('健康分','首次使用前环境预检','三类行动判断'),
                '完整技术报告':('健康分公式与技术行动门槛','API执行位置与本机接入边界','原始全部检测证据'),
                '证据补足清单':('证据补足清单','为什么还缺','最少操作')}[kind]
    if not reader.pages or '\ufffd' in text or '\u25a1' in text: raise ValueError('invalid_v35_pdf_text')
    if any(x not in compact for x in required): raise ValueError('missing_v35_pdf_sections')
    for p in reader.pages:
        if not (p.extract_text() or '').strip() or not (p.get('/Resources') or {}).get('/Font'): raise ValueError('v35_font_or_text_missing')
    for key, val in (('/CCAuditorRunId',run_id),('/CCAuditorEvidenceSHA256',digest),('/CCAuditorAssessmentSHA256',assessment_sha)):
        if val is not None and reader.metadata.get(key)!=val: raise ValueError('v35_provenance_mismatch')
    if run_id is not None and run_id not in compact: raise ValueError('v35_run_text_corrupt')
    if digest is not None and (digest[:12] if kind=='简明报告' else digest) not in compact: raise ValueError('v35_hash_text_corrupt')
    return {'pages':len(reader.pages),'text_extractable':True,'font_resources_verified':True}


def build(report_path):
    from .preflight_v3 import read, source_build
    from .pdf_report_renderer import pdf_backend
    from .pdf_render_v35 import render_brief, render_html
    from .pdf_v33 import gap_html
    from ..model import canonical
    from ..storage import no_reparse
    report,digest=read(report_path); view=assess(report)
    gaps=checklist(report,remaining_gaps(report,view),view)
    edition='3.6' if str(report['version']).startswith('3.6') else '3.5'
    directory=Path(report_path).parent/('report_v'+edition.replace('.','_'));no_reparse(directory);directory.mkdir(exist_ok=True)
    names=['简明报告','完整技术报告']+(['证据补足清单'] if gaps else [])
    paths=[directory/('CC_Auditor_'+n+'_v'+edition+'.pdf') for n in names]
    Reader,Writer=pdf_backend(); source=source_build()['toolkit_source_sha256']
    assessment={'source_run_id':report['run_id'],'source_sha256':digest,'presentation_version':VERSION,
                'renderer_build_sha256':source,'application_version':report['version'],'offline_reassessment':not str(report['version']).startswith(('3.5','3.6')),**view,'remaining_gaps':gaps}
    assessment_sha=hashlib.sha256(canonical(assessment)).hexdigest()
    for p in paths:no_reparse(p)
    if any(p.exists() for p in paths):
        if all(p.is_file() and Reader(str(p)).metadata.get('/CCAuditorAssessmentSHA256')==assessment_sha for p in paths):
            for n,p in zip(names,paths):validate(p,n,report['run_id'],digest,assessment_sha)
            return dict(zip(names,map(str,paths)))
        raise FileExistsError('preserve_prior_v35_reports')
    stages=[p.with_name('.render-'+secrets.token_hex(8)+'.pdf') for p in paths]
    try:
        layout=render_brief(report,digest,stages[0],view,gaps)
        render_html(technical_html(report,digest,view,gaps).replace('CC Auditor 3.5','CC Auditor '+edition),stages[1],'CC Auditor '+edition+' 完整技术报告')
        if gaps:render_html(('<h2>合成示例，不是本机实测</h2>' if report.get('synthetic') else '')+gap_html(report,digest,gaps),stages[2],'CC Auditor '+edition+' 证据补足清单')
        for n,p in zip(names,stages):
            validate(p,n);reader=Reader(BytesIO(p.read_bytes()));writer=Writer();writer.clone_document_from_reader(reader)
            writer.add_metadata({'/CCAuditorRunId':report['run_id'],'/CCAuditorEvidenceSHA256':digest,
                                 '/CCAuditorAssessmentSHA256':assessment_sha,'/CCAuditorPresentation':VERSION,
                                 '/CCAuditorRendererBuildSHA256':source})
            writer.add_outline_item(n,0);stream=BytesIO();writer.write(stream);p.write_bytes(stream.getvalue())
            validate(p,n,report['run_id'],digest,assessment_sha)
        for tmp,final in zip(stages,paths):tmp.rename(final)
        (directory/'assessment.json').write_text(json.dumps(assessment,ensure_ascii=False,indent=2),encoding='utf-8')
        (directory/'layout.json').write_text(json.dumps(layout,ensure_ascii=False,indent=2),encoding='utf-8')
    finally:
        for p in stages:
            if p.exists():p.unlink()
    return dict(zip(names,map(str,paths)))
