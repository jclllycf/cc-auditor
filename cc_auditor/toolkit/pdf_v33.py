"""单值决策报告、逐证据技术报告、条件式补证清单。只重排已保存的证据。"""
import hashlib,json,secrets,sys
from pathlib import Path
from io import BytesIO
from .fixed_risk_v33 import SURFACES,STATE_ZH,FACTORS
from .plain_decisions_v33 import assess,checklist,actions
from .evidence_completion_v33 import remaining_gaps
from .pdf_v31 import e

VERSION='3.4.preuse.4'
APP=None
INSTALL_ZH={'not_required':'无需安装客户端','not_installed':'尚未安装或创建','installed':'已发现安装资料','unknown':'安装资料未核对'}

def short_pdf(report,digest,path,view,gaps):
    from .pdf_render_v34 import render_brief
    return render_brief(report,digest,path,view,gaps)

def technical_html(report,digest,view,gaps):
    from .pdf_report_renderer import fact_table
    from .pdf_v31 import LAYERS,STATE,describe,brief_value
    style='<style>body{font-family:Microsoft YaHei,SimSun;font-size:9pt;color:#263c43}h1{font-size:24pt;color:#195e63}h2{font-size:15pt;color:#195e63;margin-top:20px}h3{font-size:10pt;margin-top:13px}p{line-height:135%;margin:5px 0}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d6e0df;padding:5px;text-align:left}th{background:#eff4f2}.page{page-break-before:always}.meta{font-size:7pt;color:#526b72}pre{white-space:pre-wrap;font-family:Microsoft YaHei;font-size:8.5pt;}</style>'
    out=[style,'<h1>CC Auditor 3.4 首次使用前完整技术报告</h1><p>'+e(view['headline'])+'<br>'+e(view['disclaimer'])+'</p>',
         '<p>来源运行 '+e(report['run_id'])+'；原始采集版本 '+e(report['version'])+'；原始时间 '+e(report['created_at_utc'])+'<br>原始 JSON SHA-256 '+digest+'<br>模型 '+e(view['model_version'])+'</p>',
         '<h2>确定指数与行动门槛</h2><p>各端基础权重合计 100。适用权重归一化到 100；不适用移出分母。状态系数：完成 0、确认故障 1、未配置 1、部分证据 0.25、未取得证据 0.55。同一实际根因只保留最大贡献；未知不是确认故障。贡献总和采用十进制四舍五入取整数（HALF_UP）。确认关键严重故障时指数至少 75，单列下限调整。0–24 低关注；25–49 中等；50–74 高；75–100 严重。分数未用账户封禁样本校准。</p>',
         '<p>“适合开始准备：是”要求指数小于 50、未确认最低技术项故障或必要的本机基础条件未配置、用户真实资格自述满足本地政策参考。未测与故障分开记账；部分证据可以贡献工程关注指数，但无需先安装或运行 Claude。服务端决策、实际账号状态及最终公网出口均不由本报告证明。</p>']
    for s,a in view['surface_assessments'].items():
        out.append('<h2 class="page">'+e(SURFACES[s])+'：'+str(a['risk_index'])+'/100 · '+e(a['risk_level'])+' · 适合开始准备：'+a['recommend_now']+'</h2><p>'+e(a['reason'])+'<br>下一步：'+e(a['next_action'])+'<br>安装状态 '+e(a['installation_state'])+'；配置状态 '+e(a['configuration_state'])+'；实际可运行证明 '+e(a['operational_verification'])+'</p>')
        out.append('<p>确认故障贡献 '+a['confirmed_fault_contribution']+'；条件未配置贡献 '+a['missing_condition_contribution']+'；部分/缺证审慎贡献 '+a['evidence_gap_contribution']+'；严重故障下限调整 '+str(a['critical_floor_adjustment'])+'</p><table><tr><th>规则 / 原始权重</th><th>状态 / 归一权重</th><th>最终贡献 / 证据</th></tr>')
        for r in a['ledger']:out.append('<tr><td>'+e(r['rule_id'])+'<br>'+e(r['title'])+' / '+str(r['weight'])+'</td><td>'+STATE_ZH[r['state']]+'<br>'+r['normalized_weight']+'<br>'+e(r['evidence_lifecycle'])+'</td><td>'+r['contribution']+'<br>'+e('、'.join(r['evidence_ids']) or '来源中无本范围证据')+'</td></tr>')
        out.append('</table>')
        for r in a['ledger']:out.append('<h3>'+e(r['title'])+'</h3><p>'+e(r['positive'] if r['state']=='passed' else r['problem'])+'<br>最低条件：'+str(r['critical_minimum'])+'；根因 '+e(r['root_cause'])+'；去重前贡献 '+r['contribution_before_dedup']+'<br>行动：'+e(r['action'])+'</p>')
        if s=='web':
            out.append('<p>'+e(a['aggregation'])+'；参与档案 '+e('、'.join(a['selected_profile_keys']))+'</p>')
            for p in a['profiles']:out.append('<h3>'+e(p['browser_name']+' / '+p['profile_alias'])+'</h3><pre>'+e(json.dumps({k:p[k] for k in ('profile_key','risk_index','recommend_now','reason','ledger')},ensure_ascii=False,indent=2))+'</pre>')
    for title,value in (('三类使用决策与条件',view['usage_scenarios']),('自动补证完整轨迹',report.get('evidence_completion_v33',{'status':'历史来源没有记录；本次离线未执行补证'})),('应用宿主限定证据',report.get('program_context_v33',{'status':'来源未采集'})),('路径关联与归因边界',report.get('path_evidence_v33',{})),('Windows 与浏览器地区参考',report.get('browser_region_signals',{'status':'来源未采集'})),('最终关键缺口',gaps)):
        out.append('<h2 class="page">'+title+'</h2><pre>'+e(json.dumps(value,ensure_ascii=False,indent=2))+'</pre>')
    out.append('<h2 class="page">Windows 与代理的当前事实</h2>'+fact_table(report))
    out.append('<h2 class="page">十二层原始逐项测量（独立于本版指数）</h2>')
    out.append('<p>以下只展示采集时的原始判据、状态及来源。原始 points 字段属于历史采集器标注，并非 v3.4 风险扣分；本版唯一有效计分依据为前文四端评分账本。</p>')
    for layer,title in LAYERS.items():
        out.append('<h2>'+e(layer+' · '+title)+'</h2>')
        for item in (c for c in report['checks'] if c.get('layer')==layer):
            explanation,follow=describe(item)
            out.append('<h3>'+e(item['evidence_id']+' · '+item['title'])+'</h3>')
            out.append('<p>'+e(explanation)+'<br>原始状态：'+e(STATE.get(item['state'],item['state']))+'；视点 '+e(item.get('scope',''))+'<br>判据：'+e(item.get('criterion',''))+'<br>说明：'+e(item.get('reason') or '仅在本次测量范围内解释')+'<br>下一步：'+e(follow)+'</p>')
            out.append('<p class="meta">检查 '+e(item['id'])+' · 来源 '+e(item.get('source',''))+' · 采集 '+e(item.get('captured_at_utc',''))+' · 摘要 '+e(brief_value(item))+'</p>')
    out.append('<h2 class="page">代理规则、已有连接与浏览器档案</h2>')
    for title,value in (('离线规则与激活记录',report.get('target_routes',{})),('日常浏览器档案',report.get('profiles',[])),('中立网络接收端',report.get('network_events',[])+report.get('independent_network_events',[])),('零 Anthropic 接触记录',report.get('zero_contact',{}))):
        out.append('<h3>'+e(title)+'</h3><pre>'+e(json.dumps(value,ensure_ascii=False,indent=2))+'</pre>')
    out.append('<p>客户端缺席和历史连接缺席不构成预检故障；已有连接仅可用于研发校准。规则模拟、中立测点和实际服务端出口属于不同证据视点。账号、注册、支付及服务端判定仍需真实服务确认。</p>')
    return ''.join(out)

def gap_html(report,digest,gaps):
    out=['<style>body{font-family:Microsoft YaHei;color:#17373b;font-size:11pt}h1{font-size:23pt}h2{font-size:15pt;color:#99611b}p{line-height:155%}</style><h1>证据补足清单</h1><p>只列自动补证后仍影响本次计划的关键缺口。没有把缺测当故障；不会要求提供密码、Cookie、Key 或身份/付款文件。</p>']
    if not report.get('evidence_completion_v33'):out.append('<p><b>本份来自历史实测的离线重排：原始数据没有 v3.3 自动补证记录，本次未执行新增检测。以下是历史资料缺口，不能当作新版已尝试仍失败。</b></p>')
    for i,g in enumerate(gaps,1):
        tried='；'.join(a['source']+'：'+a['status']+'（第'+str(a.get('attempt',1))+'次）' for a in g['attempts']) or '历史来源未记录该自动尝试；本次离线重排未执行，或该项只能由本人声明'
        out.append('<h2>'+str(i)+' · '+e(g['title'])+'</h2><p><b>为什么还缺：</b>'+e(g['final_reason'])+'<br><b>已经尝试：</b>'+e(tried)+'<br><b>最少操作：</b>'+e(g['minimum_action'])+'<br><b>价值：</b>'+e(g['value'])+'<br>优先级 '+e(g['priority'])+'；所需范围 '+e(g['consent_scope'])+'</p>')
    out.append('<p>同一来源运行 '+e(report['run_id'])+'<br>原始证据 SHA-256 '+digest+'</p>');return ''.join(out)

def build(report_path):
    from .preflight_v3 import read,source_build
    from .pdf_report_renderer import pdf_backend
    from .pdf_render_v34 import render_html as render
    from .pdf_v34_validation import validate_pdf
    from ..model import canonical
    from ..storage import no_reparse
    report,digest=read(report_path);view=assess(report);gaps=checklist(report,remaining_gaps(report,view),view)
    directory=Path(report_path).parent/'report_v3_4';no_reparse(directory);directory.mkdir(exist_ok=True)
    names=['简明报告','完整技术报告']+(['证据补足清单'] if gaps else []);paths=[directory/('CC_Auditor_'+n+'_v3.4.pdf') for n in names]
    PdfReader,PdfWriter=pdf_backend();source=source_build()['toolkit_source_sha256']
    renderer_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest() if not getattr(sys,'frozen',False) else source
    model_sha=hashlib.sha256(Path(__file__).with_name('fixed_risk_v33.py').read_bytes()+Path(__file__).with_name('evidence_completion_v33.py').read_bytes()).hexdigest() if not getattr(sys,'frozen',False) else source
    assessment={'source_run_id':report['run_id'],'source_sha256':digest,'presentation_version':VERSION,'renderer_sha256':renderer_sha,'model_sha256':model_sha,**view,'remaining_gaps':gaps}
    assessment_sha=hashlib.sha256(canonical(assessment)).hexdigest()
    for p in paths:no_reparse(p)
    if not gaps and (directory/'CC_Auditor_证据补足清单_v3.4.pdf').exists():raise FileExistsError('preserve_prior_model_checklist')
    if any(p.exists() for p in paths):
        if all(p.is_file() and PdfReader(str(p)).metadata.get('/CCAuditorAssessmentSHA256')==assessment_sha for p in paths):
            for name,p in zip(names,paths):validate_pdf(p,name,report['run_id'],digest,assessment_sha)
            return dict(zip(names,map(str,paths)))
        raise FileExistsError('preserve_existing_v34_report_set')
    staged=[p.with_name('.render-'+secrets.token_hex(8)+'.pdf') for p in paths]
    try:
        layout=short_pdf(report,digest,staged[0],view,gaps);render(technical_html(report,digest,view,gaps).replace('Microsoft YaHei','CC Auditor Sans SC'),staged[1],'CC Auditor 完整技术报告 3.4')
        if gaps:render(gap_html(report,digest,gaps).replace('Microsoft YaHei','CC Auditor Sans SC'),staged[2],'CC Auditor 证据补足清单 3.4')
        for name,p in zip(names,staged):
            validate_pdf(p,name)
            reader=PdfReader(BytesIO(p.read_bytes()));wr=PdfWriter();wr.clone_document_from_reader(reader)
            wr.add_metadata({'/CCAuditorEvidenceSHA256':digest,'/CCAuditorRunId':report['run_id'],'/CCAuditorPresentation':VERSION,'/CCAuditorAssessmentSHA256':assessment_sha,'/CCAuditorModelSHA256':model_sha,'/CCAuditorRendererSourceSHA256':renderer_sha,'/CCAuditorRendererBuildSHA256':source});wr.add_outline_item(name,0)
            stream=BytesIO();wr.write(stream);p.write_bytes(stream.getvalue())
            validate_pdf(p,name,report['run_id'],digest,assessment_sha)
        for tmp,final in zip(staged,paths):tmp.rename(final)
        (directory/'assessment.json').write_text(json.dumps(assessment,ensure_ascii=False,indent=2),encoding='utf-8')
        (directory/'layout.json').write_text(json.dumps(layout,ensure_ascii=False,indent=2),encoding='utf-8')
    finally:
        for p in staged:
            if p.exists():p.unlink()
    return dict(zip(names,map(str,paths)))
