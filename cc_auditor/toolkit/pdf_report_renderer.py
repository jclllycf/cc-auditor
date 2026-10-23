"""同一不可变 JSON → 两份中文 PDF；仅使用已有 Qt，离线渲染，不启动浏览器。"""
import html
import json
import sys
import re
from io import BytesIO
from pathlib import Path
from .preflight_v3 import read,STATE_ZH

_APP=None
def _e(value):return html.escape(str(value),quote=True)
def _value(value):
    text=json.dumps(value,ensure_ascii=False,sort_keys=True) if isinstance(value,(dict,list)) else str(value)
    return _e(text)

def _yes(value):return '是' if value is True else '否' if value is False else '未取得有效结果'

def _binding(value):
    return {'user_attested_targeted_launch_browser_pid':'用户确认并定向打开，回调进程已关联；档案身份仍是部分证据','user_attested_targeted_launch_only':'用户确认并定向打开，回调进程未独立关联','unverified':'未完成归属核验'}.get(value,'尚未核验')

def fact_table(report):
    byid={c['id']:c['value'] if c['state'] in ('passed','fault','reference') else None for c in report['checks']};locale=byid.get('locale') or {};proxy=byid.get('proxy_registry_ok') or {};tun=byid.get('adapters_ok') or {}
    software=(report.get('proxy_discovery') or {}).get('software',[])
    probes=[p for p in report.get('generic_probe_egress',[]) if p.get('status')=='observed' and p.get('source')=='generic_neutral_probe']
    countries=sorted({p['country_code'] for p in probes if p.get('country_code')})
    rows=[('系统语言',', '.join(locale.get('ui_languages',[])) or locale.get('format_language') or '未取得'),('系统时区',locale.get('timezone') or '未取得'),
          ('系统代理开关',_yes(proxy.get('system_proxy_enabled'))),('系统代理地址',proxy.get('system_proxy_sanitized') or '未配置或未取得'),
          ('已发现运行的代理软件',', '.join(dict.fromkeys(p['executable'] for p in software)) or '未发现 / 未授权'),
          ('TUN 接管 IPv4 / IPv6',_yes(tun.get('tun_owns_ipv4_default_route'))+' / '+_yes(tun.get('tun_owns_ipv6_default_route'))),
          ('Windows VPN 已连接数量',str(tun.get('windows_vpn_connected_count','未取得'))),
          ('中立探针出口国家代码',', '.join(countries) or '本轮未取得有效国家数据'),('Claude 各入口最终出口','本轮尚无独立证据；不能用上项代替')]
    return '<table><tr><th>当前实测/配置事实</th><th>结果</th></tr>'+''.join('<tr><td>'+_e(a)+'</td><td>'+_e(b)+'</td></tr>' for a,b in rows)+'</table>'

def documents(report,digest):
    s=report['summary'];rid=report['run_id'];score=str(s['technical_score'])+'/100' if s['technical_score'] is not None else '证据不足，暂不评总体分'
    common=f"<p class='meta'>报告 {rid}<br>扫描 {report['created_at_utc']} · 版本 {report['version']} · 规则 {report['ruleset']}</p>"
    if report.get('synthetic'):common+='<p><b>合成测试报告：仅用于软件回归，不是这台电脑的实测结论。</b></p>'
    metrics=f"<table><tr><th>技术就绪</th><th>有效结论覆盖</th><th>通过 / 异常 / 参考 / 未充分检测</th></tr><tr><td>{score}</td><td>{s['coverage_percent']}%（{s['observed']}/{s['applicable']}）</td><td>{s['passed']} / {s['faults']} / {s['reference']} / {s['unknown']}</td></tr></table>"
    ranked=sorted(report['checks'],key=lambda c:0 if c['state']=='fault' else 1 if c['id'].startswith('target_egress') else 2 if c['state'] in ('unknown','partial','failed') else 3)
    seen=set();issues=[]
    for c in ranked:
        key='target_final_egress' if c['id'].startswith('target_egress') else c['issue_id']
        if key not in seen:issues.append(c);seen.add(key)
    style="""<style>body{font-family:'Microsoft YaHei','SimSun';font-size:10pt;color:#243d45}h1{font-size:25pt;color:#155e69;margin:8px 0}h2{font-size:17pt;color:#155e69;margin-top:20px}h3{font-size:12pt;margin-top:16px}p{line-height:145%}table{border-collapse:collapse;width:100%;margin:12px 0}td,th{border:1px solid #cbd9dc;padding:7px;text-align:left;vertical-align:top}th{background:#e8f0f1}.meta{font-size:8pt;color:#4c6871}.page{page-break-before:always}.note{background:#edf4f4}pre{white-space:pre-wrap;font-size:8pt}</style>"""
    short=[style,'<h1>CC Auditor</h1><h2>简明使用前检测报告</h2>',common,
        '<h2>'+_e(s['conclusion'])+'</h2>',metrics,
        '<p>分数只反映工程技术检查，不能预测封禁或替代真实使用资格。未知不扣成故障，也不算通过。</p>',
        '<p>已测正常项目（节选）：'+_e('、'.join([c['title'] for c in report['checks'] if c['state']=='passed'][:6]) or '目前没有足够有效测量')+'。</p>',
        fact_table(report)]
    short.extend(["<h2 class='page'>各入口与日常浏览器</h2>",'<table><tr><th>入口</th><th>本次结论与边界</th></tr>'])
    for surface,title in [('desktop','Desktop 桌面端'),('web','Web 网页端'),('cli','Code CLI'),('api','API 调用端')]:
        short.append('<tr><td>'+title+'</td><td>基础条件见已测项；目标最终公网出口尚未验证。通用 IP 回显不能替代此入口。</td></tr>')
    short.append('</table><p>注册资格：'+_e(s['policy_eligibility'])+'</p>')
    for p in report['profiles'][:5]:
        short.append('<p><b>'+_e(p['browser_name']+' / '+p['profile_alias'])+'</b>：静态 '+('已查' if p['static_profile_checked'] else '未完成')+'；动态 '+('收到本工具页面回调' if p['dynamic_profile_checked'] else '尚未完成')+'；'+_e(_binding(p.get('profile_binding')))+'；工具实验键 '+('页面报告已清理' if p.get('cleanup_status')=='reported_clean' else '未做或未证实清理')+'。</p>')
    if len(report['profiles'])>5:short.append('<p>另有 '+str(len(report['profiles'])-5)+' 个真实档案，完整技术版逐个列出。</p>')
    short.append('<h3>代理与出口要分清</h3><p>GUI / 内核 / 监听 / 配置 / 生效路径分别判断。已有 Claude 进程不扣分，不应为提高得分关闭正常工作客户端。没有独立证据时，链式代理的最终出口保持未知。</p>')
    short.extend(["<h2 class='page'>本次做了什么，接下来怎么做</h2>",
        '<p>授权范围：'+_e('、'.join(report['approval']['scopes']))+'。没有主动打开、刷新或请求 Claude；既有程序或 Agent 自身通信不属于扫描器的零接触审计。</p>',
        '<p>中立测点 HTTP 请求：确认已发 '+str(sum(x.get('request_sent') is True for x in report['network_events']))+' 次；是否已发不明 '+str(sum(x.get('request_sent') is None for x in report['network_events']))+' 次。此计数不包含 DNS/TCP/TLS 握手，也不是整机抓包计数。对方及 Agent 云模型可能接收披露的信息，本地清理不能撤回。</p>',
        '<p>1. 先处理已证实的技术问题，保持证书校验。<br>2. 按真实条件核对所在地和主体资格，不从 IP、语言、时区判断身份。<br>3. 对未充分检查的日常 Profile 或路径，在明确授权下补充证据。<br>4. 不擅自改代理、节点、DNS 或清除整个 Profile；检测器仅清理自己的实验键。</p>',
        '<p>本次原有 Profile 设置未修改；报告保存在本机。完整技术版保留全部测点、来源与未知原因。</p>',
        "<p class='meta'>同一 JSON SHA-256："+digest+'</p>'])
    short.append('<h3>本次最需要补足的证据</h3>')
    for c in issues[:3]:short.append('<p>'+_e(c['evidence_id']+' · '+c['title'])+'：'+STATE_ZH[c['state']]+'。'+_e(c['reason'] or c['criterion'])+'</p>')
    full=[style,'<h1>CC Auditor</h1><h2>全项目详细检测报告</h2>',common,metrics,'<p>'+_e(s['deduplication'])+'</p>',
        '<p>已测子集参考分：'+str(s['measured_subset_score'])+'；总体可否评分由覆盖门槛单列，不将低覆盖满分称为全面正常。</p>',
        '<h2>目录</h2><p>一、本轮授权与执行边界<br>二、十二层全部检查与证据<br>三、逐日常 Profile 状态<br>四、代理配置模拟和已有连接<br>五、中立探针及清理记录</p>',
        '<h2>一、本轮授权与执行边界</h2><p>'+_value(report['approval'])+'</p><p>执行源码：'+_value(report.get('source_build'))+'</p><p>证据完整性 SHA-256：'+digest+'</p>',
        "<h2 class='page'>二、十二层全部检查与证据</h2>"]
    for layer in ('L'+str(i).zfill(2) for i in range(1,13)):
        full.append('<h2>'+layer+'</h2>')
        for c in [x for x in report['checks'] if x['layer']==layer]:
            full.append('<h3>'+_e(c['evidence_id']+' / '+c['id']+' / '+c['title'])+'</h3><p><b>'+STATE_ZH[c['state']]+'</b>；范围 '+_e(c['scope'])+'；扣分 '+str(c['points'])+'；问题标识 '+_e(c['issue_id'])+'<br>来源 '+_e(c['source'])+'；时间 '+_e(c['captured_at_utc'])+'<br>标准：'+_e(c['criterion'])+'<br>依据：'+_e(c['reason'] or '仅按本次有效测量/权限判断，缺少数据时保留未知。')+'<br>下一步：'+_e(c['next_step'])+'</p><p class="meta">证据摘要：'+_value(c['value'])+'</p>')
    full.append("<h2 class='page'>三、逐日常 Profile 状态</h2>")
    for p in report['profiles']:full.append('<h3>'+_e(p['browser_name']+' / '+p['profile_alias'])+'</h3><p>'+_value(p)+'</p>')
    full.extend(["<h2 class='page'>四、代理配置模拟和已有连接</h2>",'<p>以下标签已匿名化。节点命名不证明国家；配置存在不证明启用；规则表命中不证明最终公网出口。未联系目标域名。</p><p>'+_value(report['target_routes'])+'</p>',
        "<h2 class='page'>五、中立探针及清理记录</h2>",'<p>'+_value(report['network_events'])+'</p><p>'+_value(report['zero_contact'])+'</p><p>'+_value(report['cleanup'])+'</p><p>采集器异常：'+_value(report.get('collector_errors',[]))+'</p>',
        '<p>服务端私有规则、账号历史、物理所在地、真实注册/付费结果并非本机预检可知数据。所有模拟和未测项已在证据状态中分开。</p>'])
    return ''.join(short),''.join(full)

def render(text,path,title):
    global _APP
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QTextDocument,QPdfWriter,QPageSize,QPageLayout,QPainter,QFont
    from PySide6.QtCore import QSizeF,QMarginsF,QRectF,Qt
    _APP=QApplication.instance() or QApplication([])
    writer=QPdfWriter(str(path));writer.setResolution(96);writer.setTitle(title);writer.setCreator('CC Auditor 3 - local Qt renderer')
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4));writer.setPageMargins(QMarginsF(15,15,15,18))
    doc=QTextDocument();doc.setDefaultFont(QFont('Microsoft YaHei',10));doc.setHtml(text)
    rect=writer.pageLayout().paintRectPixels(96);height=rect.height()-26;doc.setPageSize(QSizeF(rect.width(),height))
    painter=QPainter(writer)
    try:
        for page in range(doc.pageCount()):
            if page:writer.newPage()
            painter.save();painter.setClipRect(QRectF(0,0,rect.width(),height));painter.translate(0,-page*height)
            doc.drawContents(painter,QRectF(0,page*height,rect.width(),height));painter.restore()
            painter.setFont(QFont('Microsoft YaHei',8));painter.drawText(QRectF(0,height+5,rect.width(),20),Qt.AlignmentFlag.AlignCenter,f'CC Auditor · {page+1} / {doc.pageCount()}')
    finally:painter.end()
    if not path.is_file() or path.stat().st_size<1000:raise ValueError('pdf_generation_failed')
    return doc.pageCount()

def build_legacy_pdf_reports(report_path):
    report,digest=read(report_path);directory=Path(report_path).parent;rid=report['run_id']
    paths=[directory/f'CC_Auditor_简明报告_{rid}.pdf',directory/f'CC_Auditor_完整技术报告_{rid}.pdf']
    from ..storage import no_reparse
    for path in paths:no_reparse(path)
    if all(p.is_file() for p in paths):
        PdfReader,_=pdf_backend()
        if all(p.stat().st_size<32*1024*1024 and PdfReader(str(p)).metadata.get('/CCAuditorEvidenceSHA256')==digest and PdfReader(str(p)).metadata.get('/CCAuditorRunId')==rid for p in paths):return {'简明报告':str(paths[0]),'完整技术报告':str(paths[1])}
        raise ValueError('existing_pdf_does_not_match_evidence')
    if any(p.exists() for p in paths):raise FileExistsError('partial_pdf_pair_exists_keep_json')
    for text,path,title in zip(documents(report,digest),paths,('简明使用前预检','全项目详细使用前预检')):
        render(text,path,title);add_outlines(path,'完整' in path.name,rid,digest)
    return {'简明报告':str(paths[0]),'完整技术报告':str(paths[1])}


def build_pdf_reports(report_path):
    report,_=read(report_path)
    if str(report.get('version','')).startswith(('3.5','3.6')):
        from .pdf_v35 import build
        return build(report_path)
    from .pdf_v33 import build
    return build(report_path)


def pdf_backend():
    vendor=Path(__file__).parent.parent/'_vendor_pdf'
    if vendor.is_dir() and str(vendor) not in sys.path:sys.path.insert(0,str(vendor))
    from pypdf import PdfReader,PdfWriter
    return PdfReader,PdfWriter


def add_outlines(path,technical,rid,digest):
    PdfReader,PdfWriter=pdf_backend()
    reader=PdfReader(BytesIO(path.read_bytes()));writer=PdfWriter();writer.clone_document_from_reader(reader)
    writer.add_metadata({'/CCAuditorEvidenceSHA256':digest,'/CCAuditorRunId':rid})
    texts=[re.sub(r'\s+','',p.extract_text()) for p in reader.pages]
    sections=['一、本轮授权与执行边界','二、十二层全部检查与证据','三、逐日常Profile状态','四、代理配置模拟和已有连接','五、中立探针及清理记录'] if technical else ['简明使用前检测报告','各入口与日常浏览器','本次做了什么，接下来怎么做']
    writer.add_outline_item('CC Auditor · '+('完整技术报告' if technical else '简明报告'),0)
    for title in sections:
        candidates=[i for i,t in enumerate(texts) if title in t]
        if not candidates:raise ValueError('pdf_section_missing')
        writer.add_outline_item(title,max(candidates))
    if technical:
        parent=writer.add_outline_item('十二层逐项证据',next(i for i,t in enumerate(texts) if 'L01' in t))
        for n in range(1,13):
            layer='L'+str(n).zfill(2);page=next(i for i,t in enumerate(texts) if layer in t);writer.add_outline_item(layer,page,parent=parent)
    output=BytesIO();writer.write(output);path.write_bytes(output.getvalue())
