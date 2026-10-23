"""v3.1 一页白话结论 + 逐项技术报告。旧证据与旧 PDF 永不覆盖。"""
from __future__ import annotations
import hashlib
import html
import json
from pathlib import Path
from .risk_v31 import assess

VERSION='3.1.0'
APP=None
LAYERS={'L01':'电脑与系统基础','L02':'代理软件与配置','L03':'IPv6、网卡与接管','L04':'DNS 实际去向',
        'L05':'各应用路径与探针出口','L06':'IP 注册、路由与声誉参考','L07':'TLS / HTTP 接收端',
        'L08':'证书与连接安全','L09':'日常浏览器档案','L10':'页面能力与独立网络实测','L11':'浏览器扩展能力','L12':'规则与既有连接研究'}
STATE={'passed':'已测通过','fault':'已确认异常','reference':'取得参考事实','partial':'仅有部分证据',
       'unknown':'需要补测','failed':'本轮未取得有效结果','unsupported':'尚无适用接收端','permission':'本轮未批准此项'}
EXPLAIN={
 'proxy_rules':('核对每个 Claude 入口假设会走的规则和转发链。','读取当前内核规则和选择状态；配置模拟不能替代实际连接。'),
 'proxy_inventory':('找出真正运行的代理内核，区分软件安装、进程运行和网络接管。','结合 PID、监听、TUN/系统代理和控制接口核对。'),
 'existing_client':('只观察已经存在的客户端连接，不产生新的 Claude 请求。','取得只读连接快照；没有记录不代表没有联网。'),
 'dns_receiver':('DNS 把域名翻译成地址；本项查看独立权威端实际看到谁来查询。','获批后以随机测试名查询；分别保存系统与浏览器所见解析器，不自动把不同解析器判为泄漏。'),
 'ipv6_bypass':('IPv6 是另一条网络通道，可能与 IPv4 使用不同路线。','分别核对真实浏览器和 Python 的 IPv4/IPv6 回显；失败不是确认旁路。'),
 'webrtc_stun':('WebRTC 是浏览器语音/视频数据通道；STUN 回显 UDP 的公网地址。','获批后用独立 STUN 接收端观察；与 HTTPS 不同只表示需核对路径。'),
 'browser_tls_fingerprint':('JA3/JA4 是网站可观察的 TLS 握手摘要，不是身份或封禁概率。','必须由真实浏览器连接独立接收端，不能使用 Python 的 TLS 结果代替。'),
 'neutral_tls':('检查 Python 探针到中立网站的加密连接。','仅适用于当前 Python 进程，不证明真实浏览器或 Claude 的握手。'),
 'tls_bypass':('检查检测器继承的环境有没有明确关闭证书验证。','只代表本进程可见的环境；不能推及受保护进程。'),
 'locale':('显示语言和时区只是这台电脑的设置。','不从语言、时区、民族、国籍或出口推断所在地或处罚。'),
 'generic_probe':('查询本检测器访问普通查 IP 网站时的出口。','与 Claude 的目标、进程条件不同，不能跨入口归因。'),
 'claude_processes':('已有 Claude 和辅助进程是正常环境事实。','不因进程存在或数量扣分，不关闭、重启用户应用。'),
 'proxy_signatures':('检查代理文件的本地缓存签名结果。','离线签名不是发布者真实性或无恶意行为证明；缺签名不自动扣分。'),
 'pac_evaluation':('PAC 脚本可让不同网址走不同代理。','本工具不运行未知脚本；配置存在不等于已经知道其实际决策。'),
}


def e(v):return html.escape(str(v),quote=True)


def describe(c):
    key=c['id']
    if key.startswith('target_egress_'):
        return ('确认该入口访问 Claude 时最终对外呈现的公网地址。','需要与该入口绑定的独立证据；通用查 IP、节点名、第一跳均不能代替。')
    if key in EXPLAIN:return EXPLAIN[key]
    if '_identity' in key:return ('区分用户日常档案与其他档案，避免用空白环境代替。','用户勾选、定向启动及浏览器 PID 只是部分归属证据，不可伪造身份尚未实现。')
    if key.endswith('_dynamic'):return ('在所选日常档案中打开工具自己的测试页。','收到本轮随机令牌回调才算运行完成；没有窗口时请手动开普通空白页后补测。')
    if key.endswith('_static'):return ('只读指定设置，了解该日常档案的代理/DNS/WebRTC 配置。','不读取 Cookie、账号或历史；配置值不等于已发生的流量。')
    if key.endswith('_extensions'):return ('扩展有能力影响网络或页面，但能力不代表实际行为。','只读取匿名权限类别，不从权限数推断已注入 Claude。')
    if key.endswith('_cleanup'):return ('清理本工具页面创建的随机实验键。','页面回报不等于操作系统级无残留；不删除用户历史或会话。')
    if c['layer']=='L10':return ('检测本工具页面的 '+c['title']+' 可用性。','只代表当前工具 origin；API 存在不证明远程握手或 Claude 网站可用。')
    if c['layer']=='L06':return ('解释普通探针 IP 的公开注册/路由/供应商标签。','注册国家不等于地理位置；供应商分数不是 Claude 风险，冲突需保留。')
    return (c['title']+'：本轮本机条件或配置事实。',c['criterion'])


def brief_value(c):
    v=c.get('value')
    if v is None:return '本轮没有可供下结论的有效测量。'
    if type(v) is bool:return '是' if v else '否'
    if c['id']=='proxy_rules':
        return '候选配置 '+str(len(v.get('configs',[])))+' 份；控制器有效响应记录 '+str(sum(x.get('status')=='observed' for x in v.get('controllers',[])))+' 条（同一内核可能重复）；既有目标连接快照记录 '+str(len(v.get('existing_connections',[])))+' 条。详细链路见后文。'
    if c['id']=='claude_processes':return '现有 Claude 进程 '+str(v.get('count','未取得'))+' 个；仅作事实，扣分 0。'
    if c['id']=='generic_probe':return '中立探针 '+str(len(v))+' 条结果；按目标和执行者分别记录。见网络接收端记录。'
    if isinstance(v,list):
        if not v:return '没有有效记录；不推断从未发生。'
        return '；'.join(str(x) if not isinstance(x,dict) else '、'.join(k+'='+str(x[k]) for k in ('status','kind','resolver_ip','mapped_ip','ip','tls','rpki_state','count') if k in x) or '已保存结构化参考证据，见同一 JSON' for x in v[:4])[:450]
    if isinstance(v,dict):
        fields=[k+'：'+str(x) for k,x in v.items() if not isinstance(x,(dict,list)) and k not in ('reason','scope')]
        return '；'.join(fields)[:450] or '结构化证据已保存于同一 JSON；见相关档案/链路记录。'
    return str(v)[:450]


def card_content(report,risk):
    profiles=report.get('profiles') or [];labels=[]
    selected=set(report.get('approval',{}).get('profiles',[]))
    for name in dict.fromkeys(p['browser_name'] for p in profiles):
        ps=[p for p in profiles if p['browser_name']==name]
        done=sum(bool(p.get('dynamic_profile_checked')) for p in ps)
        unselected=sum(p['profile_key'] not in selected for p in ps) if 'profiles' in report.get('approval',{}) else 0
        labels.append(name.replace('Google ','').replace('Microsoft ','')+'：'+('本轮未选择动态检查' if unselected==len(ps) else str(done)+' 个已测，'+str(len(ps)-done)+' 个待补'))
    if not labels:labels=['本轮没有日常档案的有效页面结果。']
    measured=[c['id'] for c in report['checks'] if c['id'] in ('dns_receiver','ipv6_bypass','webrtc_stun') and c['state'] in ('reference','passed')]
    return [
        ('电脑基础', '正常' if risk['windows_ok'] else '需要核对',
         'Windows、内存与可用空间已查。证书检查只代表本轮可见范围。' if risk['windows_ok'] else '安装基础条件尚未全部通过，先看技术版中的具体结果。'),
        ('代理与 Claude 路线','重点补检' if risk['action_level']!='green' else '已核对',
         '已读到内核运行规则；各入口最后出口仍需独立证据。' if risk['runtime_bound'] else '找到了代理线索，但还没读到当前生效规则；普通查 IP 不能代替 Claude 路线。'),
        ('日常浏览器','分别看结果','；'.join(labels[:2])+('。其余浏览器见技术版。' if len(labels)>2 else '。')),
        ('DNS / IPv6 / 语音通道','已取得部分实测' if measured else '需要补测',
         '独立接收端取得 '+str(len(measured))+'/3 类路径事实；不等于已证明没有泄漏。' if measured else '目前没有独立的 DNS、IPv6、WebRTC 泄漏验证；配置看起来正常也不能代替实测。')]


def short_pdf(report,digest,path,risk):
    global APP
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QPdfWriter,QPageSize,QPainter,QColor,QFont,QTextDocument
    from PySide6.QtCore import QRectF,QMarginsF
    APP=QApplication.instance() or QApplication([])
    writer=QPdfWriter(str(path));writer.setResolution(72);writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(15,14,15,14));writer.setTitle('CC Auditor 3.1 · 一页使用前预检');writer.setCreator('CC Auditor 3.1 offline renderer')
    painter=QPainter(writer);bounds=[]
    width=writer.pageLayout().paintRectPixels(72).width();height=writer.pageLayout().paintRectPixels(72).height()
    dark='#172e38';muted='#51646c';accent={'green':'#166653','amber':'#986413','red':'#9d3434'}[risk['action_level']]
    pale={'green':'#eef7f1','amber':'#fff7e8','red':'#fcf0ee'}[risk['action_level']]
    def box(x,y,w,h,color,radius=8):
        painter.setPen(QColor(color));painter.setBrush(QColor(color));painter.drawRoundedRect(QRectF(x,y,w,h),radius,radius)
    def text(x,y,w,h,content,size=10,color=dark,bold=False):
        doc=QTextDocument();doc.documentLayout().setPaintDevice(writer);font=QFont('Microsoft YaHei',size);font.setBold(bold);doc.setDefaultFont(font);doc.setDocumentMargin(0)
        doc.setHtml('<div style="color:'+color+';line-height:110%">'+e(content).replace('\n','<br>')+'</div>');doc.setTextWidth(w)
        actual=doc.size().height()
        if actual>h+1:raise ValueError('pdf_text_overflow:'+str((content[:18],actual,h)))
        bounds.append({'text':content,'x':x,'y':y,'width':w,'height':actual,'font_pt':size})
        painter.save();painter.translate(x,y);doc.drawContents(painter,QRectF(0,0,w,h));painter.restore()
    try:
        text(0,0,width,24,'CC AUDITOR  /  使用前环境预检',10,bold=True)
        text(0,24,width,18,'一页结论 · 先看需要做什么',9,muted)
        box(0,52,width,145,pale);box(0,52,4,145,accent,0)
        text(18,63,width-36,20,risk['label']+' · '+risk['action'],11,accent,True)
        headline=risk['headline'].replace('，Claude','，\nClaude')
        text(18,91,width-36,68,headline,20,dark,True)
        text(18,163,width-36,27,'没有发现故障，不等于所有关键路线都已查清。' if not risk['confirmed_fault_count'] else '以下异常已有本轮证据，请优先处理具体问题。',9,muted)
        c=risk['completeness'];gap=12;col=(width-2*gap)/3
        for i,(number,label) in enumerate(((c['passed'],'已测且通过'),(c['fault'],'已确认故障'),(c['needs_verification'],'还需验证'))):
            x=i*(col+gap);box(x,211,col,65,'#f3f6f5');text(x+12,216,col-24,35,str(number),23,accent if i==1 and number else dark,True);text(x+12,254,col-24,18,label+' 项',9,muted)
        text(0,290,width,22,'这台电脑，哪些放心，哪些先核实',12,bold=True)
        cardw=(width-12)/2
        for i,(title,status,detail) in enumerate(card_content(report,risk)):
            x=(i%2)*(cardw+12);y=321+(i//2)*102
            box(x,y,cardw,92,'#f6f8f7');text(x+12,y+9,cardw-24,18,title+' · '+status,10,dark,True);text(x+12,y+33,cardw-24,54,detail,9,muted)
        text(0,534,width,22,'最有价值的三步',12,bold=True)
        for i,a in enumerate(risk['actions']):
            y=557+i*52;text(0,y,22,22,str(i+1).zfill(2),11,accent,True);text(30,y,width-30,18,a['title'],10,dark,True);text(30,y+18,width-30,31,a['detail'],8,muted)
        footer='展示 3.1 / 测量 '+report['version']+' · '+report['created_at_utc'][:16].replace('T',' ')+' UTC · 原始报告 '+report['run_id'][:8]
        if report.get('synthetic'):footer='合成测试，非实机结果 · '+footer
        text(0,718,width,16,footer,7,muted)
        text(0,733,width,16,'有效事实 '+str(c['observed'])+'/'+str(c['total'])+'（'+str(c['percent'])+'%），其中 '+str(c['reference'])+' 项为参考，并非通过数。',7,muted)
        text(0,748,width,16,risk['disclaimer'],7,muted)
        if height<760:raise ValueError('pdf_page_bounds')
    finally:painter.end()
    return bounds


def technical_html(report,digest,risk):
    from .pdf_report_renderer import fact_table
    body=["<style>body{font-family:'Microsoft YaHei';font-size:9pt;color:#263c43}h1{font-size:24pt;color:#195e63}h2{font-size:15pt;color:#195e63;margin-top:20px}h3{font-size:10pt;margin-top:13px}p{line-height:132%;margin:4px 0}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d6e0df;padding:5px;text-align:left}th{background:#eff4f2}.meta{font-size:7pt;color:#526b72}.page{page-break-before:always}</style>",
          '<h1>CC Auditor</h1><h2>完整技术报告 · 3.1</h2>',
          '<p><b>'+e(risk['label']+' · '+risk['headline'])+'</b></p><p>'+e(risk['disclaimer'])+'</p>',
          '<p>原始运行编号 '+e(report['run_id'])+'<br>测量时间 '+e(report['created_at_utc'])+'<br>证据 JSON SHA-256 '+digest+'</p>']
    if report.get('synthetic'):body.append('<p><b>合成测试报告，不能当作当前电脑实测。</b></p>')
    c=risk['completeness'];body.append('<p>适用 '+str(c['total'])+'；通过 '+str(c['passed'])+'；确认异常 '+str(c['fault'])+'；参考 '+str(c['reference'])+'；待补 '+str(c['needs_verification'])+'。有效事实 '+str(c['observed'])+'/'+str(c['total'])+'（'+str(c['percent'])+'%），不是合格率。不突出已测子集 100 分。</p>')
    body.append('<h2>先看：最重要的结论与证据缺口</h2>')
    for item in report['checks']:
        if item['state']=='fault':body.append('<p><b>已确认异常：'+e(item['title'])+'</b> · '+e(item['evidence_id'])+'；'+e(item.get('reason') or item['criterion'])+'</p>')
    for g in risk['critical_gaps']:body.append('<p><b>'+e(g['title'])+'</b>：'+e(g['detail'])+'<br>如何补测：'+e(g['action'])+'<br><span class="meta">关联证据 '+e('、'.join(g['evidence_ids']))+'；这是缺口，不是已确认故障。</span></p>')
    body.append('<h2 class="page">当前电脑与代理事实</h2>'+fact_table(report))
    body.append('<h2 class="page">全部检测项：判据、结果和下一步</h2>')
    for layer,title in LAYERS.items():
        body.append('<h2>'+layer+' · '+title+'</h2>')
        for item in (x for x in report['checks'] if x['layer']==layer):
            explain,follow=describe(item);state=STATE[item['state']]
            meaning='已确认该范围的技术问题，按具体异常处理。' if item['state']=='fault' else '只在所测范围通过，不延伸为账号可用保证。' if item['state']=='passed' else '参考事实，不是通过或故障。' if item['state']=='reference' else '本项没有充分结果；不当作已出现故障，也不计通过。'
            body+=['<h3>'+e(item['evidence_id']+' · '+item['title'])+'</h3>',
                   '<p>'+e(explain)+'<br><b>本次结果：'+state+'</b>。'+e(brief_value(item))+'</p>',
                   '<p>合格/可下结论判据：'+e(item['criterion'])+'<br>风险含义：'+e(meaning)+' 扣分 '+str(item['points'])+'；相同问题 '+e(item['issue_id'])+' 只计一次。<br>未测/失败原因：'+e(item.get('reason') or ('本轮未取得满足判据的证据，具体权限/回调/接收端状态见本项数据。' if item['state'] not in ('passed','reference','fault') else '不适用；测量范围见判据。'))+'<br>如何补测/复核：'+e(follow)+'</p>',
                   '<p class="meta">检查 ID '+e(item['id'])+' · 来源 '+e(item['source'])+' · 视点/范围 '+e(item['scope'])+' · 时间 '+e(item['captured_at_utc'])+'</p>']
    body.append('<h2 class="page">逐入口代理链路</h2><p>以下为静态或运行规则的模拟，不主动解析/连接目标。匿名链名不代表节点地区；最后公网出口始终单独记录。</p>')
    for config in (report.get('target_routes') or {}).get('configs',[]):
        body.append('<h3>'+e(config.get('id'))+' · '+e(config.get('kernel','unknown'))+' · '+e(config.get('activation',config.get('status','unknown')))+'</h3>')
        for route in config.get('runtime_rules',config.get('routes',[])):
            t=route.get('target',{});body.append('<p>'+e(t.get('surface',''))+' / '+e(t.get('process','未指定进程'))+' / '+e(t.get('host',''))+'<br>规则 '+e(route.get('rule_type'))+' #'+e(route.get('rule_index'))+'；链 '+e(' → '.join(route.get('configured_chain',[])) or '未确定')+'；链状态 '+e(route.get('chain_state'))+'<br>'+e(route.get('reason',''))+' 最终公网出口：'+e(route.get('final_public_egress') or '没有独立证据')+'</p>')
    for controller in (report.get('target_routes') or {}).get('controllers',[]):
        body.append('<p>控制器 '+e(controller.get('config_id'))+'：'+e(controller.get('status'))+'；'+e(controller.get('reason','只读运行接口已响应'))+'</p>')
    observed=(report.get('target_routes') or {}).get('existing_connections',[])
    body.append('<h2>既有 Claude 目标连接：真实规则与链标签</h2>')
    if not observed:body.append('<p>本轮未取得此类现有连接快照，不推断此前从未联网。</p>')
    else:
        body.append('<p>以下 '+str(len(observed))+' 条为控制器快照记录；不同候选接口可能读取同一内核，同一连接也可能重复出现，不能当成独立连接数量。进程分类不能独立确认浏览器档案。链标签保留控制器原顺序，不推断最终公网出口或节点国家。</p>')
        for i,entry in enumerate(observed,1):
            body.append('<p><b>快照 '+str(i)+' · '+e(entry.get('process'))+' / '+e(entry.get('host'))+'</b><br>实际命中规则类型：'+e(entry.get('rule_type'))+'；端口 '+e(entry.get('port'))+'。<br>控制器链标签：'+e(' / '.join(entry.get('chain',[])) or '未取得')+'。<br>来源 '+e(entry.get('source'))+'；时间 '+e(entry.get('captured_at_utc'))+'；关联配置候选 '+e(entry.get('config_id'))+'。<br>归属强度：'+e(entry.get('attribution'))+'。最后公网出口：'+e(entry.get('final_public_egress') or '没有独立证据')+'。</p>')
    body.append('<h2>逐日常浏览器档案</h2>')
    for p in report.get('profiles',[]):
        body.append('<h3>'+e(p['browser_name']+' / '+p['profile_alias'])+'</h3><p>版本 '+e(p.get('version',''))+'；静态 '+('已完成' if p.get('static_profile_checked') else '未完成')+'；工具页面 '+('已回调' if p.get('dynamic_profile_checked') else '未完成')+'；扩展 '+e(p.get('extension_count','未取得'))+'。<br>档案核验：'+e(p.get('profile_binding','未取得'))+'；不是不可伪造的身份。实验键清理：'+e(p.get('cleanup_status'))+'。<br>'+e(p.get('reason',''))+'</p>')
        if 'profiles' in report.get('approval',{}) and p['profile_key'] not in report['approval']['profiles']:body.append('<p>本档案未在本轮选择动态检查，因此没有执行页面/外部测点；这不是已确认的技术故障。</p>')
        net=(p.get('dynamic_result') or {}).get('data',{}).get('independent_network',{})
        for key,row in net.items():
            if isinstance(row,dict):body.append('<p>独立 '+e(key)+'：'+e(brief_value({'id':key,'value':row}))+'</p>')
    body.append('<h2>中立接收端与证据范围</h2>')
    for event in report.get('network_events',[])+report.get('independent_network_events',[]):
        body.append('<p>'+e(event.get('target_host',event.get('receiver','')))+' · '+e(event.get('source',event.get('kind','')))+' · '+e(event.get('status'))+'<br>出口/被查 IP '+e(event.get('ip',event.get('queried_probe_ip',event.get('mapped_ip','未取得'))))+'；地区标签 '+e(event.get('country_code','无'))+'；供应商标签 '+e(str(event.get('vendor_labels',{})))+'<br>'+e(event.get('reason',event.get('meaning','仅代表该测点及执行者，不是 Claude 路线。')))+'</p>')
        for row in event.get('resolvers',[]):body.append('<p>权威端所见递归解析器 '+e(row.get('resolver_ip'))+'；解析器到权威端的传输 '+e(row.get('authoritative_transport'))+'，不代表客户端到解析器的传输。</p>')
    body+=['<h2>白话术语与边界</h2><p>TUN：让网络流量经过虚拟网卡；接管默认路由不证明每个应用的最终出口。<br>Fake-IP：代理先给域名一个保留段地址，再在内核中映射；不能把它当真实服务器地址。<br>代理链：流量经一个或多个转发环节；配置或节点名称不证明最后出口。<br>Profile（日常档案）：浏览器保存设置、扩展与会话的独立目录，本工具不读取账号/历史。<br>DNS 泄漏：实际查询偏离用户预期路径；需要预期规则与独立接收端共同核实。解析器和 HTTPS IP 不同本身不足以确认。<br>JA3/JA4：TLS 握手摘要；不同网站或连接可能不同，不是所在地或处罚概率。</p>',
           '<h2>授权、保留与清理</h2><p>本轮批准：'+e('、'.join(report.get('approval',{}).get('scopes',[])))+'。批准时间 '+e(report.get('approval',{}).get('approved_at_utc','未取得'))+'。没有修改原有 Profile/代理/节点/证书。工具页只清理自建实验键；浏览器自有缓存/历史不保证清除，外部接收端或云端已接收的数据不能撤回。</p>',
           '<p>零接触范围：扫描器没有主动 Claude 请求；不涵盖用户原有程序或 Agent 通信，没有整机 PCAP。真实资格与服务器私有决定不由此报告确定。</p>',
           '<p class="meta">展示版本 '+VERSION+'；原始证据版本 '+e(report['version'])+'；全部原始测点保存在同一 evidence.json。离线改版不会补造新测量。源码摘要 '+e((report.get('source_build') or {}).get('toolkit_source_sha256','未取得'))+'</p>']
    return ''.join(body)


def build(report_path):
    from .preflight_v3 import read,source_build
    from .pdf_report_renderer import render,pdf_backend
    from ..storage import no_reparse
    report,digest=read(report_path);directory=Path(report_path).parent/'report_v3_1';no_reparse(directory);directory.mkdir(exist_ok=True)
    paths=[directory/'CC_Auditor_简明报告_v3.1.pdf',directory/'CC_Auditor_完整技术报告_v3.1.pdf']
    for p in paths:no_reparse(p)
    PdfReader,PdfWriter=pdf_backend()
    risk=assess(report)
    if any(p.exists() for p in paths):
        if all(p.is_file() and PdfReader(str(p)).metadata.get('/CCAuditorEvidenceSHA256')==digest and PdfReader(str(p)).metadata.get('/CCAuditorPresentation')==VERSION for p in paths):return dict(zip(('简明报告','完整技术报告'),map(str,paths)))
        raise FileExistsError('keep_existing_v31_report_pair')
    import secrets
    staged=[p.with_name(".render-"+secrets.token_hex(8)+".pdf") for p in paths]
    try:
        layout=short_pdf(report,digest,staged[0],risk);render(technical_html(report,digest,risk),staged[1],'完整技术报告 3.1')
        for p in staged:
            from io import BytesIO
            reader=PdfReader(BytesIO(p.read_bytes()));writer=PdfWriter();writer.clone_document_from_reader(reader)
            writer.add_metadata({'/CCAuditorEvidenceSHA256':digest,'/CCAuditorRunId':report['run_id'],'/CCAuditorPresentation':VERSION,'/CCAuditorSourceRunId':report['run_id']})
            renderer_trace={'/CCAuditorRendererSourceSHA256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()} if not getattr(__import__('sys'),'frozen',False) else {'/CCAuditorRendererBuildSHA256':source_build()['toolkit_source_sha256']}
            writer.add_metadata(renderer_trace)
            writer.add_outline_item('简明报告' if p==staged[0] else '完整技术报告',0)
            if p==staged[1]:
                texts=[page.extract_text() for page in reader.pages]
                for layer,title in LAYERS.items():
                    page=next(i for i,t in enumerate(texts) if layer in t);writer.add_outline_item(layer+' '+title,page)
            output=BytesIO();writer.write(output);p.write_bytes(output.getvalue())
        for temp,final in zip(staged,paths):temp.rename(final)
        (directory/'presentation.json').write_text(json.dumps({'presentation_version':VERSION,'source_run_id':report['run_id'],'source_sha256':digest,'risk_assessment':risk,'simple_layout':layout},ensure_ascii=False,indent=2),encoding='utf-8')
    finally:
        for temp in staged:
            if temp.exists():temp.unlink()
    return dict(zip(('简明报告','完整技术报告'),map(str,paths)))
