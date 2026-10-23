"""Offline ReportLab rendering, pinned private fonts and a restricted HTML reader.

No URL, image, CSS, attachment or external resource loading is supported.
Qt remains the native consent UI; PDF text maps are generated independently.
"""
import hashlib,html,sys
from pathlib import Path
from html.parser import HTMLParser

_READY=False


def fonts():
    global _READY
    vendor=Path(__file__).resolve().parents[1]/'_vendor_reportlab'
    if vendor.is_dir() and str(vendor) not in sys.path:sys.path.insert(0,str(vendor))
    if _READY:return
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from .report_fonts_v34 import FONT_ASSETS
    root=Path(sys._MEIPASS) if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2]
    for filename,digest in FONT_ASSETS.items():
        path=root/'assets/report-fonts'/filename
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('report_font_missing_or_changed')
        pdfmetrics.registerFont(TTFont('CCBold' if 'Bold' in filename else 'CCRegular',str(path)))
    pdfmetrics.registerFontFamily('CCRegular',normal='CCRegular',bold='CCBold',italic='CCRegular',boldItalic='CCBold')
    _READY=True


def render_brief(report,digest,path,view,gaps):
    fonts()
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import Paragraph
    from .fixed_risk_v33 import SURFACES
    from .plain_decisions_v35 import actions
    page_w,page_h=A4;left=42.52;top=34.02;w=page_w-left*2
    canvas=Canvas(str(path),pagesize=A4,pageCompression=1);canvas.setTitle('CC Auditor '+str(report['version'])+' 首次使用前环境预检')
    bounds=[];page=1;dark='#16373b';muted='#546c70';green='#147363';amber='#9a641d';red='#a53e3e'
    def box(x,y,width,height,color):
        canvas.setFillColor(HexColor(color));canvas.roundRect(left+x,page_h-top-y-height,width,height,7,stroke=0,fill=1)
    def text(x,y,width,height,content,size=9,color=dark,bold=False,compact=False):
        original=str(content);content=original
        style=ParagraphStyle('brief',fontName='CCBold' if bold else 'CCRegular',fontSize=size,leading=size*1.32,textColor=HexColor(color),wordWrap='CJK')
        def paragraph(value):
            p=Paragraph(html.escape(value).replace('\n','<br/>'),style);_,h=p.wrap(width,height);return p,h
        p,h=paragraph(content)
        if compact:
            while h>height and len(content)>3:
                content=content[:-3].rstrip('…')+'…';p,h=paragraph(content)
        if h>height+0.5:raise ValueError('v34_brief_text_overflow:'+original[:24])
        bounds.append(dict(page=page,text=content,full_text=original,x=x,y=y,width=width,height=h,font_pt=size))
        p.drawOn(canvas,left+x,page_h-top-y-h)
    def footer():
        text(0,744,w,17,'健康分越高越好；资格另行核对，不是封禁概率或服务承诺。',8,muted)
        text(0,763,w,18,'运行 '+report['run_id']+'  ·  证据 '+digest[:12]+'  ·  '+str(page)+'/2',7.3,muted)
    text(0,0,w,20,'CC AUDITOR   /   首次使用前环境预检',10,bold=True)
    text(0,30,w,30,'已测入口是否适合开始技术准备：'+('是' if view['recommend_now'] else '否'),15,bold=True)
    text(0,69,w,25,'本次计划：'+' / '.join(SURFACES[s] for s in view['selected_surfaces']),8.5,muted,compact=True)
    text(0,94,w,28,'合成验收样本，不是本机实测' if report.get('synthetic') else '确认技术故障 '+str(report['summary']['faults'])+' 项 · 当前证据缺口 '+str(len(gaps))+' 项\n原始采集 '+str(report['created_at_utc'])[:10]+' · 同一 JSON 评估，本页不代表新增测量',8,muted)
    cw=(w-12)/2
    for i,(s,a) in enumerate(view['surface_assessments'].items()):
        x=i%2*(cw+12);y=129+i//2*142;color=muted if a['health_score'] is None else green if a['health_score']>=70 else amber if a['health_score']>=50 else red
        box(x,y,cw,139,'#edf4f3');text(x+12,y+10,cw-24,17,SURFACES[s]+(' · 已选' if s in view['selected_surfaces'] else ' · 参考'),10,bold=True)
        text(x+12,y+35,78,42,('--' if a['health_score'] is None else str(a['health_score'])),25,color,True)
        text(x+92,y+36,cw-104,32,'/ 100 健康分 · '+a['health_level']+'\n适合开始准备：'+a['recommend_now'],8.5,color,True)
        good=a['positive_factors'];text(x+12,y+77,cw-24,31,('本机接入基础 '+str(a['local_client_readiness']['health_score'])+'/100；实际 API 链路未评分' if s=='api' and a['health_score'] is None and a['applicable'] else '地区：'+a['observed_egress']['summary']),8,muted,compact=True)
        text(x+12,y+109,cw-24,27,'判断：'+a['reason'],8,color,compact=True)
    text(0,425,w,20,'三类行动判断',11,bold=True);sw=(w-16)/3
    for i,(key,title) in enumerate((('daily_use','日常使用'),('registration','注册'),('payment','支付'))):
        a=view['usage_scenarios'][key];x=i*(sw+8);box(x,453,sw,97,'#f5f0e7');text(x+10,463,sw-20,17,title,10,bold=True)
        text(x+10,487,sw-20,20,a['recommend_text'],9,green if a['recommend_now'] else amber,True)
        text(x+10,514,sw-20,28,a['reason'] if a['planned'] else '不在本次计划，未要求补检',8,muted,compact=True)
    text(0,569,w,20,'最有价值的下一步',11,bold=True)
    for i,action in enumerate(actions(report,view,gaps)):text(0,600+i*43,w,35,str(i+1).zfill(2)+'  '+action,9,muted,compact=True)
    footer();canvas.showPage();page=2
    text(0,0,w,28,'判断依据与具体处理事项',17,bold=True);y=48
    installed={'not_required':'无需安装客户端','not_installed':'尚未安装或创建','installed':'已发现安装资料','unknown':'安装资料未核对'}
    for s in view['selected_surfaces']:
        a=view['surface_assessments'][s];text(0,y,w,22,SURFACES[s]+'  '+('--' if a['health_score'] is None else str(a['health_score']))+'/100 · 适合开始准备：'+a['recommend_now'],11,bold=True);y+=28
        positive=('仅本机系统接入基础 '+str(a['local_client_readiness']['health_score'])+'/100；真实 API 请求执行链路未测' if s=='api' and a['health_score'] is None and a['applicable'] else '；'.join(p['text'] for p in a['positive_factors'][:2]) or '本入口不适用或缺少必要观测')
        text(0,y,w,30,'已满足：'+positive,9,green,compact=True);y+=34
        text(0,y,w,33,'主要原因：'+a['reason'],9,amber,compact=True);y+=36
        text(0,y,w,34,'具体行动：'+a['next_action']+'；当前状态：'+installed.get(a['installation_state'],'未核对')+'，实际服务未实测',9,muted,compact=True);y+=45
    if y<650:
        text(0,y,w,23,'怎样理解这份报告',11,bold=True);y+=30
        text(0,y,w,min(710-y,90),'尚未安装 Claude、没有 API 项目或历史连接，属于正常首次使用场景，不扣环境风险。\n'+('本轮还有 '+str(len(gaps))+' 个当前可补证缺口，另附《证据补足清单》。' if gaps else '本轮没有需要另列的当前可补证缺口。')+'\n注册、登录、实际服务可用性及银行交易必须由真实服务确认。',9,muted,compact=True)
    footer();canvas.save();return bounds


def render_html(source,path,title):
    from .pdf_render_v34 import render_html as render
    return render(source,path,title,prevent_orphan_json_tail=True)
