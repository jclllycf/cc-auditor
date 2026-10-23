"""V3 MCP 门面：仅一条预检工作流，旧 PIN/自动提权入口不公开。"""
import json
import re
import sys
from pathlib import Path
from ..model import root_dir
from . import preflight_v3 as core
from .consent_v3 import BROKER,SCOPES

def _spec(name,description,properties):return {'name':name,'description':description,'inputSchema':{'type':'object','properties':properties,'required':['scan_id'] if 'scan_id' in properties else [],'additionalProperties':False}}
SID={'scan_id':{'type':'string','pattern':'^[0-9a-f]{32}$'}}
MCP_TOOLS_SPEC=[
 _spec('audit_capabilities','说明统一使用前预检范围、版本、授权和缺口；不运行检查。',{}),
 _spec('prepare_deep_preflight','发现本机浏览器候选并准备首次使用前授权卡；计划入口/用途、主要 Profile、应用目录和可选类别自述由本机用户选择；不联网。',{'scopes':{'type':'array','items':{'type':'string','enum':list(SCOPES)}}}),
 _spec('run_approved_deep_preflight','显示一次原生确认窗口，在批准范围自动采集与有界补证；输出四端健康分（越高越好）与技术准备建议，固定双 PDF，有当前关键缺口才另附第三份。不接受 PIN/布尔批准。',SID),
 _spec('poll_deep_preflight','查看本轮状态；MCP 同步运行结束后返回最小报告路径。',SID),
 _spec('cancel_deep_preflight','撤销本轮授权；运行中的采集在下一有界阶段检查时停止，不停止用户应用。stdio 同步调用期间不能并发接收取消。',SID),
 _spec('build_pdf_reports','仅从本工具保存并校验的同一 JSON 生成固定双 PDF 和必要时的证据补足清单，不再检测环境。',SID),
 _spec('get_preflight_evidence','按层返回最多十条脱敏证据；不要把原始用户配置或完整 Profile 上传模型。',{**SID,'layer':{'type':'string','pattern':'^L(?:0[1-9]|1[0-2])$'}}),
]

def dispatch_mcp_tool(name,arguments=None):
    args={} if arguments is None else arguments;spec=next((x for x in MCP_TOOLS_SPEC if x['name']==name),None)
    if not spec:raise PermissionError('旧接口已停用；请使用统一 prepare / run 工作流。')
    if type(args) is not dict or set(args)-set(spec['inputSchema']['properties']):raise ValueError('unsupported_tool_arguments')
    if 'scan_id' in spec['inputSchema']['properties'] and (type(args.get('scan_id')) is not str or not re.fullmatch('[0-9a-f]{32}',args['scan_id'])):raise ValueError('invalid_scan_id')
    if name=='audit_capabilities':return {'version':core.VERSION,'workflow':'single_preuse_preflight','active_anthropic_probing':False,'scope_groups':SCOPES,
        'assessment_contract':'3.5.health.region.1','outputs':['surface_assessments','usage_scenarios','location_observability','remaining_gaps_v33'],
        'limitations':['无需 Claude；不主动访问它。','四端健康分不是封禁概率，缺证贡献与确认故障贡献分别记账。','一次原生授权后有界自动补证；固定双 PDF，当前关键缺口仍在时另附第三份。','代理配置模拟、已有连接、通用探针出口分别归因。','Google 专属地区不作为 Claude 资格；真实 Profile 使用本人确认与定向回调 PID 判据。']}
    if name=='prepare_deep_preflight':return core.prepare(args.get('scopes'))
    sid=args['scan_id']
    if name=='run_approved_deep_preflight':return core.run(sid)
    if name=='cancel_deep_preflight':BROKER.revoke(sid);return {'status':'revoked','scan_id':sid}
    if name=='poll_deep_preflight':
        r=core.RUNS.get(sid)
        return r.get('result',{'status':BROKER.pending.get(sid,{}).get('state','unknown'),'scan_id':sid}) if r else {'status':'unknown'}
    path=root_dir()/'data/preflight_v3'/sid/'evidence.json'
    if name=='build_pdf_reports':
        from .pdf_report_renderer import build_pdf_reports
        return build_pdf_reports(path)
    report,_=core.read(path);layer=args.get('layer')
    if layer is not None and not re.fullmatch(r'L(?:0[1-9]|1[0-2])',layer):raise ValueError('invalid_layer')
    from .plain_decisions_v35 import assess
    view=assess(report)
    return {'scan_id':sid,'surface_assessments':{k:{x:a[x] for x in ('health_level','health_score','technical_environment_ready','recommend_now','reason','next_action')} for k,a in view['surface_assessments'].items()},
        'usage_scenarios':view['usage_scenarios'],
        'browser_region_status':report.get('browser_region_signals',{}).get('status','present' if report.get('browser_region_signals') else 'not_collected_in_source'),
        'checks':[{k:c[k] for k in ('id','title','state','source','reason','criterion','evidence_id')} for c in report['checks'] if layer is None or c['layer']==layer][:10]}

def handle_jsonrpc_message(message):
    if type(message) is not dict or message.get('jsonrpc')!='2.0':return {'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid Request'}}
    mid=message.get('id');method=message.get('method');params=message.get('params') or {}
    if type(params) is not dict:return {'jsonrpc':'2.0','id':mid,'error':{'code':-32602,'message':'Invalid params'}}
    if mid is None and isinstance(method,str) and method.startswith('notifications/'):return None
    def response(result):return {'jsonrpc':'2.0','id':mid,'result':result}
    if method=='initialize':
        requested=params.get('protocolVersion','2024-11-05');protocol=requested if requested in ('2024-11-05','2025-03-26','2025-06-18') else '2025-06-18'
        return response({'protocolVersion':protocol,'capabilities':{'tools':{'listChanged':False}},'serverInfo':{'name':'cc-auditor-preflight','version':core.VERSION}})
    if method=='ping':return response({})
    if method=='tools/list':return response({'tools':MCP_TOOLS_SPEC})
    if method=='tools/call':
        try:
            out=dispatch_mcp_tool(params.get('name'),params.get('arguments'))
            return response({'content':[{'type':'text','text':json.dumps(out,ensure_ascii=False)}],'structuredContent':out,'isError':False})
        except Exception as error:
            # Never serialize raw exception text that may contain a private path or credential.
            return response({'content':[{'type':'text','text':json.dumps({'status':'error','error':type(error).__name__,'message_zh':'未执行或未完成；请核对本轮授权、工具参数和本机诊断记录。'},ensure_ascii=False)}],'isError':True})
    return {'jsonrpc':'2.0','id':mid,'error':{'code':-32601,'message':'Method not found'}}

def serve_stdio():
    for stream in (sys.stdin,sys.stdout):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    for line in sys.stdin:
        try:
            if len(line)>1024*1024:raise ValueError('request_limit')
            out=handle_jsonrpc_message(json.loads(line))
            if out is not None:print(json.dumps(out,ensure_ascii=False),flush=True)
        except (ValueError,TypeError):print(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Parse error'}}),flush=True)
    return 0
