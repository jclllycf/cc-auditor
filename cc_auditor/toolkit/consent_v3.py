"""一次本机确认。无 PIN、布尔批准、模拟点击或可回显的授权秘密。"""
import copy
import secrets
import threading
import time
from .zero_contact_guard import utc_now

_APP=None
SCOPES={'local_system':'本机系统、代理/路由、进程身份（不因 Claude 进程扣分）',
    'proxy_config':'本地代理配置/已运行内核已知启动参数、管道名称元数据与只读接口；不提权，密钥不返回模型',
    'browser_static':'真实日常 Profile 的指定诊断键与扩展权限；不读 Cookie/历史/密码',
    'browser_dynamic':'已打开的日常 Profile 的自有 127.0.0.1 页面；仅工具实验键读写并清理',
    'neutral_network':'向固定中立测点查询出口；对方及 Agent 云端可能收到最小化网络信息',
    'existing_connections':'已有 Claude/浏览器连接元数据，同一内核最多两次有界快照；不启动/刷新/登录客户端',
    'independent_network':'独立实测：系统/浏览器 DNS、IPv4/IPv6、STUN UDP、真实浏览器 TLS/HTTP2/JA4；会向下列接收端暴露本次 IP 与协议元数据',
    'browser_region':'Windows 国家/格式，真实 Profile 网页语言，浏览器 Local State 实验国家/版本/时间及限定管理策略；不读 seed 内容、账号、历史或登录资料',
    'program_context':'可选应用校准：固定安装位置、PATH、已运行 WorkBuddy/Codex/Cursor/Windsurf/Antigravity 的名称和文件版本（不凭品牌猜模型或执行位置）、相关浏览器限定 TLS/代理启动开关；用户/机器代理变量存在性与 WinHTTP；仅在下方亲自选择的 API 目录读取依赖清单/已安装 SDK 元数据；只对已运行 WSL/本机容器执行固定只读元数据命令，SSH 仅配置结构计数不连接。若同时批准独立网络，允许已绑定 Python/Node 执行工具自有中立 TLS 探针；不运行 Claude、SDK 或项目代码。目录路径和机密不返回 Agent。'}

class Broker:
    def __init__(self):self.pending={};self.lock=threading.Lock()
    def prepare(self,profiles,scopes=None):
        selected=list(SCOPES if scopes is None else scopes)
        if not set(selected)<=set(SCOPES):raise ValueError('unknown_scope')
        sid=secrets.token_hex(16)
        from .network_v3 import DESTINATIONS
        from .deep_network_v31 import DESTINATIONS as DEEP_DESTINATIONS
        from .preflight_v3 import source_build
        manifest={'scan_id':sid,'created_at_utc':utc_now(),'expires_epoch':time.time()+900,'requested_scopes':selected,
            'profiles':copy.deepcopy(profiles),'destinations':list(DESTINATIONS)+list(DEEP_DESTINATIONS),'source_build':source_build(),
            'write_scope':'仅本轮报告目录及本工具本地 origin 的随机实验键；不更改原有网络/代理/Profile 设置。',
            'cloud_disclosure':'工具返回给 Agent 的摘要可能进入其模型服务；本地清理不能撤回已外发数据。'}
        with self.lock:self.pending[sid]={'manifest':manifest,'state':'pending'}
        return copy.deepcopy(manifest)
    def approve_and_consume(self,sid):
        with self.lock:
            record=self.pending.get(sid)
            if not record or record['state']!='pending':raise PermissionError('invalid_or_replayed_scan')
            if time.time()>record['manifest']['expires_epoch']:raise PermissionError('approval_expired')
            record['state']='presenting';manifest=copy.deepcopy(record['manifest'])
        decision=_native_consent(manifest)
        with self.lock:
            if self.pending[sid]['state']!='presenting':raise PermissionError('approval_revoked')
            if time.time()>manifest['expires_epoch']:raise PermissionError('approval_expired')
            if decision is None:record['state']='declined';raise PermissionError('user_declined')
            scopes=decision['scopes']
            if not set(scopes)<=set(manifest['requested_scopes']):raise PermissionError('scope_mismatch')
            if not set(decision['profiles'])<={p['profile_key'] for p in manifest['profiles']}:raise PermissionError('profile_mismatch')
            if decision['profiles'] and 'browser_dynamic' not in scopes:raise PermissionError('profile_scope_missing')
            record['state']='consumed'
        from .fixed_risk_v33 import declarations
        declared=declarations(decision.get('declarations'))
        if declared['primary_profile'] and declared['primary_profile'] not in {p['profile_key'] for p in manifest['profiles']}:raise PermissionError('primary_profile_mismatch')
        record['private_options']=decision.get('private_options',{}) if 'program_context' in scopes else {}
        return {'scan_id':sid,'approved_at_utc':utc_now(),'expires_epoch':manifest['expires_epoch'],'scopes':scopes,'user_declarations':declared,
            'profiles':decision['profiles'],'channel':'native_local_human_confirmation','destinations':manifest['destinations'],
            'write_scope':manifest['write_scope'],'cloud_disclosure':manifest['cloud_disclosure'],'source_build':manifest['source_build']}
    def revoke(self,sid):
        with self.lock:
            if sid in self.pending:self.pending[sid]['state']='revoked'
    def take_private_options(self,sid):
        with self.lock:return self.pending.get(sid,{}).pop('private_options',{})
    def cancelled(self,sid):
        with self.lock:return self.pending.get(sid,{}).get('state')=='revoked'

def _native_consent(manifest):
    global _APP
    from PySide6.QtWidgets import QApplication,QDialog,QVBoxLayout,QLabel,QCheckBox,QDialogButtonBox,QScrollArea,QWidget,QComboBox,QLineEdit,QFormLayout,QHBoxLayout,QPushButton,QFileDialog
    from PySide6.QtGui import QRegularExpressionValidator,QFont
    from PySide6.QtCore import QRegularExpression
    from PySide6.QtCore import Qt,QTimer
    _APP=QApplication.instance() or QApplication([])
    from .report_fonts_v34 import ensure_report_font
    _APP.setFont(QFont(ensure_report_font(),10))
    from .preflight_v3 import VERSION
    dialog=QDialog();dialog.setWindowTitle('CC Auditor '+VERSION+' · 首次使用前一次授权')
    available=_APP.primaryScreen().availableGeometry()
    dialog.resize(min(850,max(320,available.width()-40)),min(800,max(300,available.height()-70)))
    layout=QVBoxLayout(dialog)
    title=QLabel('一次确认，按你允许的范围检查');title.setStyleSheet('font-size:23px;font-weight:bold;color:#17616c');layout.addWidget(title)
    text=QLabel('不会为检测而访问/解析 Claude 目标、启动 Claude 或修改网络设置。\n未安装 Claude 也可以检测；已有客户端连接仅作为可选校准资料。\n'+manifest['cloud_disclosure']);text.setWordWrap(True);layout.addWidget(text)
    area=QScrollArea();area.setWidgetResizable(True);w=QWidget();body=QVBoxLayout(w);area.setWidget(w);layout.addWidget(area)
    fields={}
    all_scopes=QCheckBox('勾选全部列明检测范围（可逐项取消；仍需下方确认）');body.addWidget(all_scopes)
    scope_titles={'local_system':'本机系统与运行时候选','proxy_config':'代理软件、运行配置与控制接口','browser_static':'日常浏览器静态诊断','browser_dynamic':'日常浏览器工具页实测','neutral_network':'中立 IP / 归属 / 路由 / 声誉查询','existing_connections':'已有客户端连接元数据（可选研究）','independent_network':'独立 DNS / 双栈 / UDP / 浏览器 TLS 测点','browser_region':'Windows 与浏览器地区参考','program_context':'系统环境与可选应用资料自动补证'}
    for key in manifest['requested_scopes']:
        c=QCheckBox(scope_titles[key]);c.setChecked(key in ('local_system','proxy_config','browser_static'));body.addWidget(c);fields[key]=c
        description=QLabel(SCOPES[key]);description.setWordWrap(True);description.setStyleSheet('color:#526873;margin-left:23px;margin-bottom:7px;');body.addWidget(description)
    all_scopes.toggled.connect(lambda checked:[c.setChecked(checked) for c in fields.values()])
    supplement=QLabel('在已勾选范围内自动补证：每个来源最多重试一次，额外总预算 75 秒。首次失败和重试都保留；不会自动扩大范围。只读目录元数据有大小/重解析点限制；不会安装任何组件。');supplement.setWordWrap(True);body.addWidget(supplement)
    info=QLabel('外部目标（只有勾选相应联网项时）：'+', '.join(manifest['destinations'])+'。通用查询阶段最长 30 秒；独立 DNS/STUN 阶段有界等待，浏览器测点约 10 秒/档案，不跟重定向。接收端会看到源 IP；注册/路由/声誉查询还会提交探针 IP/前缀/ASN。DNS 测试发送随机测试名，权威端可见递归解析器；STUN 可见 UDP 公网地址；tls.peet.ws 可见浏览器 TLS/HTTP 指纹并可能保留。无媒体权限、无 TURN/付款，不声称第三方一定删除。\n'+manifest['write_scope']+'\n动态检查前请手动打开所选日常档案的普通空白页，尤其 Edge；工具不启动已关闭浏览器、不恢复原有会话。');info.setWordWrap(True);body.addWidget(info)
    profile_boxes=[]
    for item in manifest['profiles']:
        c=QCheckBox(item['browser_name']+' · '+item['profile_alias']+'（这是我已打开的日常 Profile）');body.addWidget(c);profile_boxes.append((item,c))
    heading=QLabel('本次使用计划与可选自述（可以保留未提供；不会读取账户或支付资料）');heading.setWordWrap(True);body.addWidget(heading)
    planned={};surface_row=QHBoxLayout()
    for key,label in (('desktop','桌面端'),('web','网页端'),('cli','命令行'),('api','API')):
        c=QCheckBox(label);c.setChecked(key in ('desktop','web'));surface_row.addWidget(c);planned[key]=c
    body.addLayout(surface_row);form=QFormLayout();body.addLayout(form)
    bools={}
    for key,label,default in (('plan_daily','计划日常使用',True),('plan_registration','计划注册',False),('plan_payment','计划支付',False),('eligibility_confirmed','已按本人真实条件核对当前官方地区/主体资格',False),('console_billing_ready','已有 Console 计费权限并会核对预付条件',False)):
        c=QCheckBox(label);c.setChecked(default);form.addRow(c);bools[key]=c
    project={};project_button=QPushButton('可选：已有 API 项目时补充宿主资料（首次用户无需选择）');project_label=QLabel('未选择项目不影响首次环境预检；所选路径仅留本机')
    def select_project():
        path=QFileDialog.getExistingDirectory(dialog,'选择要预检的实际 API 项目目录')
        if path:project['api_project']=path;project_label.setText('已选择一个本机目录；路径不返回 Agent')
    project_button.clicked.connect(select_project);form.addRow(project_button);form.addRow(project_label)
    primary=QComboBox();primary.addItem('未指定：按本轮已选档案保守合成','')
    for item in manifest['profiles']:primary.addItem(item['browser_name']+' / '+item['profile_alias'],item['profile_key'])
    form.addRow('主要日常浏览器档案',primary)
    combos={}
    for key,title,choices in (
        ('cli_host','CLI 计划使用的环境',[('尚未决定（先检查本机 Windows）','unknown'),('本机 Windows 终端','windows'),('WSL','wsl'),('容器','container'),('远程服务器','remote')]),
        ('api_host','API 计划使用的环境',[('尚未决定（先检查本机 Windows）','unknown'),('本机 Python（无需先创建项目）','python'),('本机 Node（无需先创建项目）','node'),('WSL','wsl'),('容器','container'),('远程服务器','remote')]),
        ('api_execution_mode','API 实际请求发送方式（不知道可以保留）',[('尚未识别；不按应用品牌猜测','unknown'),('本机 SDK 直接调用','local_sdk_direct'),('本机桌面 Agent 直接调用','local_agent_direct'),('云端 Agent 执行请求','agent_platform_cloud'),('第三方授权模型网关','third_party_gateway'),('平台内置非 Claude 模型；无 Claude API 意图','platform_builtin_model')]),
        ('entity','真实使用主体',[('未提供','unknown'),('个人','individual'),('组织（仍需核对主体资格）','organization')]),
        ('payment_method','打算使用的付款类别',[('未提供','unknown'),('信用卡','credit'),('借记卡','debit'),('PayPal','paypal'),('其他类别','other')]),
        ('billing_matches_bank','账单资料与银行记录一致',[('未提供','unknown'),('是（本人自述）','yes'),('否','no')]),
        ('three_ds','发卡行支持完成 3DS',[('未提供','unknown'),('是（本人自述）','yes'),('否 / 尚不支持','no')])):
        c=QComboBox()
        for label,value in choices:c.addItem(label,value)
        form.addRow(title,c);combos[key]=c
    countries={}
    for key,title in (('physical_country','当前真实物理所在地代码'),('issuer_country','付款方式真实发行地区代码'),('billing_country','真实账单地区代码')):
        c=QLineEdit();c.setMaxLength(2);c.setPlaceholderText('可留空；两位代码，如 US / JP / CN');c.setValidator(QRegularExpressionValidator(QRegularExpression('[A-Za-z]{0,2}'),c));form.addRow(title,c);countries[key]=c
    note=QLabel('以上均为用户自愿声明，不是自动定位。只记录地区代码/类别，不填姓名、卡号、账号、完整地址或密码。本机候选运行时/PATH 元数据在“本机系统”范围内，不会运行 Claude。地区配置差异不会自动扣分。');note.setWordWrap(True);body.addWidget(note)
    validation=QLabel('');validation.setWordWrap(True);validation.setStyleSheet('color:#a13030');layout.addWidget(validation)
    def confirm():
        if any(c.isChecked() for item,c in profile_boxes) and not fields.get('browser_dynamic',QCheckBox()).isChecked():
            validation.setText('已选择动态检测档案：请同时允许“日常浏览器工具页实测”，或取消档案勾选。');return
        if not any(c.isChecked() for c in planned.values()):
            validation.setText('请选择至少一个计划使用入口。');return
        dialog.accept()
    buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel);buttons.button(QDialogButtonBox.StandardButton.Ok).setText('批准以上勾选范围并开始');buttons.button(QDialogButtonBox.StandardButton.Cancel).setText('拒绝本次检查');buttons.accepted.connect(confirm);buttons.rejected.connect(dialog.reject);layout.addWidget(buttons)
    timer=QTimer(dialog);timer.setSingleShot(True);timer.timeout.connect(dialog.reject);timer.start(max(1,int((manifest['expires_epoch']-time.time())*1000)))
    if dialog.exec()!=QDialog.DialogCode.Accepted:return None
    declared={key:c.currentData() for key,c in combos.items()};declared.update({key:c.text().strip().upper() for key,c in countries.items()});declared.update(surfaces=[key for key,c in planned.items() if c.isChecked()],primary_profile=primary.currentData())
    declared.update({key:c.isChecked() for key,c in bools.items()})
    return {'scopes':[k for k,c in fields.items() if c.isChecked()], 'profiles':[item['profile_key'] for item,c in profile_boxes if c.isChecked()],'declarations':declared,'private_options':project}

BROKER=Broker()
