"""Dated, offline research references. No runtime documentation fetches."""
RETRIEVED = "2026-10-16"
SOURCES = {
    "policy": ("地区政策", "https://www.anthropic.com/legal/supported-regions", "effective 2026-05-12"),
    "privacy": ("隐私政策", "https://www.anthropic.com/legal/privacy", "effective 2026-09-10"),
    "location": ("位置数据说明", "https://privacy.claude.com/en/articles/11186740-does-claude-use-my-location", "2026-03-16"),
    "commercial": ("商业产品位置说明", "https://privacy.claude.com/en/articles/11186730-does-claude-use-my-team-members-location", "2026-03-16"),
    "desktop": ("Desktop Code", "https://code.claude.com/docs/en/desktop", "mutable documentation"),
    "cowork": ("Cowork 架构", "https://support.claude.com/en/articles/14479288-claude-cowork-architecture-overview", "mutable documentation"),
    "web": ("Code on the web", "https://code.claude.com/docs/en/claude-code-on-the-web", "mutable documentation"),
    "data": ("Code 数据使用", "https://code.claude.com/docs/en/data-usage", "mutable documentation"),
    "otel": ("OpenTelemetry", "https://code.claude.com/docs/en/monitoring-usage", "mutable documentation"),
    "hooks": ("Hooks", "https://code.claude.com/docs/en/hooks", "mutable documentation"),
    "api": ("API 错误参考", "https://platform.claude.com/docs/en/api/errors", "mutable documentation"),
    "billing": ("API 与订阅计费", "https://support.claude.com/en/articles/8977456-how-do-i-pay-for-my-claude-api-usage", "mutable documentation"),
    "appeal": ("官方警告与申诉", "https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals", "mutable documentation"),
    "insights": ("Clio / Insights", "https://www.anthropic.com/news/clio", "2024-12-12; update 2026-08-24"),
    "browser": ("浏览器语言 API", "https://developer.mozilla.org/en-US/docs/Web/API/Navigator/languages", "mutable documentation"),
    "process": ("Windows 进程采集实现", "https://github.com/giampaolo/psutil/tree/release-7.2.2", "psutil 7.2.2"),
}
SURFACES = {"desktop": "Claude Desktop", "web": "Claude Web", "api": "Anthropic API", "cli": "Claude Code CLI"}
SUBTYPES = {"desktop": ["Code", "Chat", "Cowork"], "web": ["Chat", "Code"], "api": ["Direct API", "Provider / Gateway"], "cli": ["Standalone CLI"]}
PHASES = {"idle": "空闲 / 后台", "working": "工作中", "daily": "日常使用", "registration": "注册核对", "billing": "计费核对", "history": "历史"}
CONTEXTS = {"unknown": "尚未确认", "local": "本机", "cloud": "Anthropic 云端", "ssh": "SSH 远端", "wsl": "WSL / 本地虚拟机", "self_hosted": "自托管", "provider": "其他提供商"}
STATUSES = {"observed": "已观察", "documented": "文档说明", "partial": "部分覆盖", "error": "采集失败", "skipped": "未选择", "gated": "需要授权", "not_applicable": "不适用", "unknown": "未知", "user_supplied": "用户提供"}

CAPABILITIES = {
    "host": ("审计器运行环境", "系统、运行时与工具版本；描述运行审计器的主机。"),
    "process": ("进程与资源采样", "只读采集 Claude 候选及其子进程分类、内存和 CPU 时间；不读命令行。"),
    "connections": ("进程连接摘要", "仅选中进程的 TCP 状态与地址类别；不保存 IP、端口或通信正文。"),
    "installation": ("CLI 安装与终端", "检查已知安装位置、二进制版本资源和终端可用性；不运行 Claude。"),
    "api_environment": ("API 调用环境", "SDK 安装元数据和特定环境变量是否存在；不读取密钥值或凭据文件。"),
    "connectivity": ("官方 API TLS 连通性", "单独授权后由审计器直连 api.anthropic.com:443；不发送认证或推理请求。"),
    "browser": ("独立浏览器诊断", "打开自有离线页面采集浏览器能力；手动导入结果，与 Claude 网页分开。"),
}
ALLOWED = {"desktop": {"host", "process", "connections"}, "web": {"host", "browser"}, "api": {"host", "api_environment", "connectivity"}, "cli": {"host", "process", "connections", "installation", "api_environment"}}
DEFAULTS = {"desktop": ("host", "process"), "web": ("host", "browser"), "api": ("host", "api_environment"), "cli": ("host", "process", "installation")}

API_ERRORS = {
    400: ("请求格式", "检查请求结构和参数；此状态不能说明地理位置或账号被停用。"),
    401: ("认证失败", "凭据无效或缺失。请在自己的应用中核对；本工具不读取或验证密钥。"),
    402: ("计费问题", "核对 Console 计费与额度；消费订阅和 API 账目可能不同。"),
    403: ("权限不足", "检查组织、资源及政策权限；不能仅凭 403 判定地域原因。"),
    404: ("资源不存在", "检查官方端点和资源标识。"),
    413: ("请求过大", "减小请求大小；此状态不代表封禁。"),
    429: ("速率或支出限制", "可能涉及请求/Token 速率、月度额度或工作区支出限制。"),
    500: ("服务内部错误", "保存自己的脱敏时间和错误类别；不要启用完整请求体调试日志。"),
    504: ("超时", "超时不证明请求没有执行，也不证明没有费用。"),
    529: ("服务过载", "等待后按官方重试建议处理；不要进行压力测试。"),
}

# Twelve families summarized from BEHAVIOR_SIGNAL_STUDY.md. No personal classification.
SIGNALS = [
    ("提示语言", "提交内容可见；未提交的其他应用输入不可据此读取。", "公开内容处理及 Insights 语言维度分析。", "没有证实语言决定所在地或封禁。", "翻译、学习、多语言生活；语言不等于实际地点。", "insights"),
    ("界面语言", "浏览器偏好与原生应用语言可能可读。", "公开设备/浏览器数据类别；未确认每个客户端的精确字段。", "具体地域判定用途未知。", "偏好、企业配置和历史设置。", "privacy"),
    ("输入语言", "原生系统有输入法 API；网页仅有自身输入与浏览器偏好。", "未找到枚举输入法清单的具体官方确认。", "未知；本应用不枚举输入法。", "多语输入与辅助功能需求。", "privacy"),
    ("文件名与路径", "上传、授权工具结果或工作上下文可能包含。", "Code 上下文可上送；运行指标文档排除路径。", "路径文字对应的执行政策规则未知。", "项目由客户或第三方命名；路径可能泄露个人信息。", "data"),
    ("时区与时间", "客户端时间设置和服务端到达时间是不同视角。", "隐私政策列出时区和使用时间类别。", "工作作息或时区的地域权重未知。", "旅行、夜班、远程协作和陈旧设置。", "privacy"),
    ("应用功能", "客户端可观察自己的功能事件。", "使用与故障处理类别已披露。", "使用某个功能作为地域触发器未获证实。", "工作流选择不能证明来源。", "privacy"),
    ("登录变化", "自己的登录/退出和认证流程可见。", "账号管理与使用类别已披露。", "具体切换阈值及个人原因未知。", "设备更新、SSO 到期、旅行等可能原因。", "privacy"),
    ("网络变化", "本机网络、浏览器路径和远程执行路径不同。", "IP 及未具体说明的其他信号用于粗略地区处理。", "安全/合规用途公开；具体决策未知。", "NAT、移动网络、企业出口和云端执行；出口不等于人。", "location"),
    ("软件版本", "壳、内置引擎、CLI、SDK 和浏览器各有版本。", "公开系统/浏览器类别及版本相关 Code 遥测说明。", "某版本导致个人封禁未获证实。", "升级、受管设备、独立引擎更新。", "data"),
    ("请求头", "由实际请求客户端、运行库和代理共同决定。", "连接类别公开；完整字段与权重未公开。", "审计器自己的握手不能当作 Claude 指纹。", "库、网关与平台升级都会改变。", "api"),
    ("会话活动", "自己的事件、进程和资源变化可以分层观察。", "公开使用模式分析和特定滥用调查。", "普通空闲或长会话的处置阈值未知。", "批处理、辅助工具、延迟清理。", "insights"),
    ("API 与自动化", "服务端可观察请求、用量和限制；终端不等于请求量。", "官方速率/支出限制及违规行为处置。", "429 不等于封禁或地点判定。", "合法批量工作、重试与故障应分开。", "api"),
]

def source(key):
    title, url, revision = SOURCES[key]
    return {"id": key, "title": title, "url": url, "retrieved_on": RETRIEVED, "revision": revision}

def checklist(surface, phase):
    if phase == "registration":
        return ["核对当前官方支持地区政策与适用产品", "按真实的所在地和实体情况自行核对资格", "使用官方注册入口；不提供登录或身份材料给本工具", "如已有错误，只对照官方说明，不推测服务端原因"]
    if phase == "billing":
        return ["确认消费订阅、Console API 或提供商账单的实际归属", "核对官方额度、支付渠道与错误说明", "不向本工具提供卡号、地址、验证码或账单截图", "需要账户处理时使用官方支持或申诉渠道"]
    return []
