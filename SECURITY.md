# 安全反馈与支持边界

## 报告漏洞

请报告会突破原生授权范围、绕过目标限制、泄露机密、错误读取私人资料、污染公开包或执行非预期代码的问题。尽量提供版本、SHA-256、操作系统、最少复现步骤和脱敏异常信息。

如本仓库的 **Security → Advisories → Report a vulnerability** 已启用，请使用其私密漏洞报告功能。若该入口不可用，先在普通 Issue 中只描述问题类别并请求私密联系渠道，**不要公开漏洞细节、令牌、完整报告或个人网络配置**。维护者尚未提供私密渠道时，保留敏感复现资料，等待明确的安全接收方式；本项目不承诺未建立的邮箱或响应时限。

## 当前支持

首个公开发行线为 v3.6 候选/预发布。以 Release 实际版本与验收回执为准；没有完成独立零 Claude Windows 和代理验收的版本不得声称稳定支持。历史研发版保留供对照，不承诺持续修复。新问题优先在最新候选复现，升级前先备份自己的结果。

## 安全边界

- 真人授权卡负责授予本轮检测范围；Skill、Agent 自动审批、`scan_id`、聊天同意或管理员权限都不能替代。
- 预检不主动请求或解析 Anthropic / Claude 目标；仅获准的固定中立目标用于网络测量。此边界针对扫描器，不代表整台电脑或 Agent 自己没有其它联网。
- 不读取 Cookie、密码、API Key、聊天/付款正文，不进行 HTTPS 截获、根证书安装、客户端注入或地区伪装。
- 不为了提高分数修改用户网络、代理、时区、语言、身份或现有进程。未知和缺测不当成确认故障或通过。
- 探针、离线规则模拟和既有客户端校准各自归因，不能互相代替真实目标出口。
- 工具依赖本机 Windows、运行时和所调用本地组件的正常可信状态；本地 JSON 哈希不等于厂商签名或远程证明，也不能防御已控制当前用户环境的攻击者。

不要通过公开 Issue 发送凭据、浏览器档案、完整用户报告或代理节点。请勿在未经授权的他人设备/账号上测试漏洞，不要以扫描为由绕过组织策略、目录信任或 Windows 安全拦截。

## English

Use GitHub private vulnerability reporting **if enabled**. Otherwise open a minimal issue requesting a private channel without exposing exploit details or personal data. Include the affected version, archive hash, OS and a redacted reproduction. No response-time commitment or unpublished security email is implied. The scanner's consent and destination boundaries do not attest to the security of the whole PC or the Agent provider.
