# CC Auditor · Windows 使用前环境预检

[English](README.en.md) · [安装说明](INSTALL_WINDOWS_ZH.md) · [Skill / MCP 配置](MCP_CONFIGURATION_ZH.md) · [隐私](PRIVACY_ZH.md) · [支持范围](SUPPORT_MATRIX_ZH.md)

**先检查当前电脑，再决定是否开始安装和配置 Claude。** CC Auditor 面向尚未使用过 Claude 的普通 Windows 用户，检查系统、日常浏览器、代理规则和获准的中立网络测点，生成容易阅读的中文 PDF。

当前为 **v3.6 发布候选**。是否已经提供下载、通过哪些真实环境验收，以本仓库实际 Release 和随附验收回执为准；候选版本不等于稳定版。本工具与 Anthropic 无隶属关系。

## 你会得到什么

| 结果 | 帮你决定什么 |
|---|---|
| Desktop / Web / CLI / API 分开的环境健康分 | 当前环境是否适合开始安装及技术准备，100 分最好 |
| 日常使用、注册、支付三类行动判断 | 已满足哪些条件，当前有哪些障碍，哪些须本人或实际服务确认 |
| 地区、代理、DNS、IPv4 / IPv6 和浏览器证据 | 哪个视点实际测到了什么，哪些仍存在缺口 |
| 两份固定中文 PDF | 先读简明决策报告，必要时查看完整技术依据 |
| 条件式《证据补足清单》 | 自动补证后，仍需你做的最少操作 |

无需安装 Claude、SDK 或 Python，无需 Claude 账号、Cookie、API Key 或历史连接。未安装客户端和未填写所在地不会扣技术健康分。健康分不是封禁概率，也不保证注册、付款或模型调用成功。

## 最快开始：直接运行 Windows Toolkit

1. 在本仓库 **Releases** 下载 `Windows_x64.zip` 便携包和 `SHA256SUMS.txt`。GitHub 自动生成的 `Source code` 压缩包不能直接代替 Windows 程序。
2. 按[安装说明](INSTALL_WINDOWS_ZH.md)核对 SHA-256，完整解压到自己可写的目录，例如 `C:\Tools\CC-Auditor`。首次电脑若缺少微软 Visual C++ x64 运行库，先按说明从微软官方安装。
3. 如果检测 Web，打开日常 Chrome、Edge 或 Firefox 的普通窗口。无需打开 Claude。
4. 双击包内 `CC_Auditor\启动预检.cmd`，亲自选择授权范围与日常 Profile，并确认。
5. 在程序返回的路径查看简明报告。证据与 PDF 保存在 EXE 同目录的 `data\preflight_v3\<本轮编号>\` 下。

**只用 Toolkit 就能完成预检。** 不需要先配置任何 AI Agent；程序不会替你安装或更改代理、DNS、浏览器语言与地区设置。

## 可选：让本机非 Claude Agent 帮你读报告

Toolkit 是实际执行检查的 Windows 程序；MCP 提供受控调用接口；Skill 说明调用顺序与解释规则。单独安装 Skill 不会获得本机访问权限。

安装整个 `skills/cc-auditor-preflight` 文件夹，并把 Agent 的本机 stdio MCP 命令设为：

```text
C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe --mcp
```

详细配置见[Skill / MCP 配置](MCP_CONFIGURATION_ZH.md)。先只调用 `audit_capabilities` 检查版本和接口，再发起预检。每轮扫描都需要你亲自确认原生授权卡；Agent 不能替你批准或填写资格自述。云端 Agent 不会因读到 Skill 而自动连接这台电脑。

## 结果的边界

- 探针看到的公网出口属于该测量视点，不能直接归为 Claude 最终出口。规则模拟也不等于真实服务请求。
- IP、网页语言、时区和 Google 专属地区设置不能证明你的物理所在地或账号资格。
- 未授权、未测、失败与已证实异常分别显示；缺少 DNS 回执不自动等于 DNS 泄漏。
- API 在云端 Agent 或第三方网关执行时，不用本机分数代替远端链路。执行位置未知时明确保留未知。
- 本扫描流程不主动请求或解析 Claude / Anthropic 目标。获准的第三方测点可接收 IP、DNS 和协议元数据；通过 Agent 返回的摘要可能进入其模型服务。详见[隐私说明](PRIVACY_ZH.md)。

## 反馈、源码与许可

请先查看[支持矩阵](SUPPORT_MATRIX_ZH.md)和[安全反馈说明](SECURITY.md)。公开反馈只附脱敏复现步骤与版本，切勿上传真实网络配置、完整报告、Profile 或密钥。

原创代码采用 MIT，Copyright (c) 2026 jclllycf，详见 `LICENSE`。第三方组件遵循各自许可证，见发行包内许可证和 notices。版本变化见[更新记录](CHANGELOG.md)。
