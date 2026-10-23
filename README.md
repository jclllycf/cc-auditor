# CC Auditor · Claude 使用前环境预检

**建议的使用方式：让本机 Agent 调用 Skill + MCP Toolkit。** 不熟悉命令行也可以按逐步教程操作；没有 Agent 的用户仍可独立运行 Windows EXE。

[推荐：Agent 完整新手教程](AGENT_QUICKSTART_ZH.md) · [Windows 安装](INSTALL_WINDOWS_ZH.md) · [MCP 配置](MCP_CONFIGURATION_ZH.md) · [英文](README.en.md) · [隐私](PRIVACY_ZH.md) · [支持范围](SUPPORT_MATRIX_ZH.md)

> 当前公开版本：**v3.6.0-beta.1 预发布**，不是正式稳定版。这个项目不是 Anthropic 官方产品，也不能保证 Claude 注册、付款或未来使用成功。

CC Auditor 面向通常尚未接触 Claude 的 Windows 用户，在获得本人授权后检查系统、日常浏览器 Profile、代理和中立网络测点。无需先安装 Claude、Python 或 SDK，也不需要 Claude 账号或 API Key。Desktop / Web / CLI / API 各有独立**正向健康分，分数越高越好**，与真实资格和付款条件分开。

## ⭐ 推荐快速开始：本地 Agent 自动预检

1. **下载安装包**：从 [v3.6.0-beta.1 Release](https://github.com/jclllycf/cc-auditor/releases/tag/v3.6.0-beta.1) 下载 Windows x64 ZIP 和 SHA256SUMS.txt。不要下载 GitHub 自动生成的 Source code ZIP 来运行。
2. **完整解压**：例如解压为 `C:\Tools\CC-Auditor\CC_Auditor\`，确保同目录有 `CC_Auditor.exe`、`_internal` 和 `skills`。先阅读 [Windows 安装步骤](INSTALL_WINDOWS_ZH.md)。
3. **连接你的 Agent**：使用你熟悉的、能够访问本机 Windows 工具的 Agent，按照 [通用 Agent 新手教程](AGENT_QUICKSTART_ZH.md) 安装 Skill，并将本地 EXE 注册为 MCP 工具；具体配置以该 Agent 支持的方式为准。不限某一品牌或命令行产品，纯云端 Agent 需另有经授权的本机执行连接。
4. **复制下面的完整中文指令给 Agent**；然后由你自己点击 Windows 原生授权卡，Agent 不能代替批准。
5. **看报告**：Agent 应读回四端健康分、主要问题与 PDF 所在路径；完整报告仍只保存在本机。

**直接复制给你使用的 Agent（需具备本机 MCP 工具连接）：**

> 请使用 $cc-auditor-preflight Skill 和本机 cc-auditor-preflight MCP，为这台 Windows 执行一次 Claude 首次使用前环境深度预检。先调用 audit_capabilities 检查工具版本，再调用 prepare_deep_preflight，使用它返回的 scan_id 调用 run_approved_deep_preflight。我会亲自阅读并批准弹出的原生授权卡；你不能替我批准。请在已授权范围内自动完成检测，不要访问 Claude/Anthropic 官方服务，不修改代理、浏览器设置或系统配置。完成后用中文总结 Desktop、Web、CLI、API 四端环境健康分及是否适合开始准备、已确认问题、需补证项目，并给出生成的 PDF 本地路径。不要上传完整原始证据、Cookie、密钥或私人报告。

**[从零开始的通用 Agent 教程：安装、连接、复制任务、授权与排错](AGENT_QUICKSTART_ZH.md)**

## 备用：不用 Agent，直接完成扫描

从同一 Release 下载并完整解压后，打开日常浏览器的普通 Profile 窗口，双击 `CC_Auditor\启动预检.cmd`，自己确认授权并等待程序生成 PDF。**不需要先安装 Skill 或配置 MCP。** 这是备用运行方式，不是推荐 Agent 路线的必经步骤。

## 能输出什么

| 输出 | 作用 |
|---|---|
| Desktop / Web / CLI / API 健康分 | 评估使用前的可观测技术条件，100 分最好 |
| 日常使用、注册、支付条件 | 技术准备与真实服务资格、支付条件分开 |
| 简明报告 PDF | 给非技术用户的结论和主要行动 |
| 完整技术报告 PDF | 各项测试、证据和评分依据 |
| 条件式证据补足清单 PDF | 有当前可补的重要缺口时才生成 |

## 重要边界与发布状态

- 本产品扫描器默认不主动访问或解析 Claude / Anthropic 目标；获得授权的独立第三方网络测点可能记录 IP、DNS 或 TLS 元数据。
- 健康分不是官方封禁概率；公网探针出口不等于未来 Claude 的最终出口；浏览器语言、地区设置和缺少所在地声明不等于真实物理所在地。
- 原始结果只在用户本机保存；Agent 读到的脱敏摘要可能进入 Agent 自身的模型服务。详见 [隐私说明](PRIVACY_ZH.md)。
- **公开 GitHub Release 已提供 Windows ZIP**；完整项目源码及 Skill 的集成 PR 仍处于审核中，见 [PR #1](https://github.com/jclllycf/cc-auditor/pull/1)。公开的主分支此时优先提供可靠的新手文档与 Skill 入口；这不代表已通过 Agent 自动化全流程和全部代理实机矩阵。
- 出现 Windows 安全阻拦时不要关闭安全软件绕过；请先核对来源、ZIP 哈希和 [故障说明](INSTALL_WINDOWS_ZH.md)。

## 开发与开源

[最新发布](https://github.com/jclllycf/cc-auditor/releases/tag/v3.6.0-beta.1) · [源码 PR](https://github.com/jclllycf/cc-auditor/pull/1) · [变更记录](CHANGELOG.md) · [安全反馈](SECURITY.md)

项目原创代码 MIT License，第三方依赖按各自许可证分发。欢迎提交脱敏反馈，不要公开真实代理配置、完整报告、账号或 API 密钥。
