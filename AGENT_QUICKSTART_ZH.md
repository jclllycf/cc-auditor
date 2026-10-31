# CC Auditor｜给第一次使用 Agent 的用户：从下载到拿到报告

> **推荐方式：Agent Skill + MCP Toolkit。** 本文不需要你先懂 MCP、TOML 或 API。当前版本 `v3.6.0-beta.1` 是公开预发布版，建议从 Releases 获取文件；Agent 全流程在不同客户端上的正式验收仍有待完成。

## 先弄明白三个组件

- **Toolkit / EXE**：真正读取电脑与生成本机 PDF 的程序；不需要 Python，不需要 Claude 账号。
- **MCP**：让本机 Agent 能通过受控工具接口启动这个 EXE。
- **Skill**：告诉 Agent 正确的检测流程、能做什么以及不能做什么。只安装 Skill 不会自动连接电脑。

## 第一步：下载

1. 打开 [v3.6.0-beta.1 下载页面](https://github.com/jclllycf/cc-auditor/releases/tag/v3.6.0-beta.1)。
2. 在 **Assets** 下下载 `CC_Auditor_3.6.0-beta.1_Windows_x64.zip` 和 `SHA256SUMS.txt`，**不要**下载 GitHub 自动生成的 Source code ZIP 代替它。
3. 可直接使用：[Windows x64 便携包](https://github.com/jclllycf/cc-auditor/releases/download/v3.6.0-beta.1/CC_Auditor_3.6.0-beta.1_Windows_x64.zip)；[SHA-256 清单](https://github.com/jclllycf/cc-auditor/releases/download/v3.6.0-beta.1/SHA256SUMS.txt)。

## 第二步：解压并核对位置

1. 在文件资源管理器，右键 ZIP → **全部解压**。推荐解压后把文件夹放到 `C:\Tools\CC-Auditor`。也可以放在 Downloads 的独立文件夹，但后面两处配置必须改成自己的实际路径。
2. 打开解压后的文件夹，找到 **CC_Auditor.exe**、**_internal** 和 **skills** 文件夹，确保三者没有分开。
3. 此教程以下统一以可执行文件位于 `C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe` 为例；**如果文件位置不同，配置里的路径也必须改**。
4. 若 Windows 提示缺少 Visual C++ x64 运行库，按 [微软官方说明](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)安装对应 x64 组件。不要从陌生网站下载 DLL 或关闭安全保护。

### 建议核对下载完整性

在包含 ZIP 的文件夹打开 PowerShell，输入：

```powershell
Get-FileHash -LiteralPath '.\CC_Auditor_3.6.0-beta.1_Windows_x64.zip' -Algorithm SHA256
```

比较得到的 64 位 Hash 与同版 `SHA256SUMS.txt` 里 Windows ZIP 对应行是否相同。不同就停止使用并重新从 Release 下载。

## 第三步：让你的 Agent 连接本机 Toolkit

**不限定 Agent 品牌。** 你可以使用任何能够调用本机 Windows 工具、支持 MCP（或具有等效本机工具集成）且能读取 Skill 指导文档的 Agent。是否支持这些能力，应以该 Agent 当前版本的实际功能为准；有些 Agent 仅运行在云端，**不能自动直接访问你电脑上的 EXE**。

请按这几个**通用步骤**操作：

1. 在 Toolkit 解压目录找到 `skills\cc-auditor-preflight\`，其中必须包含 `SKILL.md` 和 `references\CONFIGURATION.md`。
2. 打开你常用 Agent 的“Skills / 技能”安装位置，**复制整个 `cc-auditor-preflight` 文件夹**。不同 Agent 的安装目录不同，按照该 Agent 的官方说明操作；若没有 Skill 安装机制，也可让 Agent 读取本 Skill 文档并遵循它的工具调用约束。
3. 在 Agent 的“MCP / 工具 / 本地命令”配置里添加一个 **stdio 类型**的本机工具，名称建议为 `cc-auditor-preflight`，**可执行文件路径为你的真实 `CC_Auditor.exe` 路径**，启动参数为 `--mcp`。例如教程默认路径：`C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe`。
4. 保留 Agent 自己的工具审批；单次调用超时建议足够覆盖原生授权和深度扫描（例如 20 分钟）。不要运行 `启动预检.cmd` 作为 MCP stdio 命令，因为它不是标准协议入口。
5. 重新加载 Agent 的工具和 Skill，给它发送下面的**连接验证指令**：

> 请检查是否已连接本机 CC Auditor 的 MCP 工具，只调用 `audit_capabilities` 并报告实际程序版本和可用接口。不要开始扫描，也不要修改本机文件。

如果成功返回真实版本和工具能力，才进入第四步。如果找不到工具，先检查是否完整解压、MCP 命令路径是否正确、该 Agent 是否真正支持本机 stdio MCP、以及是否需要重新载入配置。

**关于 Agent 的选择：** Codex、Gemini、其他桌面 Agent、Agent 平台等都可以按各自支持的实际能力接入，**本项目不要求使用特定提供商**。如果某 Agent 没有本地 MCP/Tool 接口，不能只靠一句对话就读取你的 Windows；这时用具备本机访问能力的 Agent，或者采用文末的独立 EXE 方式。

### 技术配置样例（只是示例，不是限定支持名单）

各种 Agent 的配置文件格式不一样，**不要把一种 Agent 的 TOML 或 JSON 原封不动复制到另一种 Agent**。以下两个片段仅帮助理解“路径 + 参数”的组合；你的 Agent 可能有更简单的图形设置页面。

<details>
<summary>示例 A：使用 TOML 配置 MCP 的本机 Agent</summary>

```toml
[mcp_servers.cc-auditor-preflight]
command = 'C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe'
args = ["--mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 1200
```

此配置仅适用于采用对应字段规范的 Agent，例如部分 Codex CLI 版本。
</details>

<details>
<summary>示例 B：使用 JSON mcpServers 配置的本机 Agent</summary>

```json
{
  "mcpServers": {
    "cc-auditor-preflight": {
      "command": "C:\\Tools\\CC-Auditor\\CC_Auditor\\CC_Auditor.exe",
      "args": ["--mcp"]
    }
  }
}
```

仅将 `mcpServers` 项合并到已有设置；字段、超时单位和确认机制应符合对应 Agent 的规范。
</details>

更完整的本机配置示例、不同超时含义和故障排查参见 [Skill 与 MCP 技术说明](MCP_CONFIGURATION_ZH.md)。

## 第四步：复制这段任务，交给 Agent

**整段复制到新的本机 Agent 对话：**

> 请使用我已安装的 cc-auditor-preflight Skill 与已连接的本机 MCP 工具，对这台 Windows 电脑做一次 Claude 使用前深度环境预检。我尚未必安装或使用 Claude；未安装不是故障。先执行 audit_capabilities 验证工具版本，再执行 prepare_deep_preflight，从真实工具返回值取得 scan_id，之后调用 run_approved_deep_preflight(scan_id)。我会自己在 Windows 原生授权界面选择范围并点击批准；不要替我批准或从聊天内容伪造批准。请在批准范围内自动检测 Windows、实际生效的代理与路由、日常真实浏览器 Profile、DNS/IPv4/IPv6、已授权的中立测点。不要主动访问 Claude 或 Anthropic，不改变系统网络设置，不读取或上传 Cookie、密码和完整私人文件。扫描完成后请用简体中文汇报 Desktop、Web、CLI、API 四端正向健康分、技术准备情况、主要正常因素、关键问题及具体下一步，并显示两份 PDF 的本地路径；有需要时显示第三份证据补足清单。只回传脱敏摘要，不自动上传完整原始报告或证据。

**接下来你应当看到：** Agent 首先读到 Toolkit 的实际版本，然后出现 Windows 原生授权卡；由你自己勾选范围和日常 Profile，批准后 Agent 等待一次扫描返回并汇报。**不要让 Agent 自动点击批准。**

## 第五步：找到报告

正常完成后，Agent 应给出两份 PDF 的 Windows 本地路径：简明使用前报告和完整技术报告。若还有能补的重要缺口，会有第三份证据补足清单。通常文件位于 EXE 旁的 `data\preflight_v3\<本轮编号>\` 目录；以 Agent 返回的 `pdf_paths` 为准。

请先看简明版的四端健康分、是否适合开始安装配置和前几项优先行动；没有确认的最终 Claude 出口、注册资格和支付成功率不能被当成已验证。

## 遇到问题时怎么处理

| 现象 | 如何处理 |
|---|---|
| 点击蓝色链接 404 | 从本页重新打开完整 URL；如果是源代码/Skill 路径，请核对仓库分支。当前主分支提供本指南，完整源码 PR 仍在审核。 |
| 找不到 Skill | 确认复制的是整个文件夹（含 SKILL.md 与 references），并重新载入 Agent。 |
| MCP 无工具 | 检查实际 EXE 绝对路径、参数 \`--mcp\`、Agent 是否支持本机 stdio MCP，及工具是否需要重载；按该 Agent 自己的工具管理界面核对。 |
| EXE 报缺 DLL | 完整解压，检查 _internal，并按微软官方安装 x64 VC++ 运行库；不要去下载来历不明的 DLL。 |
| Agent 提示权限拒绝 | 通过 Agent/Windows 自己提供的正规审批流程授权，不绕过组织或系统权限设置。 |
| 授权卡没有显示 | 检查任务栏与多显示器，确认没有重复启动；取消后重新 prepare，不复用旧 scan_id。 |
| 浏览器测试未完成 | 先打开日常 Profile 普通窗口，确实批准相应动态检测；不要用无痕或临时空白 Profile 代替。 |
| 等待超时 | 不要并行重复扫描。保留工具返回的诊断摘要，检查客户端工具超时与本机 EXE 是否仍在运行。 |

## 不使用 Agent 也可以完成扫描

如果暂时不想配置 Agent，可以直接双击 `CC_Auditor\启动预检.cmd`，亲自在原生界面批准，并在本机查看 PDF。后面随时可以再安装 Skill 和 MCP。

## 当前发布边界

这是 beta 预发布，不是已全面验收的稳定版。CI 成功和单台 Windows 实测不能证明所有 Agent 客户端与所有代理软件都已覆盖。本工具并非 Anthropic 官方产品，不保证真实账号、注册、支付或封禁结果。完整源码集成仍在 [PR #1](https://github.com/jclllycf/cc-auditor/pull/1) 审查。
