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

## 第三步：选一种本机 Agent（推荐 Codex CLI 或 Gemini CLI）

下面只需选 **A 或 B 一种**。**如果你的 Agent 完全在云端运行，无法直接使用这台电脑的 Windows EXE 路径**；必须配置可访问本机的受支持执行环境。普通 Claude、网页聊天和其他不支持本机 stdio MCP 的 Agent 不能直接照用以下本地配置。

### A. 本机 Codex CLI（或实际使用同一 Codex 配置的本机客户端）

1. 在文件资源管理器地址栏输入 `%USERPROFILE%\.agents\skills` 并回车。如果不存在，先新建这个文件夹。
2. 从 Toolkit 的 `skills` 目录把整个 `cc-auditor-preflight` 文件夹复制进去。确认最终存在 `%USERPROFILE%\.agents\skills\cc-auditor-preflight\SKILL.md`，以及 `references\CONFIGURATION.md`。
3. 打开 `%USERPROFILE%\.codex\config.toml`（如果没有，先新建）；只把以下配置**追加/合并**进去，不要删除已有配置。如果已经存在同名 `[mcp_servers.cc-auditor-preflight]`，请修改那一项，不要重复写同名表：

```toml
[mcp_servers.cc-auditor-preflight]
command = 'C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe'
args = ["--mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 1200
```

4. 保存并重新启动本机 Codex CLI。在终端运行 `codex mcp list`，应能看到 `cc-auditor-preflight`（这里只能证明已注册）。
5. 在 Codex 对话输入：「请调用 cc-auditor-preflight 的 audit_capabilities，先只检查 MCP 能否正常连接，不要开始扫描。」若返回实际工具版本，再使用下方完整任务指令。

### B. Gemini CLI

1. 在 `%USERPROFILE%\.gemini\skills` 下复制完整的 `cc-auditor-preflight` 文件夹（包括 references）。
2. 打开 `%USERPROFILE%\.gemini\settings.json`，保留原来的设置，把下列 MCP 服务**合并**进 JSON 的 `mcpServers`，不要直接把下面整个示例替换已有文件：

```json
{
  "mcpServers": {
    "cc-auditor-preflight": {
      "command": "C:\\Tools\\CC-Auditor\\CC_Auditor\\CC_Auditor.exe",
      "args": ["--mcp"],
      "timeout": 1200000,
      "trust": false
    }
  }
}
```

3. 在 Gemini CLI 使用 `/skills reload`，再查看 `/skills list` 和 `/mcp`；不同版本的命令可能略有变化，以当前 CLI 提示为准。
4. 在对话输入：「请调用 cc-auditor-preflight 的 audit_capabilities，先验证本地连接，不要开始扫描。」确认返回版本后再使用下方完整任务指令。

### 其它本机 Agent

如果 Agent 支持本地 stdio MCP，配置 EXE 绝对路径与参数 `--mcp`；Skill 要放入该 Agent 自己支持的目录。具体字段和目录不能直接套用 Codex/Gemini 例子，请参考 [技术配置说明](MCP_CONFIGURATION_ZH.md)。

## 第四步：复制这段任务，交给 Agent

**整段复制到新的本机 Agent 对话：**

> 请使用 cc-auditor-preflight Skill 和已经连接的本机 MCP 工具，对这台 Windows 电脑做一次 Claude 使用前深度环境预检。我尚未必安装或使用 Claude；未安装不是故障。先执行 audit_capabilities 验证工具版本，再执行 prepare_deep_preflight，从真实工具返回值取得 scan_id，之后调用 run_approved_deep_preflight(scan_id)。我会自己在 Windows 原生授权界面选择范围并点击批准；不要替我批准或从聊天内容伪造批准。请在批准范围内自动检测 Windows、实际生效的代理与路由、日常真实浏览器 Profile、DNS/IPv4/IPv6、已授权的中立测点。不要主动访问 Claude 或 Anthropic，不改变系统网络设置，不读取或上传 Cookie、密码和完整私人文件。扫描完成后请用简体中文汇报 Desktop、Web、CLI、API 四端正向健康分、技术准备情况、主要正常因素、关键问题及具体下一步，并显示两份 PDF 的本地路径；有需要时显示第三份证据补足清单。只回传脱敏摘要，不自动上传完整原始报告或证据。

**接下来你应当看到：** Agent 首先读到 Toolkit 的实际版本，然后出现 Windows 原生授权卡；由你自己勾选范围和日常 Profile，批准后 Agent 等待一次扫描返回并汇报。**不要让 Agent 自动点击批准。**

## 第五步：找到报告

正常完成后，Agent 应给出两份 PDF 的 Windows 本地路径：简明使用前报告和完整技术报告。若还有能补的重要缺口，会有第三份证据补足清单。通常文件位于 EXE 旁的 `data\preflight_v3\<本轮编号>\` 目录；以 Agent 返回的 `pdf_paths` 为准。

请先看简明版的四端健康分、是否适合开始安装配置和前几项优先行动；没有确认的最终 Claude 出口、注册资格和支付成功率不能被当成已验证。

## 遇到问题时怎么处理

| 现象 | 如何处理 |
|---|---|
| 点击蓝色链接 404 | 从本页重新打开完整 URL；如果是源代码/Skill 路径，请核对仓库分支。当前主分支提供本指南，完整源码 PR 仍在审核。 |
| 找不到 Skill | 确认复制的是整个文件夹（含 SKILL.md 与 references），并重新载入 Agent。 |
| MCP 无工具 | 检查路径是否指向实际 EXE、args 是否为 --mcp、工具超时是否足够；Codex 用 codex mcp list，Gemini 用 /mcp。 |
| EXE 报缺 DLL | 完整解压，检查 _internal，并按微软官方安装 x64 VC++ 运行库；不要去下载来历不明的 DLL。 |
| Agent 提示权限拒绝 | 通过 Agent/Windows 自己提供的正规审批流程授权，不绕过组织或系统权限设置。 |
| 授权卡没有显示 | 检查任务栏与多显示器，确认没有重复启动；取消后重新 prepare，不复用旧 scan_id。 |
| 浏览器测试未完成 | 先打开日常 Profile 普通窗口，确实批准相应动态检测；不要用无痕或临时空白 Profile 代替。 |
| 等待超时 | 不要并行重复扫描。保留工具返回的诊断摘要，检查客户端工具超时与本机 EXE 是否仍在运行。 |

## 不使用 Agent 也可以完成扫描

如果暂时不想配置 Agent，可以直接双击 `CC_Auditor\启动预检.cmd`，亲自在原生界面批准，并在本机查看 PDF。后面随时可以再安装 Skill 和 MCP。

## 当前发布边界

这是 beta 预发布，不是已全面验收的稳定版。CI 成功和单台 Windows 实测不能证明所有 Agent 客户端与所有代理软件都已覆盖。本工具并非 Anthropic 官方产品，不保证真实账号、注册、支付或封禁结果。完整源码集成仍在 [PR #1](https://github.com/jclllycf/cc-auditor/pull/1) 审查。
