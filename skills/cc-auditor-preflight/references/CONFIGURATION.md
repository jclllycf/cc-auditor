# Skill 与 MCP 配置

适用：在**这台 Windows** 上运行的非 Claude Agent。只用 EXE 的用户可跳过整页。本文按 2026-10-22 查询的官方 Codex / Gemini CLI 格式编写；配置语法核对与某个 Agent 版本已实机验收是不同事实，实际测试范围见 Release 回执。

## 两个组件分别做什么

| 组件 | 作用 |
|---|---|
| Windows Toolkit | 执行本机采集、原生授权、评分及本地 PDF 输出 |
| stdio MCP 服务 | Agent 启动同一 EXE，通过标准输入输出调用七项工具 |
| `cc-auditor-preflight` Skill | 告诉 Agent 调用顺序、隐私边界和解释方法 |

先完整安装 Toolkit，再安装整个 Skill 文件夹（包括 `references`）。不要只复制 `SKILL.md`。不需要 Claude API Key、MCP OAuth、HTTP 服务器或公开网络端口。云端或 WSL 中的 Agent 不能直接把本地 Windows 路径当成自己的执行环境；本版本没有自动远程接入安装流程。

## Codex CLI / 本机 Codex 配置

把以下一项合并到 `%USERPROFILE%\.codex\config.toml`；若已设置自定义 `CODEX_HOME`，修改该账户实际使用的配置。保留其它已有项，先备份，不覆盖整份文件。

```toml
[mcp_servers.cc-auditor-preflight]
command = 'C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe'
args = ["--mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 1200
```

TOML 单引号字符串中的反斜杠不需双写。`tool_timeout_sec` 给真人阅读授权卡和完整扫描留出时间，不扩大工具本身的许可或授权有效期。Codex 默认工具超时较短，因此不要遗漏该项。

将包内 `skills\cc-auditor-preflight` 整个文件夹复制到 `%USERPROFILE%\.agents\skills\cc-auditor-preflight`。只想对一个项目生效时，放在该项目 `.agents\skills\`。不要同时安装多个同名副本。旧版 Codex 的兼容目录可能为 `.codex\skills`，当前推荐 `.agents\skills`。

重启或重新载入 Codex，先用 `codex mcp list` 检查是否列出服务器；该命令只证明配置已登记。随后在对话中要求“调用 `cc-auditor-preflight` 的 `audit_capabilities`，暂不扫描”，收到实际版本和 `active_anthropic_probing=false` 才说明已连通。Skill 可用时，以 `$cc-auditor-preflight` 明确调用。

官方格式：[Codex MCP](https://developers.openai.com/codex/mcp)、[Codex Skills](https://developers.openai.com/codex/skills)。

## Gemini CLI

将以下服务器项合并到 `%USERPROFILE%\.gemini\settings.json` 的 `mcpServers`。已有 JSON 配置不能被整个替换；注意逗号和双反斜杠。

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

`timeout` 单位毫秒。保留 `trust: false` 和 Agent 自带的确认机制；它与 Toolkit 原生授权卡各自生效。不要为了减少提示改成自动批准。

将包内 `CC_Auditor\skills\cc-auditor-preflight` 整个文件夹复制到 `%USERPROFILE%\.gemini\skills\cc-auditor-preflight`，保留 `references`。已有同名版本时先备份，只保留一个生效副本。

在已打开的 Gemini CLI 对话中自行执行 `/skills reload`，再用 `/skills list` 与 `/mcp` 查看发现状态。若当前版本不支持本地安装命令，可将整个文件夹手动复制到 `%USERPROFILE%\.gemini\skills\cc-auditor-preflight` 后重新载入，不同时保留重复副本。

先只要求 `audit_capabilities`，确认连通后再要求使用该 Skill 做一次预检。官方格式：[Gemini MCP](https://geminicli.com/docs/tools/mcp-server/)、[Gemini Skills](https://geminicli.com/docs/cli/skills/)。

## 其它支持 stdio MCP 的本机 Agent

选择“本地命令 / stdio”类型，填 EXE 的绝对路径、参数 `--mcp`，将单次工具超时设为足以完成本机授权和扫描的时长（建议 20 分钟）。保留工具审批。

部分客户端使用上述 `mcpServers` JSON，另一些如 VS Code 使用自己的 `servers` 结构；**MCP 协议没有规定所有客户端共用一份配置文件**。请按该客户端官方文档转换字段，不能把 JSON 格式随意粘进 TOML。不要用 `cmd /c`、`pause` 或启动扫描的 `.cmd` 包装 stdio 命令，以免普通输出干扰协议。详情：[MCP stdio 规范](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#stdio)。

## 正确调用一次预检

1. `audit_capabilities({})`：确认实际程序、健康分契约和范围，不运行深测。
2. `prepare_deep_preflight({})`：准备本轮编号并发现浏览器候选；此步骤会读取有限候选元数据，不联网。
3. `run_approved_deep_preflight({"scan_id":"上一步返回的编号"})`：显示原生授权卡；本人选择并批准后执行。示意字符串须换成工具返回的真实 32 位编号，不要在终端直接照抄为有效 JSON。
4. 查看返回的健康分、建议、`pdf_paths` 和 `evidence_path`。只向模型提供脱敏摘要，不自动上传 PDF 或完整 JSON。

本服务同步执行长调用；不要发起并行重复扫描。`poll_deep_preflight` 用于读取已存在会话状态，不会让正在阻塞的同一 stdio 服务并发处理。运行中取消优先使用原生界面；`cancel_deep_preflight` 无法抢占同一同步长调用。`get_preflight_evidence` 返回最多十条脱敏证据，`build_pdf_reports` 从已保存 JSON 重建报告，不新增测量。

授权编号不是访问令牌，也不能代替本人批准。进程重启、授权过期或扫描已消耗后重新 `prepare`；不要保存旧编号重放。若目录信任、组织策略或 Agent 权限阻止启动，交给所有者在该工具支持的界面确认，不改用其它壳或关闭策略绕过。
