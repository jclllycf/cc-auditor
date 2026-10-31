# v3.7 证据诊断升级 · 实施与复用清单

基线：`6c4d7a2f153323248f7751853607e818695523be`；分支：`codex/v3.7-evidence-20261031`。
2026-10-31 开发前使用 Python 3.12 运行原有 203 项离线测试，全部通过。
随附 Pillow 原生扩展为 cp312；Python 3.14 基线的三项 PDF 失败属于解释器不兼容，未通过改写第三方依赖规避。

## 函数级复用与缺口（编码前核对）

| 复用位置 | 已有行为 | 本轮增量 |
|---|---|---|
| `preflight_v3.make_report/run/save/read` | 授权编排、摘要、不可变 JSON 与哈希核验 | 附加版本化诊断；旧 schema 和评分契约保留；旧 JSON 可离线解释 |
| `profiles_v3.discover/dynamic_profile` | 定向打开日常 Profile、PID 有限归属；编号按发现顺序 | 增加仅在本进程有效的加盐路径绑定，禁止拿编号当稳定身份 |
| `deep_network_v31.parse_dns_txt/parse_stun/sanitize_browser` | 固定接收器、异常与地址族校验 | 使用显式特殊地址分类，补无效候选与零候选的区别 |
| `route_correlation.inspect_routes` | 只读 PID 归属控制器、当前规则/模式/选择组；文件不等于 runtime | 增加脱敏有效配置投影与指纹；不把未公开的 DNS 字段补成配置已生效 |
| `zero_contact_guard` / 浏览器 loopback CSP | 固定中立目的地，无任意 URL | 不新增接收器、不加载外部检测站、不把历史访问当本轮零接触证据 |
| `health_v35.assess` | 四端健康分、资格分离、缺证扣分上限 | 不改变公式；新证据诊断不暗中改变旧分数含义 |
| `mcp_v3.dispatch_mcp_tool` | 七工具、原生授权、最多十条证据 | 在现有读取工具增加诊断视图及可选历史扫描对照，不增加写权限 |
| `pdf_v35.technical_html/build` | 同一 JSON 派生双 PDF，固定字体与校验 | 增加证据诊断/修复预案章节；离线快照与真实复测分开 |
| `release_guard` / `run_tests` | 发布隐私边界、203 项离线回归 | 增加负例、候选变更审查；不改写 v3.6 发行清单冒充新发行 |

## 来源的用途与边界

读取两轮本机 NetworkLab 初检/修复记录及已有 EnvGuardCC 静态审查，仅吸收方法与负例。
安装版 `client-engine.ts:isPublicIp` 和 `emoji-style.ts:run` 本轮再次静态检查：特殊地址排除不完整，Emoji 标签来自 UA 正则。
REA 对这两个源文件作静态解析；没有启动 EnvGuardCC、执行保护脚本或接触账号。其它文件未在本轮全面审计。
私人报告、IP、配置、截图和原始 REA 本机路径不复制进公开样例。

- 原始现场复盘保留在本地项目中；本候选公开的是本文件的复用结论、下列任务规范和合成负例。
- [Issue 4：测量与第三方分数](https://github.com/jclllycf/cc-auditor/issues/4)
- [Issue 5：方案、审批、同视点复检与回滚](https://github.com/jclllycf/cc-auditor/issues/5)
- [IANA IPv4 特殊用途注册表](https://www.iana.org/assignments/iana-ipv4-special-registry)
- [IANA IPv6 特殊用途注册表](https://www.iana.org/assignments/iana-ipv6-special-registry)

本机初检记录明确记载：历史 Net.Coffee 首页曾发起未预期的第三方探测，已停止，历史轮次不能宣称零 Anthropic 联系。本轮不打开这些测试站；升级验证仅使用合成输入。

## 本轮交付边界与后续顺序

本轮完成 M0 证据契约及可运行诊断切片：特殊地址、独立 Profile、来源/干预态/失败状态、只读修复预案、严格前后对照和报告接线。
有效配置仅扩展现有已授权读取结果，尚不承诺完整 GUI 合并脚本追踪或全部协议归因。

下一步按顺序推进：

1. 有效 DNS 源/生成/运行态链与规则数据版本；取得授权后逐 Profile 新鲜接收端回执。
2. 多协议与故障态矩阵；真实断网、停内核等测试逐项另行授权，具备离线恢复。
3. 独立修复执行器：固定操作白名单、原生二次审批、冲突检查、敏感备份与恢复验证。本轮只输出方案。
4. 多代理真实验收、独立零 Claude Windows 新用户验收，再生成新发行清单及发布候选。

现有 Beta、安装包、生产代理、浏览器设置和防火墙均不属于本轮修改目标。
