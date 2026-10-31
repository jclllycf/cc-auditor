# 检测覆盖对照与下一步升级

2026-10-31 · v3.7.0-dev1 开发源码；不是新 EXE 的实机验收。

目前已包含网站常见检测中的一部分，并新增了本机只读证据与详细浏览器特征；**尚不能宣称完整包含所有网站或 EnvGuardCC 的检测**。实现范围、本轮授权、采样状态、Profile 归属与服务端未知分别报告。没有用管理员权限或 Agent 权限代替用户原生授权。

## 对照来源与方法

- EnvGuardCC：本机安装包 `package.json` 版本 0.1.0，配置中 50 个检测 ID，其中 `apiReachability` 默认关闭。对照限定在已安装版本的配置和选定浏览器源码，不声称覆盖其所有版本或已运行该软件的真实保护功能。
- 配置文件 SHA-256：`1756f3376d517207cb06e4e5fa0131a8e00d333635c33f68fb4631fc3f1a2628`。REA 仅作静态解析，未执行检测器、网关、注入或保护脚本。描述与实现独立编写，没有移植其风险权重或保护代码。
- 网站：参考现场记录中的 IPLeak、BrowserLeaks DNS/WebRTC、DNSLeakTest Extended、IPPure、IPv6 与指纹类别。当前按**功能类别**对照，没有新加载这些页面，没有完成各网站当前版本的一一实测或比较排名。
- 可执行对照账本：`cc_auditor/toolkit/coverage_v37.py`，50 个 EnvGuardCC ID 各映射一次；MCP `audit_capabilities` 返回实现范围，`get_preflight_evidence(view="coverage")` 返回同一账本与该轮详细浏览器状态。能力存在不等于本机测过或通过。

## 已有能力与这次新增

| 类别 | 当前实现 | 实测边界 |
|---|---|---|
| 语言、时区、UTC 偏移、平台、低熵 Client Hints | 原有浏览器工具页 | 本页报告值；不证明物理所在地 |
| IPv4 / IPv6 / DNS / ICE / TLS、HTTP2、JA4 | 原有独立测点 + v3.7 地址语义和完成态 | 逐 Profile 接收回执；未知和超时不算通过 |
| 多源 IP 参考、RDAP、BGP/RPKI、声誉 | 原有本机中立请求 | 本机视点；尚不能自动继承为浏览器出口 |
| Windows / 浏览器地区、Profile 指定诊断键、扩展权限、代理、路由、有限进程关联 | 原有本机只读采集 | 网站通常看不到的本机层；配置不等于生效或因果 |
| 字体候选 | **新增** 12 个固定候选 × 3 个 fallback 的渲染度量差异 | 不是完整安装清单，不推断民族、国家或厂家 |
| Emoji | **新增**固定字符实际像素与色彩统计 | 不从 UA 猜样式，不识别国别或系统身份 |
| Canvas | **新增**固定画布绘制、非透明像素统计、连续回读比较 | 不生成稳定 Canvas 哈希，不声称跨站唯一性或真实性 |
| WebGL | **新增**厂商/渲染器、扩展数、最大纹理尺寸 | 浏览器可掩蔽或改变；不是 Bot Score |
| Audio | **新增**单声道、4096 帧、44100 Hz 离线合成渲染 | 不播放声音、不录音、不申请麦克风；无稳定音频哈希 |
| 权限 | **新增**定位、通知、摄像头、麦克风、local-fonts 状态查询 | 不申请权限、不枚举设备或字体；只适用临时工具 origin |
| 请求头 | **新增**环回 POST 的三个 Fetch Metadata 字段；保留语言/UA | 不是完整外站请求头或目标站点观察 |

新增六组详细浏览器探针使用单独 `browser_feature_details` 范围，原生卡默认不勾选。必须同时批准 `browser_dynamic` 并选中已打开的日常 Profile。未经该范围授权，页面不注入新探针，服务端不接受其详细字段作为结果。

每组单独保留 `observed / unsupported / failed / timeout`；缺数据是 `not_run`，未授权是 `not_authorized`。失败与缺项可在原有 75 秒总预算内重试一次，不扩大权限，不重试明确不支持项，原样保留首次尝试。新项目暂不进入健康分，不把权限 denied 或不同字体当成故障。

原始渲染器与候选差异写入本机 JSON / 技术 PDF；默认 MCP 状态视图不回传这些细节。它们仍是具有识别性的环境信息，不能把无哈希理解成整份报告匿名。

## EnvGuardCC 50 项功能映射

以下是类别映射，**不是“50 项全部实现”计数**。`partial` 的具体缺项见上表及可执行账本。

| 类别 | 对照 ID | 范围 |
|---|---|---|
| 浏览器语言/时区 | timezone, language, languageVariant, timezoneOffset | 工具页可观测值 |
| 系统区域 | locale | Windows 与浏览器配置参考 |
| 字体 | chineseFonts, vendorFonts | 部分：固定候选度量，不移植分类 |
| Emoji | emojiStyle | 实际渲染统计，不复制系统归因 |
| 浏览器/平台 | domesticBrowser, os, clientHints | 平台事实；不复制品牌风险权重 |
| 本机 IP 参考 | country, proxyCountry, exitType, multiSourceConsistency, ipSourceCount, countrySet | 部分：本机视点，不保证代理节点或 Profile 等价 |
| 浏览器地址 | ipv4 | 另有 IPv6 接收回执 |
| 浏览器归属 | browserIpLocation, browserIpOrg | **待接入**逐 Profile IP 的多源查询 |
| WebRTC | webrtcSupport, webrtcCandidates, webrtcLeak, webrtcLeakCount, webrtcFirstIp, webrtcRegion, webrtcConsistency | 部分：候选与完成态；不是这些风险判定的完整等价实现 |
| DNS | dnsMode, dnsReview, dnsConsistency | 部分：回执/配置；完整运行因果归属待补 |
| 请求头 | requestHeaders, httpLanguage, secFetch | 部分：受限工具 origin |
| 边缘节点 | edgeCountry, edgeColo, edgeCity, edgeAsn, edgeOrg, edgeAsnSecondary | **待实现**中立 HTTP edge 接收链；不同于目标站点 edge |
| 目标网关 | gatewayProfile, deviceLineage, gatewayAsn | **默认不测**：零主动 Claude 接触；不猜内部画像 |
| 目标可达性 | claudeReachability, anthropicReachability, apiReachability, claudeTrigger, claudeLatency | **默认不测**：零主动接触边界，不用中立成功冒充 |
| 来源/风险推断 | domesticDevice, ipCountryRisk, claudeAccessRisk | **不移植**无证据的设备国别或账号风险结论 |

## Agent 权限带来的增量与后续顺序

Agent 可以在用户批准范围内关联 Windows 生效配置、指定 Profile 设置、应用进程与接收回执，这是单个网页难以完成的部分。当前仍不自动提权、绕过浏览器/操作系统限制或修改防护配置。

1. **逐 Profile 多源出口归属 + 中立 HTTP edge**：复用已有白名单传输层；只查询当次浏览器实测 IP，并绑定 IP/来源/时间/视点。增加接收端前更新代码白名单与原生卡；不允许任意 URL。验收包含源间分歧、IPv6、回执不匹配、限流与过期。
2. **生效 DNS/路由归因**：进一步关联源配置、GUI 覆写、运行内核、浏览器 DoH、扩展、代理规则版本与实际命中。核对业务意图和网络视点后，才能确认偏差；不按节点组名猜出口。
3. **多轮/多接收器验证**：补有界的 Extended DNS、多 STUN 以及不同应用视点；保留每轮失败，不把增加请求数当全面覆盖。与同一日常 Profile 的网站人工回执逐项对照，公开差异而非排名。
4. **故障态与修复闭环**：停内核、断线、WFP/防火墙、回滚及多代理矩阵需要单独授权和离线恢复方案。现有只读修复预案没有执行器，配置检查不代表 Kill Switch 验收。

站点私有 Cloudflare Bot Score、账号资格与服务端风控不因本机管理员权限而可读取。它们保持独立的未知/不可用状态，不伪造统一“纯净度”或封禁概率。

实现依据：[Permissions.query](https://developer.mozilla.org/en-US/docs/Web/API/Permissions/query)、[OfflineAudioContext](https://developer.mozilla.org/en-US/docs/Web/API/OfflineAudioContext)。权限查询和离线渲染的 API 文档已通过 Context7 核对；浏览器实际支持度仍按本次返回值报告。
