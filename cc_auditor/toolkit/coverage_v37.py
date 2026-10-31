"""A versioned capability crosswalk, never a claim that the host passed tests."""
from __future__ import annotations

from collections import Counter

CONTRACT = '3.7.coverage.1'
# Independently authored descriptions. IDs refer to the installed app's config,
# not its private algorithms, brand/country scoring or protection injections.
GROUPS = (
    ('browser_locale','浏览器语言、时区与偏移','bounded_observation','browser_probe.py',
     '自有页配置；不代表物理所在地或资格。'),
    ('system_region','Windows 国家、格式与限定浏览器策略','bounded_observation','region_v32.py',
     '本机设置、Local State 与限定策略；不作 Claude 地区事实。'),
    ('fonts','固定字体候选渲染差异','partial','browser_details_v37.py',
     '12 个候选、3 个 fallback 的度量差异；不是完整字体清单或厂家识别。'),
    ('emoji','Emoji 实际像素统计','bounded_observation','browser_details_v37.py',
     '固定字符的有色/非透明像素数；不从 UA 猜 Emoji 或系统归属。'),
    ('browser_identity','浏览器、平台与低熵 Client Hints','bounded_observation','browser_probe.py',
     '浏览器报告值，可被策略或扩展改变，不作品牌风险分类。'),
    ('host_ip_intel','本机中立出口、多源归属与声誉参考','partial','network_v3.py',
     '保留来源与分歧；不继承为日常浏览器、节点或目标站点出口。'),
    ('browser_ip','逐 Profile IPv4 / IPv6 接收回执','bounded_observation','deep_network_v31.py',
     '固定中立接收器；不能代表所有站点的出口。'),
    ('browser_ip_geo','逐 Profile 多源地理/ASN/组织交叉查询','not_implemented','',
     '已有浏览器 IP 回执，尚未接入该 IP 的逐 Profile 多源归属链。'),
    ('ice','逐 Profile ICE / STUN 候选与特殊地址分类','partial','deep_network_v31.py',
     '完整收集态与 RFC/IANA 分类；公网候选本身不确认泄漏，尚缺完整业务意图关联。'),
    ('dns','系统/浏览器权威 DNS 回执与配置角色','partial','deep_network_v31.py',
     '有接收回执与 DNS 角色快照；尚未完成全部运行内核/DoH 因果归属。'),
    ('request_headers','环回请求语言、UA 与 Fetch Metadata','partial','browser_probe.py',
     '语言/UA 与低熵 UA-CH；新增 POST Fetch Metadata。不是外部站点请求头全量捕获。'),
    ('neutral_edge','中立 HTTP 接收端 edge colo / city / ASN','not_implemented','',
     '尚无明确授权的 edge trace 接收链；STUN 使用 Cloudflare 不等于 HTTP edge 测量。'),
    ('target_gateway','目标站点网关/挑战/边缘内部画像','excluded_zero_contact','',
     '预检不主动接触 Claude；已有连接元数据不能代替网关服务端画像。'),
    ('target_reachability','Claude / Anthropic 目标可达性与延时','excluded_zero_contact','',
     '违反零主动接触默认范围，不用中立端点成功冒充目标成功。'),
    ('origin_classifier','设备/语言/国家到账号风险的分类','not_inferred','',
     '记录可观测事实，不复制国别/字体/品牌或账号风控推断。'),
    ('canvas','Canvas 绘制与重复回读','bounded_observation','browser_details_v37.py',
     '128×32 固定画布，像素统计与连续回读相等性；无稳定指纹哈希。'),
    ('webgl','WebGL 厂商、渲染器与能力','bounded_observation','browser_details_v37.py',
     '受策略掩蔽的浏览器报告值，不证明真人/机器人。'),
    ('audio','离线 Audio 渲染能力','bounded_observation','browser_details_v37.py',
     '单声道 4096 帧合成缓冲；不播放、不使用麦克风、不生成音频指纹哈希。'),
    ('permissions','临时 origin 权限状态','bounded_observation','browser_details_v37.py',
     '只 query 五种权限，不 request；不继承为其他站点的授权状态。'),
    ('storage','Cookie / Storage / IndexedDB 实验写入与清理','bounded_observation','browser_probe.py',
     '仅本工具随机实验键；不读取已有站点数据。'),
    ('tls','真实浏览器 TLS / HTTP2 / JA4 接收回执','partial','deep_network_v31.py',
     '固定中立端点回执；非目标站点握手，非站点私有评分。'),
    ('bot_score','第三方或目标站点私有 Bot Score','server_private','',
     '本机管理员权限不能获取站点私有风控状态；无测量结果便不打分。'),
    ('local_correlation','本机路由、代理、Profile 与应用运行视点','partial','preflight_v3.py',
     '网站外的本机只读证据；尚无全链路进程归属或断网/故障态验收。'),
)

ENV_MAP = {
    'browser_locale': 'timezone language languageVariant timezoneOffset',
    'system_region': 'locale',
    'fonts': 'chineseFonts vendorFonts',
    'emoji': 'emojiStyle',
    'browser_identity': 'domesticBrowser os clientHints',
    'host_ip_intel': 'country proxyCountry exitType multiSourceConsistency ipSourceCount countrySet',
    'browser_ip': 'ipv4',
    'browser_ip_geo': 'browserIpLocation browserIpOrg',
    'ice': 'webrtcSupport webrtcCandidates webrtcLeak webrtcLeakCount webrtcFirstIp webrtcRegion webrtcConsistency',
    'dns': 'dnsMode dnsReview dnsConsistency',
    'request_headers': 'requestHeaders httpLanguage secFetch',
    'neutral_edge': 'edgeCountry edgeColo edgeCity edgeAsn edgeOrg edgeAsnSecondary',
    'target_gateway': 'gatewayProfile deviceLineage gatewayAsn',
    'target_reachability': 'claudeReachability anthropicReachability apiReachability claudeTrigger claudeLatency',
    'origin_classifier': 'domesticDevice ipCountryRisk claudeAccessRisk',
}


def catalog():
    rows=[]
    for key,title,support,module,boundary in GROUPS:
        rows.append({'id':key,'title_zh':title,'implementation':support,'module':module,
                     'envguard_ids':ENV_MAP.get(key,'').split(), 'boundary_zh':boundary})
    return {'contract':CONTRACT,'reviewed_at':'2026-10-31','groups':rows,
            'envguard_reference':{'version':'0.1.0','configured_items':50,'disabled_ids':['apiReachability'],
                                 'evidence':'installed_package_selected_static_sources_not_runtime_verification'},
            'implementation_counts':dict(Counter(r['implementation'] for r in rows)),
            'website_comparison_scope':'capability_families_only_not_current_site_by_site_parity',
            'full_superset_claim':False,'implemented_does_not_mean_measured':True}


def summary(report):
    from .browser_details_v37 import summarize
    return {**catalog(),'browser_detail_attempts':summarize(report),
            'synthetic':report.get('synthetic') is True,
            'measurement_note_zh':'能力对照不是本机检测结果。浏览器状态只描述本次临时工具 origin；归属强度和采样时间另列。'}
