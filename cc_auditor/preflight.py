"""Offline, pre-install checks. No client, process scan or network is required."""
from __future__ import annotations
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import time
import uuid
import psutil
from . import VERSION
from .model import utc, fingerprint, root_dir, canonical
from . import storage

SCHEMA = "cc-auditor-preflight/1"
SURFACES = {"desktop":"桌面端", "web":"Web 网页端", "api":"API", "cli":"Code CLI"}
LEVELS = {"blocker":"需先处理", "review":"建议核对", "unknown":"尚未验证", "pass":"此项正常", "info":"使用提醒"}
SOURCES = {
    "desktop": ("官方桌面端安装要求", "https://support.claude.com/en/articles/10065433-install-claude-desktop"),
    "setup": ("官方 Code 系统与终端要求", "https://code.claude.com/docs/en/setup"),
    "network": ("官方 Code 网络配置", "https://code.claude.com/docs/en/network-config"),
    "location": ("官方位置数据说明", "https://privacy.claude.com/en/articles/11186740-does-claude-use-my-location"),
    "policy": ("官方地区政策", "https://www.anthropic.com/legal/supported-regions"),
    "local": ("本工具本地检查规则与限制", ""),
}
ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "ANTHROPIC_BASE_URL",
             "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")
BROWSER_NAMES = {"Chrome":"chrome.exe", "Edge":"msedge.exe", "Firefox":"firefox.exe"}

def _local_file(value):
    """Do not follow network drives or reparse paths while checking executable metadata."""
    import ctypes
    p=Path(value)
    if not p.is_absolute() or not re.fullmatch(r"[A-Za-z]:\\",p.anchor): return False
    if ctypes.windll.kernel32.GetDriveTypeW(str(p.anchor)) not in (2,3,6): return False
    try:
        for part in [*reversed(p.parents),p]:
            info=part.lstat()
            if getattr(info,"st_file_attributes",0) & stat.FILE_ATTRIBUTE_REPARSE_POINT: return False
        return stat.S_ISREG(info.st_mode)
    except OSError: return False

def _which(exe):
    for folder in os.get_exec_path()[:64]:
        if folder and _local_file(Path(folder.strip('"'))/exe): return True
    return False

def _registry():
    import winreg
    result = {"status":"observed", "manual_proxy_enabled":False, "manual_proxy_address_present":False, "pac_present":False}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            for field, name in (("manual_proxy_enabled","ProxyEnable"), ("manual_proxy_address_present","ProxyServer"), ("pac_present","AutoConfigURL")):
                try: result[field] = bool(winreg.QueryValueEx(key, name)[0])
                except FileNotFoundError: pass
    except FileNotFoundError: pass
    except OSError: result["status"] = "unknown"
    return result

def _browsers():
    import winreg
    found = set(); denied = False
    for name, exe in BROWSER_NAMES.items():
        if _which(exe): found.add(name)
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(hive, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exe, 0, winreg.KEY_READ | view) as key:
                        value = winreg.QueryValueEx(key, "")[0]
                        if isinstance(value, str) and _local_file(value.strip('"')): found.add(name)
                except FileNotFoundError: pass
                except OSError: denied = True
    return {"status":"partial" if denied else "observed", "names":sorted(found)}

def _hosts():
    # Only fixed service names are matched; addresses and unrelated lines never leave this function.
    targets = {"claude.ai", "api.anthropic.com", "console.anthropic.com", "platform.claude.com"}
    import ctypes
    buffer=ctypes.create_unicode_buffer(32768)
    length=ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,len(buffer))
    if not 0<length<len(buffer): return {"status":"unknown","service_entries":0,"blocking_entries":0}
    path = Path(buffer.value) / "System32/drivers/etc/hosts"
    result = {"status":"observed", "service_entries":0, "blocking_entries":0}
    try:
        if not _local_file(path): raise OSError()
        with path.open("rb") as stream: raw = stream.read(65537)
        if len(raw)>65536: return {**result, "status":"unknown"}
        for line in raw.decode("utf-8-sig", errors="replace").splitlines():
            fields = line.split("#",1)[0].split()
            if len(fields)<2 or not any(x.lower().rstrip(".") in targets for x in fields[1:]): continue
            result["service_entries"] += 1
            try:
                address = ipaddress.ip_address(fields[0])
                if address.is_loopback or address.is_unspecified: result["blocking_entries"] += 1
            except ValueError: result["status"] = "partial"
    except OSError: result["status"] = "unknown"
    return result

def collect(progress=None):
    """Read narrowly scoped host facts, not a record of the user's software/activity."""
    notify = progress or (lambda *_: None)
    facts = {}
    notify(10, "检查 Windows 与硬件")
    try:
        v = sys.getwindowsversion()
        arch = os.environ.get("PROCESSOR_ARCHITEW6432") or platform.machine()
        arch = {"amd64":"x64", "x86_64":"x64", "arm64":"arm64", "aarch64":"arm64", "x86":"x86"}.get(arch.lower(), "other")
        facts["os"] = {"status":"observed", "major":v.major, "build":v.build, "arch":arch}
    except (AttributeError, OSError): facts["os"] = {"status":"unknown", "major":0, "build":0, "arch":"other"}
    try: facts["memory"] = {"status":"observed", "ram_gb":round(psutil.virtual_memory().total/1_000_000_000,2)}
    except OSError: facts["memory"] = {"status":"unknown", "ram_gb":0}
    try:
        drive = os.environ.get("SystemDrive", "C:")
        if not re.fullmatch(r"[A-Za-z]:", drive): raise OSError()
        facts["disk"] = {"status":"observed", "system_free_gb":round(shutil.disk_usage(drive+"\\").free/1_000_000_000,2)}
    except OSError: facts["disk"] = {"status":"unknown", "system_free_gb":0}
    notify(35, "检查浏览器与终端入口，不启动 Claude")
    try: facts["browsers"] = _browsers()
    except (OSError, ImportError): facts["browsers"] = {"status":"unknown", "names":[]}
    facts["tools"] = {key:_which(exe) for key,exe in (("powershell","powershell.exe"),("pwsh","pwsh.exe"),("cmd","cmd.exe"),("git","git.exe"),("claude_on_path","claude.exe"))}
    notify(60, "检查代理、证书与目标服务 hosts 配置")
    try: facts["proxy"] = _registry()
    except (OSError, ImportError): facts["proxy"] = {"status":"unknown", "manual_proxy_enabled":False, "manual_proxy_address_present":False, "pac_present":False}
    facts["environment"] = {name:any(key.upper()==name for key in os.environ) for name in ENV_NAMES}
    facts["insecure_tls"] = os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED")=="0" or os.environ.get("PYTHONHTTPSVERIFY")=="0"
    facts["hosts"] = _hosts() if sys.platform=="win32" else {"status":"unknown", "service_entries":0, "blocking_entries":0}
    notify(90, "整理四个入口的结果与改善建议")
    return facts

def assess(f):
    rows=[]
    def add(id, surfaces, level, title, observed, action, source="local"):
        rows.append(dict(id=id,surfaces=list(surfaces),level=level,title=title,observed=observed,action=action,source=source))
    all_surfaces=list(SURFACES)
    w=f["os"]; known=w["status"]=="observed"
    windows_label="Windows 11" if w["major"]==10 and w["build"]>=22000 else "Windows 10" if w["major"]==10 else "Windows"
    add("desktop_os",["desktop"], "pass" if known and w["major"]>=10 else "blocker" if known else "unknown",
        "桌面端系统兼容性", f"{windows_label}（NT 主版本 {w['major']}，内部版本 {w['build']}）。" if known else "无法读取 Windows 版本。",
        "官方桌面端要求 Windows 10 或更高；Code / Cowork 的具体模式要求仍需核对。" if known and w["major"]>=10 else "下载前先核对并升级到官方支持的 Windows 系统；本工具不会改系统。", "desktop")
    supported=known and w["major"]>=10 and w["build"]>=17763 and w["arch"] in ("x64","arm64")
    add("cli_os",["cli"],"pass" if supported else "blocker" if known else "unknown", "CLI 系统与架构",
        f"{windows_label} / build {w['build']} / {w['arch']}。" if known else "系统版本未确认。",
        "官方要求 Windows 10 1809+ / Server 2019+ 和 x64 / ARM64；旧系统先升级。", "setup")
    m=f["memory"]; good=m["status"]=="observed"
    add("cli_memory",["cli"],"pass" if good and m["ram_gb"]>=4 else "blocker" if good else "unknown", "CLI 内存要求",
        f"物理内存约 {m['ram_gb']} GB（十进制）。" if good else "内存读取失败。",
        "官方最低要求 4 GB RAM。此检查不代表复杂任务性能；低于要求时先改善硬件。", "setup")
    d=f["disk"]; good=d["status"]=="observed"
    add("disk",["desktop","cli"],"review" if good and d["system_free_gb"]<1 else "info" if good else "unknown", "系统盘可用空间",
        f"系统盘剩余约 {d['system_free_gb']} GB。" if good else "系统盘空间未能读取。",
        "低于 1 GB 是本工具的通用空间提醒，并非 Anthropic 官方安装阈值。安装位置、更新和工作区需要另留余量。")
    b=f["browsers"]; found=b["names"]
    add("browser",["web"],"info" if found else "review" if b["status"]=="observed" else "unknown", "浏览器入口",
        "检测到已知浏览器："+"、".join(found)+"。" if found else "已知 App Paths / PATH 中没有确认 Chrome、Edge 或 Firefox；便携版可能未登记。",
        "用已更新的浏览器访问 claude.ai。实际版本、JavaScript、站点权限、扩展与登录能力尚未验证；缺少登记不等于不能使用。")
    t=f["tools"]; shell=any(t[k] for k in ("powershell","pwsh","cmd"))
    add("shell",["cli"],"pass" if shell else "review", "CLI 终端准备",
        "可找到 Windows 终端入口。" if shell else "在当前 PATH 中未找到常见 Windows 终端入口。",
        "原生 CLI 可使用 PowerShell / CMD。Git for Windows 现在是可选项，不应因未安装 Git 或 Node.js 而拦住原生安装。", "setup")
    p=f["proxy"]; env=f["environment"]; proxy_env=any(env[k] for k in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"))
    configured=p["manual_proxy_enabled"] or p["pac_present"] or proxy_env
    add("proxy",all_surfaces,"review" if configured else "info" if p["status"]=="observed" else "unknown", "网络路径配置",
        f"系统手动代理开关：{'开' if p['manual_proxy_enabled'] else '关'}；PAC：{'存在' if p['pac_present'] else '未发现'}；进程代理环境变量：{'存在' if proxy_env else '未发现'}。" if p["status"]=="observed" else "系统代理设置无法完整读取。",
        "核对代理是否由你或管理员配置，并分别测试浏览器与客户端的实际连接。代理存在本身不是账号风险；此检查未读取地址、未检测 VPN/TUN、未测出口或判断所在地。", "network")
    cert=any(env[k] for k in ENV_NAMES if k not in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY","ANTHROPIC_BASE_URL"))
    add("cert",all_surfaces,"review" if cert else "info", "自定义证书环境",
        "当前进程继承了自定义 CA / 证书路径变量。" if cert else "未发现所检查的自定义证书环境变量。",
        "企业证书可能合法。向管理员确认用途；本项未审计系统证书库，也不能排除 HTTPS 检查，不会修改或安装证书。", "network")
    add("tls",["api","cli"],"blocker" if f["insecure_tls"] else "info", "TLS 校验开关",
        "当前进程存在关闭 Node/Python TLS 校验的变量。" if f["insecure_tls"] else "未发现所检查的关闭 TLS 校验变量。",
        "如检测到关闭校验，先由你或管理员移除不安全配置并修复信任链；不要用关闭证书校验来解决连接问题。只覆盖检测器继承的环境。", "network")
    add("api_endpoint",["api","cli"],"review" if env["ANTHROPIC_BASE_URL"] else "info", "API 端点覆盖",
        "当前进程存在 ANTHROPIC_BASE_URL。" if env["ANTHROPIC_BASE_URL"] else "当前进程未发现 ANTHROPIC_BASE_URL。",
        "若使用网关，请确认运营者、数据流向和提供商条款；本工具不读取地址或密钥，不能验证实际应用配置。", "network")
    h=f["hosts"]; good=h["status"]=="observed"
    add("hosts",all_surfaces,"blocker" if h["blocking_entries"] else "review" if h["service_entries"] else "info" if good else "unknown", "目标服务 hosts 覆盖",
        f"命中固定服务域名的条目 {h['service_entries']} 条，其中回环 / 未指定地址 {h['blocking_entries']} 条。" if good else "hosts 检查未完整完成。",
        "回环 / 未指定地址可能阻止正常访问；其他固定映射可能过期。请让配置者核对对应条目，不要整体清空 hosts；DNS、代理及服务缓存仍可能改变结果。")
    add("installation",["cli"],"info","不需要预先安装 Claude",
        "PATH 中存在 Claude 可执行入口。" if t["claude_on_path"] else "PATH 中没有发现 Claude 可执行入口，这是安装前的正常状态。",
        "本次预检没有运行 Claude，没有检查登录状态，也不要求安装任何 Claude 客户端。")
    add("cli_permissions",["cli"],"review","编码前的文件权限准备","官方文档说明原生 Windows 当前不支持 Code 命令沙箱。",
        "安装前规划独立工作目录与最小授权；实际运行时逐项审核文件与命令权限。需要官方命令沙箱时再评估 WSL 2，预检不会替你安装或启用。", "setup")
    add("api_setup",["api"],"info","API 不需要桌面端","API 调用可以来自任意选定的应用或服务器；本工具没有读取密钥。",
        "在实际调用主机准备官方 SDK 或 HTTP 客户端；本机检测器里是否安装 SDK 不决定你的应用能否使用 API。")
    add("connectivity",all_surfaces,"unknown","实际连接尚未验证","此默认预检没有对外请求，也没有抓包。",
        "本地检查完成后，可单独进行有明确目标的联网实测。检测器的连接不能替代 Claude 客户端、浏览器或远端运行环境的实测。", "network")
    add("region",all_surfaces,"unknown","地区资格与账号结果","本机不能确认你的实际所在地、实体资格或 Anthropic 的后台判断。",
        "自行对照官方支持地区政策与真实情况决定是否使用。官方披露使用 IP 和其他信号；语言、时区、国籍与 IP 地理库不能直接代替实际所在地。", "location")
    return rows

def run(progress=None):
    started=time.monotonic(); facts=collect(progress)
    report={"schema":SCHEMA,"version":VERSION,"run_id":uuid.uuid4().hex,"captured_at_utc":utc(),"source_sha256":fingerprint(),
            "duration_ms":round((time.monotonic()-started)*1000),"facts":facts,"findings":assess(facts),
            "external_requests":False,"claude_required":False,"account_outcome":"unknown","policy_eligibility":"not_assessed"}
    validate(report)
    if progress: progress(100,"本地预检完成")
    return report

def validate(r):
    storage.bounded(r)
    keys={"schema","version","run_id","captured_at_utc","source_sha256","duration_ms","facts","findings","external_requests","claude_required","account_outcome","policy_eligibility"}
    if type(r) is not dict or set(r)!=keys or r["schema"]!=SCHEMA: raise ValueError("invalid_preflight")
    if not re.fullmatch(r"[0-9a-f]{32}",r["run_id"]) or not re.fullmatch(r"[0-9a-f]{64}",r["source_sha256"]): raise ValueError("invalid_identity")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",r["version"]): raise ValueError("invalid_version")
    from datetime import datetime
    if datetime.fromisoformat(r["captured_at_utc"]).utcoffset() is None: raise ValueError("invalid_time")
    if type(r["duration_ms"]) is not int or not 0<=r["duration_ms"]<=120000: raise ValueError("invalid_duration")
    if r["external_requests"] is not False or r["claude_required"] is not False or r["account_outcome"]!="unknown" or r["policy_eligibility"]!="not_assessed": raise ValueError("unsupported_claim")
    f=r["facts"]
    expected={"os":{"status","major","build","arch"},"memory":{"status","ram_gb"},"disk":{"status","system_free_gb"},"browsers":{"status","names"},"tools":{"powershell","pwsh","cmd","git","claude_on_path"},"proxy":{"status","manual_proxy_enabled","manual_proxy_address_present","pac_present"},"environment":set(ENV_NAMES),"hosts":{"status","service_entries","blocking_entries"}}
    if type(f) is not dict or set(f)!=set(expected)|{"insecure_tls"}: raise ValueError("invalid_facts")
    for group,names in expected.items():
        if type(f[group]) is not dict or set(f[group])!=names: raise ValueError("invalid_fields")
        for k,v in f[group].items():
            if k=="status":
                if v not in ("observed","partial","unknown"): raise ValueError("invalid_status")
            elif k=="arch":
                if v not in ("x64","arm64","x86","other"): raise ValueError("invalid_arch")
            elif k=="names":
                if type(v) is not list or v!=sorted(set(v)) or not set(v)<=set(BROWSER_NAMES): raise ValueError("invalid_browsers")
            elif group in ("tools","proxy","environment"):
                if type(v) is not bool: raise ValueError("invalid_flag")
            elif type(v) not in (int,float) or not 0<=v<=1e9: raise ValueError("invalid_number")
    if type(f["insecure_tls"]) is not bool or f["hosts"]["blocking_entries"]>f["hosts"]["service_entries"]: raise ValueError("invalid_facts")
    if r["findings"]!=assess(f): raise ValueError("invalid_findings")
    return r

def render(r):
    validate(r); esc=lambda x:html.escape(str(x),quote=True)
    out=['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>安装前环境预检</title><style>body{font:16px/1.7 system-ui;background:#f0f4f9;color:#23334b;margin:40px auto;max-width:1000px;padding:0 24px}article{background:white;padding:20px;margin:16px 0;border-radius:12px}small{color:#596a80}h1,h2{line-height:1.3}</style><h1>安装前环境预检</h1>', '<p>不需要安装 Claude。没有对外请求；没有评估账号安全或后台地区判定。</p>', '<small>'+esc(r['captured_at_utc'])+'</small>']
    for key,title in SURFACES.items():
        out.append('<h2>'+esc(title)+'</h2>')
        for row in r['findings']:
            if key not in row['surfaces']: continue
            src=SOURCES[row['source']]
            out.append('<article><b>'+esc(LEVELS[row['level']]+' · '+row['title'])+'</b><p>'+esc(row['observed'])+'</p><p>'+esc(row['action'])+'</p><small>'+esc(src[0])+' '+esc(src[1])+' · 规则核对 2026-10-16</small></article>')
    return ''.join(out)+'</html>'

def save(r,directory=None):
    validate(r); directory=storage.safe_dir(directory or root_dir()/"data/preflight")
    path=directory/(r['run_id']+'.json')
    payload={"report":r,"sha256":hashlib.sha256(canonical(r)).hexdigest()}
    with path.open('x',encoding='utf-8') as out: json.dump(payload,out,ensure_ascii=False,indent=2,allow_nan=False)
    with path.with_suffix('.html').open('x',encoding='utf-8') as out: out.write(render(r))
    return path

def read(path):
    data=storage.read_json(path)
    if type(data) is not dict or set(data)!={"report","sha256"}: raise ValueError("invalid_envelope")
    r=validate(data['report'])
    if data['sha256']!=hashlib.sha256(canonical(r)).hexdigest(): raise ValueError("damaged_report")
    return r
