"""Narrow Windows settings and bounded, unauthenticated network probes."""
from __future__ import annotations
import ctypes
from ctypes import wintypes as W
import datetime as dt
import ipaddress
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PS_NETWORK = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$r=@{adapters_ok=$false;routes_ok=$false;dns_ok=$false;vpn_ok=$false;adapters=@();routes=@();dns=@();vpn_connected=0}
try {$r.adapters=@(Get-NetAdapter -IncludeHidden | Select-Object -First 64 -Property ifIndex,Name,InterfaceDescription,Status,HardwareInterface);$r.adapters_ok=$true}catch{}
try {$r.routes=@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1')} | Select-Object -First 64 -Property InterfaceIndex,DestinationPrefix,RouteMetric);$r.routes_ok=$true}catch{}
try {$r.dns=@(Get-DnsClientServerAddress | Select-Object -First 64 -Property InterfaceIndex,AddressFamily,ServerAddresses);$r.dns_ok=$true}catch{}
try {$r.vpn_connected=@(Get-VpnConnection -ErrorAction Stop | Where-Object {$_.ConnectionStatus -eq 'Connected'}).Count;$r.vpn_ok=$true}catch{}
$r | ConvertTo-Json -Depth 5 -Compress
'''
TUN_PATTERNS = {'Mihomo / Clash':r'mihomo|clash|meta tunnel', 'Wintun':r'wintun', 'WireGuard':r'wireguard', 'OpenVPN / TAP':r'openvpn|tap-windows|tap-win32', 'Tailscale':r'tailscale', 'ZeroTier':r'zerotier', 'TUN':r'\btun\b|tun adapter|sing-box|nekoray', '其他 VPN':r'nordvpn|protonvpn|mullvad|surfshark|expressvpn|fortinet|anyconnect|globalprotect|openconnect'}

from .tls_safety import verified_context

def clean(value,limit=100):
    if not isinstance(value,str): return ''
    return ''.join(c for c in value if c.isprintable())[:limit]

def proxy_value(value):
    """Host and port only; credentials, paths and query strings never leave here."""
    if not isinstance(value,str) or len(value)>4096: return ''
    entries=[]
    for part in value.split(';')[:6]:
        scheme=''; address=part.strip()
        if '=' in address: scheme,address=address.split('=',1); scheme=scheme.lower()
        if scheme and scheme not in ('http','https','socks','socks4','socks5'): continue
        try:
            parsed=urllib.parse.urlsplit(address if '://' in address else '//'+address)
            host=parsed.hostname
            if not host or len(host)>253 or not re.fullmatch(r'[\w.:%-]+',host): continue
            port=parsed.port
            if ':' in host: host='['+host+']'
            entries.append((scheme+'=' if scheme else '')+host+(':'+str(port) if port else ''))
        except ValueError: continue
    return '; '.join(entries)

def local_preferences():
    result={'language_status':'error','ui_languages':[],'format_language':'','input_languages':[],
        'timezone_status':'error','timezone':'','utc_offset':'','clock_local':'','admin':False,
        'proxy_status':'error','system_proxy':'','system_proxy_enabled':False,'pac_configured':False,'auto_detect':None,
        'environment_proxies':{},'api_endpoint_override':False,'root_cert_count':None}
    try:
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        buf=ctypes.create_unicode_buffer(85)
        if kernel.GetUserDefaultLocaleName(buf,len(buf)): result['format_language']=clean(buf.value,85)
        count=W.ULONG(); length=W.ULONG()
        kernel.GetUserPreferredUILanguages(8,ctypes.byref(count),None,ctypes.byref(length))
        if 0<length.value<4096:
            languages=ctypes.create_unicode_buffer(length.value)
            if kernel.GetUserPreferredUILanguages(8,ctypes.byref(count),languages,ctypes.byref(length)):
                result['ui_languages']=[clean(x,85) for x in languages[:].split('\0') if x][:12]
        n=ctypes.windll.user32.GetKeyboardLayoutList(0,None)
        if 0<n<=64:
            values=(ctypes.c_void_p*n)(); ctypes.windll.user32.GetKeyboardLayoutList(n,values)
            for value in values:
                name=ctypes.create_unicode_buffer(85)
                if kernel.LCIDToLocaleName(int(value)&0xffff,name,len(name),0) and name.value not in result['input_languages']: result['input_languages'].append(clean(name.value,85))
        if result['ui_languages'] or result['format_language']: result['language_status']='ok'
        class TZ(ctypes.Structure):
            _fields_=[('Bias',W.LONG),('StandardName',W.WCHAR*32),('StandardDate',W.WORD*8),('StandardBias',W.LONG),('DaylightName',W.WCHAR*32),('DaylightDate',W.WORD*8),('DaylightBias',W.LONG),('TimeZoneKeyName',W.WCHAR*128),('DynamicDaylightTimeDisabled',W.BOOL)]
        tz=TZ(); code=kernel.GetDynamicTimeZoneInformation(ctypes.byref(tz))
        if code!=0xffffffff:
            now=dt.datetime.now().astimezone(); result.update(timezone_status='ok',timezone=clean(tz.TimeZoneKeyName,128),utc_offset=now.strftime('%z'),clock_local=now.isoformat(timespec='seconds'))
        result['admin']=bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError,AttributeError,ValueError): pass
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings') as key:
            for name in ('ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect'):
                try: value=winreg.QueryValueEx(key,name)[0]
                except FileNotFoundError: continue
                if name=='ProxyEnable': result['system_proxy_enabled']=bool(value)
                elif name=='ProxyServer': result['system_proxy']=proxy_value(value)
                elif name=='AutoConfigURL': result['pac_configured']=bool(value)
                else: result['auto_detect']=bool(value)
        result['proxy_status']='ok'
    except FileNotFoundError: result['proxy_status']='ok'
    except (OSError,ImportError): pass
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'):
        value=os.environ.get(key) or os.environ.get(key.lower())
        if value: result['environment_proxies'][key]=proxy_value(value) or '已设置（地址格式不支持）'
    result['api_endpoint_override']='ANTHROPIC_BASE_URL' in os.environ
    try: result['root_cert_count']=len(ssl.enum_certificates('ROOT'))
    except (OSError,AttributeError): pass
    return result

def project_network(data):
    output={'status':'ok','adapters_ok':data.get('adapters_ok') is True,'routes_ok':data.get('routes_ok') is True,
        'dns_ok':data.get('dns_ok') is True,'vpn_ok':data.get('vpn_ok') is True,'vpn_connected':0,'tunnels':[],'dns_servers':[],
        'ipv4_default':False,'ipv6_default':False,'active_adapter_count':0}
    count=data.get('vpn_connected'); output['vpn_connected']=count if type(count) is int and 0<=count<=64 else 0
    routes=[x for x in data.get('routes',[])[:64] if isinstance(x,dict)]
    for row in routes:
        prefix=row.get('DestinationPrefix','')
        if prefix=='0.0.0.0/0': output['ipv4_default']=True
        if prefix=='::/0': output['ipv6_default']=True
    active_indices=set()
    for adapter in data.get('adapters',[])[:64]:
        if not isinstance(adapter,dict): continue
        active=adapter.get('Status')=='Up'; index=adapter.get('ifIndex')
        if active: output['active_adapter_count']+=1; active_indices.add(index)
        description=str(adapter.get('InterfaceDescription',''))+' '+str(adapter.get('Name',''))
        for family,pattern in TUN_PATTERNS.items():
            if re.search(pattern,description,re.I):
                owned=[r.get('DestinationPrefix') for r in routes if r.get('InterfaceIndex')==index]
                covers_v4='0.0.0.0/0' in owned or {'0.0.0.0/1','128.0.0.0/1'}<=set(owned)
                covers_v6='::/0' in owned or {'::/1','8000::/1'}<=set(owned)
                output['tunnels'].append({'family':family,'active':active,'default_v4':covers_v4,'default_v6':covers_v6}); break
    for row in data.get('dns',[])[:64]:
        if not isinstance(row,dict) or row.get('InterfaceIndex') not in active_indices: continue
        for raw in (row.get('ServerAddresses') or [])[:8]:
            try: address=str(ipaddress.ip_address(raw))
            except ValueError: continue
            if address not in output['dns_servers']: output['dns_servers'].append(address)
    output['dns_servers']=output['dns_servers'][:16]
    return output

def windows_network():
    empty={'status':'error','adapters_ok':False,'routes_ok':False,'dns_ok':False,'vpn_ok':False,'vpn_connected':0,'tunnels':[],'dns_servers':[],'ipv4_default':False,'ipv6_default':False,'active_adapter_count':0}
    # Trusted fixed system executable, no user profile, no elevation, no credential fields.
    system=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(system,len(system)): return empty
    executable=Path(system.value)/'WindowsPowerShell/v1.0/powershell.exe'
    try:
        result=subprocess.run([str(executable),'-NoLogo','-NoProfile','-NonInteractive','-Command',PS_NETWORK],capture_output=True,timeout=12,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode or len(result.stdout)>256*1024: return empty
        data=json.loads(result.stdout.decode('utf-8-sig'))
        return project_network(data)
    except (OSError,ValueError,subprocess.TimeoutExpired,TypeError): return empty

def _opener():
    proxies={}
    for kind,value in urllib.request.getproxies().items():
        if kind not in ('http','https'): continue
        parsed=urllib.parse.urlsplit(value if '://' in value else 'http://'+value)
        if parsed.username or parsed.password: raise ValueError('authenticated_proxy_not_used')
        if parsed.scheme not in ('http','https') or not parsed.hostname: raise ValueError('unsupported_proxy')
        proxies[kind]=value if '://' in value else 'http://'+value
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs): return None
    return urllib.request.build_opener(urllib.request.ProxyHandler(proxies),urllib.request.HTTPSHandler(context=verified_context()),NoRedirect())

def _fetch_json(url):
    started=time.monotonic()
    request=urllib.request.Request(url,headers={'User-Agent':'CC-Environment-Auditor/1.2','Accept':'application/json'})
    with _opener().open(request,timeout=5) as response:
        raw=response.read(32769)
        if len(raw)>32768: raise ValueError('oversized_response')
        date=response.headers.get('Date'); age=response.headers.get('Age','0')
        clock=None
        try:
            from email.utils import parsedate_to_datetime
            if int(age)<60: clock=round((parsedate_to_datetime(date)-dt.datetime.now(dt.timezone.utc)).total_seconds(),1)
        except (ValueError,TypeError,AttributeError): pass
    return json.loads(raw),round((time.monotonic()-started)*1000),clock

def ip_lookup(provider):
    output={'status':'error','error':'network_failed','ip':'','country':'','country_code':'','region':'','city':'','asn':'','isp':'','ip_timezone':'',
        'is_vpn':None,'is_proxy':None,'is_tor':None,'is_datacenter':None,'is_mobile':None,'risk_score':None,'duration_ms':0,'clock_delta_seconds':None}
    try:
        url={'ipquery':'https://api.ipquery.io/?format=json','ipwho':'https://ipwho.is/?fields=ip,success,country,country_code,region,city,connection.asn,connection.isp,timezone.id'}[provider]
        data,elapsed,clock=_fetch_json(url)
        if not isinstance(data,dict) or data.get('success') is False: raise ValueError('invalid_response')
        address=ipaddress.ip_address(data.get('ip',''))
        if not address.is_global: raise ValueError('non_public_ip')
        location=data.get('location',{}) if provider=='ipquery' else data
        isp=data.get('isp',{}) if provider=='ipquery' else data.get('connection',{})
        for key in ('country','country_code','region','city'):
            output[key]=clean(location.get('state') if key=='region' and provider=='ipquery' else location.get(key),96)
        output['ip_timezone']=clean(location.get('timezone') if provider=='ipquery' else (data.get('timezone') or {}).get('id'),96)
        asn=isp.get('asn');output['asn']=clean(str(asn),32) if type(asn) in (str,int) else ''; output['isp']=clean(isp.get('isp') or isp.get('org'),96)
        if not re.fullmatch('[A-Z]{2}',output['country_code']):raise ValueError('invalid_country')
        risk=data.get('risk') or {}
        for key in ('is_vpn','is_proxy','is_tor','is_datacenter','is_mobile'):
            if type(risk.get(key)) is bool: output[key]=risk[key]
        score=risk.get('risk_score')
        if type(score) in (int,float) and 0<=score<=100: output['risk_score']=score
        output.update(status='ok',error='',ip=str(address),duration_ms=elapsed,clock_delta_seconds=clock)
    except urllib.error.HTTPError as error: output['error']='http_'+str(error.code) if error.code in (400,401,403,404,429,500,502,503) else 'http_error'
    except (OSError,ValueError,TypeError,KeyError,ssl.SSLError): pass
    return output

def tls_probe(host):
    output={'status':'error','error':'connection_failed','tls':'','issuer':'','dns_ipv4_count':0,'dns_ipv6_count':0,'mapped_address_count':0,'duration_ms':0}
    started=time.monotonic()
    try:
        addresses=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
        unique={(family,endpoint[0]) for family,_,_,_,endpoint in addresses}
        for family,value in unique:
            address=ipaddress.ip_address(value)
            if family==socket.AF_INET: output['dns_ipv4_count']+=1
            elif family==socket.AF_INET6: output['dns_ipv6_count']+=1
            if not address.is_global: output['mapped_address_count']+=1
        with socket.create_connection((host,443),timeout=4) as stream:
            with verified_context().wrap_socket(stream,server_hostname=host) as secure:
                cert=secure.getpeercert(); issuer=''
                for component in cert.get('issuer',()):
                    for key,value in component:
                        if key in ('organizationName','commonName'): issuer=clean(value,96); break
                output.update(status='ok',error='',tls=clean(secure.version(),20),issuer=issuer)
    except ssl.SSLCertVerificationError: output['error']='certificate_failed'
    except (OSError,ValueError,ssl.SSLError): pass
    output['duration_ms']=round((time.monotonic()-started)*1000)
    return output

def ip_echo(version):
    try:
        data,elapsed,_=_fetch_json('https://api'+str(version)+'.ipify.org?format=json')
        address=ipaddress.ip_address(data.get('ip',''))
        if not address.is_global or address.version!=version: raise ValueError()
        return {'status':'ok','ip':str(address),'duration_ms':elapsed}
    except (OSError,ValueError,TypeError): return {'status':'error','error':'connection_failed'}

def reputation(address):
    result={'status':'error','error':'network_failed','is_abuser':None,'recent_abuse':None,'score':None,'confidence':'','category':'','is_vpn':None,'is_proxy':None,'is_tor':None,'is_datacenter':None}
    try:
        ip=ipaddress.ip_address(address)
        if not ip.is_global: raise ValueError()
        data,_,_=_fetch_json('https://api.ffraud.com/public/ip/'+str(ip))
        if data.get('success') is not True: raise ValueError()
        for target,key in [('is_abuser','is_abuser'),('recent_abuse','recent_abuse'),('is_vpn','vpn'),('is_proxy','proxy'),('is_tor','tor'),('is_datacenter','hosting')]:
            if type(data.get(key)) is bool: result[target]=data[key]
        score=data.get('fraud_score')
        if type(score) in (int,float) and 0<=score<=100: result['score']=score
        result.update(status='ok',error='',confidence=clean(data.get('confidence'),32),category=clean(data.get('connection_type'),64))
    except urllib.error.HTTPError as error: result['error']='http_429' if error.code==429 else 'http_error'
    except (OSError,ValueError,TypeError,AttributeError): pass
    return result

NETWORK_KEYS=('ipquery','ipwho','web_tls','api_tls','ipv4','ipv6','reputation','stripe_tls','checkout_tls','routes')

def _network_child(pipe,groups=None):
    # Private, disposable child bounds platform DNS as well as socket timeouts.
    """Public preflight: legacy active probe disabled."""
    raise PermissionError("legacy_active_probe_disabled_in_public_preflight")

def network_checks(cancel=None,progress=None,groups=None):
    """Public preflight: legacy active probe disabled."""
    raise PermissionError("legacy_active_probe_disabled_in_public_preflight")
