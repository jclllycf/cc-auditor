"""获批的中立 DNS/STUN 接收端；差异不是自动确认泄漏，无任意目标参数。"""
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from .zero_contact_guard import utc_now

DESTINATIONS = ('*.test.dnscheck.tools (随机测量名，仅 DNS)', 'ws.dnscheck.tools (WSS)',
                'stun.cloudflare.com:3478 (UDP)', 'api4.ipify.org (浏览器 HTTPS)',
                'api6.ipify.org (浏览器 HTTPS)', 'tls.peet.ws/api/all (浏览器 TLS/HTTP2 指纹)')


def _event(kind):
    return {'kind': kind, 'captured_at_utc': utc_now(), 'status': 'failed', 'actual_claude_path': False,
            'scope': '仅当前检测器/工具页面到独立接收端，不能代表 Claude', 'request_sent': False}


def parse_dns_txt(lines):
    result=[]
    for line in lines:
        match=re.match(r'^FROM: ([0-9a-fA-F:.]+)#\d+ \((UDP|TCP|TLS|QUIC)\)', str(line),re.IGNORECASE)
        if match:
            try:
                ip=ipaddress.ip_address(match[1])
                if ip.is_global:result.append({'resolver_ip':str(ip),'authoritative_transport':match[2].upper()})
            except ValueError:pass
    return result[:8]


def dns_receiver():
    event=_event('system_authoritative_dns');event['receiver']='dnscheck.tools'
    if os.name!='nt':event['reason']='system_dns_adapter_requires_windows';return event
    host=secrets.token_hex(4)+'.test.dnscheck.tools'
    # Host constructed here, no shell/user-controlled interpolation; no server override.
    script="[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); @(Resolve-DnsName -Name '"+host+"' -Type TXT -DnsOnly -NoHostsFile -ErrorAction Stop | ForEach-Object { $_.Strings }) | ConvertTo-Json -Compress"
    import ctypes
    buf=ctypes.create_unicode_buffer(32768);ctypes.windll.kernel32.GetWindowsDirectoryW(buf,len(buf))
    exe=os.path.join(buf.value,'System32','WindowsPowerShell','v1.0','powershell.exe')
    try:
        event['request_sent']=None
        out=subprocess.run([exe,'-NoProfile','-NonInteractive','-Command',script],capture_output=True,encoding='utf-8',timeout=15)
        if out.returncode:raise ValueError('system_dns_query_failed')
        raw=json.loads(out.stdout);rows=parse_dns_txt(raw if isinstance(raw,list) else [raw])
        event.update(status='observed' if rows else 'failed',resolvers=rows,request_sent=True,
                     meaning='权威接收端返回其所见递归解析器；不证明用户到解析器是否加密，也不自行判断泄漏。')
    except (OSError,ValueError,subprocess.TimeoutExpired):event['reason']='receiver_or_system_query_unavailable'
    return event


def parse_stun(data,transaction):
    if len(data)<20:raise ValueError('stun_short')
    typ,length,cookie=struct.unpack('!HHI',data[:8])
    if typ!=0x0101 or cookie!=0x2112a442 or data[8:20]!=transaction or length+20!=len(data):raise ValueError('stun_transaction')
    pos=20
    while pos+4<=len(data):
        attr,size=struct.unpack('!HH',data[pos:pos+4]);pos+=4;value=data[pos:pos+size];pos+=(size+3)&~3
        if len(value)!=size:raise ValueError('stun_attribute')
        if attr not in (0x0020,0x0001) or size not in (8,20):continue
        family=value[1];count=4 if family==1 else 16 if family==2 else 0
        if count+4!=size:continue
        address=value[4:];mask=struct.pack('!I',cookie)+transaction
        if attr==0x0020:address=bytes(v^mask[i] for i,v in enumerate(address))
        ip=ipaddress.ip_address(address)
        if not ip.is_global:raise ValueError('stun_nonpublic')
        return str(ip)
    raise ValueError('stun_mapped_address_absent')


def stun_receiver(allow_fake=False):
    from .network_v3 import FAKE_NETWORKS
    event=_event('python_udp_stun');event['receiver']='stun.cloudflare.com:3478'
    try:
        rows=socket.getaddrinfo('stun.cloudflare.com',3478,socket.AF_UNSPEC,socket.SOCK_DGRAM)
        for af,kind,proto,_,endpoint in rows[:2]:
            ip=ipaddress.ip_address(endpoint[0].split('%')[0])
            if not ip.is_global and not (allow_fake and any(ip.version==n.version and ip in n for n in FAKE_NETWORKS)):continue
            transaction=secrets.token_bytes(12);payload=struct.pack('!HHI',1,0,0x2112a442)+transaction
            try:
                with socket.socket(af,kind,proto) as sock:
                    sock.settimeout(3);sock.connect(endpoint);event['request_sent']=None;sock.send(payload);event['request_sent']=True
                    data=sock.recv(2048)
                    event.update(status='observed',mapped_ip=parse_stun(data,transaction),
                                 meaning='独立 UDP 回显；与 HTTPS 出口不同只表示路径差异，未核实预期规则前不判泄漏。')
                    return event
            except (OSError,ValueError):continue
        event['reason']='stun_no_valid_response'
    except (OSError,ValueError):event['reason']='stun_dns_or_transport_failed'
    return event


def _worker(sender,allow_fake):
    from concurrent.futures import as_completed
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            for f in as_completed([pool.submit(dns_receiver),pool.submit(stun_receiver,allow_fake)]):sender.send(f.result())
    finally:sender.close()


def checks(allow_fake=False):
    import multiprocessing as mp,time
    context=mp.get_context('spawn');recv,send=context.Pipe(False);child=context.Process(target=_worker,args=(send,allow_fake),daemon=True)
    child.start();send.close();results=[];deadline=time.monotonic()+23
    try:
        while time.monotonic()<deadline:
            try:
                if recv.poll(.1):results.append(recv.recv())
                elif not child.is_alive():break
            except (OSError,EOFError):break
    finally:
        if child.is_alive():child.terminate()
        child.join(1);recv.close()
    for kind in ('system_authoritative_dns','python_udp_stun'):
        if not any(r.get('kind')==kind for r in results):results.append({**_event(kind),'reason':'bounded_timeout_or_worker_failed','request_sent':None})
    return results


def sanitize_browser(value):
    if not isinstance(value,dict):raise ValueError('invalid_browser_network')
    out={'scope':'real_profile_tool_origin_only','actual_claude_path':False}
    for key in ('ipv4','ipv6','stun','dns','tls'):
        v=value.get(key)
        if not isinstance(v,dict):continue
        row={'status':v.get('status') if v.get('status') in ('observed','failed','not_supported') else 'failed'}
        if v.get('reason') in ('websocket_unavailable','receiver_open_no_authoritative_event','receiver_timeout','authoritative_observed'):row['reason']=v['reason']
        if type(v.get('queries_started')) is int and 0<=v['queries_started']<=2:row['queries_started']=v['queries_started']
        for field in ('ip','mapped_ip'):
            try:
                ip=ipaddress.ip_address(v.get(field,''))
                if ip.is_global:row[field]=str(ip)
            except ValueError:pass
        if key=='dns':
            row['resolver_ips']=[]
            for raw in (v.get('resolver_ips') or [])[:8]:
                try:
                    ip=ipaddress.ip_address(raw)
                    if ip.is_global:row['resolver_ips'].append(str(ip))
                except ValueError:pass
            if not row['resolver_ips']:row['status']='failed'
        if key=='tls':
            for field in ('ja4','ja3_hash','http_version','tls_version'):
                raw=v.get(field)
                if isinstance(raw,str) and re.fullmatch(r'[A-Za-z0-9_./ -]{1,160}',raw):row[field]=raw
            if not row.get('ja4') and not row.get('ja3_hash'):row['status']='failed'
        if key in ('ipv4','ipv6') and not row.get('ip'):row['status']='failed'
        if key in ('ipv4','ipv6') and row.get('ip') and ipaddress.ip_address(row['ip']).version!=(4 if key=='ipv4' else 6):row.update(status='failed',reason='echo_family_mismatch')
        if key=='stun' and not row.get('mapped_ip'):row['status']='failed'
        out[key]=row
    return out


# Independent implementation of public Web APIs; never load remote JS or read third-party cookies.
BROWSER_JS = r"""
async function ccNetworkCheck(){
 const result={};
 const request=async(url)=>{const c=new AbortController();const t=setTimeout(()=>c.abort(),6500);try{const r=await fetch(url,{credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:c.signal});if(!r.ok)throw Error();return await r.json()}finally{clearTimeout(t)}};
 const echo=async(key,url)=>{result[key]={status:'failed'};try{let d=await request(url);result[key]={status:'observed',ip:d.ip}}catch{}};
 const stun=()=>new Promise(done=>{let pc;let finished=false;const finish=()=>{if(finished)return;finished=true;try{pc.close()}catch{};done()};result.stun={status:'failed'};try{pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'}],iceCandidatePoolSize:0});pc.createDataChannel('cc-diagnostic');pc.onicecandidate=e=>{if(e.candidate){const s=e.candidate.candidate.split(' ');if(s[7]==='srflx'){result.stun={status:'observed',mapped_ip:s[4]};finish()}}else finish()};pc.createOffer().then(o=>pc.setLocalDescription(o)).catch(finish);setTimeout(finish,6500)}catch{finish()}});
 const dns=()=>new Promise(done=>{let ws;const nonce=crypto.getRandomValues(new Uint32Array(1))[0].toString(16);result.dns={status:'failed',resolver_ips:[],reason:'receiver_timeout',queries_started:0};let finished=false;const finish=()=>{if(finished)return;finished=true;try{ws.close()}catch{};done()};try{ws=new WebSocket('wss://ws.dnscheck.tools/watch/'+nonce);ws.onmessage=e=>{try{let d=JSON.parse(e.data);if(typeof d.qname==='string'&&d.qname.toLowerCase().includes(nonce+'-nxdomain.test.dnscheck.tools')&&typeof d.remoteIp==='string'){result.dns.resolver_ips.push(d.remoteIp);result.dns.status='observed';result.dns.reason='authoritative_observed'}}catch{}};ws.onopen=()=>{result.dns.reason='receiver_open_no_authoritative_event';result.dns.queries_started=1;fetch('https://a.'+nonce+'-nxdomain.test.dnscheck.tools/',{mode:'no-cors',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(5000)}).catch(()=>{});setTimeout(finish,5500)};ws.onerror=()=>{result.dns.reason='websocket_unavailable';finish()};setTimeout(finish,7000)}catch{finish()}});
 const tls=async()=>{result.tls={status:'failed'};try{let d=await request('https://tls.peet.ws/api/all');result.tls={status:'observed',ja4:d.tls?.ja4,ja3_hash:d.tls?.ja3_hash,http_version:d.http_version,tls_version:d.tls?.tls_version_negotiated}}catch{}};
 await Promise.all([echo('ipv4','https://api4.ipify.org/?format=json'),echo('ipv6','https://api6.ipify.org/?format=json'),stun(),dns(),tls()]);return result;
}
"""
