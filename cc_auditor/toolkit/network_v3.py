"""固定中立目标，禁跳转/任意 URL；DNS 地址固定，TLS SNI 强校验。"""
import http.client
import ipaddress
import json
import re
import socket
import time
from urllib.parse import quote
from pathlib import Path
from ..tls_safety import verified_context
from .zero_contact_guard import utc_now

ENDPOINTS={'ipv4':('api4.ipify.org','/?format=json'),'ipv6':('api6.ipify.org','/?format=json'),
    'ipquery':('api.ipquery.io','/?format=json'),'ipwho':('ipwho.is','/?fields=ip,success,country_code,connection.asn')}
RIRS=('rdap.arin.net','rdap.db.ripe.net','rdap.apnic.net','rdap.lacnic.net','rdap.afrinic.net')
DESTINATIONS=sorted({v[0] for v in ENDPOINTS.values()}|set(RIRS)|{'stat.ripe.net','api.ffraud.com'})
FAKE_NETWORKS=tuple(ipaddress.ip_network(x) for x in ('198.18.0.0/15','2001:2::/48','fdfe:dcba:9876::/48'))


def _allowed_path(host,path):
    if (host,path) in ENDPOINTS.values():return True
    if host in RIRS:return bool(re.fullmatch(r'/registry/ip/[0-9a-fA-F:.]+',path) if host=='rdap.arin.net' else re.fullmatch(r'/rdap/ip/[0-9a-fA-F:.]+',path) if host in ('rdap.lacnic.net','rdap.afrinic.net') else re.fullmatch(r'/ip/[0-9a-fA-F:.]+',path))
    if host=='api.ffraud.com':return bool(re.fullmatch(r'/public/ip/[0-9a-fA-F:.]+',path))
    if host=='stat.ripe.net':return bool(re.fullmatch(r'/data/network-info/data.json\?resource=[0-9a-fA-F:.]+',path) or re.fullmatch(r'/data/rpki-validation/data.json\?resource=AS\d{1,10}&prefix=[0-9a-fA-F:.%/0-9]+',path))
    return False


def _request(host,path,family,allow_fake,entry):
    if host not in DESTINATIONS or not _allowed_path(host,path):raise PermissionError('destination_not_allowlisted')
    rows=socket.getaddrinfo(host,443,family,type=socket.SOCK_STREAM)
    if not rows:raise ValueError('dns_no_records')
    addresses=[ipaddress.ip_address(x[4][0].split('%')[0]) for x in rows]
    def acceptable(addr):return addr.is_global or allow_fake and any(addr in n for n in FAKE_NETWORKS if n.version==addr.version)
    if any(not acceptable(a) for a in addresses):raise ValueError('nonpublic_dns_mapping_requires_separate_receiver')
    entry['dns_resolution']='fake_ip_via_observed_active_tun' if any(not a.is_global for a in addresses) else 'public_pinned'
    fam,_,_,_,endpoint=rows[0]
    with socket.socket(fam,socket.SOCK_STREAM) as raw:
        raw.settimeout(4);raw.connect(endpoint)
        with verified_context().wrap_socket(raw,server_hostname=host) as secure:
            request=('GET '+path+' HTTP/1.1\r\nHost: '+host+'\r\nUser-Agent: CC-Auditor-Preflight/3\r\nAccept: application/json\r\nConnection: close\r\n\r\n').encode('ascii')
            entry['request_sent']=None
            secure.sendall(request);entry['request_sent']=True
            response=http.client.HTTPResponse(secure);response.begin()
            if response.status!=200:raise ValueError('http_'+str(response.status))
            data=response.read(262145)
            if len(data)>262144:raise ValueError('response_too_large')
            entry['tls']=secure.version();entry['http_status']=response.status
            cert=secure.getpeercert();entry['certificate']={'validated_hostname':host,'not_after':cert.get('notAfter'),'issuer_common_names':[v for group in cert.get('issuer',()) for k,v in group if k=='commonName'][:3]}
            return json.loads(data)


def _entry(host,source='generic_neutral_probe'):
    return {'source':source,'executor':'cc_auditor_python','target_host':host,'captured_at_utc':utc_now(),'status':'failed','request_sent':False,
            'transport':'direct_tcp_system_route_TUN_may_apply','actual_claude_path':False,'final_claude_egress':None}


def fetch(key,allow_fake=False):
    if key not in ENDPOINTS:raise PermissionError('endpoint_not_allowlisted')
    host,path=ENDPOINTS[key];start=time.monotonic();entry=_entry(host)
    try:
        family=socket.AF_INET6 if key=='ipv6' else socket.AF_INET if key=='ipv4' else socket.AF_UNSPEC
        data=_request(host,path,family,allow_fake,entry);address=ipaddress.ip_address(data.get('ip',''))
        if not address.is_global:raise ValueError('invalid_echo_address')
        if key in ('ipv4','ipv6') and address.version!=(6 if key=='ipv6' else 4):raise ValueError('echo_family_mismatch')
        code=data.get('country_code') or (data.get('location') or {}).get('country_code')
        risk=data.get('risk') or {};isp=data.get('isp') or {};connection=data.get('connection') or {}
        entry.update(status='observed',ip=str(address),country_code=code.upper() if isinstance(code,str) and len(code)==2 and code.isascii() and code.isalpha() else None,
            evidence_level='third_party_receiver',asn=str(isp.get('asn') or connection.get('asn') or '')[:24],
            vendor_labels={k:risk[k] for k in ('is_vpn','is_proxy','is_tor','is_datacenter','is_mobile') if type(risk.get(k)) is bool},
            vendor_score=risk.get('risk_score') if type(risk.get('risk_score')) in (int,float) and 0<=risk['risk_score']<=100 else None)
    except (OSError,ValueError,TypeError,AttributeError,http.client.HTTPException) as error:
        entry['reason']=str(error) if isinstance(error,ValueError) and str(error).replace('_','').isalnum() else 'dns_tcp_tls_or_http_failed'
    entry['duration_ms']=round((time.monotonic()-start)*1000);return entry


def intelligence(host,ip,allow_fake):
    entry=_entry(host,'generic_probe_ip_intelligence');entry['queried_probe_ip']=ip
    try:
        if host in RIRS:
            prefix='/registry/ip/' if host=='rdap.arin.net' else '/ip/' if host in ('rdap.db.ripe.net','rdap.apnic.net') else '/rdap/ip/'
            data=_request(host,prefix+ip,socket.AF_UNSPEC,allow_fake,entry)
            start=ipaddress.ip_address(data.get('startAddress',''));end=ipaddress.ip_address(data.get('endAddress',''));addr=ipaddress.ip_address(ip)
            if not start<=addr<=end:raise ValueError('rdap_range_mismatch')
            entry.update(status='observed',registry={'range_start':str(start),'range_end':str(end),'registration_country':str(data.get('country',''))[:2],
                'note':'注册归属不是物理位置或代理实际地理位置。'})
        elif host=='api.ffraud.com':
            data=_request(host,'/public/ip/'+ip,socket.AF_UNSPEC,allow_fake,entry)
            if data.get('success') is not True:raise ValueError('provider_unsuccessful')
            entry.update(status='observed',vendor_labels={k:data[k] for k in ('is_abuser','recent_abuse','vpn','proxy','tor','hosting') if type(data.get(k)) is bool},
                vendor_score=data.get('fraud_score') if type(data.get('fraud_score')) in (int,float) and 0<=data['fraud_score']<=100 else None,
                note='供应商声誉分类仅参考；不是纯净证明或 Claude 风险分。')
        elif host=='stat.ripe.net':
            data=_request(host,'/data/network-info/data.json?resource='+ip,socket.AF_UNSPEC,allow_fake,entry).get('data') or {}
            prefix=ipaddress.ip_network(data.get('prefix',''));asns=[int(x) for x in data.get('asns',[])[:8] if str(x).isdigit() and 0<int(x)<4294967296]
            if ipaddress.ip_address(ip) not in prefix or not asns:raise ValueError('routing_not_observed')
            entry.update(status='observed',bgp={'prefix':str(prefix),'origin_asns':asns,'source':'RIPEstat network-info snapshot','rpki_state':'not_queried'})
        else:raise PermissionError('unlisted_intelligence_host')
    except (OSError,ValueError,TypeError,AttributeError,http.client.HTTPException):entry['reason']='receiver_unavailable_or_response_invalid'
    return entry


def _child(pipe,allow_fake):
    from concurrent.futures import ThreadPoolExecutor,as_completed
    echoes=[]
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for k,(host,_) in ENDPOINTS.items():pipe.send((k,{**_entry(host),'status':'in_progress','request_sent':None}))
            futures={pool.submit(fetch,k,allow_fake):k for k in ENDPOINTS}
            for f in as_completed(futures):
                value=f.result();echoes.append(value);pipe.send((futures[f],value))
        ip=next((v['ip'] for v in echoes if v.get('status')=='observed' and ':' not in v.get('ip','')),None)
        if ip:
            with ThreadPoolExecutor(max_workers=7) as pool:
                rir=rir_for_ip(ip)
                hosts=([rir] if rir else [])+['api.ffraud.com','stat.ripe.net']
                for host in hosts:pipe.send((host,{**_entry(host,'generic_probe_ip_intelligence'),'status':'in_progress','queried_probe_ip':ip,'request_sent':None}))
                futures={pool.submit(intelligence,h,ip,allow_fake):h for h in hosts}
                for f in as_completed(futures):
                    value=f.result();pipe.send((futures[f],value))
                    if value.get('bgp'):
                        b=value['bgp'];entry=_entry('stat.ripe.net','generic_probe_rpki');entry['queried_probe_ip']=ip
                        pipe.send(('rpki',{**entry,'status':'in_progress','request_sent':None}))
                        try:
                            path='/data/rpki-validation/data.json?resource=AS'+str(b['origin_asns'][0])+'&prefix='+quote(b['prefix'],safe='')
                            out=_request('stat.ripe.net',path,socket.AF_UNSPEC,allow_fake,entry).get('data') or {}
                            state=out.get('status');entry.update(status='observed' if state in ('valid','invalid_asn','invalid_length','unknown') else 'failed',rpki_state=state if state in ('valid','invalid_asn','invalid_length','unknown') else None)
                        except (OSError,ValueError,TypeError,http.client.HTTPException):entry['reason']='rpki_receiver_unavailable'
                        pipe.send(('rpki',entry))
    finally:pipe.close()


def rir_for_ip(ip):
    from urllib.parse import urlsplit
    address=ipaddress.ip_address(ip)
    if address.version!=4:return None
    data=json.loads(Path(__file__).with_name('rdap_ipv4_bootstrap.json').read_text(encoding='utf-8'))
    for ranges,urls in data['services']:
        if any(address in ipaddress.ip_network(n) for n in ranges):
            return next((urlsplit(u).hostname for u in urls if u.startswith('https://') and urlsplit(u).hostname in RIRS),None)
    return None


def checks(allow_fake=False):
    import multiprocessing as mp
    context=mp.get_context('spawn');parent,child=context.Pipe(False);process=context.Process(target=_child,args=(child,allow_fake),daemon=True)
    process.start();child.close();result={};deadline=time.monotonic()+30
    try:
        while time.monotonic()<deadline:
            try:
                if parent.poll(.1):
                    k,value=parent.recv();result[k]=value
                elif not process.is_alive():break
            except (EOFError,OSError):break  # Windows PeekNamedPipe can raise 109 on normal EOF.
    finally:
        if process.is_alive():process.terminate()
        process.join(1);parent.close()
    for k in ENDPOINTS:
        if k not in result:result[k]={**_entry(ENDPOINTS[k][0]),'reason':'total_timeout','request_sent':None}
    for entry in result.values():
        if entry['status']=='in_progress':entry.update(status='failed',reason='total_timeout',request_sent=None)
    return list(result.values())
