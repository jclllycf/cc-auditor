"""多品牌进程/端口/安装线索；私有路径与配置只留本机内存。"""
import hashlib
import os
import re
import secrets
from pathlib import Path
import psutil
from ..collectors import file_version
from .zero_contact_guard import utc_now

FAMILIES={
 'mihomo':('mihomo.exe','clash-meta.exe','clash.exe','verge-mihomo.exe','verge-mihomo-alpha.exe','clash-meta-alpha.exe'),
 'clash-gui':('clash-verge.exe','clash for windows.exe','clash-win64.exe','clash-party.exe','clash-nyanpasu.exe'),
 'v2rayN':('v2rayn.exe',),'xray':('xray.exe',),'v2fly':('v2ray.exe',),'sing-box':('sing-box.exe','singbox.exe'),
 'hiddify':('hiddify.exe','hiddify-next.exe'),'nekoray':('nekoray.exe','nekobox.exe'),
 'shadowsocks':('shadowsocks.exe','ss-local.exe','shadowsocksr.exe','shadowsocksr-dotnet4.0.exe'),
 'other-vpn':('wireguard.exe','openvpn.exe','tailscale.exe','zerotier-one_x64.exe','warp-svc.exe')}
CORE={'mihomo','xray','v2fly','sing-box','shadowsocks','other-vpn'}
class Runtime:
    def __init__(self):self.salt=secrets.token_bytes(32);self.processes=[];self.configs=[];self.controllers=[];self.launch={};self.launch_status={}
    def alias(self,value):return '标签-'+hashlib.blake2b(str(value).encode(),key=self.salt,digest_size=5).hexdigest()

def discover():
    runtime=Runtime();result={'captured_at_utc':utc_now(),'source':'local_process_and_listener_inventory','status':'observed','software':[],'errors':[],
        'installed_only':[],'effective_proxy':'unverified','scope':'进程、固定安装线索和本地监听；不扫描全盘，不执行代理程序。'}
    names={n:f for f,ns in FAMILIES.items() for n in ns}
    try:
        candidates=list(psutil.process_iter(['name','ppid'],ad_value=None))
        for old in candidates:
            name=(old.info.get('name') or '').lower()
            if name not in names:continue
            try:
                p=psutil.Process(old.pid);exe=p.exe();created=p.create_time()
                if p.name().lower()!=name or not p.is_running():continue
                item={'family':names[name],'role':'core' if names[name] in CORE else 'gui','pid':p.pid,'parent_pid':p.ppid(),
                    'created_epoch':created,'executable':Path(exe).name,'binary_version':file_version(exe),
                    'identity':'name_path_version_candidate','signature':'not_checked','listeners':[],'installed':True,'running':True,'effective':'unverified'}
                result['software'].append(item);runtime.processes.append({'public':item,'process':p,'exe':exe})
            except (psutil.Error,OSError):result['errors'].append('candidate_identity_unavailable')
        from .signature_v3 import verify_offline
        for record in runtime.processes[:16]:record['public']['signature']=verify_offline(record['exe'])
        bypid={x['pid']:x for x in result['software']}
        for c in psutil.net_connections(kind='tcp'):
            if c.pid in bypid and c.status==psutil.CONN_LISTEN and c.laddr:
                bypid[c.pid]['listeners'].append({'host':c.laddr.ip,'port':c.laddr.port})
        for f,ns in FAMILIES.items():
            if any(x['family']==f for x in result['software']):continue
            for root in (os.environ.get('LOCALAPPDATA',''),os.environ.get('ProgramFiles','')):
                if not root:continue
                if any((Path(root)/folder/exe).is_file() for folder in (f,'Programs/'+f) for exe in ns):
                    result['installed_only'].append({'family':f,'installed_hint':True,'running':False,'effective':'unverified'});break
    except (psutil.Error,OSError):result['errors'].append('process_or_listener_query_failed')
    if result['errors']:result['status']='partial'
    result['errors']=sorted(set(result['errors']));return result,runtime

def config_candidates(runtime):
    candidates=[]
    for record in runtime.processes:
        p=record['process'];exe=Path(record['exe']);base=exe.parent
        for name in ('config.json','config.yaml','config.yml','clash-verge.yaml','gui-config.json','binConfigs/config.json','binConfigs/configPre.json'):
            candidates.append((base/name,record['public']['family']))
        # Acquire only known configuration switches; never retain or serialize command lines.
        try:
            args=p.cmdline()
            try:cwd=p.cwd()
            except (psutil.Error,OSError):cwd=None
            meta=parse_launch_args(args,record['public']['family'],cwd)
            runtime.launch[p.pid]=meta;runtime.launch_status[p.pid]='known_switches_read'
            for config_path in meta.get('files',[]):candidates.append((config_path,record['public']['family']))
            del args
        except (psutil.Error,OSError):runtime.launch_status[p.pid]='os_permission_or_process_changed'
    app=Path(os.environ.get('APPDATA',''))
    for folder in ('io.github.clash-verge-rev.clash-verge-rev','io.github.clash-verge-rev.clash-verge-rev.dev','clash-verge','mihomo','sing-box','v2rayN'):
        for file in ('clash-verge.yaml','config.yaml','config.yml','config.json'):
            candidates.append((app/folder/file,'hint'))
    seen=set();out=[]
    for p,f in candidates:
        try:
            if not p.is_absolute() or str(p).startswith('\\\\') or not p.is_file():continue
            key=str(p.absolute()).casefold()
            if key in seen:continue
            seen.add(key);out.append((p,f))
        except OSError:continue
    return out[:32]


def parse_launch_args(args,core,cwd):
    """内核相关参数；秘密仅存私有 Runtime，不返回报告。Mihomo -config 不是路径。"""
    meta={'files':[]};i=1
    switches={'-f','-d','-ext-ctl','-ext-ctl-pipe','-secret'} if core=='mihomo' else {'-c','-config','--config','-d','--config-directory'}
    while i<len(args):
        arg=args[i];key,sep,value=arg.partition('=')
        if key in switches:
            if not sep:
                i+=1
                if i>=len(args):break
                value=args[i]
            if key in ('-ext-ctl','-ext-ctl-pipe','-secret'):meta[key[1:]]=value
            elif value and value!='-' and not value.startswith('\\\\'):
                path=Path(value)
                if not path.is_absolute():
                    if cwd is None:i+=1;continue
                    path=Path(cwd)/path
                if key in ('-d','--config-directory'):
                    meta['files'].extend(path/x for x in ('config.yaml','config.yml','config.json'))
                else:meta['files'].append(path)
        i+=1
    return meta


def correlate_system_proxy(discovery,topology):
    """把已开启系统代理的本地监听归属到 PID；不外推任何应用的目标路径。"""
    from urllib.parse import urlsplit
    proxy=(topology or {}).get('proxy_configuration') or {};owners=[]
    if proxy.get('system_proxy_enabled'):
        for field in str(proxy.get('system_proxy_sanitized','')).split(';'):
            try:
                value=field.split('=',1)[-1].strip();parts=urlsplit(value if '://' in value else 'http://'+value)
                if parts.hostname not in ('127.0.0.1','localhost','::1'):continue
                for item in discovery['software']:
                    if any(x['port']==parts.port and x['host'] in ('127.0.0.1','::1','0.0.0.0','::') for x in item['listeners']):
                        owners.append(item['pid']);item['effective']='system_proxy_local_listener_attributed'
            except ValueError:continue
    discovery['system_proxy_owner_pids']=sorted(set(owners))
    if owners:discovery['effective_proxy']='system_proxy_local_listener_attributed_not_all_apps'
    return discovery


def claude_identity(instances):
    from .signature_v3 import verify_offline
    result=[];signatures={}
    for item in instances[:64]:
        row=dict(item)
        try:
            p=psutil.Process(item['pid'])
            if abs(p.create_time()-item['created_epoch'])>.001 or p.name().lower() not in ('claude','claude.exe') or not p.is_running():raise ValueError('identity_changed')
            exe=p.exe()
            if exe not in signatures:signatures[exe]=verify_offline(exe)
            row.update(binary_version=file_version(exe),signature=signatures[exe],executable=Path(exe).name,identity_state='pid_creation_time_path_parent_checked')
        except (psutil.Error,OSError,ValueError):row['identity_state']='unavailable_or_changed'
        result.append(row)
    return result
