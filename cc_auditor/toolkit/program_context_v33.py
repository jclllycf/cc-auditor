"""获批的相关宿主元数据；只检查限定文件，不执行 Claude/项目代码或读取密钥。"""
import json,os,re,shutil,subprocess,sys,tomllib
from pathlib import Path
import psutil
from ..collectors import file_version,classify
from ..storage import no_reparse
from .zero_contact_guard import utc_now

MAX_FILE=2*1024*1024
KNOWN_RUNTIME_NAMES={'python.exe','python3.exe','node.exe'}
AGENT_IDENTITIES={'workbuddy.exe':'WorkBuddy','codex.exe':'Codex','cursor.exe':'Cursor',
                  'windsurf.exe':'Windsurf','antigravity.exe':'Antigravity'}
META_SCRIPT="""for c in claude python3 node sh; do if command -v "$c" >/dev/null 2>&1; then printf '%s=present\\n' "$c"; fi; done; printf 'http_proxy=%s\\nhttps_proxy=%s\\nall_proxy=%s\\n' "${HTTP_PROXY:+present}${http_proxy:+present}" "${HTTPS_PROXY:+present}${https_proxy:+present}" "${ALL_PROXY:+present}${all_proxy:+present}"""
PYTHON_PROBE=r'''
import json,ssl,socket,ipaddress,http.client
out={'status':'failed','tls_verified':False,'vantage':'specified_python_isolated_stdlib_not_sdk','anthropic_requests_sent':0}
try:
 rows=socket.getaddrinfo('api4.ipify.org',443,socket.AF_INET,type=socket.SOCK_STREAM)
 for info in rows:
  a=ipaddress.ip_address(info[4][0].split('%')[0])
  if not a.is_global and not (ALLOW_FAKE and a in ipaddress.ip_network('198.18.0.0/15')):raise ValueError('nonpublic_receiver_address')
 with socket.socket(rows[0][0],socket.SOCK_STREAM) as raw:
  raw.settimeout(5);raw.connect(rows[0][4])
  with ssl.create_default_context().wrap_socket(raw,server_hostname='api4.ipify.org') as secure:
   secure.sendall(b'GET /?format=json HTTP/1.1\r\nHost: api4.ipify.org\r\nUser-Agent: CC-Auditor-Runtime/3.3\r\nConnection: close\r\n\r\n')
   response=http.client.HTTPResponse(secure);response.begin()
   if response.status!=200:raise ValueError('receiver_status')
   data=json.loads(response.read(4097));a=ipaddress.ip_address(data.get('ip',''))
   if not a.is_global:raise ValueError('invalid_echo')
   out.update(status='observed',tls_verified=True,ip=str(a),receiver='api4.ipify.org',transport='direct_tcp_system_route_TUN_may_apply')
except ssl.SSLCertVerificationError:out.update(reason='certificate_verification_failed',certificate_fault=True)
except Exception:out['reason']='neutral_transport_unavailable'
print(json.dumps(out))
'''


def _read(path):
    for part in [*reversed(Path(path).absolute().parents),Path(path).absolute()]:no_reparse(part)
    with Path(path).open('rb') as f:data=f.read(MAX_FILE+1)
    if len(data)>MAX_FILE:raise ValueError('metadata_too_large')
    return data.decode('utf-8-sig')


def _version(value):
    return value if isinstance(value,str) and re.fullmatch(r'[0-9][0-9A-Za-z.+~^<>=|,* -]{0,70}',value) else 'declared_version_not_exported'


def inspect_project(root,preferred=None):
    """root 只来自原生目录选择；文件内容留本地，只输出 SDK 是否存在。"""
    root=Path(root)
    if not root.is_absolute() or str(root).startswith('\\\\'):raise ValueError('project_root_not_local')
    no_reparse(root);root=root.resolve()
    if not root.is_dir():raise ValueError('project_root_not_local')
    out={'status':'observed','project_alias':'用户选定 API 项目','project_selected':True,'sdk_declared':False,'sdk_installed':False,'metadata_reads':[],'dotenv_content_read':False,'private_project_code_read':False,'runtime_candidate_found':False,'host_bound':False,'configured':False,'host_kind':'unknown'}
    private={};installed_kinds=set()
    for name in ('package.json','pyproject.toml','requirements.txt','requirements-dev.txt'):
        p=root/name
        if not p.is_file():continue
        try:
            raw=_read(p);sdk=None
            if name=='package.json':
                obj=json.loads(raw);sdk=(obj.get('dependencies') or {}).get('@anthropic-ai/sdk') or (obj.get('devDependencies') or {}).get('@anthropic-ai/sdk')
                if sdk:out['client_kind']='node_sdk'
            elif name=='pyproject.toml':
                obj=tomllib.loads(raw);sdk=next((x for x in (obj.get('project') or {}).get('dependencies',[]) if isinstance(x,str) and re.match(r'^anthropic(?:\W|$)',x,re.I)),None) or (((obj.get('tool') or {}).get('poetry') or {}).get('dependencies') or {}).get('anthropic')
                if sdk:out['client_kind']='python_sdk'
            else:
                sdk=next((line for line in raw.splitlines() if re.match(r'^anthropic(?:[=<>!~\s\[]|$)',line.strip(),re.I)),None)
                if sdk:out['client_kind']='python_sdk'
            out['metadata_reads'].append({'file_category':name,'status':'read_allowlisted_dependency_fields'})
            if sdk:out['sdk_declared']=True
        except (OSError,ValueError,TypeError,AttributeError,RecursionError):out['metadata_reads'].append({'file_category':name,'status':'unreadable_or_unsupported'})
    node=root/'node_modules/@anthropic-ai/sdk/package.json'
    if node.is_file():
        try:
            obj=json.loads(_read(node));out.update(sdk_installed=True,sdk_version=_version(obj.get('version')),client_kind='node_sdk');installed_kinds.add('node_sdk')
        except (OSError,ValueError,TypeError):pass
    # 不 import SDK、不运行 pip/npm/项目脚本、不读 .env 或认证配置。
    for envname in ('.venv','venv'):
        site=root/envname/'Lib/site-packages'
        if site.is_dir():
            for meta in sorted(site.glob('anthropic-*.dist-info/METADATA'))[:2]:
                try:
                    text=_read(meta);m=re.search(r'^Version:\s*([^\r\n]+)',text,re.M)
                    out.update(sdk_installed=True,sdk_version=_version(m.group(1)) if m else None,client_kind='python_sdk');installed_kinds.add('python_sdk')
                except (OSError,ValueError):pass
        python=root/envname/'Scripts/python.exe'
        if python.is_file():
            no_reparse(python);private['python_exe']=str(python);out['runtime_candidate_found']=True
            out['runtime_version']=file_version(python) or None
    if out.get('client_kind')=='node_sdk':
        exe=shutil.which('node.exe')
        if exe:private['node_exe']=exe;out['runtime_candidate_found']=True;out['runtime_version']=file_version(exe) or None
    if preferred in ('python','node') and preferred+'_sdk' in installed_kinds:
        out['client_kind']=preferred+'_sdk'
        if preferred=='node':
            exe=shutil.which('node.exe')
            if exe:private['node_exe']=exe
    chosen=out.get('client_kind');runtime_key='python_exe' if chosen=='python_sdk' else 'node_exe'
    if runtime_key in private:private={runtime_key:private[runtime_key]}
    else:private={}
    out['runtime_candidate_found']=bool(private)
    out['configured']=True if out['sdk_installed'] else False if out['sdk_declared'] else None
    out['host_bound']=bool(out['sdk_installed'] and out['runtime_candidate_found'] and (len(installed_kinds)<=1 or preferred in ('python','node')))
    if len(installed_kinds)>1 and preferred not in ('python','node'):out['reason']='multiple_installed_client_kinds_require_actual_runtime_selection'
    out['host_kind']='python' if out.get('client_kind')=='python_sdk' else 'node' if out.get('client_kind')=='node_sdk' else 'unknown'
    out['meaning']='限定项目依赖与运行时元数据，不证明 key、余额或业务请求已被服务接受。'
    return out,private


def _run(args,timeout=5):
    env=dict(os.environ)
    for key in ('NODE_OPTIONS','NODE_PATH','NODE_V8_COVERAGE'):env.pop(key,None)
    r=subprocess.run(args,capture_output=True,timeout=timeout,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    data=r.stdout[:65536];text=data.decode('utf-16-le' if b'\x00' in data[:30] else 'utf-8',errors='replace').replace('\x00','')
    return r.returncode,text


def inspect_subsystems(dec):
    out={'wsl':{'status':'not_installed','running_candidates':[]},'containers':{'status':'not_installed','candidates':[]},'ssh':{'status':'not_present','host_blocks':0,'remote_connections_attempted':False}};private={}
    wsl=shutil.which('wsl.exe')
    if wsl:
        try:
            code,text=_run([wsl,'--list','--running','--quiet']);names=[s.strip().lstrip('\ufeff') for s in text.splitlines() if re.fullmatch(r'[\w .()-]{1,80}',s.strip().lstrip('\ufeff'))] if code==0 else []
            out['wsl']['status']='observed' if code==0 else 'query_unavailable'
            for i,name in enumerate(names[:4],1):
                row={'alias':'WSL-'+str(i),'running_at_discovery':True,'metadata_checked':False};out['wsl']['running_candidates'].append(row)
                if dec.get('cli_host')=='wsl' or dec.get('api_host')=='wsl':
                    code2,current=_run([wsl,'--list','--running','--quiet'])
                    if code2 or name not in [s.strip().lstrip('\ufeff') for s in current.splitlines()]:continue
                    c,meta=_run([wsl,'--distribution',name,'--exec','/bin/sh','-c',META_SCRIPT]);row.update(metadata_checked=c==0,cli_present='claude=present' in meta,python_present='python3=present' in meta,node_present='node=present' in meta,shell_ready='sh=present' in meta,proxy_markers_present=any(k+'=present' in meta for k in ('http_proxy','https_proxy','all_proxy')))
                    if c==0:private[row['alias']]={'kind':'wsl','prefix':[wsl,'--distribution',name,'--exec'],'name':name,'wsl_exe':wsl}
        except (OSError,subprocess.TimeoutExpired):out['wsl']['status']='bounded_query_failed'
    docker=shutil.which('docker.exe')
    if docker:
        try:
            # context inspect 是本地元数据；只允许本机命名管道引擎，禁止 SSH/TCP 远端。
            code,text=_run([docker,'context','inspect','--format','{{json .Endpoints.docker.Host}}']);host=json.loads(text) if code==0 else ''
            override=host
            if not isinstance(override,str) or not re.fullmatch(r'npipe:/{2,4}\./pipe/[\w.-]{1,100}',override):out['containers']['status']='remote_or_unattributed_engine_not_contacted'
            else:
                # 显式绑定已验证的本机端点，不让上下文在检查与执行间漂移。
                bound=[docker,'--host',override]
                code,text=_run(bound+['ps','--quiet']);ids=[s.strip() for s in text.splitlines() if re.fullmatch(r'[0-9a-f]{12,64}',s.strip())] if code==0 else []
                out['containers']['status']='observed' if code==0 else 'engine_unavailable'
                for i,cid in enumerate(ids[:4],1):
                    row={'alias':'容器-'+str(i),'running_at_discovery':True,'metadata_checked':False};out['containers']['candidates'].append(row)
                    if dec.get('cli_host')=='container' or dec.get('api_host')=='container':
                        c,meta=_run(bound+['exec',cid,'/bin/sh','-c',META_SCRIPT]);row.update(metadata_checked=c==0,cli_present='claude=present' in meta,python_present='python3=present' in meta,node_present='node=present' in meta,shell_ready='sh=present' in meta)
                        if c==0:private[row['alias']]={'kind':'container','prefix':bound+['exec',cid]}
        except (OSError,ValueError,subprocess.TimeoutExpired):out['containers']['status']='bounded_query_failed'
    ssh=Path.home()/'.ssh/config'
    if ssh.is_file():
        try:
            text=_read(ssh);out['ssh'].update(status='observed',host_blocks=len(re.findall(r'^\s*Host\s+',text,re.M|re.I)),proxy_jump_configured=bool(re.search(r'^\s*ProxyJump\s+',text,re.M|re.I)))
        except (OSError,ValueError):out['ssh']['status']='unreadable'
    return out,private


def collect(declarations,private_options=None):
    private_options=private_options or {};private={};now=utc_now()
    out={'captured_at_utc':now,'scope':'program_context','status':'observed','audit':[],'desktop':{'status':'observed','installed':False,'versions':[]},'cli':{'status':'observed','installed':False,'host_bound':False,'host_kind':'windows','candidate_count':0},'api':{'status':'observed','configured':False,'host_bound':False,'project_selected':False},'browser_flags':{},'profile_flags':{}}
    out['agent_platform_candidates']=[];agent_seen=set()
    cli_paths=[];roots=[Path.home()/'.local/bin/claude.exe',Path(os.environ.get('APPDATA',''))/'npm/claude.cmd',Path.home()/'.claude/local/claude.exe']
    for cmd in ('claude.exe','claude.cmd'):
        p=shutil.which(cmd)
        if p:roots.append(Path(p))
    for p in roots:
        if p.is_file() and str(p.resolve()).casefold() not in {str(x.resolve()).casefold() for x in cli_paths}:
            try:
                no_reparse(p)
                if classify(str(p))!='desktop_shell_candidate':cli_paths.append(p)
            except (OSError,ValueError):out['cli']['candidate_read_partial']=True
    for p in psutil.process_iter(['name'],ad_value=None):
        name=(p.info.get('name') or '').lower()
        if name in AGENT_IDENTITIES and name not in agent_seen:
            agent_seen.add(name)
            row={'application':AGENT_IDENTITIES[name],'source':'approved_running_process_identity',
                 'status':'candidate_only','execution_mode':'unknown','anthropic_usage_inferred':False}
            try:row['file_version']=file_version(p.exe()) or None
            except (psutil.Error,OSError):row['file_version']=None
            out['agent_platform_candidates'].append(row)
        if name not in ('claude.exe','chrome.exe','msedge.exe','firefox.exe'):continue
        try:
            exe=p.exe()
            if name=='claude.exe':
                kind=classify(exe)
                if kind=='desktop_shell_candidate' or '\\app-claude\\' in exe.lower() or '\\claude\\app-' in exe.lower():
                    out['desktop'].update(installed=True,source='existing_process_path_classification',process_observed=True);private['desktop_exe']=exe
                    out['desktop']['versions'].append(file_version(exe) or None)
            else:
                bid={'chrome.exe':'chrome','msedge.exe':'edge','firefox.exe':'firefox'}[name];flags=out['browser_flags'].setdefault(bid,{'status':'observed','ignore_certificate_errors':False,'explicit_proxy_override_present':False})
                args=p.cmdline();flags['ignore_certificate_errors']|=any(a.split('=',1)[0] in ('--ignore-certificate-errors','--ignore-ssl-errors') for a in args);flags['explicit_proxy_override_present']|=any(a.startswith(('--proxy-server','--proxy-pac-url')) for a in args);del args
        except (psutil.Error,OSError):
            if name!='claude.exe':out['browser_flags'].setdefault({'chrome.exe':'chrome','msedge.exe':'edge','firefox.exe':'firefox'}[name],{'status':'partial'})
    local=Path(os.environ.get('LOCALAPPDATA',''))
    for p in (local/'AnthropicClaude/claude.exe',local/'Programs/Claude/Claude.exe',local/'Claude/claude.exe'):
        if p.is_file():out['desktop'].update(installed=True,source='fixed_installation_path');out['desktop']['versions'].append(file_version(p) or None);private['desktop_exe']=str(p)
    windowsapps=Path(os.environ.get('ProgramFiles','C:/Program Files'))/'WindowsApps'
    try:
        import itertools
        out['desktop']['msix_package_candidates']=sum('claude' in p.name.lower() for p in itertools.islice(windowsapps.iterdir(),4096))
        if out['desktop']['msix_package_candidates']:out['desktop'].update(installed=True,source='msix_package_directory_metadata')
    except OSError:
        out['desktop']['installation_query_partial']=True
        if not out['desktop']['installed']:out['desktop']['installed']=None
    out['cli'].update(installed=bool(cli_paths),candidate_count=len(cli_paths),shell_ready=any(shutil.which(x) for x in ('powershell.exe','pwsh.exe','cmd.exe')))
    host=declarations.get('cli_host','unknown')
    if host in ('unknown','windows') and len(cli_paths)==1:out['cli']['host_bound']=True;out['cli']['host_selection']='single_local_candidate_inferred'
    if len(cli_paths)==1:private['cli_exe']=str(cli_paths[0])
    if host in ('wsl','container','remote'):out['cli'].update(installed=None,host_kind=host,host_bound=False)
    subs,sub_private=inspect_subsystems(declarations);out['subsystems']=subs;private['subsystems']=sub_private
    matches=[r for r in (subs['wsl']['running_candidates'] if host=='wsl' else subs['containers']['candidates'] if host=='container' else []) if r.get('cli_present')]
    if len(matches)==1:
        r=matches[0];out['cli'].update(installed=True,host_bound=True,candidate_count=1,shell_ready=r.get('shell_ready'),host_alias=r['alias']);private['cli_subsystem']=sub_private[r['alias']]
    elif host in ('wsl','container'):out['cli'].update(candidate_count=len(matches),installed=False if not matches and subs['wsl' if host=='wsl' else 'containers']['status']=='observed' else None)
    project=private_options.get('api_project')
    if project:
        try:out['api'],private['api']=inspect_project(project,declarations.get('api_host'))
        except (OSError,ValueError):out['api']={'status':'failed','project_selected':True,'configured':None,'reason':'selected_project_unreadable_or_unsupported'}
    if declarations.get('api_host') in ('wsl','container','remote'):out['api'].update(host_kind=declarations['api_host'],host_bound=False,reason='指定的远端/子系统应用未绑定；不会借用本机项目结果')
    bind_preuse_environments(out,private,declarations,subs,sub_private)
    # 分类只使用用户枚举和本轮限定宿主元数据，不从平台品牌推断请求位置。
    from .api_execution_v35 import classify as classify_api
    out['api_execution_v35']=classify_api({'user_declarations':declarations,'program_context_v33':out})
    out['audit']=[{'source':'fixed_installation_paths_and_related_processes','status':'completed','captured_at_utc':now},{'source':'selected_project_allowlisted_dependency_metadata','status':'completed' if project else 'no_project_selected','captured_at_utc':now},{'source':'running_subsystem_metadata_only','status':'completed','captured_at_utc':now}]
    return out,private


def bind_preuse_environments(out,private,declarations,subsystems,sub_private):
    """Bind the selected *environment* independently of Claude/SDK presence."""
    for surface in ('cli','api'):
        host=declarations.get(surface+'_host')
        if host not in ('wsl','container','remote'):continue
        context=out.setdefault(surface,{})
        context.update(host_kind=host,preuse_host_bound=False)
        if surface=='cli':context['shell_ready']=None
        if host=='remote':continue  # No SSH or remote engine connection.
        source=subsystems.get('wsl' if host=='wsl' else 'containers',{})
        rows=source.get('running_candidates' if host=='wsl' else 'candidates',[])
        rows=[r for r in rows if r.get('running_at_discovery') and r.get('metadata_checked') and r.get('shell_ready')]
        if source.get('status')!='observed' or len(rows)!=1:continue
        row=rows[0];context.update(preuse_host_bound=True,preuse_host_alias=row['alias'],preuse_host_basis='single_running_environment_metadata_no_claude_required')
        if surface=='cli':context['shell_ready']=True
        if row.get('python_present') and row['alias'] in sub_private:
            private[surface+'_subsystem']=sub_private[row['alias']]


def python_transport(exe,allow_fake=False,prefix=None,family=4):
    code=PYTHON_PROBE.replace('ALLOW_FAKE','True' if allow_fake else 'False')
    if family==6:code=code.replace('api4.ipify.org','api6.ipify.org').replace('socket.AF_INET,','socket.AF_INET6,').replace("a in ipaddress.ip_network('198.18.0.0/15')","any(a in ipaddress.ip_network(n) for n in ('2001:2::/48','fdfe:dcba:9876::/48'))")
    args=(prefix or [])+[str(exe),'-I','-S','-B','-c',code]
    try:
        rc,text=_run(args,timeout=12);out=json.loads(text) if rc==0 else {}
        if out.get('status') not in ('observed','failed'):raise ValueError('runtime_probe_invalid')
        if out.get('status')=='observed':
            import ipaddress
            if ipaddress.ip_address(out.get('ip','')).version!=family:raise ValueError('echo_family_mismatch')
        return out
    except (OSError,ValueError,subprocess.TimeoutExpired):return {'status':'failed','reason':'specified_runtime_probe_unavailable','tls_verified':False}


def windows_transport(allow_fake=False,family=4):
    # Windows 系统网络视点；不是 Electron 或 SDK 实际握手。无重定向/认证/Cookie。
    exe=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        address=receiver_address(allow_fake,family)
        script="""$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();$c=[Net.Sockets.TcpClient]::new();try{$a=$c.BeginConnect('ADDRESS',443,$null,$null);if(-not $a.AsyncWaitHandle.WaitOne(5000)){throw 'timeout'};$c.EndConnect($a);$s=[Net.Security.SslStream]::new($c.GetStream(),$false);$s.ReadTimeout=5000;$s.WriteTimeout=5000;$s.AuthenticateAsClient('api4.ipify.org');$b=[Text.Encoding]::ASCII.GetBytes("GET /?format=json HTTP/1.0`r`nHost: api4.ipify.org`r`nConnection: close`r`n`r`n");$s.Write($b);$buf=[byte[]]::new(4096);$ms=[IO.MemoryStream]::new();while(($n=$s.Read($buf,0,$buf.Length)) -gt 0){$ms.Write($buf,0,$n);if($ms.Length -gt 8192){throw 'limit'}};$t=[Text.Encoding]::UTF8.GetString($ms.ToArray());if($t -notmatch '^HTTP/1.[01] 200 '){throw 'receiver'};$d=($t -split "`r`n`r`n",2)[1]|ConvertFrom-Json;@{status='observed';tls_verified=$true;ip=$d.ip;receiver='api4.ipify.org';vantage='windows_sslstream_direct_system_route_not_electron';transport='direct_tcp_system_route_TUN_may_apply'}|ConvertTo-Json -Compress}catch{@{status='failed';tls_verified=$false;reason='system_neutral_https_unavailable'}|ConvertTo-Json -Compress}finally{$c.Dispose()}""".replace('ADDRESS',address)
        if family==6:script=script.replace('api4.ipify.org','api6.ipify.org').replace('[Net.Sockets.TcpClient]::new()','[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)')
        rc,text=_run([str(exe),'-NoProfile','-NonInteractive','-Command',script],12);out=json.loads(text)
        import ipaddress
        if out.get('status')=='observed' and (not ipaddress.ip_address(out.get('ip','')).is_global or ipaddress.ip_address(out['ip']).version!=family):raise ValueError('invalid_runtime_echo')
        return out
    except (OSError,ValueError,subprocess.TimeoutExpired):return {'status':'failed','tls_verified':False,'reason':'system_neutral_https_unavailable'}


def receiver_address(allow_fake=False,family=4):
    import socket,ipaddress
    addresses=[ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo('api4.ipify.org' if family==4 else 'api6.ipify.org',443,socket.AF_INET if family==4 else socket.AF_INET6,type=socket.SOCK_STREAM)]
    fake=[ipaddress.ip_network(n) for n in (('198.18.0.0/15',) if family==4 else ('2001:2::/48','fdfe:dcba:9876::/48'))]
    if not addresses or any(a.version!=family or not a.is_global and not (allow_fake and any(a in n for n in fake)) for a in addresses):raise ValueError('receiver_address_rejected')
    return str(addresses[0])


def bind_browser_flags(profiles):
    out={}
    for profile in profiles:
        peers=profile.get('browser_peer') or (profile.get('dynamic_result') or {}).get('browser_peer') or []
        if not peers:continue
        row={'status':'partial','ignore_certificate_errors':False,'explicit_proxy_override_present':False,'binding':'callback_peer_pid_and_ancestry','processes_checked':0}
        out[profile['profile_key']]=row;peer=peers[0]
        try:
            p=psutil.Process(peer['pid'])
            if abs(p.create_time()-peer['created_epoch'])>0.01:continue
            current=p;visited=set()
            for _ in range(4):
                if current is None or current.pid in visited:break
                visited.add(current.pid)
                if current.name().lower() not in ('chrome.exe','msedge.exe','firefox.exe'):break
                args=current.cmdline();row['ignore_certificate_errors']|=any(a.split('=',1)[0] in ('--ignore-certificate-errors','--ignore-ssl-errors') for a in args);row['explicit_proxy_override_present']|=any(a.startswith(('--proxy-server','--proxy-pac-url')) for a in args);del args;row['processes_checked']+=1;current=current.parent()
            if row['processes_checked']:row['status']='observed'
        except (psutil.Error,OSError,KeyError,TypeError):row['status']='partial'
    return out


def node_transport(exe,allow_fake=False,prefix=None,family=4):
    # 自有脚本，不加载 SDK/项目代码；固定 lookup 地址，保留主机名/SNI 和证书验证。
    try:
        if prefix:return {'status':'unsupported','reason':'subsystem_node_pinned_resolver_not_implemented','tls_verified':False}
        address=receiver_address(allow_fake,family)
        script="""const https=require('node:https');let out={status:'failed',tls_verified:false,vantage:'specified_node_builtin_not_sdk',anthropic_requests_sent:0};const req=https.get({hostname:'api4.ipify.org',path:'/?format=json',family:4,rejectUnauthorized:true,lookup:(h,o,cb)=>cb(null,'ADDRESS',4),timeout:5000,agent:false},r=>{let t='';r.on('data',b=>{t+=b;if(t.length>4096)req.destroy()});r.on('end',()=>{try{let d=JSON.parse(t);if(r.statusCode!==200||typeof d.ip!=='string')throw 0;console.log(JSON.stringify({...out,status:'observed',tls_verified:true,ip:d.ip,receiver:'api4.ipify.org',transport:'direct_tcp_system_route_TUN_may_apply'}))}catch{console.log(JSON.stringify(out))}})});req.on('timeout',()=>req.destroy());req.on('error',e=>console.log(JSON.stringify({...out,reason:'specified_node_transport_failed',certificate_fault:['CERT_HAS_EXPIRED','UNABLE_TO_VERIFY_LEAF_SIGNATURE','DEPTH_ZERO_SELF_SIGNED_CERT','ERR_TLS_CERT_ALTNAME_INVALID'].includes(e.code)})));""".replace('ADDRESS',address)
        if family==6:script=script.replace('api4.ipify.org','api6.ipify.org').replace('family:4','family:6').replace("',4)","',6)")
        rc,text=_run([str(exe),'-e',script],10);out=json.loads(text)
        import ipaddress
        if out.get('status')=='observed' and (not ipaddress.ip_address(out.get('ip','')).is_global or ipaddress.ip_address(out['ip']).version!=family):raise ValueError('invalid_echo')
        return out
    except (OSError,ValueError,subprocess.TimeoutExpired):return {'status':'failed','reason':'specified_node_probe_unavailable','tls_verified':False}


def proxy_markers():
    """限定变量只输出存在性；不读任意进程环境或输出代理口令。"""
    keys=('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','NODE_TLS_REJECT_UNAUTHORIZED','SSL_CERT_FILE','REQUESTS_CA_BUNDLE')
    out={'collector':{k:bool(os.environ.get(k)) for k in keys},'user':{},'machine':{},'winhttp':{'status':'not_checked'}}
    try:
        import winreg
        for kind,hive,path in (('user',winreg.HKEY_CURRENT_USER,'Environment'),('machine',winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment')):
            try:
                with winreg.OpenKey(hive,path) as key:
                    for name in keys:
                        try:out[kind][name]=bool(winreg.QueryValueEx(key,name)[0])
                        except OSError:out[kind][name]=False
            except OSError:out[kind]['query_unavailable']=True
        exe=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/netsh.exe'
        code,text=_run([str(exe),'winhttp','show','proxy'])
        out['winhttp']={'status':'observed' if code==0 else 'failed','proxy_endpoint_marker_present':bool(re.search(r'(?:[\w.-]+|\[[\da-fA-F:]+\]):\d{2,5}',text)),'raw_output_exported':False}
    except (ImportError,OSError,subprocess.TimeoutExpired):out['winhttp']['status']='unavailable'
    return out
