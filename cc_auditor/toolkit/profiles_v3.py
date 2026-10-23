"""发现真实 Profile；诊断键/扩展在用户批准后读取，结果不包含个人路径。"""
import json
import configparser
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
import psutil
from ..collectors import file_version
from ..storage import no_reparse
from .browser_discovery import BROWSER_CATALOG,CHROMIUM_USER_DATA_PATHS
from .zero_contact_guard import utc_now

def discover():
    public=[];private={};seen=set();running={};running_roots={}
    try:
        for p in psutil.process_iter(['name'],ad_value=None):
            name=(p.info.get('name') or '').lower()
            if any(name==e['exe'].lower() for e in BROWSER_CATALOG):
                try:
                    exe=p.exe().casefold();running[exe]=True
                    args=p.cmdline()
                    for i,arg in enumerate(args):
                        value=arg.split('=',1)[1] if arg.startswith('--user-data-dir=') else args[i+1] if arg=='--user-data-dir' and i+1<len(args) else None
                        if value and Path(value).is_absolute() and not value.startswith('\\\\'):running_roots[exe]=Path(value)
                    del args
                except (psutil.Error,OSError):pass
    except (psutil.Error,OSError):pass
    roots=[x for x in (os.environ.get('ProgramFiles'),os.environ.get('ProgramFiles(x86)'),os.environ.get('LOCALAPPDATA'),os.environ.get('APPDATA')) if x]
    for entry in BROWSER_CATALOG:
        found=None
        for p in running:
            if Path(p).name.lower()==entry['exe'].lower():found=Path(p);break
        if found is None:
            for root in roots:
                for rel in entry['rel_paths']:
                    p=Path(root)/rel
                    if p.is_file():found=p;break
                if found is not None:break
        if found is None:continue
        userroot=Path(os.environ.get('LOCALAPPDATA',''))/CHROMIUM_USER_DATA_PATHS[entry['id']] if entry['id'] in CHROMIUM_USER_DATA_PATHS else None
        if str(found).casefold() in running_roots:userroot=running_roots[str(found).casefold()]
        if userroot is None:
            # Portable Chromium uses only an already-existing nearby root; no folders are created.
            for candidate in (found.parent/'User Data',found.parent.parent/'User Data',found.parent/'Data/profile'):
                if (candidate/'Local State').is_file():userroot=candidate;break
        if entry['id']=='firefox':userroot=Path(os.environ.get('APPDATA',''))/'Mozilla/Firefox/Profiles'
        paths=[]
        if userroot and userroot.is_dir():
            try:
                paths=[p for p in userroot.iterdir() if p.is_dir() and (entry['id']=='firefox' or p.name=='Default' or re.fullmatch(r'Profile \d+',p.name))][:24]
            except OSError:pass
        # No invented profile_1 when no real profile directory was discovered.
        for idx,path in enumerate(sorted(paths),1):
            if str(path).casefold() in seen:continue
            try:no_reparse(path)
            except ValueError:continue
            seen.add(str(path).casefold());key=entry['id']+'-profile-'+str(idx)
            row={'browser_id':entry['id'],'browser_name':entry['name'],'engine':entry['engine'],'version':file_version(found) or '',
                'profile_key':key,'profile_alias':'日常档案 '+str(idx),'browser_running':str(found).casefold() in running,
                'static_profile_checked':False,'dynamic_profile_checked':False,'actual_profile_verified':False,
                'write_tests_performed':False,'rollback_status':'not_needed','cleanup_status':'not_performed'}
            public.append(row);private[key]={'public':row,'exe':found,'root':userroot,'path':path}
    return public,private

def static_profile(record):
    pub=dict(record['public']);p=record['path'];pub['checked_at_utc']=utc_now();pub['extension_count']=None;pub['network_preferences']={};pub['extension_capabilities']=[]
    try:
        prefs=p/'Preferences';no_reparse(prefs)
        if prefs.is_file() and prefs.stat().st_size<=16*1024*1024:
            raw=json.loads(prefs.read_text(encoding='utf-8'))
            for k in ('proxy','dns_over_https','webrtc'):
                node=raw.get(k) or {}
                if isinstance(node,dict):
                    safe={x:node[x] for x in ('mode','ip_handling_policy','secure_dns_mode') if x in node and isinstance(node[x],(str,bool,int))}
                    pub['network_preferences'][k]={'configured':bool(node),'diagnostic_values':safe}
            pub['session_restore_configured']=(raw.get('session') or {}).get('restore_on_startup')==1
            pub['last_exit_crashed']=(raw.get('profile') or {}).get('exit_type')=='Crashed';pub['static_profile_checked']=True
            del raw
        elif (p/'prefs.js').is_file():
            prefs=p/'prefs.js';no_reparse(prefs)
            if prefs.stat().st_size<=4*1024*1024:
                text=prefs.read_text(encoding='utf-8');keys=('network.proxy.type','network.trr.mode','media.peerconnection.enabled','browser.sessionstore.resume_from_crash')
                for k in keys:
                    m=re.search(r'user_pref\("'+re.escape(k)+r'",\s*(true|false|\d+)\s*\)',text)
                    pub['network_preferences'][k]=json.loads(m.group(1)) if m else None
                pub['static_profile_checked']=True
                del text
        extroot=p/'Extensions'
        if extroot.is_dir():
            count=0
            for ext in list(extroot.iterdir())[:128]:
                no_reparse(ext)
                if not ext.is_dir():continue
                versions=sorted([x for x in ext.iterdir() if x.is_dir()],key=lambda x:tuple(int(t) for t in re.findall(r'\d+',x.name)),reverse=True)
                for v in versions[:1]:
                    manifest=v/'manifest.json';no_reparse(manifest)
                    if manifest.is_file() and manifest.stat().st_size<256*1024:
                        m=json.loads(manifest.read_text(encoding='utf-8'));perms=(m.get('permissions') or [])+(m.get('host_permissions') or [])
                        pub['extension_capabilities'].append({'alias':'扩展 '+str(count+1),'proxy_permission':'proxy' in perms,'debugger_permission':'debugger' in perms,'broad_site_permission':any(x in perms for x in ('<all_urls>','*://*/*')),'effect_on_claude':'not_observed'})
                        count+=1
            pub['extension_count']=count
        elif (p/'extensions.json').is_file():
            x=p/'extensions.json';no_reparse(x)
            if x.stat().st_size<4*1024*1024:
                raw=json.loads(x.read_text(encoding='utf-8'));pub['extension_count']=sum(1 for a in raw.get('addons',[]) if a.get('active') is True)
    except (OSError,ValueError,TypeError,KeyError):pub['static_error']='部分诊断键/扩展目录读取失败'
    return pub

def dynamic_profile(record,timeout=35,independent_network=False):
    from .browser_probe import ToolkitBrowserLoopbackSession
    pub=dict(record['public']);pub.update(checked_at_utc=utc_now(),status='not_tested',reason='未安全复用日常 Profile',profile_binding='unverified')
    # Approval card attests the selected existing daily profile. Never create a fresh user-data-dir.
    exe=record['exe'];pub['browser_running']=has_visible_window(exe)
    if not pub['browser_running']:
        pub['reason']='所选浏览器未运行；请手动打开该日常档案的普通空白页，再重新授权补测。不会启动或恢复私人会话。'
        return pub
    peers=[]
    def observe(address,server_port):
        try:
            for c in psutil.net_connections(kind='tcp'):
                if c.pid and c.laddr and c.raddr and c.laddr.port==address[1] and c.raddr.port==server_port:
                    p=psutil.Process(c.pid)
                    if Path(p.exe()).resolve()==exe.resolve():peers.append({'pid':p.pid,'created_epoch':p.create_time(),'binary':exe.name})
        except (psutil.Error,OSError):pass
    session=ToolkitBrowserLoopbackSession(peer_observer=observe,independent_network=independent_network)
    def launch(url):
        if pub['engine']=='Gecko':args=[str(exe),'-P',firefox_profile_name(record['path']),'-new-tab',url]
        else:args=[str(exe),'--user-data-dir='+str(record['root']),'--profile-directory='+record['path'].name,'--new-tab',url,'--no-first-run','--no-default-browser-check']
        # A background process alone is not an open browser; do not trigger session restore.
        if not has_visible_window(exe):raise ValueError('browser_has_no_open_window')
        subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        out=session.run(launch,timeout=timeout)
        if out.get('status')!='ok':pub.update(status='timeout',reason='本次工具页回调超时；请保持已选日常档案的测试页打开，重新授权后补测。未计为动态通过');return pub
        data=out['data'];bst=data.get('bounded_storage_tests') or {}
        pub.update(status='observed',data=data,dynamic_profile_checked=True,actual_profile_verified=False,
            profile_binding='user_attested_targeted_launch_browser_pid' if peers else 'user_attested_targeted_launch_only',browser_peer=peers[:1],
            reason='用户确认的日常 Profile 定向开页；网页本身不能提供不可伪造的 Profile 身份。',
            write_tests_performed=bool(bst),cleanup_status='reported_clean' if bst and all(bst.get(k) is True for k in ('cookie_cleaned','local_storage_cleaned','session_storage_cleaned','indexeddb_cleaned','all_cleaned')) else 'unverified',
            rollback_status='not_needed_no_existing_settings_changed')
    except (OSError,ValueError):pub.update(status='not_tested',reason='没有可复用的可见浏览器窗口。请手动打开此日常档案的普通空白页，重新授权补测；未创建临时档案或恢复会话。')
    finally:
        try:session.server.server_close()
        except OSError:pass
    return pub


def firefox_profile_name(profile):
    ini=profile.parent.parent/'profiles.ini';no_reparse(ini)
    if not ini.is_file() or ini.stat().st_size>128*1024:raise ValueError('firefox_profile_mapping_unavailable')
    parser=configparser.ConfigParser();parser.read(ini,encoding='utf-8')
    for name in parser.sections():
        if not name.startswith('Profile'):continue
        item=parser[name];raw=item.get('Path','');path=ini.parent/raw if item.get('IsRelative','1')=='1' else Path(raw)
        if path.resolve()==profile.resolve() and item.get('Name'):return item['Name']
    raise ValueError('firefox_profile_mapping_unavailable')


def has_visible_window(exe):
    if os.name!='nt':return False
    import ctypes
    from ctypes import wintypes
    owners=set()
    for p in psutil.process_iter(['name'],ad_value=None):
        try:
            if Path(p.exe()).resolve()==exe.resolve():owners.add(p.pid)
        except (psutil.Error,OSError):pass
    seen=[];user=ctypes.WinDLL('user32',use_last_error=True)
    callback=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
    def visit(hwnd,extra):
        pid=wintypes.DWORD();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
        if pid.value in owners and user.IsWindowVisible(hwnd):seen.append(True)
        return True
    user.EnumWindows(callback(visit),0);return bool(seen)
