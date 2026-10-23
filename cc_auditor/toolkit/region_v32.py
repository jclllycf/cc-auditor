"""获批后的离线地区参考；严格字段允许列表，不读取账号/历史或实验 seed 内容。"""
from pathlib import Path
import json,re,os
from datetime import datetime,timedelta,timezone
from ..storage import no_reparse
from .zero_contact_guard import utc_now

COUNTRY_KEYS=('variations_country','variations_safe_seed_session_consistency_country','variations_safe_seed_permanent_consistency_country','variations_permanent_overridden_country')
TIME_KEYS=('variations_last_fetch_time','variations_seed_date','variations_safe_seed_date','variations_safe_seed_fetch_time')
NUMBER_KEYS=('variations_seed_milestone','variations_safe_seed_milestone','variations_failed_to_fetch_seed_streak','variations_crash_streak')
POLICIES={'ChromeVariations':{0,1,2},'DnsOverHttpsMode':{'off','automatic','secure'},'WebRtcIPHandling':{'default','default_public_and_private_interfaces','default_public_interface_only','disable_non_proxied_udp'},'ProxyMode':{'direct','auto_detect','pac_script','fixed_servers','system'},'QuicAllowed':{0,1}}


def languages(value):
    if isinstance(value,str):value=value.split(',')
    if not isinstance(value,list):return None
    return [v.strip() for v in value[:20] if isinstance(v,str) and re.fullmatch(r'[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*',v.strip())] or None


def _country(v):return v.lower() if isinstance(v,str) and re.fullmatch('[A-Za-z]{2}',v) else None


def _version(v):return v if isinstance(v,str) and re.fullmatch(r'\d{1,4}(?:\.\d{1,6}){1,3}',v) else None


def _stamp(v):
    if not isinstance(v,(str,int)) or isinstance(v,bool) or not re.fullmatch(r'\d{1,18}',str(v)):return None
    try:
        dt=datetime(1601,1,1,tzinfo=timezone.utc)+timedelta(microseconds=int(v))
        return {'raw_chromium_time':str(v),'utc':dt.isoformat(),'freshness':'time_metadata_only_not_active_seed_proof'}
    except (OverflowError,ValueError):return None


def _json(path,limit=16*1024*1024):
    no_reparse(path)
    with path.open('rb') as f:raw=f.read(limit+1)
    if len(raw)>limit:raise ValueError('diagnostic_file_too_large')
    obj=json.loads(raw)
    if not isinstance(obj,dict):raise ValueError('diagnostic_file_not_object')
    return obj


def parse_local_state(raw,version=''):
    result={'country_values':{},'seed_metadata':{},'permanent_consistency':None,'stored_browser_version':None}
    for k in COUNTRY_KEYS:
        if k in raw:result['country_values'][k]={'status':'observed' if _country(raw[k]) else 'unsupported_shape','value':_country(raw[k])}
    k='variations_permanent_consistency_country';v=raw.get(k)
    if isinstance(v,list) and len(v)==2 and _version(v[0]) and _country(v[1]):
        result['permanent_consistency']={'status':'observed','version':v[0],'country':_country(v[1]),'matches_executable_version':v[0]==version if version else None}
    elif v is not None:result['permanent_consistency']={'status':'unsupported_shape','value_not_exported':True}
    for k in TIME_KEYS:
        if k in raw:result['seed_metadata'][k]=_stamp(raw[k]) or {'status':'unsupported_shape'}
    for k in NUMBER_KEYS:
        v=raw.get(k)
        if type(v) is int and 0<=v<=100000:result['seed_metadata'][k]=v
    browser=raw.get('browser') or {}
    result['stored_browser_version']=_version(browser.get('last_version')) if isinstance(browser,dict) else None
    result['application_locale']=languages((raw.get('intl') or {}).get('app_locale')) if isinstance(raw.get('intl'),dict) else None
    result['seed_interpretation']='只取得时间/国家/版本元数据；未读取 seed 内容，不能判断本次实际启用 regular 或 safe seed。'
    return result


def read_device(record,alias):
    path=record['root']/'Local State';out={'device_key':alias,'browser_name':record['public']['browser_name'],'scope':'device/local_state','source':'existing_browser_root/Local State/allowlisted_keys',
        'captured_at_utc':utc_now(),'visibility':'google_specific_local_only','website_directly_readable':False,'scoring_impact':0,'physical_location_inferred':False,'status':'not_supported',
        'version':record['public'].get('version'),'channel':{'status':'not_independently_verified','reason':'未请求更新服务；文件版本不能单独证明更新渠道或最新安全版本。'}}
    if record['public'].get('engine')!='Chromium':return out
    try:
        out.update(parse_local_state(_json(path),out.get('version','')));out['status']='observed'
        out['file_mtime_utc']=datetime.fromtimestamp(path.stat().st_mtime,timezone.utc).isoformat()
        out['freshness_boundary']='文件修改时间不等于该字段更新时间；缺键保持未保存，不推定国家或正常状态。'
    except FileNotFoundError:out['status']='not_present'
    except (OSError,ValueError,TypeError,RecursionError):out['status']='unreadable_or_invalid'
    return out


def read_profile(record):
    out={'profile_key':record['public']['profile_key'],'scope':'per_profile','source':'existing_profile/Preferences/intl','captured_at_utc':utc_now(),
        'visibility':'local_preference_with_separate_website_observation','scoring_impact':0,'status':'not_supported'}
    if record['public'].get('engine')!='Chromium':return out
    try:
        raw=_json(record['path']/'Preferences');intl=raw.get('intl') or {}
        out.update(status='observed',accept_languages=languages(intl.get('accept_languages')),selected_languages=languages(intl.get('selected_languages')),forced_languages=languages(intl.get('forced_languages')))
    except FileNotFoundError:out['status']='not_present'
    except (OSError,ValueError,TypeError,AttributeError,RecursionError):out['status']='unreadable_or_invalid'
    return out


def windows_region():
    out={'status':'unsupported','scope':'windows_user_settings','captured_at_utc':utc_now(),'visibility':'local_only','scoring_impact':0,'physical_location_inferred':False,'source':'HKCU/Control Panel/International and Geo'}
    if os.name!='nt':return out
    import winreg
    observed={}
    for sub,key,dst,pattern in ((r'Control Panel\International\Geo','Name','home_region_code',r'[A-Za-z]{2}'),(r'Control Panel\International\Geo','Nation','home_geo_id',r'\d{1,6}'),(r'Control Panel\International','LocaleName','format_locale',r'[A-Za-z0-9-]{2,40}')):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,sub) as h:v,_=winreg.QueryValueEx(h,key)
            if isinstance(v,str) and re.fullmatch(pattern,v):observed[dst]=v
        except OSError:pass
    return {**out,**observed,'status':'observed' if observed else 'unavailable','meaning':'用户选择的 Windows 国家/地区和格式；不是物理所在地，也不自动暴露为网页地区。'}


def managed_policies():
    out={'status':'unsupported','scope':'device_and_current_user_policy','source':'Windows policy registry allowlist','values':[],'scoring_impact':0,'visibility':'local_only_configuration'}
    if os.name!='nt':return out
    import winreg
    for hive,hname in ((winreg.HKEY_LOCAL_MACHINE,'HKLM'),(winreg.HKEY_CURRENT_USER,'HKCU')):
        for browser,sub in (('chrome',r'SOFTWARE\Policies\Google\Chrome'),('edge',r'SOFTWARE\Policies\Microsoft\Edge')):
            try:
                with winreg.OpenKey(hive,sub) as h:
                    for key,choices in POLICIES.items():
                        try:
                            value,_=winreg.QueryValueEx(h,key)
                            if type(value) in (str,int) and value in choices:out['values'].append({'browser':browser,'hive':hname,'key':key,'value':value})
                        except OSError:pass
            except OSError:pass
    out['status']='observed';out['meaning']='只检查列出的键；没有这些键不证明浏览器完全不受管理，也不证明最终生效值。';return out


def collect(records):
    devices=[];profiles=[];seen={}
    for record in records.values():
        if record['public'].get('engine')!='Chromium':continue
        root=str(record['root']).casefold()
        if root not in seen:
            seen[root]='browser-device-'+str(len(seen)+1);devices.append(read_device(record,seen[root]))
        p=read_profile(record);p['device_key']=seen[root];profiles.append(p)
    return {'version':'3.2.region.1','windows':windows_region(),'devices':devices,'profiles':profiles,'managed_policies':managed_policies(),
        'google_account_region':{'status':'not_collected','reason':'未读取 Google/Outlook 账户、Gemini 资格、Cookie、账号标识或浏览习惯；它们不能替代 Claude 资格。'}}


def attach_website(region,profiles):
    """只附加本轮工具 origin 所见值，不能声称 Claude 确实收到了相同值。"""
    lookup={p['profile_key']:p for p in region.get('profiles',[])}
    for p in profiles:
        key=p['profile_key'];data=(p.get('dynamic_result') or {}).get('data',{})
        if key not in lookup:continue
        row=lookup[key];nav=languages(data.get('languages'));header=data.get('request_accept_language')
        row['website_observation']={'status':'observed' if p.get('dynamic_profile_checked') else 'not_measured','source':'this_run_127.0.0.1_tool_origin','captured_at_utc':p.get('checked_at_utc'),
            'visibility':'website_visible_at_probe_origin','navigator_languages':nav,'accept_language':header if isinstance(header,str) and re.fullmatch(r'[A-Za-z0-9,;= ._*+-]{0,256}',header) else None,
            'timezone':data.get('timezone'),'claude_received_these_values':'not_observed','scoring_impact':0}
        row['language_comparison']='observed_difference_reference_only' if nav and row.get('accept_languages') and nav[0].casefold()!=row['accept_languages'][0].casefold() else 'first_language_matches' if nav and row.get('accept_languages') else 'not_comparable'
    win=region.get('windows',{}).get('home_region_code','').lower()
    for d in region.get('devices',[]):
        country=d.get('country_values',{}).get('variations_country',{}).get('value')
        d['windows_country_comparison']='different_reference_only' if win and country and win!=country else 'same_reference_only' if win and country else 'not_comparable'
    return region
