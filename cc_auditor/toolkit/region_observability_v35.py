"""离线融合本轮地区事实；不新增网络请求、不推断账号身份或身体所在地。"""
import ipaddress
import re
from .region_v32 import languages


def _ip(value):
    try:
        address = ipaddress.ip_address(value)
        return str(address) if address.is_global else None
    except (ValueError, TypeError): return None


def _country(value):
    return value.upper() if isinstance(value, str) and re.fullmatch('[A-Za-z]{2}', value) else None


def synthesize(report):
    net = []; visible = []; local = []; conflicts = []
    time = report.get('created_at_utc'); region = report.get('browser_region_signals') or {}
    probes = report.get('generic_probe_egress') or []
    geo = {}
    for p in probes:
        ip = _ip(p.get('ip')); country = _country(p.get('country_code'))
        if p.get('status') == 'observed' and ip:
            row = {'vantage': 'scanner_system_neutral', 'receiver': p.get('target_host'),
                   'ip': ip, 'country': country, 'asn': p.get('asn'),
                   'vendor_labels': p.get('vendor_labels'), 'captured_at_utc': p.get('captured_at_utc'),
                   'source': p.get('source'), 'actual_claude_path': False,
                   'independence_limit': '多家 IP 数据库仅描述同一网络地址；不是独立物理定位'}
            net.append(row)
            if country: geo.setdefault(ip, []).append(row)
    for p in report.get('profiles', []):
        key = p['profile_key']; data = (p.get('dynamic_result') or {}).get('data') or {}
        if p.get('dynamic_profile_checked'):
            visible.append({'profile_key': key, 'source': 'this_run_tool_origin',
                'captured_at_utc': p.get('checked_at_utc'), 'navigator_languages': languages(data.get('languages')),
                'accept_language': data.get('request_accept_language'), 'timezone': data.get('timezone'),
                'ua_client_hints': {k: data.get(k) for k in ('family', 'version', 'platform', 'ua_ch_platform', 'ua_ch_brands', 'ua_ch_mobile')},
                'claude_observed': False, 'scoring_impact': 0})
        protocols = data.get('independent_network') or {}
        addresses = {}
        for kind in ('ipv4', 'ipv6', 'stun'):
            event = protocols.get(kind) or {}; ip = _ip(event.get('ip') or event.get('mapped_ip'))
            if event.get('status') != 'observed' or not ip: continue
            addresses[kind] = ip
            matches = geo.get(ip, []); countries = sorted({g['country'] for g in matches})
            net.append({'vantage': 'browser:' + key + ':' + kind, 'profile_key': key,
                'ip': ip, 'countries': countries, 'geolocation_sources': [g['receiver'] for g in matches],
                'captured_at_utc': p.get('checked_at_utc'), 'actual_claude_path': False,
                'country_status': 'matched_same_ip' if countries else 'not_geolocated',
                'boundary': '仅本工具页面的 HTTPS 或 UDP 测点；不是 Claude 目标出口'})
        if len(set(addresses.values())) > 1:
            conflicts.append({'kind':'protocol_or_address_family_difference','profile_key':key,
                              'addresses':addresses,'meaning':'协议或地址族出口不同，不自动判定泄漏','scoring_impact':0})
        dns = protocols.get('dns') or {}
        for value in dns.get('resolver_ips', []) if dns.get('status') == 'observed' else []:
            ip = _ip(value)
            if ip: net.append({'vantage': 'browser:' + key + ':recursive_dns', 'ip': ip,
                               'country': None, 'actual_claude_path': False, 'captured_at_utc': p.get('checked_at_utc')})
    for ip, rows in geo.items():
        countries = sorted({r['country'] for r in rows})
        if len(countries) > 1: conflicts.append({'kind': 'same_ip_geo_database_disagreement', 'ip': ip, 'countries': countries, 'scoring_impact': 0})
    for key in ('windows', 'managed_policies'):
        if region.get(key): local.append({'kind': key, 'value': region[key], 'website_directly_readable': False, 'scoring_impact': 0})
    for device in region.get('devices', []):
        local.append({'kind': 'browser_local_state', 'device_key': device.get('device_key'),
            'country_values': device.get('country_values'), 'permanent_consistency': device.get('permanent_consistency'),
            'browser_version': device.get('version'), 'captured_at_utc': device.get('captured_at_utc'),
            'website_directly_readable': False, 'google_specific': True, 'scoring_impact': 0})
    for p in region.get('profiles', []):
        local.append({'kind': 'profile_language_preferences', 'profile_key': p.get('profile_key'),
                      'selected_languages': p.get('selected_languages'), 'accept_languages': p.get('accept_languages'),
                      'website_directly_readable': False, 'scoring_impact': 0})
        for key in ('language_comparison',):
            if p.get(key) in ('different', 'mismatch'):
                conflicts.append({'kind': 'local_and_website_language_difference', 'profile_key': p.get('profile_key'), 'scoring_impact': 0})
    countries = sorted({r['country'] for r in net if r.get('country')})
    by_vantage = {r['vantage']: sorted(set(([r['country']] if r.get('country') else r.get('countries', [])))) for r in net}
    summary = ('中立测点出口地区参考：' + '、'.join(countries) + '；不可归因为 Claude 出口' if countries else
               '已取得中立出口 IP，尚无同一 IP 的有效地区数据' if net else '本轮没有取得可用中立出口地区证据')
    paths = report.get('path_evidence_v33') or {}
    surfaces = {}
    for s in ('desktop', 'web', 'cli', 'api'):
        surfaces[s] = {'summary': summary if s != 'api' else '按实际 API 执行位置判断；本机地区不可代替云端',
                       'target_final_egress_verified': False, 'target_country': None,
                       'evidence_scope': 'neutral_measurements_only', 'route_proof_basis': (paths.get(s) or {}).get('proof_basis')}
    return {'version': '3.5.region.observability.1', 'captured_at_utc': time,
            'network_egress_by_vantage': net, 'network_egress_countries_by_vantage': by_vantage,
            'web_visible_hints': visible, 'local_only_hints': local, 'conflicts': conflicts,
            'apparent_region_summary': summary, 'surface_region_summaries': surfaces,
            'physical_location_independently_verified': False,
            'physical_location_estimate': None,
            'self_declared_physical_country': _country((report.get('user_declarations') or {}).get('physical_country')),
            'physical_location_evidence_limit': '物理位置无法独立确认；IP、语言、时区和浏览器实验地区均不能证明身体所在地',
            'scoring_impact': 0}
