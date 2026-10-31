"""Non-secret projections of already approved config reads, not a new collector."""
from .evidence_v37 import digest


def _projection(config):
    config = config if isinstance(config, dict) else {}
    tun = config.get('tun') if isinstance(config.get('tun'), dict) else {}
    dns = config.get('dns') if isinstance(config.get('dns'), dict) else {}

    def boolean(mapping, key):
        value = mapping.get(key)
        return value if type(value) is bool else None

    roles = {}
    for key in ('default-nameserver', 'nameserver', 'proxy-server-nameserver', 'direct-nameserver', 'nameserver-policy'):
        value = dns.get(key)
        roles[key] = {'present': key in dns, 'entry_count': len(value) if isinstance(value, (list, dict)) else None}
    return {'mode': config.get('mode') if config.get('mode') in ('rule', 'global', 'direct') else 'unknown',
            'tun': {'enable': boolean(tun, 'enable'), 'strict-route': boolean(tun, 'strict-route'),
                    'dns_hijack_entry_count': len(tun.get('dns-hijack', [])) if isinstance(tun.get('dns-hijack'), list) else None},
            'dns': {'exposed': isinstance(config.get('dns'), dict), 'enable': boolean(dns, 'enable'),
                    'respect-rules': boolean(dns, 'respect-rules'), 'roles': roles}}


def snapshot(source_config, runtime_settings=None):
    source = _projection(source_config)
    runtime = _projection(runtime_settings)
    differences = []
    for group in ('tun', 'dns'):
        for key in ('enable', 'strict-route') if group == 'tun' else ('enable', 'respect-rules'):
            a, b = source[group].get(key), runtime[group].get(key)
            if a is not None and b is not None and a != b:
                differences.append(group + '.' + key)
    return {'contract': '3.7.effective-policy.1', 'source': source, 'runtime': runtime,
            'source_config_sha256': digest(source_config) if isinstance(source_config, dict) else None,
            'runtime_projection_sha256': digest(runtime) if isinstance(runtime_settings, dict) else None,
            'runtime_full_config_sha256': None, 'observed_flag_differences': differences,
            'dns_authority': 'runtime_partial' if runtime['dns']['exposed'] else 'not_exposed_by_runtime_api',
            'source_generated_runtime_equivalence': 'not_proven', 'system_kill_switch_verified': False,
            'note_zh': '只投影已有授权读取中的非机密字段；运行接口未提供的字段保持未知，不以源配置补齐。'}
