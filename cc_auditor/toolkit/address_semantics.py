"""Deterministic address semantics, without DNS or Python-version is_private rules.

IANA IPv4/IPv6 special-purpose registries, last-updated 2025-10-09,
reviewed 2026-10-31. Reachability is a registry property, not a route test.
Multicast is intentionally excluded from public *unicast* candidates.
"""
from __future__ import annotations

import ipaddress
import re

REGISTRY_REVIEW = '2026-10-31'
REGISTRY_SOURCES = (
    'https://www.iana.org/assignments/iana-ipv4-special-registry',
    'https://www.iana.org/assignments/iana-ipv6-special-registry',
)
_ROWS = (
    ('0.0.0.0/8', 'this_network', False),
    ('10.0.0.0/8', 'private_use', False),
    ('100.64.0.0/10', 'shared_address_space', False),
    ('127.0.0.0/8', 'loopback', False),
    ('169.254.0.0/16', 'link_local', False),
    ('172.16.0.0/12', 'private_use', False),
    ('192.0.0.0/24', 'protocol_assignment', False),
    ('192.0.0.9/32', 'protocol_anycast', True),
    ('192.0.0.10/32', 'protocol_anycast', True),
    ('192.0.2.0/24', 'documentation', False),
    ('192.31.196.0/24', 'as112', True),
    ('192.52.193.0/24', 'amt', True),
    ('192.88.99.0/24', 'deprecated_6to4', None),
    ('192.88.99.2/32', 'relay_anycast', False),
    ('192.168.0.0/16', 'private_use', False),
    ('192.175.48.0/24', 'as112', True),
    ('198.18.0.0/15', 'benchmarking', False),
    ('198.51.100.0/24', 'documentation', False),
    ('203.0.113.0/24', 'documentation', False),
    ('224.0.0.0/4', 'multicast', False),
    ('240.0.0.0/4', 'reserved', False),
    ('255.255.255.255/32', 'limited_broadcast', False),
    ('::/128', 'unspecified', False),
    ('::1/128', 'loopback', False),
    ('::ffff:0:0/96', 'ipv4_mapped', False),
    ('64:ff9b::/96', 'translation', True),
    ('64:ff9b:1::/48', 'local_translation', False),
    ('100::/64', 'discard_only', False),
    ('100:0:0:1::/64', 'dummy', False),
    ('2001::/23', 'protocol_assignment', False),
    ('2001::/32', 'teredo', None),
    ('2001:1::1/128', 'protocol_anycast', True),
    ('2001:1::2/128', 'protocol_anycast', True),
    ('2001:1::3/128', 'protocol_anycast', True),
    ('2001:2::/48', 'benchmarking', False),
    ('2001:3::/32', 'amt', True),
    ('2001:4:112::/48', 'as112', True),
    ('2001:10::/28', 'deprecated_orchid', None),
    ('2001:20::/28', 'orchid', True),
    ('2001:30::/28', 'drone_id', True),
    ('2001:db8::/32', 'documentation', False),
    ('2002::/16', 'six_to_four', None),
    ('2620:4f:8000::/48', 'as112', True),
    ('3fff::/20', 'documentation', False),
    ('5f00::/16', 'segment_routing', False),
    ('fc00::/7', 'unique_local', False),
    ('fe80::/10', 'link_local', False),
    ('ff00::/8', 'multicast', False),
)
_NETWORKS = sorted(((ipaddress.ip_network(n), k, g) for n, k, g in _ROWS),
                   key=lambda x: x[0].prefixlen, reverse=True)


def classify_address(value):
    """Classify a literal or mDNS host. Never resolve names or infer geography."""
    result = {'category': 'invalid', 'family': None, 'globally_reachable': None,
              'public_unicast_candidate': False, 'registry_review': REGISTRY_REVIEW}
    if not isinstance(value, str) or len(value) > 256:
        return result
    value = value.strip()
    if re.fullmatch(r'[a-zA-Z0-9-]{1,63}\.local\.?', value, re.IGNORECASE):
        return {**result, 'category': 'mdns_name', 'globally_reachable': False}
    if '%' in value:
        value, zone = value.split('%', 1)
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', zone) or ':' not in value:
            return result
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return result
    result.update(address=str(ip), family=ip.version)
    for network, category, globally_reachable in _NETWORKS:
        if ip.version == network.version and ip in network:
            result.update(category=category, globally_reachable=globally_reachable,
                          matched_prefix=str(network))
            # Mapped IPv4 and NAT64 are not proof of native IPv6 connectivity.
            if category == 'ipv4_mapped':
                result['embedded_ipv4'] = classify_address(str(ip.ipv4_mapped))
            result['public_unicast_candidate'] = globally_reachable is True
            return result
    if ip.version == 6 and ip not in ipaddress.ip_network('2000::/3'):
        return {**result, 'category': 'unallocated_or_special'}
    return {**result, 'category': 'global_unicast', 'globally_reachable': True,
            'public_unicast_candidate': True}


def is_public_unicast(value):
    return classify_address(value)['public_unicast_candidate']


def classify_ice_candidate(address, candidate_type='unknown'):
    result = classify_address(address)
    result['candidate_type'] = candidate_type if candidate_type in ('host', 'srflx', 'prflx', 'relay') else 'unknown'
    result['meaning'] = ('receiver_mapping_sample' if result['public_unicast_candidate']
                         else 'local_candidate_exposed' if result['category'] in ('private_use', 'unique_local', 'link_local')
                         else 'not_confirmed_public_egress')
    result['proves_native_ipv6'] = result['family'] == 6 and result['category'] == 'global_unicast'
    result['proves_leak'] = False
    return result
