"""Field-study negative replays. Every input is synthetic; no host/network reads."""
import copy
import json
import unittest
from unittest.mock import patch

from cc_auditor.toolkit.address_semantics import classify_address, classify_ice_candidate, is_public_unicast
from cc_auditor.toolkit.evidence_v37 import analyze, interpret, compact
from cc_auditor.toolkit.review_v37 import compare, remediation_plan
from cc_auditor.toolkit.effective_policy_v37 import snapshot
from cc_auditor.toolkit.deep_network_v31 import sanitize_browser, parse_dns_txt

NOW = '2026-10-31T12:00:00Z'
LATER = '2026-10-31T12:05:00Z'


def observation(kind='check', **changes):
    value = {'id': 'sample-a', 'kind': kind, 'state': 'observed', 'synthetic': True,
             'scope': {'device_session': 'fixture-device', 'profile_binding': 'fixture-profile-a',
                       'profile_key': 'chrome-profile-1', 'space_alias': 'main', 'transport': 'https', 'target_class': 'neutral'},
             'source_kind': 'synthetic', 'measurement_mode': 'raw_observed', 'execution_origin': 'synthetic',
             'vantage': 'browser_tool_origin', 'receiver_id': 'fixture_receiver', 'authorized': True,
             'policy_snapshot_id':'fixture-intent-v1','software_version':'fixture-1',
             'captured_at_utc': NOW, 'runtime_sha256': '1' * 64, 'data': {}}
    value.update(changes)
    return value


def report(*records, later=False):
    return {'version':'3.7.0-dev1','run_id': ('b' if later else 'a') * 32, 'created_at_utc': LATER if later else NOW,
            'synthetic': True, 'checks': [], 'profiles': [], 'approval': {'scopes': ['independent_network']},
            'diagnostic_context_v37': {'device_session': 'fixture-device', 'execution_origin': 'synthetic',
                                       'network_context_id': 'fixture-same-node', 'policy_snapshot_id': 'fixture-intent-v1'},
            'diagnostic_observations_v37': list(records)}


def outcome(kind, **data):
    return interpret(observation(kind, data=data), NOW)


class FieldStudy34(unittest.TestCase):
    def test_C01_profile_b_never_inherits_a(self):
        a = observation(state='passed')
        b = observation(id='sample-b', state='not_run', scope={**a['scope'], 'profile_key': 'chrome-profile-2'})
        rows = analyze(report(a, b))['observations']
        self.assertEqual([r['state'] for r in rows], ['pass_scoped', 'not_run'])

    def test_C02_cloud_is_wrong_vantage(self):
        self.assertEqual(interpret(observation(state='passed', execution_origin='cloud'), NOW)['classification'], 'wrong_vantage')

    def test_C03_http_region_does_not_decide_dns_intent(self):
        row = outcome('dns', authoritative_receipt=True, http_region='US', observed_resolver_regions=['CN'])
        self.assertEqual(row['state'], 'needs_attribution')

    def test_C04_domestic_direct_dns_can_match_policy(self):
        self.assertEqual(outcome('dns', authoritative_receipt=True, policy_bound=True, expected_resolver_regions=['CN'], observed_resolver_regions=['CN'])['state'], 'pass_scoped')

    def test_C05_real_receiver_overrides_static_nameserver_expectation(self):
        row = outcome('dns', authoritative_receipt=True, policy_bound=True, expected_resolver_regions=['US'], observed_resolver_regions=['US', 'CN'], strict_route=False)
        self.assertEqual(row['classification'], 'dns_policy_mismatch')
        self.assertFalse(row['root_cause_confirmed'])

    def test_C06_bootstrap_is_separate(self):
        self.assertEqual(outcome('dns', dns_role='bootstrap', observed_resolver_regions=['CN'])['classification'], 'separate_dns_role')

    def test_C07_receivers_disagree(self):
        self.assertEqual(outcome('dns', authoritative_receipt=True, conflicting_receivers=True)['classification'], 'receiver_disagreement')

    def test_C08_runtime_rule_and_intent_can_confirm_mismatch(self):
        self.assertEqual(outcome('route', policy_bound=True, runtime_match=True, expected_route='proxy', observed_route='direct')['state'], 'confirmed_mismatch')

    def test_C09_domestic_cdn_mismatch_is_business_routing(self):
        self.assertEqual(outcome('route', policy_bound=True, runtime_match=True, expected_route='direct', observed_route='proxy')['classification'], 'runtime_route_mismatch')

    def test_C10_no_resolve_static_suspicion_not_cause(self):
        row = outcome('route', resolution_rule_without_no_resolve=True)
        self.assertEqual(row['state'], 'reference')
        self.assertFalse(row['root_cause_confirmed'])

    def test_C11_relay_name_not_final_exit(self):
        row = outcome('route', policy_bound=True, runtime_match=True, expected_route='chain-hk-us', observed_route='chain-hk-us', ingress='HK', final_exit='US')
        self.assertEqual(row['state'], 'pass_scoped')
        self.assertIn('未推断最终公网出口', row['explanation_zh'])

    def test_C12_five_protocols_one_failure_domain(self):
        self.assertEqual(outcome('redundancy', failure_domain_aliases=['vps-a'] * 5)['classification'], 'single_failure_domain')

    def test_C13_no_direct_does_not_prove_core_down_protection(self):
        self.assertEqual(outcome('failure_state', configured_protection=True, core_stopped=True, group_has_direct=False)['classification'], 'configured_unproven_fault')

    def test_C14_strict_route_not_firewall_proof(self):
        row = outcome('failure_state', configured_protection=True, strict_route=True)
        self.assertEqual(row['state'], 'partial')

    def test_C15_main_space_does_not_cover_secure_folder(self):
        main = observation(state='passed')
        sf = observation(id='sf', state='not_run', scope={**main['scope'], 'space_alias': 'secure-folder'})
        self.assertEqual(analyze(report(main, sf))['gaps'][0]['scope']['space_alias'], 'secure-folder')

    def test_C16_same_display_name_different_binding_not_comparable(self):
        a = observation(state='passed'); b = copy.deepcopy(a)
        b['scope']['profile_binding'] = 'different-container-runtime'
        self.assertEqual(compare(report(a), report(b, later=True))['status'], 'not_comparable')

    def test_C17_stopped_dynamic_vpn_not_pass(self):
        self.assertEqual(interpret(observation('failure_state', state='not_run', data={'configured_protection': True}), NOW)['state'], 'not_run')

    def test_C18_browser_udp_not_all_apps(self):
        row = outcome('ice', candidates=[], gathering_complete=True, udp_blocking_observed=True)
        self.assertIn('原生 UDP', row['side_effects'][0])

    def test_C19_private_vpn_ice_not_public(self):
        row = classify_ice_candidate('172.19.0.1', 'host')
        self.assertEqual(row['meaning'], 'local_candidate_exposed')
        self.assertFalse(row['public_unicast_candidate'])

    def test_C20_benchmark_not_public(self):
        self.assertEqual(classify_address('198.18.0.1')['category'], 'benchmarking')
        self.assertFalse(is_public_unicast('198.19.255.255'))

    def test_C21_cgnat_not_public(self):
        self.assertEqual(classify_address('100.64.0.1')['category'], 'shared_address_space')
        self.assertFalse(is_public_unicast('100.127.255.254'))

    def test_C22_documentation_ipv6_not_public(self):
        self.assertFalse(is_public_unicast('2001:db8::1'))
        self.assertFalse(is_public_unicast('3fff::1'))

    def test_C23_resolver_ipv6_not_terminal_ipv6(self):
        self.assertEqual(outcome('ipv6', resolver_ipv6=True, terminal_ipv6_observed=False)['classification'], 'not_public_terminal_ipv6')

    def test_C24_zero_candidates_with_explicit_blocking(self):
        row = outcome('ice', candidates=[], gathering_complete=True, udp_blocking_observed=True)
        self.assertEqual(row['classification'], 'pass_scoped_under_blocking')

    def test_C25_two_stun_samples_do_not_cover_all_udp(self):
        row = outcome('ice', candidates=[{'address': '8.8.8.8', 'type': 'srflx'}, {'address': '1.1.1.1', 'type': 'srflx'}], gathering_complete=True)
        self.assertEqual(row['state'], 'reference')
        self.assertFalse(row['root_cause_confirmed'])

    def test_C26_different_times_do_not_prove_one_connection(self):
        row = outcome('ice', candidates=[{'address': '8.8.8.8', 'type': 'srflx'}], gathering_complete=True, http_country='CN', ice_country='US')
        self.assertEqual(row['classification'], 'public_ice_sample')

    def test_C27_js_error_is_missing_score(self):
        self.assertEqual(outcome('external_score', probe_error=True, score=0)['state'], 'failed')

    def test_C28_external_score_is_not_health_or_ban_probability(self):
        row = outcome('external_score', score=90, claimed_bot_score=10)
        self.assertEqual(row['state'], 'reference')
        self.assertFalse(row['affects_health_score'])

    def test_C29_memory_bucket_not_identity_spoofing(self):
        self.assertEqual(outcome('fingerprint', device_memory=16, physical_memory=24)['classification'], 'browser_capability_reference')

    def test_C30_equal_fingerprints_do_not_merge_profiles(self):
        a = observation('fingerprint', data={'canvas_hash': 'same'})
        b = observation('fingerprint', id='profile-b', scope={**a['scope'], 'profile_key': 'chrome-profile-2'}, data={'canvas_hash': 'same'})
        self.assertEqual(len(analyze(report(a, b))['features']), 2)

    def test_C31_unapproved_subrequest_stays_blocked(self):
        self.assertEqual(outcome('destination', unapproved_subrequest=True)['state'], 'blocked_by_policy')

    def test_C32_proxy_and_direct_reset_endpoint_unverified(self):
        self.assertEqual(outcome('endpoint', proxy='reset', direct='reset')['classification'], 'endpoint_unverified')

    def test_C33_policy_unknown_not_technical_fault(self):
        self.assertEqual(outcome('policy', physical_country=None, eligibility=None)['state'], 'reference')

    def test_C34_stale_runtime_not_pass(self):
        self.assertEqual(interpret(observation(state='passed', captured_at_utc='2026-10-30T12:00:00Z'), NOW)['state'], 'expired')


class EvidenceContractSafety(unittest.TestCase):
    def test_authorization_and_instrumentation_precede_green(self):
        self.assertEqual(interpret(observation(state='passed', authorized=False), NOW)['state'], 'blocked_by_policy')
        row = interpret(observation(state='passed', measurement_mode='instrumented'), NOW)
        self.assertEqual(row['state'], 'inconclusive')

    def test_missing_time_and_future_time_cannot_pass(self):
        for value in (None, '2026-10-31T12:00:00', '2026-11-01T12:00:00Z', 'invalid'):
            self.assertEqual(interpret(observation(state='passed', captured_at_utc=value), NOW)['state'], 'inconclusive')

    def test_indirect_config_does_not_prove_runtime(self):
        row = interpret(observation(state='passed', synthetic=False, source_kind='observed_config', execution_origin='local_windows'), NOW)
        self.assertEqual(row['state'], 'reference')

    def test_special_address_boundaries_and_global_exceptions(self):
        for value in ('192.0.0.9', '192.0.0.10', '2001:1::3', '8.8.8.8', '2606:4700:4700::1111'):
            self.assertTrue(is_public_unicast(value), value)
        for value in ('198.18.0.0', '100.64.0.0', '127.0.0.1', '224.0.0.1', 'ff02::1', 'fc00::1', 'fe80::1%2', '::ffff:127.0.0.1', '2002::1'):
            self.assertFalse(is_public_unicast(value), value)
        self.assertEqual(classify_address('random.local')['category'], 'mdns_name')
        self.assertEqual(classify_address('999.1.2.3')['category'], 'invalid')

    def test_sanitizer_distinguishes_zero_candidates_from_failed_gathering(self):
        a = sanitize_browser({'stun': {'status': 'observed', 'candidates': [], 'gathering_complete': True}})['stun']
        b = sanitize_browser({'stun': {'status': 'observed', 'candidates': []}})['stun']
        self.assertEqual(a['status'], 'completed_without_public_mapping'); self.assertEqual(b['status'], 'failed')

    def test_sanitizer_rejects_invalid_candidate_and_keeps_benchmark_class(self):
        with self.assertRaises(ValueError):
            sanitize_browser({'stun': {'status': 'observed', 'candidates': [{'address': 'not-an-ip', 'type': 'host'}]}})
        value = sanitize_browser({'stun': {'status': 'observed', 'gathering_complete': True, 'candidates': [{'address': '198.18.0.1', 'type': 'host'}]}})
        self.assertEqual(value['stun']['candidates'][0]['address_category'], 'benchmarking')

    def test_resolver_parser_does_not_accept_special_ranges(self):
        self.assertEqual(parse_dns_txt(['FROM: 198.18.0.1#53 (UDP)', 'FROM: 100.64.0.1#53 (TCP)']), [])

    def test_effective_config_missing_runtime_dns_not_filled_from_source(self):
        source = {'dns': {'enable': True, 'nameserver': ['https://resolver.invalid/dns-query']}, 'secret': 'synthetic-sensitive-marker'}
        row = snapshot(source, {'tun': {'enable': True, 'strict-route': False}})
        self.assertEqual(row['dns_authority'], 'not_exposed_by_runtime_api')
        self.assertFalse(row['runtime']['dns']['roles']['nameserver']['present'])
        self.assertNotIn('synthetic-sensitive-marker', json.dumps(row))
        self.assertNotIn('resolver.invalid', json.dumps(row))

    def test_config_drift_detected_without_kill_switch_claim(self):
        row = snapshot({'tun': {'strict-route': True}}, {'tun': {'strict-route': False}})
        self.assertEqual(row['observed_flag_differences'], ['tun.strict-route'])
        self.assertFalse(row['system_kill_switch_verified'])

    def test_same_scoped_samples_can_compare_but_do_not_prove_repair(self):
        a = observation('dns', data={'authoritative_receipt': True, 'policy_bound': True, 'observed_resolver_regions': ['CN'], 'expected_resolver_regions': ['US']})
        b = copy.deepcopy(a); b['data']['observed_resolver_regions'] = ['US']; b['captured_at_utc'] = LATER
        result = compare(report(a), report(b, later=True))
        self.assertEqual(result['status'], 'comparable')
        self.assertEqual((result['rows'][0]['before'], result['rows'][0]['after']), ('confirmed_mismatch', 'pass_scoped'))
        self.assertFalse(result['repair_proven']); self.assertIsNone(result['health_score_delta'])

    def test_different_network_intent_or_authorization_refuses_comparison(self):
        a = report(observation('dns')); b = report(observation('dns'), later=True)
        b['diagnostic_context_v37']['policy_snapshot_id'] = 'new-user-intent'
        self.assertEqual(compare(a, b)['status'], 'not_comparable')
        b['approval']['scopes'] = []
        self.assertIn('authorization_scope_changed', compare(a, b)['reasons'])

    def test_planner_never_turns_features_or_unknowns_into_executable_actions(self):
        a = analyze(report(observation('fingerprint'), observation(id='missing', state='not_run')))
        self.assertEqual(remediation_plan(a)['proposals'], [])
        b = analyze(report(observation(state='fault')))
        plan = remediation_plan(b)
        self.assertFalse(plan['automatic_execution']); self.assertFalse(plan['executor_implemented'])
        self.assertFalse(plan['proposals'][0]['executable'])
        self.assertIn('private_backup_verified', plan['proposals'][0]['preconditions'])

    def test_core_has_no_network_or_process_side_effects(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('subprocess.Popen', side_effect=AssertionError('launch forbidden')):
            value = analyze(report(observation('dns', data={'authoritative_receipt': True})))
            self.assertEqual(len(value['observations']), 1)
            self.assertEqual(compact(value)['returned'], 1)

    def test_legacy_schema_is_interpretable_without_invented_binding(self):
        from tests_toolkit.test_v34_clean_preuse import clean_user
        old = clean_user()
        old.pop('diagnostic_context_v37', None)
        result = analyze(old)
        self.assertEqual(result['health_contract_unchanged'], '3.5.health.region.1')
        self.assertFalse(any(r['state'] == 'pass_scoped' for r in result['observations']))

    def test_new_version_stays_on_health_contract(self):
        from tests_toolkit.test_v34_clean_preuse import clean_user
        from cc_auditor.toolkit.evidence_completion_v33 import attach
        value=clean_user();value['version']='3.7.0-dev1'
        attach(value,value['program_context_v33'],attempts=[])
        self.assertEqual(value['model_version'],'3.5.health.region.1')
        self.assertIn('health_score',value['surface_assessments']['web'])

    def test_unknown_execution_origin_never_passes(self):
        self.assertEqual(interpret(observation(state='passed',execution_origin='unknown'),NOW)['state'],'inconclusive')

    def test_retry_keeps_original_sample_time(self):
        value=report();value['approval']['profiles']=['chrome-profile-1']
        value['profiles']=[{'profile_key':'chrome-profile-1','profile_session_binding':'fixture-profile-a','checked_at_utc':NOW,
            'dynamic_result':{'checked_at_utc':NOW,'profile_binding':'user_attested_targeted_launch_browser_pid',
                'independent_network_source_attempts':{'ipv4':1},'data':{'independent_network':{'ipv4':{'status':'observed','ip':'8.8.8.8'}}}},
            'v33_attempt_history':[{'attempt':1,'result':{'checked_at_utc':'2026-10-30T12:00:00Z','profile_binding':'user_attested_targeted_launch_browser_pid'}}]}]
        row=analyze(value)['observations'][0]
        self.assertEqual(row['state'],'expired')

    def test_profile_bindings_are_session_keyed_and_not_path_strings(self):
        from cc_auditor.toolkit.profiles_v3 import profile_session_binding
        a=profile_session_binding('fixture/chrome','fixture/profile-a')
        self.assertEqual(a,profile_session_binding('fixture/chrome','fixture/profile-a'))
        self.assertNotEqual(a,profile_session_binding('fixture/chrome','fixture/profile-b'))
        self.assertNotIn('fixture',a)

    def test_diagnostics_mcp_is_bounded_and_old_interface_stays_seven_tools(self):
        from cc_auditor.toolkit.mcp_v3 import dispatch_mcp_tool,MCP_TOOLS_SPEC
        value=report(*[observation(id='sample-'+str(i),state='fault') for i in range(20)])
        with patch('cc_auditor.toolkit.preflight_v3.read',return_value=(value,'0'*64)):
            result=dispatch_mcp_tool('get_preflight_evidence',{'scan_id':'a'*32,'view':'diagnostics'})
            self.assertEqual(result['returned'],10)
            self.assertEqual(len(result['remediation_plan']['proposals']),10)
            with self.assertRaises(ValueError):dispatch_mcp_tool('get_preflight_evidence',{'scan_id':'a'*32,'view':'comparison','compare_to_scan_id':'../escape'})
        self.assertEqual(len(MCP_TOOLS_SPEC),7)

    def test_no_public_mapping_does_not_satisfy_legacy_stun_echo_score(self):
        from tests_toolkit.test_v34_clean_preuse import clean_user
        from cc_auditor.toolkit.health_v35 import assess
        value=clean_user(True)
        value['profiles'][0]['dynamic_result']['data']['independent_network']['stun']=sanitize_browser({'stun':{'status':'observed','candidates':[],'gathering_complete':True}})['stun']
        rows=assess(value)['surface_assessments']['web']['profiles'][0]['ledger']
        self.assertNotEqual(next(r for r in rows if r['rule_id']=='web.stun')['state'],'passed')

    def test_missing_or_invalid_candidates_never_green(self):
        for data in ({'gathering_complete':True},{'gathering_complete':True,'candidates':[{'address':'invalid'}]}):
            self.assertEqual(outcome('ice',**data)['state'],'inconclusive')

    def test_foreign_source_and_missing_sample_not_improvement(self):
        a=report(observation(state='fault'));b=report(later=True)
        row=compare(a,b)['rows'][0]
        self.assertEqual(row['after'],'not_run');self.assertEqual(row['status'],'not_comparable')

    def test_sensitive_timestamp_text_not_returned_to_model(self):
        value=analyze(report(observation(captured_at_utc='sensitive-not-a-time')))
        self.assertNotIn('sensitive-not-a-time',json.dumps(compact(value)))

    def test_mixed_synthetic_real_cannot_confirm_live_fault(self):
        value=report(observation(state='fault'));value['synthetic']=False
        self.assertEqual(analyze(value)['observations'][0]['classification'],'mixed_synthetic_origin')
        self.assertEqual(analyze(value)['confirmed'],[])

    def test_changed_browser_or_collector_version_refuses_comparison(self):
        a=report(observation(state='passed'));b=report(observation(state='passed',software_version='fixture-2'),later=True)
        self.assertEqual(compare(a,b)['status'],'not_comparable')
        b['version']='3.8'
        self.assertIn('collector_version_unbound_or_changed',compare(a,b)['reasons'])

    def test_duplicate_sample_identity_cannot_silently_collapse(self):
        a=report(observation(state='passed'),observation(state='fault'))
        self.assertIn('ambiguous_duplicate_samples',compare(a,report(observation(state='passed'),later=True))['reasons'])

    def test_report_export_is_offline_idempotent_and_preserves_source(self):
        import tempfile
        from pathlib import Path
        from cc_auditor.toolkit.review_v37 import export_review
        value=report(observation('fingerprint'));value['run_id']='<script>fixture</script>'
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'evidence.json';source.write_text('immutable-source','utf-8')
            with patch('cc_auditor.toolkit.preflight_v3.read',return_value=(value,'0'*64)),patch('socket.socket',side_effect=AssertionError('no network')):
                first=export_review(source);second=export_review(source)
                self.assertEqual(first,second)
                content=Path(first['html']).read_text('utf-8')
                self.assertIn("default-src 'none'",content)
                self.assertNotIn('<script>',content)
                self.assertNotIn('<img',content)
                self.assertEqual(source.read_text('utf-8'),'immutable-source')
                Path(first['html']).write_text('changed-by-user','utf-8')
                with self.assertRaises(FileExistsError):export_review(source)

    def test_loopback_records_bind_the_original_network_value(self):
        value=report();value['approval']['profiles']=['chrome-profile-1']
        value['profiles']=[{'profile_key':'chrome-profile-1','profile_session_binding':'fixture-profile-a','version':'fixture-1','checked_at_utc':NOW,
            'dynamic_result':{'checked_at_utc':NOW,'profile_binding':'user_attested_targeted_launch_browser_pid',
                'data':{'independent_network':{'ipv4':{'status':'observed','ip':'8.8.8.8'}}}}}]
        first=analyze(value)['observations'][0]['evidence_sha256']
        value['profiles'][0]['dynamic_result']['data']['independent_network']['ipv4']['ip']='1.1.1.1'
        self.assertNotEqual(first,analyze(value)['observations'][0]['evidence_sha256'])

    def test_check_identity_does_not_use_ordinal_evidence_number(self):
        value=report();value['checks']=[{'id':'tls_bypass','state':'passed','scope':'all','evidence_id':'E001','captured_at_utc':NOW}]
        self.assertEqual(analyze(value)['observations'][0]['id'],'tls_bypass')

    def test_profile_feature_without_approved_profile_never_passes(self):
        value=report();value['checks']=[{'id':'chrome-profile-1_cookies','state':'passed','scope':'chrome-profile-1','captured_at_utc':NOW}]
        value['profiles']=[{'profile_key':'chrome-profile-1','profile_session_binding':'fixture-profile-a',
                            'dynamic_result':{'profile_binding':'user_attested_targeted_launch_browser_pid'}}]
        row=analyze(value)['observations'][0]
        self.assertEqual(row['state'],'blocked_by_policy')
        self.assertEqual(row['scope']['profile_key'],'chrome-profile-1')

    def test_priority_actions_identify_scoped_safe_next_steps(self):
        value=analyze(report(observation(id='target_egress_web',state='not_run'),observation('dns',id='profile-dns',data={'authoritative_receipt':True}),observation('external_score',id='score',state='failed')))
        self.assertEqual(value['priority_findings'][0]['id'],'profile-dns')
        self.assertIn('DNS',value['priority_findings'][0]['next_action_zh'])
        self.assertNotEqual(value['priority_findings'][0]['next_action_zh'],value['priority_findings'][1]['next_action_zh'])


if __name__ == '__main__':
    unittest.main()
