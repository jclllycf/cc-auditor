"""v3.5 判断契约；仅离线合成，禁止访问实际服务。"""
import copy
import unittest
from tests_toolkit.test_v34_clean_preuse import clean_user
from cc_auditor.toolkit.health_v35 import assess, evaluate, grade
from cc_auditor.toolkit.api_execution_v35 import classify
from cc_auditor.toolkit.region_observability_v35 import synthesize


class HealthContract(unittest.TestCase):
    def test_current_attachment_exposes_health_and_never_requires_location(self):
        from cc_auditor.toolkit.evidence_completion_v33 import attach, remaining_gaps
        r=clean_user(True);r['version']='3.5.0-dev1';r['user_declarations'].pop('physical_country',None)
        attach(r,r['program_context_v33'],attempts=[])
        self.assertEqual(r['model_version'],'3.5.health.region.1')
        self.assertIn('health_score',r['surface_assessments']['web'])
        self.assertNotIn('risk_index',r['surface_assessments']['web'])
        self.assertFalse(any(g['claim']=='eligibility_declaration' for g in remaining_gaps(r)))

    def test_all_unmeasured_cannot_be_ready_despite_bounded_gap_penalty(self):
        r=clean_user(True)
        for c in r['checks']:c['state']='unknown'
        r['profiles'][0].update(static_profile_checked=False,dynamic_profile_checked=False)
        a=assess(r)['surface_assessments']['web']
        self.assertFalse(a['technical_environment_ready'])
        self.assertEqual(a['coverage']['confirmed_faults'],0)

    def test_removing_all_eligibility_declarations_cannot_change_technical_decisions(self):
        r = clean_user(); r['user_declarations']['api_execution_mode'] = 'local_sdk_direct'
        before = assess(r)
        for k in ('physical_country', 'entity', 'eligibility_confirmed'):
            r['user_declarations'].pop(k, None)
        after = assess(r)
        for s in ('desktop', 'web', 'cli', 'api'):
            a, b = before['surface_assessments'][s], after['surface_assessments'][s]
            self.assertEqual((a['health_score'], a['technical_environment_ready']), (b['health_score'], b['technical_environment_ready']))
            self.assertNotIn('真实物理所在地', b['reason'])

    def test_declared_unsupported_country_is_not_technical_defect(self):
        r = clean_user(True); a = assess(r)
        r['user_declarations'].update(physical_country='CN', entity='unknown')
        b = assess(r)
        self.assertEqual(a['surface_assessments']['web']['health_score'], b['surface_assessments']['web']['health_score'])
        self.assertEqual(a['technical_environment_ready'], b['technical_environment_ready'])
        self.assertFalse(b['eligibility']['affects_technical_score'])

    def test_certificate_failure_decreases_health_and_blocks(self):
        r = clean_user(); before = assess(r)['surface_assessments']['desktop']
        r['program_context_v33']['desktop']['neutral_transport'] = {'certificate_fault': True}
        after = assess(r)['surface_assessments']['desktop']
        self.assertLess(after['health_score'], before['health_score'])
        self.assertLessEqual(after['health_score'], 25)
        self.assertFalse(after['technical_environment_ready'])
        self.assertIn('tls', after['confirmed_blockers'])

    def test_rule_reject_cannot_be_cancelled_by_other_passes(self):
        r = clean_user(True)
        r['path_evidence_v33']['web:chrome-profile-1'] = {'status':'verified_fault', 'fault_kind':'runtime_reject', 'reason':'明确拒绝'}
        a = assess(r)['surface_assessments']['web']
        self.assertFalse(a['technical_environment_ready']); self.assertLessEqual(a['health_score'], 25)

    def test_confirmed_hosts_block_reaches_all_local_clients(self):
        r=clean_user();r['user_declarations']['api_execution_mode']='local_sdk_direct'
        hosts=next(x for x in r['checks'] if x['id']=='hosts_block');hosts.update(state='fault',value=1)
        for s,a in assess(r)['surface_assessments'].items():
            self.assertFalse(a['technical_environment_ready'],s)
            self.assertIn('hosts',a['confirmed_blockers'])
            self.assertEqual(sum(row['weight'] for row in a['ledger']),100)

    def test_unknowns_are_capped_and_never_confirmed_faults(self):
        r = clean_user(); a = assess(r)['surface_assessments']['desktop']
        rows = copy.deepcopy(a['ledger'])
        for row in rows: row.update(state='unverified')
        out = evaluate(rows)
        self.assertEqual(out['health_score'], 80)
        self.assertEqual(out['coverage']['confirmed_faults'], 0)
        self.assertFalse(out['critical_confirmed_fault'])

    def test_direction_and_no_public_ambiguous_risk_field(self):
        self.assertEqual([grade(x) for x in (100, 85, 84, 70, 69, 50, 49, 0, None)], ['优良','优良','良好','良好','需关注','需关注','需优先整改','需优先整改','未评分'])
        for a in assess(clean_user())['surface_assessments'].values():
            self.assertNotIn('risk_index', a); self.assertNotIn('risk_level', a)

    def test_uninstalled_apps_and_sdk_do_not_reduce_health(self):
        r = clean_user(); r['user_declarations']['api_execution_mode'] = 'local_sdk_direct'
        a = assess(r)
        for s in ('desktop','cli'): r['program_context_v33'][s]['installed'] = True
        r['program_context_v33']['api']['configured'] = True
        b = assess(r)
        for s in ('desktop','web','cli','api'): self.assertEqual(a['surface_assessments'][s]['health_score'], b['surface_assessments'][s]['health_score'])

    def test_web_only_ignores_all_other_unmeasured_hosts(self):
        r = clean_user(True); r['program_context_v33']['api']['host_kind'] = 'remote'
        out = assess(r)
        self.assertTrue(out['technical_environment_ready'])
        self.assertIsNone(out['surface_assessments']['api']['health_score'])


class ApiExecution(unittest.TestCase):
    def test_gateway_and_api_only_cloud_keep_two_legs_distinct(self):
        r=clean_user();r['user_declarations'].update(surfaces=['api'],api_execution_mode='third_party_gateway')
        a=assess(r);api=a['surface_assessments']['api']
        self.assertEqual(api['actual_request_origin'],'gateway_upstream')
        self.assertIsNone(api['health_score'])
        self.assertEqual(a['ready_to_begin_setup'],api['local_client_readiness']['technical_environment_ready'])

    def test_five_platform_modes_are_explicit_not_brand_inferred(self):
        for brand, mode, actual in (
            ('WorkBuddy','local_agent_direct','local_windows'),
            ('WorkBuddy','agent_platform_cloud','platform_cloud'),
            ('Codex CLI','local_agent_direct','local_windows'),
            ('Codex Cloud','agent_platform_cloud','platform_cloud'),
            ('DSH','unknown','unknown')):
            r = clean_user(); r['user_declarations']['api_execution_mode'] = mode
            r['program_context_v33']['api'].update(host_kind='windows', brand=brand)
            self.assertEqual(classify(r)['actual_request_origin'], actual)
        r['user_declarations'].pop('api_execution_mode'); self.assertEqual(classify(r)['execution_mode'], 'unknown')

    def test_cloud_does_not_receive_local_score_as_api_score(self):
        r = clean_user(); r['user_declarations']['api_execution_mode'] = 'agent_platform_cloud'
        a = assess(r)['surface_assessments']['api']
        self.assertIsNone(a['health_score']); self.assertFalse(a['remote_api_path_observed'])
        self.assertIsNotNone(a['local_client_readiness']['health_score'])
        self.assertEqual(a['critical_missing_keys'], [])

    def test_no_claude_path_is_not_applicable(self):
        r = clean_user(); r['user_declarations']['api_execution_mode'] = 'platform_builtin_model'
        a = assess(r)['surface_assessments']['api']
        self.assertFalse(a['applicable']); self.assertIsNone(a['health_score'])
        self.assertEqual(a['recommend_now'], '不适用')


class RegionEvidence(unittest.TestCase):
    def test_browser_country_timezone_and_language_never_score_or_locate(self):
        r = clean_user(True); before = assess(r)
        r['browser_region_signals'] = {'windows':{'country':'US'}, 'devices':[{'country_values':{'variations_country':{'value':'cn'}}}]}
        r['profiles'][0]['dynamic_result'].setdefault('data', {}).update(languages=['zh-CN'],timezone='Asia/Shanghai')
        after = assess(r); loc = after['location_observability']
        self.assertEqual(before['surface_assessments']['web']['health_score'], after['surface_assessments']['web']['health_score'])
        self.assertFalse(loc['physical_location_independently_verified'])
        self.assertIsNone(loc['physical_location_estimate'])
        self.assertFalse(loc['local_only_hints'][-1]['website_directly_readable'])

    def test_exact_ip_geo_join_and_conflicts_keep_target_unknown(self):
        r = clean_user(); r['generic_probe_egress'] = [
            {'status':'observed','ip':'8.8.8.8','country_code':'US','target_host':'one'},
            {'status':'observed','ip':'8.8.8.8','country_code':'CA','target_host':'two'}]
        r['profiles'][0]['dynamic_result']['data']['independent_network']['ipv4'] = {'status':'observed','ip':'1.1.1.1'}
        loc = synthesize(r)
        self.assertEqual(len([c for c in loc['conflicts'] if c['kind']=='same_ip_geo_database_disagreement']), 1)
        browser = next(x for x in loc['network_egress_by_vantage'] if x.get('vantage','').endswith(':ipv4'))
        self.assertEqual(browser['countries'], [])
        self.assertTrue(all(x['target_country'] is None for x in loc['surface_region_summaries'].values()))


if __name__ == '__main__': unittest.main()
