"""v3.3 确定决策、证据归因、授权和条件报告；仅合成样本。"""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from decimal import Decimal
from tests_toolkit.test_v32 import fixture as old_fixture
from cc_auditor.toolkit import fixed_risk_v33 as m,evidence_completion_v33 as ec,program_context_v33 as pc,route_refinement_v33 as rr
from cc_auditor.toolkit.proxy_adapters import simulate
from cc_auditor.toolkit.consent_v3 import Broker

def fixture():
    r=old_fixture();r['version']='3.4.0-rc2';r['user_declarations'].update(physical_country='US',entity='individual',plan_daily=True,plan_registration=False,plan_payment=False)
    p=r['profiles'][0];p['extension_count']=0
    p['dynamic_result']['data']['independent_network'].update(ipv4={'status':'observed','ip':'1.1.1.1'},dns={'status':'observed','resolver_ips':['8.8.8.8']},ipv6={'status':'observed','ip':'2606:4700:4700::1111'})
    r['program_context_v33']={'status':'observed','desktop':{'installed':True,'status':'observed','neutral_transport':{'status':'observed','tls_verified':True}},'cli':{'status':'observed','installed':True,'host_bound':True,'shell_ready':True,'host_kind':'windows','neutral_transport':{'status':'observed','tls_verified':True}},'api':{'status':'observed','configured':True,'host_bound':True,'host_kind':'python','neutral_transport':{'status':'observed','tls_verified':True}},'browser_flags':{'chrome':{'status':'observed','ignore_certificate_errors':False,'explicit_proxy_override_present':False}}}
    r['path_evidence_v33']={k:{'status':'passed','minimum_verified':True,'proof_basis':'runtime_rule_and_neutral_same_chain'} for k in ('desktop','cli','api','web:chrome-profile-1')}
    r['independent_network_events']=[{'kind':'system_authoritative_dns','status':'observed'}]
    return r

class FixedModels(unittest.TestCase):
    def test_known_policy_block_does_not_generate_evidence_request(self):
        r=fixture();r['user_declarations']['physical_country']='CN';self.assertFalse(m.assess(r)['recommend_now']);self.assertEqual(ec.remaining_gaps(r),[])
    def test_known_payment_block_is_not_missing_evidence(self):
        r=fixture();r['user_declarations'].update(plan_payment=True,payment_method='paypal',issuer_country='US',billing_country='US',three_ds='yes',billing_matches_bank='yes');self.assertFalse(m.assess(r)['usage_scenarios']['payment']['recommend_now']);self.assertEqual(ec.remaining_gaps(r),[])
    def test_unbound_future_local_program_uses_system_dns_preuse_baseline(self):
        r=fixture();r['program_context_v33']['api']['host_bound']=False;a=m.assess(r)['surface_assessments']['api'];self.assertEqual(next(x for x in a['ledger'] if x['key']=='dns')['state'],'passed')
    def test_plain_explanation_preserves_numeric_decision_and_names_rule(self):
        from cc_auditor.toolkit.plain_decisions_v33 import assess
        r=fixture();r['path_evidence_v33']['web:chrome-profile-1']={'status':'partial','reason':'technical','simulations':[{'status':'unverified','rule_index':2,'rule_type':'IPCIDR'}]};plain=assess(r);technical=m.assess(r)
        for s in m.SURFACES:self.assertEqual(plain['surface_assessments'][s]['risk_index'],technical['surface_assessments'][s]['risk_index']);self.assertEqual(plain['surface_assessments'][s]['recommend_use'],technical['surface_assessments'][s]['recommend_use'])
        self.assertIn('第3条',plain['surface_assessments']['web']['reason'])
    def test_sufficient_evidence_advises_yes_without_claude_contact(self):
        r=fixture();a=m.assess(r);self.assertTrue(a['surface_assessments']['web']['recommend_use']);self.assertEqual(a['surface_assessments']['web']['risk_index'],0);self.assertTrue(a['recommend_now']);self.assertEqual(ec.remaining_gaps(r),[])
    def test_unknown_final_exit_does_not_permanently_gate(self):
        r=fixture();self.assertTrue(all(c['state']=='unknown' for c in r['checks'] if c['id'].startswith('target_egress')));self.assertTrue(m.assess(r)['recommend_now'])
    def test_input_immutable_and_independent_weights(self):
        r=fixture();before=copy.deepcopy(r);a=m.assess(r);self.assertEqual(before,r);self.assertEqual(len({tuple((x['key'],x['weight']) for x in v['ledger']) for v in a['surface_assessments'].values()}),4)
        for v in a['surface_assessments'].values():self.assertEqual(sum(x['weight'] for x in v['ledger']),100);self.assertIsInstance(v['risk_index'],int)
    def test_confirmed_cert_fault_critical_floor(self):
        r=fixture();r['program_context_v33']['browser_flags']['chrome']['ignore_certificate_errors']=True;a=m.assess(r)['surface_assessments']['web'];self.assertFalse(a['recommend_use']);self.assertGreaterEqual(a['risk_index'],75);self.assertGreater(Decimal(a['confirmed_fault_contribution']),0)
    def test_other_profile_unsafe_flags_do_not_override_bound_profile(self):
        r=fixture();r['program_context_v33']['browser_flags']['chrome']['ignore_certificate_errors']=True;r['program_context_v33']['profile_flags']={'chrome-profile-1':{'status':'observed','ignore_certificate_errors':False}};self.assertTrue(m.assess(r)['surface_assessments']['web']['recommend_use'])
    def test_missing_dns_is_not_confirmed_fault(self):
        r=fixture();r['profiles'][0]['dynamic_result']['data']['independent_network']['dns']={'status':'failed'};a=m.assess(r)['surface_assessments']['web'];self.assertTrue(a['recommend_use']);self.assertIn('dns',a['critical_missing_keys']);self.assertEqual(a['confirmed_fault_contribution'],'0.000000');self.assertEqual(a['risk_index'],6)
    def test_not_configured_specific_condition(self):
        r=fixture();r['program_context_v33']['api'].update(configured=False);a=m.assess(r)['surface_assessments']['api'];self.assertTrue(a['recommend_use']);self.assertEqual(a['ledger'][0]['state'],'not_applicable');self.assertEqual(a['installation_state'],'not_installed');self.assertEqual(Decimal(a['missing_condition_contribution']),0)
    def test_process_language_google_region_and_generic_hk_do_not_add_risk(self):
        r=fixture();before=m.assess(r);r.update(generic_probe_egress=[{'ip':'1.1.1.1','country_code':'HK'}],browser_region_signals={'variations_country':'cn','language':'zh-CN'})
        next(c for c in r['checks'] if c['id']=='claude_processes')['value']={'count':999};self.assertEqual(before,m.assess(r))
    def test_unselected_edge_failure_does_not_spoil_primary_chrome(self):
        r=fixture();p=copy.deepcopy(r['profiles'][0]);p.update(profile_key='edge-profile-1',browser_id='edge',browser_name='Edge',dynamic_profile_checked=False);r['profiles'].append(p);self.assertTrue(m.assess(r)['surface_assessments']['web']['recommend_use'])
    def test_policy_separate_from_index(self):
        r=fixture();before=m.assess(r)['surface_assessments']['web']['risk_index'];r['user_declarations']['physical_country']='CN';a=m.assess(r)['surface_assessments']['web'];self.assertEqual(a['risk_index'],before);self.assertFalse(a['recommend_use']);self.assertIn('名单',a['reason'])
    def test_registration_only_consumer_when_api_not_selected(self):
        r=fixture();r['user_declarations']['plan_registration']=True;a=m.assess(r)['usage_scenarios']['registration'];self.assertTrue(a['recommend_now']);self.assertEqual(len(a['sub_scenarios']),1)
    def test_payment_explicit_categories_can_be_ready(self):
        r=fixture();r['user_declarations'].update(plan_payment=True,payment_method='credit',issuer_country='US',billing_country='US',three_ds='yes',billing_matches_bank='yes');self.assertTrue(m.assess(r)['usage_scenarios']['payment']['recommend_now'])
    def test_unplanned_payment_does_not_create_checklist(self):
        r=fixture();self.assertEqual(ec.remaining_gaps(r),[])
    def test_attach_exposes_fixed_contract_and_remains_bounded(self):
        from cc_auditor.storage import bounded
        r=fixture();ec.attach(r,r['program_context_v33'],attempts=[]);bounded(r);self.assertEqual(r['model_version'],'3.4.preuse.4');self.assertIn('risk_index',r['surface_assessments']['web']);self.assertNotIn('risk_index_upper',r['surface_assessments']['web'])
    def test_console_can_be_ready_without_permanent_server_gate(self):
        r=fixture();r['user_declarations'].update(surfaces=['api'],plan_registration=True);r['path_evidence_v33']['registration_console']={'minimum_verified':True};a=m.assess(r)['usage_scenarios']['registration'];self.assertTrue(a['recommend_now']);self.assertEqual(a['sub_scenarios'][0]['id'],'console')
    def test_active_ipv6_is_minimum_and_missing_is_not_fault(self):
        r=fixture();c=next(x for x in r['checks'] if x['id']=='routes_ok');c.update(state='reference',value={'system_has_ipv6_default_route':True});r['profiles'][0]['dynamic_result']['data']['independent_network']['ipv6']={'status':'failed'};a=m.assess(r)['surface_assessments']['web'];self.assertTrue(a['recommend_use']);self.assertIn('ipv6',a['critical_missing_keys']);self.assertEqual(a['confirmed_fault_contribution'],'0.000000')
    def test_ledger_recomputable(self):
        a=m.assess(fixture())['surface_assessments']['api'];self.assertEqual(a['risk_index'],m.round_index(sum((Decimal(x['contribution']) for x in a['ledger']),Decimal(0))))
    def test_half_up_na_renormalization_and_dedup(self):
        row=lambda w,st,c:dict(weight=w,state=st,root_cause=c,critical_fault=False)
        a=m.evaluate_ledger([row(10,'not_applicable','na'),row(45,'unverified','same'),row(45,'unverified','same')]);self.assertEqual(a['risk_index'],28);self.assertEqual(a['applicable_weight'],90)
    def test_positive_data_changes_index_not_old_range_midpoint(self):
        r=fixture();a=m.assess(r)['surface_assessments']['web'];del r['path_evidence_v33'];b=m.assess(r)['surface_assessments']['web'];self.assertLess(a['risk_index'],b['risk_index'])

class Safety(unittest.TestCase):
    def test_ipv6_runtime_scripts_keep_host_validation_and_pinned_family(self):
        observed=json.dumps({'status':'observed','tls_verified':True,'ip':'2606:4700:4700::1111'})
        with patch.object(pc,'receiver_address',return_value='2606:4700:4700::1111'),patch.object(pc,'_run',return_value=(0,observed)) as run:
            self.assertEqual(pc.windows_transport(False,6)['status'],'observed');self.assertIn('InterNetworkV6',run.call_args.args[0][-1]);self.assertIn('api6.ipify.org',run.call_args.args[0][-1]);self.assertNotIn('api4.ipify.org',run.call_args.args[0][-1])
            self.assertEqual(pc.node_transport('node.exe',family=6)['status'],'observed');self.assertIn('family:6',run.call_args.args[0][-1]);self.assertIn('rejectUnauthorized:true',run.call_args.args[0][-1])
            self.assertEqual(pc.python_transport('python.exe',family=6)['status'],'observed');self.assertIn('socket.AF_INET6',run.call_args.args[0][-1]);self.assertIn('server_hostname=',run.call_args.args[0][-1])
    def test_echo_family_mismatch_does_not_complete_ipv6(self):
        from cc_auditor.toolkit.deep_network_v31 import sanitize_browser
        self.assertEqual(sanitize_browser({'ipv6':{'status':'observed','ip':'1.1.1.1'}})['ipv6']['status'],'failed')
    def test_mixed_kernels_and_unattributed_reject_do_not_claim_fault(self):
        from types import SimpleNamespace
        r=fixture();r['approval']['scopes']=['proxy_config','independent_network'];runtime=SimpleNamespace(alias=lambda x:x,v33_controllers={'b':{'config':{'rules':['MATCH,REJECT']},'tun_enabled':True,'core':'mihomo','kernel_pids':[10],'get':lambda _: {'connections':[]}}})
        discovery={'status':'observed','software':[{'pid':10,'role':'core','family':'mihomo','running':True},{'pid':11,'role':'core','family':'xray','running':True}]};out=rr.refine(r,{'query_flags':{'routes_ok':True,'adapters_ok':True,'proxy_registry_ok':True},'vpn_and_tun_topology':{'tun_owns_ipv4_default_route':True}},discovery,runtime,{})
        self.assertEqual(out['web:chrome-profile-1']['status'],'partial');self.assertFalse(out['web:chrome-profile-1']['minimum_verified'])
    def test_same_runtime_tun_chain_can_complete_preflight(self):
        from types import SimpleNamespace
        r=fixture();runtime=SimpleNamespace(alias=lambda x:x,v33_controllers={'binding':{'config':{'rules':['MATCH,DIRECT']},'tun_enabled':True,'core':'mihomo','kernel_pids':[10],'get':lambda _: {'connections':[]}}})
        r['approval']['scopes']=['proxy_config','independent_network'];r['program_context_v33']['proxy_markers']={}
        out=rr.refine(r,{'query_flags':{'routes_ok':True,'adapters_ok':True,'proxy_registry_ok':True},'proxy_configuration':{'wpad_auto_detect':False},'vpn_and_tun_topology':{'tun_owns_ipv4_default_route':True}}, {'status':'observed','software':[{'pid':10,'role':'core','family':'mihomo','running':True}]},runtime,{})
        self.assertTrue(out['web:chrome-profile-1']['minimum_verified']);self.assertIsNone(out['web:chrome-profile-1']['final_claude_public_egress'])
    def test_generic_success_cannot_replace_missing_browser_neutral(self):
        from types import SimpleNamespace
        r=fixture();r['profiles'][0]['dynamic_result']['data']['independent_network']['ipv4']={'status':'failed'};r['approval']['scopes']=['proxy_config','independent_network'];r['generic_probe_egress']=[{'status':'observed','country_code':'US'}]
        runtime=SimpleNamespace(alias=lambda x:x,v33_controllers={'binding':{'config':{'rules':['MATCH,DIRECT']},'tun_enabled':True,'core':'mihomo','kernel_pids':[10],'get':lambda _: {'connections':[]}}})
        out=rr.refine(r,{'query_flags':{'routes_ok':True,'adapters_ok':True,'proxy_registry_ok':True},'vpn_and_tun_topology':{'tun_owns_ipv4_default_route':True}}, {'status':'observed','software':[{'pid':10,'role':'core','family':'mihomo','running':True}]},runtime,{})
        self.assertFalse(out['web:chrome-profile-1']['minimum_verified'])
    def test_retry_trace_retains_first_failure_and_does_not_lose_prior_success(self):
        r=fixture();p=r['profiles'][0];p['dynamic_result']['data']['independent_network']['dns']={'status':'failed'};r['approval']['scopes']=['browser_dynamic','independent_network']
        p['dynamic_result']['data']['independent_network'].update(scope='real_profile_tool_origin_only',actual_claude_path=False)
        d=copy.deepcopy(p['dynamic_result']);d.update(status='observed',dynamic_profile_checked=True,profile_binding=p['profile_binding']);d['data']['independent_network']['dns']={'status':'observed','resolver_ips':['8.8.8.8']};d['data']['independent_network']['ipv4']={'status':'failed'}
        with patch('cc_auditor.toolkit.profiles_v3.dynamic_profile',return_value=d):
            out=ec.complete(r,{},None,None,r['program_context_v33'],{},{p['profile_key']:{'public':{}}})
        p=out['profiles'][0];self.assertEqual(p['dynamic_result']['data']['independent_network']['dns']['status'],'observed');self.assertEqual(p['dynamic_result']['data']['independent_network']['ipv4']['status'],'observed');self.assertEqual(p['v33_attempt_history'][0]['result']['data']['independent_network']['dns']['status'],'failed');self.assertEqual(p['dynamic_result']['independent_network_source_attempts']['ipv4'],1)
    def test_bounded_failure_does_not_export_exception_secrets(self):
        r=fixture();r['approval']['scopes']=['program_context','independent_network'];r['approval']['profiles']=[]
        with patch.object(pc,'proxy_markers',return_value={}),patch.object(pc,'windows_transport',side_effect=TimeoutError('private-secret-path')):
            out=ec.complete(r,{},None,None,r['program_context_v33'],{},{});trace=out['evidence_completion_v33'];self.assertNotIn('private-secret-path',json.dumps(trace));self.assertEqual(trace['attempts'][0]['error_class'],'TimeoutError')
    def test_scope_refusal_no_network_or_program_callbacks(self):
        r=old_fixture();r['approval'].update(scopes=[],profiles=[])
        with patch.object(pc,'windows_transport') as probe,patch.object(pc,'proxy_markers') as markers,patch.object(rr,'refine') as refine:
            ec.complete(r,{},None,None,{'status':'permission'},{},{})
            probe.assert_not_called();markers.assert_not_called();refine.assert_not_called()
    def test_cancellation_no_collector(self):
        r=fixture()
        with patch.object(pc,'proxy_markers') as collect:
            result=ec.complete(r,{},None,None,{}, {},{},lambda:True);collect.assert_not_called();self.assertTrue(result['evidence_completion_v33']['cancelled'])
    def test_project_metadata_does_not_export_secret_or_other_dependency(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'package.json').write_text(json.dumps({'name':'private-project-name','dependencies':{'@anthropic-ai/sdk':'1.2.3','private-secret-name':'token-test-private'}}),encoding='utf-8');(p/'.env').write_text('ANTHROPIC_API_KEY=do-not-read',encoding='utf-8');out,_=pc.inspect_project(p);s=json.dumps(out);self.assertNotIn('private',s.replace('private_project_code_read',''));self.assertNotIn('do-not-read',s);self.assertTrue(out['sdk_declared']);self.assertFalse(out['configured'])
    def test_private_directory_not_returned_in_approval(self):
        b=Broker();manifest=b.prepare([],['program_context'])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':['program_context'],'profiles':[],'private_options':{'api_project':'D:/private-project'}}):out=b.approve_and_consume(manifest['scan_id'])
        self.assertNotIn('private-project',json.dumps(out));self.assertEqual(b.take_private_options(manifest['scan_id']),{'api_project':'D:/private-project'});self.assertEqual(b.take_private_options(manifest['scan_id']),{})
    def test_real_destination_ip_can_resolve_prior_ip_rule(self):
        t=dict(surface='web',host='claude.ai',process='chrome.exe',process_path='',port=443,network='tcp');c={'rules':['IP-CIDR,10.0.0.0/8,DIRECT','DOMAIN,claude.ai,REJECT']}
        self.assertEqual(simulate(c,t)['status'],'unverified');self.assertEqual(simulate(c,{**t,'destination_ip':'1.1.1.1'})['configured_chain'],['REJECT']);self.assertEqual(simulate(c,{**t,'destination_ip':'198.18.0.1'})['status'],'unverified')
    def test_fake_ipv6_does_not_enable_rule_skip(self):
        t=dict(surface='web',host='claude.ai',process='chrome.exe',process_path='',port=443,network='tcp',destination_ip='2001:2::1');self.assertEqual(simulate({'rules':['IP-CIDR6,::/0,DIRECT','MATCH,REJECT']},t)['status'],'unverified')

if __name__=='__main__':unittest.main()
