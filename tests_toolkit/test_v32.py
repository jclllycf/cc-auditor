"""v3.2 风险归因、地区隐私、授权及历史兼容；使用合成文件，不读真实 Profile。"""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cc_auditor.toolkit import assess_v32 as model,region_v32 as region,preflight_v3 as core
from cc_auditor.toolkit.consent_v3 import Broker


def fixture():
    p={'browser_id':'chrome','browser_name':'Google Chrome','profile_key':'chrome-profile-1','profile_alias':'日常档案 1','version':'155.0.1.1','static_profile_checked':True,'dynamic_profile_checked':True,'actual_profile_verified':False,'profile_binding':'user_attested_targeted_launch_browser_pid','cleanup_status':'reported_clean','dynamic_result':{'data':{'features':{k:True for k in ('cookies','websocket','webassembly','workers','canvas_2d')},'languages':['en-US'],'request_accept_language':'en-US,en;q=0.9','timezone':'America/Denver','independent_network':{'stun':{'status':'observed'},'dns':{'status':'failed'},'ipv6':{'status':'failed'},'tls':{'status':'failed'}}}}}
    a={'scopes':['local_system','browser_static','browser_dynamic'],'profiles':['chrome-profile-1'],'user_declarations':{'surfaces':['web'],'primary_profile':'chrome-profile-1','cli_host':'windows','api_host':'unknown'}}
    return core.make_report('f'*32,a,local={'os_compatibility':{'desktop_compatible':True,'cli_compatible':True},'resources':{'cli_ram_sufficient':True,'disk_sufficient':True},'security_and_certificates':{'insecure_tls_env_enabled':False,'root_cert_count':100,'hosts_file':{'status':'observed','blocking_entries':0}}},profiles=[p],synthetic=True)


class Models(unittest.TestCase):
    def test_distinct_ledgers_and_immutable_input(self):
        r=fixture();old=copy.deepcopy(r);a=model.assess(r);self.assertEqual(r,old)
        signatures=[]
        for s in a['surface_assessments'].values():
            self.assertEqual(sum(x['weight'] for x in s['ledger']),100);self.assertEqual(s['risk_index_lower'],0);self.assertEqual(s['confirmed_faults'],[]);signatures.append(tuple((x['key'],x['weight']) for x in s['ledger']))
        self.assertEqual(len(set(signatures)),4)
    def test_target_changes_only_one_surface(self):
        r=fixture();before=model.assess(r)
        next(c for c in r['checks'] if c['id']=='target_egress_cli')['state']='passed';after=model.assess(r)
        for s in ('desktop','web','api'):self.assertEqual(before['surface_assessments'][s],after['surface_assessments'][s])
        self.assertLess(after['surface_assessments']['cli']['risk_index_upper'],before['surface_assessments']['cli']['risk_index_upper'])
    def test_web_failure_does_not_damage_desktop_or_api(self):
        r=fixture();before=model.assess(r)
        next(c for c in r['checks'] if c['id']=='chrome-profile-1_cookies')['state']='fault';after=model.assess(r)
        self.assertGreater(after['surface_assessments']['web']['risk_index_lower'],0)
        for s in ('desktop','cli','api'):self.assertEqual(before['surface_assessments'][s],after['surface_assessments'][s])
    def test_unknowns_are_not_faults_or_red(self):
        r=fixture()
        for c in r['checks']:c['state']='unknown'
        r['profiles']=[];a=model.assess(r)
        self.assertNotIn('基础可用',a['headline'])
        for s in a['surface_assessments'].values():self.assertEqual(s['risk_index_lower'],0);self.assertEqual(s['risk_level'],'amber')
    def test_google_cn_language_hk_and_processes_do_not_penalize(self):
        r=fixture();before=model.assess(r);r.update(browser_region_signals={'variations_country':'cn','gemini':True},generic_probe_egress=[{'country_code':'HK','vendor_score':99}])
        next(c for c in r['checks'] if c['id']=='locale')['value']={'language':'zh-CN','timezone':'Asia/Shanghai'}
        next(c for c in r['checks'] if c['id']=='claude_processes')['value']={'count':32}
        self.assertEqual(before,model.assess(r))
    def test_scanner_tls_fault_not_attributed_to_desktop_or_browser(self):
        r=fixture();before=model.assess(r);next(c for c in r['checks'] if c['id']=='tls_bypass')['state']='fault'
        self.assertEqual(before,model.assess(r))
    def test_remote_host_not_covered_by_local_target(self):
        r=fixture();r['user_declarations'].update(api_host='remote',cli_host='wsl')
        for c in r['checks']:c['state']='passed'
        a=model.assess(r)
        for s in ('api','cli'):
            self.assertEqual(a['surface_assessments'][s]['ledger'][0]['support'],0);self.assertIn(a['surface_assessments'][s]['execution_boundary'],('远程服务器','WSL'))
    def test_primary_profile_is_not_replaced_by_other_browser(self):
        r=fixture();p=copy.deepcopy(r['profiles'][0]);p.update(profile_key='edge-profile-1',browser_name='Edge',dynamic_profile_checked=False);r['profiles'].append(p)
        a=model.assess(r)['surface_assessments']['web'];self.assertEqual(a['selected_profile_keys'],['chrome-profile-1']);self.assertEqual(len(a['profiles']),2)
    def test_browser_stun_cannot_be_replaced_by_python_stun(self):
        r=fixture();r['profiles'][0]['dynamic_result']['data']['independent_network']['stun']['status']='failed';r['independent_network_events']=[{'kind':'python_udp_stun','status':'observed'}]
        a=model.assess(r)['surface_assessments']['web'];self.assertEqual(next(x for x in a['ledger'] if x['key']=='stun')['support'],0)
    def test_dedup_fault_and_missing_budgets(self):
        row=lambda k:dict(key=k,title=k,weight=50,state='fault',support=1,critical=True,issue_id='same',evidence_ids=[],positive='',detail='',action='')
        a=model._model('web',[row('a'),row('b')]);self.assertEqual(a['risk_index_lower'],50);self.assertEqual(a['risk_index_upper'],50)
    def test_fully_supported_ledger_can_be_low(self):
        row=dict(key='verified',title='合成完整证据',weight=100,state='observed',support=1,critical=True,issue_id='a',evidence_ids=['E001'],positive='完整',detail='',action='')
        a=model._model('desktop',[row]);self.assertEqual(a['risk_index'],0);self.assertEqual(a['risk_level'],'green');self.assertEqual(a['confidence'],'高')
    def test_cycle_is_not_complete_rule_evidence(self):
        r=fixture();r['target_routes']={'configs':[{'activation':'controller_rules_observed','runtime_rules':[{'target':{'surface':'web','process':'chrome.exe'},'status':'simulated','chain_state':'cycle'}]}]}
        a=model.assess(r)['surface_assessments']['web'];self.assertLess(next(x for x in a['ledger'] if x['key']=='rules')['support'],1)
    def test_chrome_api_snapshot_is_not_api_application_evidence(self):
        r=fixture();before=model.assess(r);r['target_routes']={'existing_connections':[{'process':'chrome.exe','host':'api.anthropic.com','rule_type':'DomainSuffix'}]};after=model.assess(r)
        self.assertEqual(before['surface_assessments']['api'],after['surface_assessments']['api']);self.assertEqual(before['surface_assessments']['cli'],after['surface_assessments']['cli']);self.assertLess(after['surface_assessments']['web']['risk_index_upper'],before['surface_assessments']['web']['risk_index_upper'])
    def test_missing_fields_do_not_promote_registration_payment(self):
        a=model.assess(fixture())
        for k in ('registration','payment'):self.assertEqual(a['usage_scenarios'][k]['feasibility_level'],'受真实资格条件约束')
        self.assertEqual(a['usage_scenarios']['registration']['sub_scenarios'][0]['region_lookup'],'未声明')
    def test_declared_supported_not_account_guarantee(self):
        r=fixture();r['user_declarations'].update(physical_country='US',entity='individual',payment_method='credit',issuer_country='US',billing_country='US',billing_matches_bank='yes')
        a=model.assess(r);self.assertIn('列入',a['usage_scenarios']['registration']['sub_scenarios'][0]['region_lookup']);self.assertEqual(a['usage_scenarios']['payment']['feasibility_level'],'受真实资格条件约束')
    def test_declared_payment_mismatch_not_measured_fault(self):
        r=fixture();r['user_declarations'].update(payment_method='paypal',issuer_country='JP',billing_country='US');a=model.assess(r)
        sub=a['usage_scenarios']['payment']['sub_scenarios'][0];self.assertEqual(sub['confirmed_blockers'],[]);self.assertGreaterEqual(len(sub['declared_conditions_to_resolve']),2)
    def test_declarations_strip_arbitrary_sensitive_text(self):
        raw={'surfaces':['api','SECRET'],'password':'SECRET','physical_country':'secret','issuer_country':'US','payment_method':'4111111111111111','primary_profile':'SECRET@example.com'}
        out=model.declarations(raw);self.assertNotIn('SECRET',json.dumps(out));self.assertNotIn('4111',json.dumps(out));self.assertEqual(out['issuer_country'],'US')


class Region(unittest.TestCase):
    def test_localstate_pair_seed_metadata_no_secret_export(self):
        raw={'variations_country':'cn','variations_permanent_consistency_country':['155.0.1.1','cn'],'variations_last_fetch_time':'13400000000000000','variations_compressed_seed':'SECRET_SEED','variations_google_groups':{'Default':['SECRET_GAIA']},'os_crypt':{'encrypted_key':'SECRET_KEY'},'variations_safe_seed_milestone':155}
        out=region.parse_local_state(raw,'155.0.1.1');self.assertEqual(out['permanent_consistency']['country'],'cn');self.assertTrue(out['permanent_consistency']['matches_executable_version']);self.assertNotIn('SECRET',json.dumps(out))
    def test_unexpected_pair_shape_does_not_guess_country(self):
        for value in ('cn',['cn'],['cn','155.1'],{'country':'cn'}):self.assertEqual(region.parse_local_state({'variations_permanent_consistency_country':value})['permanent_consistency']['status'],'unsupported_shape')
    def test_missing_keys_are_not_empty_success(self):
        out=region.parse_local_state({});self.assertEqual(out['country_values'],{});self.assertIsNone(out['permanent_consistency'])
    def test_device_dedup_and_per_profile_languages(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'Local State').write_text(json.dumps({'variations_country':'cn'}));records={}
            for n,lang in ((1,'en-US,en'),(2,'zh-CN,zh')):
                p=root/('Profile '+str(n));p.mkdir();(p/'Preferences').write_text(json.dumps({'intl':{'accept_languages':lang},'account_info':[{'email':'SECRET'}]}))
                records[str(n)]={'root':root,'path':p,'public':{'profile_key':'chrome-profile-'+str(n),'browser_name':'Chrome','engine':'Chromium','version':'155.0.1.1'}}
            with patch.object(region,'windows_region',return_value={'home_region_code':'US'}),patch.object(region,'managed_policies',return_value={}):out=region.collect(records)
            self.assertEqual(len(out['devices']),1);self.assertEqual(len(out['profiles']),2);self.assertNotIn('SECRET',json.dumps(out));self.assertNotEqual(out['profiles'][0]['accept_languages'],out['profiles'][1]['accept_languages'])
    def test_probe_visible_is_not_claude_received(self):
        r=fixture();reg={'windows':{'home_region_code':'US'},'devices':[{'country_values':{'variations_country':{'value':'cn'}}}],'profiles':[{'profile_key':'chrome-profile-1','accept_languages':['zh-CN']}]}
        out=region.attach_website(reg,r['profiles']);p=out['profiles'][0];self.assertEqual(p['website_observation']['claude_received_these_values'],'not_observed');self.assertEqual(p['language_comparison'],'observed_difference_reference_only');self.assertEqual(out['devices'][0]['windows_country_comparison'],'different_reference_only')
    def test_bounded_file_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'Local State';p.write_bytes(b'x'*20)
            with self.assertRaises(ValueError):region._json(p,10)


class ConsentAndContract(unittest.TestCase):
    def test_browser_region_requires_new_scope(self):
        b=Broker();m=b.prepare([],['local_system'])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':['browser_region'],'profiles':[]}),self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
    def test_primary_profile_must_exist_in_manifest(self):
        b=Broker();m=b.prepare([])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':[],'profiles':[],'declarations':{'primary_profile':'chrome-profile-9'}}),self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
    def test_new_json_contains_same_pure_assessment(self):
        r=fixture();a=model.assess(r)
        self.assertEqual(r['surface_assessments'],a['surface_assessments']);self.assertEqual(r['usage_scenarios'],a['usage_scenarios'])
        self.assertEqual(r['summary'],core.summarize(r))

if __name__=='__main__':unittest.main()
