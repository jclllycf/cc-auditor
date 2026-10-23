"""v3.4 clean pre-use regression. All inputs are synthetic; no network or Claude calls."""
import copy
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from tests_toolkit.test_v33 import fixture
from cc_auditor.toolkit import fixed_risk_v33 as model
from cc_auditor.toolkit import evidence_completion_v33 as completion
from cc_auditor.toolkit import route_refinement_v33 as refinement
from cc_auditor.toolkit.proxy_adapters import simulate_symbolic


def clean_user(web_only=False):
    report=fixture()
    report['synthetic']=True
    report['user_declarations']['surfaces']=['web'] if web_only else ['desktop','web','cli','api']
    context=report['program_context_v33']
    context['desktop'].update(installed=False,process_observed=False)
    context['cli'].update(installed=False,candidate_count=0,host_bound=False,neutral_transport={})
    context['api'].update(configured=False,project_selected=False,host_bound=False,neutral_transport={})
    report['path_evidence_v33']={}
    report['target_routes']={'configs':[]}
    for check in report['checks']:
        if check['id']=='claude_processes':check['value']={'count':0}
    return report


def target():
    return {'surface':'web','host':'claude.ai','process':'chrome.exe','process_path':'',
            'port':443,'network':'tcp'}


class FirstTimeUser(unittest.TestCase):
    def test_missing_selected_container_is_explained_as_environment_not_proxy(self):
        from cc_auditor.toolkit.plain_decisions_v33 import assess
        report=clean_user();report['program_context_v33']['api'].update(host_kind='container',preuse_host_bound=False)
        a=assess(report)['surface_assessments']['api']
        self.assertFalse(a['ready_to_begin_setup'])
        self.assertIn('所选特殊环境',a['reason'])
        self.assertNotIn('代理路径依据',a['reason'])
        self.assertEqual(a['confirmed_fault_contribution'],'0.000000')

    def test_policy_obstacle_is_not_disguised_as_a_technical_route_failure(self):
        from cc_auditor.toolkit.plain_decisions_v33 import assess
        report=clean_user(web_only=True)
        report['user_declarations']['physical_country']='CN'
        report['path_evidence_v33']['web:chrome-profile-1']={'status':'partial','simulations':[
            {'status':'unverified','rule_type':'IP-CIDR','rule_index':2}]}
        a=assess(report)['surface_assessments']['web']
        self.assertFalse(a['recommend_use'])
        self.assertIn('官方支持名单',a['reason'])
        self.assertNotIn('第3条',a['reason'])
        self.assertEqual(a['confirmed_fault_contribution'],'0.000000')

    def test_no_desktop_cli_api_or_claude_connections_is_not_a_fault(self):
        report=clean_user()
        outcomes=model.assess(report)
        self.assertTrue(outcomes['ready_to_begin_setup'])
        for name,assessment in outcomes['surface_assessments'].items():
            self.assertTrue(assessment['ready_to_begin_setup'],name)
            self.assertFalse(assessment['already_operational'],name)
            self.assertEqual(assessment['operational_verification'],'not_tested_zero_anthropic_contact')
            self.assertEqual(assessment['confirmed_fault_contribution'],'0.000000')
            for row in assessment['ledger']:
                if row['evidence_lifecycle']=='future_setup':
                    self.assertEqual(row['state'],'not_applicable')
                    self.assertEqual(float(row['contribution']),0)

    def test_removing_installed_claude_only_does_not_change_any_score(self):
        baseline=fixture();before=model.assess(baseline)
        cleaned=copy.deepcopy(baseline)
        cleaned['program_context_v33']['desktop']['installed']=False
        cleaned['program_context_v33']['cli']['installed']=False
        cleaned['program_context_v33']['api']['configured']=False
        cleaned['checks']=[r for r in cleaned['checks'] if r['id']!='claude_processes']
        for name in ('desktop','web','cli','api'):
            a=before['surface_assessments'][name];b=model.assess(cleaned)['surface_assessments'][name]
            self.assertEqual(a['risk_index'],b['risk_index'],name)
            self.assertEqual(a['ready_to_begin_setup'],b['ready_to_begin_setup'],name)

    def test_web_only_not_affected_by_other_apps_or_other_profiles(self):
        report=clean_user(web_only=True);base=model.assess(report)
        report['program_context_v33']['cli']['installed']=True
        report['program_context_v33']['desktop']['installed']=True
        report['program_context_v33']['api']['configured']=True
        self.assertEqual(base['recommend_now'],model.assess(report)['recommend_now'])
        self.assertEqual(base['surface_assessments']['web']['risk_index'],model.assess(report)['surface_assessments']['web']['risk_index'])

    def test_no_installed_clients_in_third_pdf_checklist(self):
        report=clean_user()
        gaps=completion.remaining_gaps(report)
        self.assertFalse(any(x['claim'] in ('desktop.availability','cli.availability','api.application','api.runtime') for x in gaps))
        self.assertTrue(all(x['evidence_lifecycle']=='preuse_environment' for x in gaps if 'evidence_lifecycle' in x))

    def test_unbound_future_remote_host_cannot_borrow_windows_dns(self):
        report=clean_user();report['program_context_v33']['api'].update(host_kind='remote',host_bound=False)
        report['program_context_v33']['cli'].update(host_kind='wsl',host_bound=False)
        for name in ('api','cli'):
            rows=model.assess(report)['surface_assessments'][name]['ledger']
            self.assertEqual(next(r['state'] for r in rows if r['key']=='dns'),'unverified')
            self.assertNotEqual(next(r['state'] for r in rows if r['key']=='tls'),'passed')
            a=model.assess(report)['surface_assessments'][name]
            self.assertFalse(a['environment_ready'])
            self.assertEqual(a['confirmed_fault_contribution'],'0.000000')

    def test_observed_subsystem_environment_does_not_require_claude_or_sdk(self):
        from cc_auditor.toolkit.program_context_v33 import bind_preuse_environments
        report=clean_user();report['user_declarations'].update(cli_host='wsl',api_host='wsl')
        out=report['program_context_v33'];private={}
        subs={'wsl':{'status':'observed','running_candidates':[{'alias':'WSL-1','running_at_discovery':True,'metadata_checked':True,'shell_ready':True,'cli_present':False,'python_present':True}]}}
        bind_preuse_environments(out,private,report['user_declarations'],subs,{'WSL-1':{'prefix':['wsl.exe','--exec']}})
        for surface in ('cli','api'):
            self.assertTrue(out[surface]['preuse_host_bound'])
            self.assertIn(surface+'_subsystem',private)
            out[surface]['neutral_transport']={'status':'observed','tls_verified':True}
            out[surface]['neutral_dns']={'status':'observed'}
            a=model.assess(report)['surface_assessments'][surface]
            self.assertTrue(a['ready_to_begin_setup'],surface)
            self.assertEqual(a['installation_state'],'not_installed')

    def test_multiple_running_environments_are_not_silently_bound(self):
        from cc_auditor.toolkit.program_context_v33 import bind_preuse_environments
        out={'cli':{},'api':{}};row={'running_at_discovery':True,'metadata_checked':True,'shell_ready':True,'cli_present':False}
        subs={'containers':{'status':'observed','candidates':[{**row,'alias':'容器-1'},{**row,'alias':'容器-2'}]}}
        bind_preuse_environments(out,{}, {'cli_host':'container','api_host':'container'},subs,{})
        self.assertFalse(out['cli']['preuse_host_bound'])
        self.assertFalse(out['api']['preuse_host_bound'])
        self.assertIsNone(out['cli']['shell_ready'])

    def test_system_tls_can_complete_preuse_without_future_runtime(self):
        report=clean_user()
        report['program_context_v33']['desktop']['neutral_transport']={'tls_verified':True}
        for name in ('cli','api'):
            report['program_context_v33'][name].update(host_kind='windows',host_bound=False,neutral_transport={})
            row=next(r for r in model.assess(report)['surface_assessments'][name]['ledger'] if r['key']=='tls')
            self.assertEqual(row['state'],'passed',name)
            self.assertIn('系统 TLS 使用前基础',row['title'])
            self.assertIn('业务请求未测试',row['positive'])
        report['program_context_v33']['api']['neutral_transport']={'tls_verified':True}
        report['program_context_v33']['api']['host_bound']=True
        api_tls=next(r for r in model.assess(report)['surface_assessments']['api']['ledger'] if r['key']=='tls')
        self.assertEqual(api_tls['state'],'passed')
        self.assertIn('候选宿主',api_tls['title'])
        self.assertIn('SDK 业务请求未测试',api_tls['positive'])

    def test_client_and_binding_removal_preserves_measured_local_environment(self):
        original=fixture();before=model.assess(original)
        report=clean_user()
        # Compare the same pre-use route facts; optional installed-host TLS
        # and binding disappear, while the Windows baseline remains measured.
        report['path_evidence_v33']=copy.deepcopy(original['path_evidence_v33'])
        for surface in ('desktop','cli','api'):
            a=before['surface_assessments'][surface]
            b=model.assess(report)['surface_assessments'][surface]
            self.assertEqual(a['risk_index'],b['risk_index'],surface)
            self.assertEqual(a['ready_to_begin_setup'],b['ready_to_begin_setup'],surface)

    def test_system_certificate_fault_blocks_uninstalled_clients(self):
        report=clean_user()
        report['program_context_v33']['desktop']['neutral_transport']={'certificate_fault':True}
        for surface in ('desktop','cli','api'):
            a=model.assess(report)['surface_assessments'][surface]
            self.assertFalse(a['ready_to_begin_setup'],surface)
            self.assertGreaterEqual(a['risk_index'],75,surface)

    def test_registration_and_billing_future_requirements_do_not_make_scan_gaps(self):
        report=clean_user(web_only=True)
        report['user_declarations'].update(plan_registration=True,plan_payment=True,payment_method='unknown')
        report['path_evidence_v33']['registration_console']={'status':'unverified'}
        report['approval']['scopes']=['native_declaration','browser_dynamic','proxy_config','independent_network']
        gaps=completion.remaining_gaps(report)
        self.assertFalse(any(g['claim'].startswith(('registration.','payment.')) for g in gaps))
        self.assertEqual(len({g['claim'] for g in gaps}),len(gaps))

    def test_missing_independent_measurement_is_not_confirmed_failure(self):
        report=clean_user();report['profiles'][0]['dynamic_result']['data']['independent_network']['dns']={'status':'failed'}
        a=model.assess(report)['surface_assessments']['web']
        self.assertEqual(a['confirmed_fault_contribution'],'0.000000')
        self.assertIn('dns',a['critical_missing_keys'])

    def test_browser_certificate_bypass_is_confirmed_problem(self):
        report=clean_user();report['program_context_v33']['browser_flags']['chrome']['ignore_certificate_errors']=True
        a=model.assess(report)['surface_assessments']['web']
        self.assertGreaterEqual(a['risk_index'],75)
        self.assertFalse(a['ready_to_begin_setup'])


class OfflineRouteBranches(unittest.TestCase):
    def test_pass_continues_instead_of_inventing_a_pass_outbound(self):
        for first in ('DOMAIN,claude.ai,PASS','IP-CIDR,203.0.113.0/24,PASS','DOMAIN,claude.ai,PASS-RULE'):
            result=simulate_symbolic({'rules':[first,'MATCH,REJECT']},target())
            self.assertTrue(result['symbolic_consistent'])
            self.assertEqual(result['configured_chain'],['REJECT'])

    def test_xray_blackhole_is_a_configured_reject(self):
        cfg={'routing':{'rules':[{'domain':['full:claude.ai'],'outboundTag':'blocked'}]},
             'outbounds':[{'tag':'blocked','protocol':'blackhole'}]}
        self.assertEqual(simulate_symbolic(cfg,target())['configured_chain'][-1],'REJECT')

    def test_mihomo_chained_dialer_and_cycle(self):
        cfg={'rules':['MATCH,outer'],'proxies':[{'name':'outer','type':'socks5','dialer-proxy':'inner'},
                                               {'name':'inner','type':'socks5'}]}
        a=simulate_symbolic(cfg,target());self.assertEqual(a['configured_chain'],['outer','inner'])
        self.assertTrue(a['symbolic_consistent'])
        cfg['proxies'][1]['dialer-proxy']='outer'
        self.assertFalse(simulate_symbolic(cfg,target())['symbolic_consistent'])

    def test_xray_proxy_settings_chain(self):
        cfg={'routing':{'rules':[{'domain':['full:claude.ai'],'outboundTag':'outer'}]},
             'outbounds':[{'tag':'outer','protocol':'socks','proxySettings':{'tag':'inner'}},
                          {'tag':'inner','protocol':'freedom'}]}
        self.assertEqual(simulate_symbolic(cfg,target())['configured_chain'],['outer','inner'])

    def test_unknown_ip_cidr_converges_without_destination_ip(self):
        cfg={'rules':['IP-CIDR,203.0.113.0/24,DIRECT','DOMAIN,claude.ai,DIRECT','MATCH,REJECT']}
        result=simulate_symbolic(cfg,target())
        self.assertTrue(result['symbolic_consistent'])
        self.assertEqual(result['configured_chain'],['DIRECT'])
        self.assertEqual(result['branch_count'],2)

    def test_unknown_ip_cidr_diverges_without_guessing(self):
        cfg={'rules':['IP-CIDR,203.0.113.0/24,REJECT','DOMAIN,claude.ai,DIRECT','MATCH,REJECT']}
        result=simulate_symbolic(cfg,target())
        self.assertFalse(result['symbolic_consistent'])
        self.assertEqual(result['status'],'unverified')

    def test_unavailable_remote_ruleset_remains_unknown(self):
        cfg={'rules':['RULE-SET,unknown-remote,REJECT','MATCH,DIRECT']}
        result=simulate_symbolic(cfg,target())
        self.assertFalse(result['symbolic_consistent'])

    def test_future_process_condition_remains_conditional(self):
        cfg={'rules':['PROCESS-NAME,claude.exe,REJECT','MATCH,DIRECT']}
        result=simulate_symbolic(cfg,{**target(),'process':''})
        self.assertFalse(result['symbolic_consistent'])

    def test_confirmed_reject_rule_simulates_without_client(self):
        result=simulate_symbolic({'rules':['DOMAIN,claude.ai,REJECT','MATCH,DIRECT']},target())
        self.assertEqual(result['configured_chain'],['REJECT'])
        self.assertTrue(result['symbolic_consistent'])

    def test_xray_rule_branch_converges(self):
        cfg={'routing':{'rules':[{'type':'field','ip':['geoip:private'],'outboundTag':'direct'},
                                 {'type':'field','domain':['full:claude.ai'],'outboundTag':'direct'}]},
             'outbounds':[{'tag':'direct','protocol':'freedom'}]}
        self.assertTrue(simulate_symbolic(cfg,target())['symbolic_consistent'])

    def test_xray_balancer_remains_unknown(self):
        cfg={'routing':{'rules':[{'type':'field','domain':['full:claude.ai'],'balancerTag':'balance'}]},
             'outbounds':[{'tag':'direct','protocol':'freedom'}]}
        self.assertFalse(simulate_symbolic(cfg,target())['symbolic_consistent'])

    def test_singbox_actions_and_detour(self):
        cfg={'route':{'rules':[{'domain':['claude.ai'],'outbound':'proxy'}],'final':'direct'},
             'outbounds':[{'tag':'proxy','type':'socks','detour':'direct'},{'tag':'direct','type':'direct'}]}
        result=simulate_symbolic(cfg,target())
        self.assertEqual(result['configured_chain'],['proxy','direct'])
        self.assertTrue(result['symbolic_consistent'])
        cfg['route']['rules'][0]['action']='reject'
        self.assertEqual(simulate_symbolic(cfg,target())['configured_chain'],['REJECT'])

    def test_dynamic_selector_does_not_look_resolved(self):
        cfg={'rules':['MATCH,GROUP'],'proxy-groups':[{'name':'GROUP','type':'select','proxies':['DIRECT','REJECT']}]}
        self.assertFalse(simulate_symbolic(cfg,target())['symbolic_consistent'])

    def test_branch_budget_exhaustion_is_conservative(self):
        cfg={'rules':['RULE-SET,remote'+str(n)+',DIRECT' for n in range(80)]+['MATCH,DIRECT']}
        result=simulate_symbolic(cfg,target(),max_branches=4)
        self.assertTrue(result['branch_budget_exhausted'])
        self.assertFalse(result['symbolic_consistent'])

    def test_refine_without_controllers_or_anthropic_history(self):
        report=clean_user(web_only=True)
        report['approval']['scopes']=['proxy_config']
        cfg={'activation':'running_core_launch_config','parser_partial':False,'routes':[
            {'target':{'surface':'web','process':'chrome.exe'},'status':'simulated','symbolic_consistent':True,'configured_chain':['DIRECT']}]}
        report['target_routes']={'configs':[cfg]}
        result=refinement.refine(report,{}, {'status':'observed','software':[{'role':'core','running':True}]}, None,{})
        self.assertEqual(result['web:chrome-profile-1']['proof_basis'],'symbolic_running_launch_config')
        self.assertFalse(result['web:chrome-profile-1']['minimum_verified'])
        self.assertEqual(result['web:chrome-profile-1']['anthropic_requests_sent'],0)


class EntrySeparation(unittest.TestCase):
    def refine(self,mutate=None):
        report=clean_user(web_only=True)
        report['approval']['scopes']=['proxy_config','independent_network']
        report['program_context_v33']['proxy_markers']={'winhttp':{'status':'observed','proxy_endpoint_marker_present':False}}
        topology={'query_flags':{'routes_ok':True,'adapters_ok':True,'proxy_registry_ok':True},
                  'proxy_configuration':{'system_proxy_enabled':False,'pac_configured':False,'wpad_auto_detect':False},
                  'vpn_and_tun_topology':{'tun_owns_ipv4_default_route':False,'windows_vpn_connected_count':0,'active_tunnel_families':[]}}
        discovery={'status':'observed','software':[]}
        if mutate:mutate(report,topology,discovery)
        return refinement.refine(report,topology,discovery,None,{})['web:chrome-profile-1']

    def test_clean_direct_needs_no_controller_or_target_connection(self):
        a=self.refine();self.assertTrue(a['minimum_verified'])
        self.assertEqual(a['proof_basis'],'direct_baseline_and_neutral')
        self.assertIsNone(a['final_claude_public_egress'])

    def test_pac_and_wpad_cannot_be_claimed_as_direct(self):
        for key in ('pac_configured','wpad_auto_detect'):
            a=self.refine(lambda r,t,d:t['proxy_configuration'].update({key:True}))
            self.assertFalse(a['minimum_verified'],key)
            self.assertEqual(a['status'],'unverified')

    def test_browser_flag_and_profile_specific_proxy_prevent_system_attribution(self):
        mutators=[lambda r,t,d:r['program_context_v33']['browser_flags']['chrome'].update(explicit_proxy_override_present=True),
                  lambda r,t,d:r['profiles'][0].update(network_preferences={'proxy':{'diagnostic_values':{'mode':'fixed_servers'}}}),
                  lambda r,t,d:r['profiles'][0].update(extension_capabilities=[{'proxy_permission':True}])]
        for mutate in mutators:self.assertFalse(self.refine(mutate)['minimum_verified'])

    def test_unattributed_vpn_and_multiple_cores_do_not_prove_direct(self):
        self.assertFalse(self.refine(lambda r,t,d:t['vpn_and_tun_topology'].update(windows_vpn_connected_count=1))['minimum_verified'])
        self.assertFalse(self.refine(lambda r,t,d:d.update(software=[{'family':'xray'},{'family':'sing-box'}]))['minimum_verified'])

    def test_refused_probe_never_reuses_an_older_neutral_result_as_live_proof(self):
        a=self.refine(lambda r,t,d:r['approval'].update(scopes=['proxy_config']))
        self.assertFalse(a['minimum_verified'])
        self.assertEqual(a['anthropic_requests_sent'],0)

    def test_declined_third_party_receivers_still_simulates_existing_core(self):
        report=clean_user(web_only=True);report['approval']['scopes']=['proxy_config']
        runtime=SimpleNamespace(alias=lambda x:x,v33_controllers={'one':{'config':{'rules':['MATCH,DIRECT']},
            'tun_enabled':True,'core':'mihomo','kernel_pids':[10]}})
        discovery={'status':'observed','software':[{'pid':10,'role':'core','family':'mihomo','running':True}]}
        result=refinement.refine(report,{'query_flags':{'routes_ok':True,'adapters_ok':True,'proxy_registry_ok':True},
            'vpn_and_tun_topology':{'tun_owns_ipv4_default_route':True}},discovery,runtime,{})
        self.assertEqual(result['web:chrome-profile-1']['status'],'partial')
        self.assertTrue(result['web:chrome-profile-1']['simulations'])
        self.assertFalse(result['web:chrome-profile-1']['minimum_verified'])


class PDFRendererSafety(unittest.TestCase):
    def test_renderer_never_executes_user_or_working_directory_customizations(self):
        import json,os,subprocess,sys
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            tmp=Path(directory)
            for name in ('reportlab_mods.py','reportlab_settings.py','.reportlab_mods','.reportlab_settings'):
                (tmp/name).write_text('raise AssertionError("unapproved customization executed")',encoding='utf-8')
            code='import sys;sys.path.insert(0,'+repr(str(root/'cc_auditor/_vendor_reportlab'))+');import reportlab;from reportlab import rl_config;assert rl_config.TTFSearchPath == []'
            env=dict(os.environ,USERPROFILE=directory,HOME=directory,RL_pageCompression='not_an_integer')
            result=subprocess.run([sys.executable,'-c',code],cwd=directory,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_cjk_numbers_and_evidence_ids_survive_pdf_text_mapping_without_network(self):
        from cc_auditor.toolkit.pdf_render_v34 import render_html
        from cc_auditor.toolkit.pdf_report_renderer import pdf_backend
        original='环境预检 0123456789abcdef E001 E073 6ec893a32c665ba7c25631f9fd8b9e5a'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'test.pdf'
            with patch('socket.getaddrinfo',side_effect=AssertionError('no_network')),patch('socket.create_connection',side_effect=AssertionError('no_network')):
                render_html('<p>'+original+'</p><img src="https://api.anthropic.com/not-allowed"/>',path,'纯合成 PDF 字体验收')
            reader,_=pdf_backend();text=''.join(p.extract_text() for p in reader(path).pages)
            self.assertIn(original,text)
            self.assertNotIn('not-allowed',text)

    def test_pdf_guard_requires_actual_run_id_text_and_not_just_metadata(self):
        from cc_auditor.toolkit.pdf_render_v34 import render_html
        from cc_auditor.toolkit.pdf_v34_validation import validate_pdf
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'test.pdf'
            render_html('<p>首次使用前环境预检：适合开始准备，三类行动判断。当前证据足以安排环境准备，具体条件仍须本人核对。</p>',path,'纯合成测试')
            with self.assertRaisesRegex(ValueError,'run_id_text_corrupted'):
                validate_pdf(path,'简明报告','00000000000000000000000000000000')


if __name__=='__main__':unittest.main()
