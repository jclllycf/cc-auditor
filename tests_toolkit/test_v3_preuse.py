"""统一预检的行为回归；全部合成数据，本地回环/原生授权另行实机验收。"""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from cc_auditor.toolkit import proxy_adapters as a,preflight_v3 as core,network_v3,profiles_v3
from cc_auditor.toolkit.consent_v3 import Broker
from cc_auditor.toolkit import mcp_v3
from cc_auditor.toolkit.zero_contact_guard import utc_now

def target(process='claude.exe',surface='desktop'):return dict(surface=surface,host='claude.ai',process=process,process_path='',port=443,network='tcp')
def approval(scopes=None):return {'scan_id':'a'*32,'scopes':scopes or ['local_system'],'approved_at_utc':utc_now(),'channel':'synthetic_test_not_human'}
def report():
    return core.make_report('a'*32,approval(),local={'os_compatibility':{'desktop_compatible':True,'cli_compatible':True},'resources':{'cli_ram_sufficient':True,'disk_sufficient':True},'security_and_certificates':{'hosts_file':{'status':'observed','blocking_entries':0}},'cli_and_processes':{'running_claude_instances':[]}},synthetic=True)

class ProxyRules(unittest.TestCase):
    def test_mihomo_first_rule_wins(self):
        c={'rules':['PROCESS-NAME,claude.exe,ClaudeGroup','MATCH,Other']};r=a.simulate(c,target())
        self.assertEqual(r['rule_index'],0);self.assertEqual(r['configured_chain'],['ClaudeGroup']);self.assertIsNone(r['final_public_egress'])
    def test_browser_and_desktop_routes_differ(self):
        c={'rules':['PROCESS-NAME,claude.exe,DIRECT','MATCH,REJECT']}
        self.assertEqual(a.simulate(c,target())['configured_chain'],['DIRECT']);self.assertEqual(a.simulate(c,target('chrome.exe','web'))['configured_chain'],['REJECT'])
    def test_unknown_prior_rule_blocks_false_default(self):
        for rule in ('RULE-SET,remote,Proxy','GEOIP,US,Proxy','IP-CIDR,1.2.3.0/24,Proxy','SCRIPT,handler,Proxy','AND,((DOMAIN,x)),Proxy'):
            r=a.simulate({'rules':[rule,'MATCH,DIRECT']},target());self.assertEqual(r['status'],'unverified');self.assertIsNone(r['final_public_egress'])
    def test_api_process_unknown_not_skipped(self):
        self.assertEqual(a.simulate({'rules':['PROCESS-NAME,python.exe,P','MATCH,DIRECT']},target('','api'))['status'],'unverified')
    def test_domain_suffix_boundary(self):
        c={'rules':['DOMAIN-SUFFIX,claude.ai,DIRECT','MATCH,REJECT']}
        t=target();t['host']='evilclaude.ai';self.assertEqual(a.simulate(c,t)['configured_chain'],['REJECT'])
    def test_xray_and_not_or(self):
        c={'routing':{'rules':[{'domain':['full:claude.ai'],'network':'udp','outboundTag':'block'}]},'outbounds':[{'tag':'direct','protocol':'freedom'}]}
        r=a.simulate(c,target());self.assertEqual(r['rule_type'],'default_outbound');self.assertEqual(r['configured_chain'],['direct'])
    def test_xray_geosite_unknown(self):
        c={'routing':{'rules':[{'domain':['geosite:anthropic'],'outboundTag':'Proxy'}]},'outbounds':[{'tag':'direct','protocol':'freedom'}]}
        self.assertEqual(a.simulate(c,target())['status'],'unverified')
    def test_sing_box_process_and_chain(self):
        c={'route':{'rules':[{'process_name':['claude.exe'],'action':'route','outbound':'first'}]},'outbounds':[{'tag':'first','type':'socks','detour':'second'},{'tag':'second','type':'socks'}]}
        r=a.simulate(c,target(),lambda x:'alias-'+x);self.assertEqual(r['configured_chain'],['alias-first','alias-second']);self.assertEqual(r['chain_state'],'configured')
    def test_sing_box_remote_rule_set_unknown(self):
        c={'route':{'rules':[{'rule_set':['remote'],'outbound':'Proxy'}],'final':'direct'}}
        self.assertEqual(a.simulate(c,target())['status'],'unverified')
    def test_dynamic_group_unknown(self):
        c={'rules':['MATCH,Select'],'proxy-groups':[{'name':'Select','type':'select','proxies':['A']}]}
        self.assertEqual(a.simulate(c,target())['chain_state'],'runtime_selection_unknown')
    def test_cycle_bounded(self):
        c={'route':{'final':'a'},'outbounds':[{'tag':'a','type':'socks','detour':'b'},{'tag':'b','type':'socks','detour':'a'}]}
        self.assertEqual(a.simulate(c,target())['chain_state'],'cycle')
    def test_no_proxy_and_shadowsocks_do_not_fabricate_rules(self):
        self.assertEqual(a.simulate({},target())['status'],'unverified');self.assertFalse(a.capabilities('shadowsocks')['static_rules'])
    def test_config_secret_not_in_simulation(self):
        c={'route':{'rules':[{'domain':['claude.ai'],'outbound':'A'}]},'outbounds':[{'tag':'A','type':'socks','server':'SECRET_SERVER','password':'SECRET_PASSWORD'}]}
        self.assertNotIn('SECRET',json.dumps(a.simulate(c,target())))

class ConsentBoundary(unittest.TestCase):
    def test_pin_or_bool_cannot_self_approve(self):
        for name,args in [('grant_permissions',{'user_explicitly_consented':True}),('run_approved_deep_preflight',{'scan_id':'a'*32,'pin_code':'123456'}),('run_approved_deep_preflight',{'scan_id':'a'*32,'consent_ticket':'fake'})]:
            with self.assertRaises((PermissionError,ValueError)):mcp_v3.dispatch_mcp_tool(name,args)
    def test_native_decline_no_grant(self):
        b=Broker();m=b.prepare([],['neutral_network'])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value=None),self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
    def test_replay_revocation_expiry_and_sealed_scope(self):
        b=Broker();m=b.prepare([],['local_system']);m['requested_scopes'].append('neutral_network')
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':['local_system'],'profiles':[]}):
            approved=b.approve_and_consume(m['scan_id']);self.assertEqual(approved['scopes'],['local_system'])
            with self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
        for state in ('expired','revoked'):
            b=Broker();m=b.prepare([])
            if state=='expired':b.pending[m['scan_id']]['manifest']['expires_epoch']=0
            else:b.revoke(m['scan_id'])
            with self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
    def test_no_pin_exposed(self):
        m=Broker().prepare([]);self.assertNotIn('pin',json.dumps(m).lower())
    def test_scope_escalation_refused(self):
        b=Broker();m=b.prepare([],['local_system'])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':['neutral_network'],'profiles':[]}),self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])

class EvidenceAndScoring(unittest.TestCase):
    def test_sixteen_claude_helpers_zero_penalty(self):
        r=report();s=copy.deepcopy(r['summary']);r['checks']=copy.deepcopy(r['checks'])
        next(c for c in r['checks'] if c['id']=='claude_processes')['value']={'count':16,'instances':[{'pid':n+1} for n in range(16)]}
        self.assertEqual(core.summarize(r),s)
    def test_hk_generic_probe_does_not_fill_target_egress(self):
        r=core.make_report('a'*32,approval(),probes=[{'status':'observed','country_code':'HK','actual_claude_path':False}],synthetic=True)
        self.assertEqual(r['summary']['points_deducted'],0)
        for c in r['checks']:
            if c['id'].startswith('target_egress'):self.assertEqual(c['state'],'unknown');self.assertIsNone(c['value'])
    def test_unknowns_not_penalties_or_passes(self):
        r=core.make_report('a'*32,approval(),synthetic=True);self.assertEqual(r['summary']['passed'],0);self.assertEqual(r['summary']['points_deducted'],0);self.assertIsNone(r['summary']['technical_score'])
    def test_fault_included_in_observed_not_pass(self):
        r=report();c=r['checks'][0];c.update(state='fault',points=15);s=core.summarize(r)
        self.assertEqual(s['observed'],r['summary']['observed']);self.assertEqual(s['passed'],r['summary']['passed']-1);self.assertEqual(s['faults'],1)
    def test_duplicate_fault_deducted_once(self):
        r=report();r['checks'][0].update(state='fault',points=15);r['checks'].append(copy.deepcopy(r['checks'][0]));self.assertEqual(core.summarize(r)['points_deducted'],15)
    def test_report_hash_and_derived_summary(self):
        root=Path('scratch/v3-tests');root.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as td:
            p=core.save(report(),td)['json'];self.assertEqual(core.read(p)[0]['run_id'],'a'*32)
            value=json.loads(Path(p).read_text(encoding='utf-8'));value['report']['summary']['technical_score']=100;Path(p).write_text(json.dumps(value),encoding='utf-8')
            with self.assertRaises(ValueError):core.read(p)
    def test_physical_location_not_from_language(self):
        a=report();b=copy.deepcopy(a);b['checks'].append({'id':'locale2','state':'reference','points':0,'issue_id':'locale2'})
        self.assertEqual(a['summary']['points_deducted'],core.summarize(b)['points_deducted'])
    def test_stopped_daily_browser_never_launches_new_profile(self):
        rec={'public':{'browser_running':False},'exe':Path('not-launched.exe')}
        with patch.object(profiles_v3.subprocess,'Popen',side_effect=AssertionError('must not launch')):
            self.assertEqual(profiles_v3.dynamic_profile(rec)['status'],'not_tested')
    def test_network_endpoint_allowlist_before_socket(self):
        with patch.object(network_v3.socket,'getaddrinfo',side_effect=AssertionError('must not resolve')):
            for x in ('https://claude.ai','api.anthropic.com','https://example.com',{'host':'api4.ipify.org'}):
                with self.assertRaises((PermissionError,TypeError)):network_v3.fetch(x)
    def test_no_claude_dns_or_outgoing_rule_simulation(self):
        import socket
        with patch.object(socket,'getaddrinfo',side_effect=AssertionError('no DNS')):
            self.assertEqual(a.simulate({'rules':['DOMAIN,claude.ai,DIRECT']},target())['status'],'simulated')
    def test_mcp_initialization_no_fake_protocol_support(self):
        x=mcp_v3.handle_jsonrpc_message({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'9999-99-99'}})
        self.assertEqual(x['result']['serverInfo']['version'],core.VERSION);self.assertNotEqual(x['result']['protocolVersion'],'9999-99-99')
    def test_mcp_errors_do_not_leak_paths(self):
        x=mcp_v3.handle_jsonrpc_message({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'build_pdf_reports','arguments':{'scan_id':'b'*32}}})
        self.assertTrue(x['result']['isError']);self.assertNotIn('Users',json.dumps(x))

if __name__=='__main__':unittest.main()
