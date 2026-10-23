"""安全边界与真实失效回归。全部 fixture，绝不触发真人批准或公网连接。"""
import json,tempfile,unittest,socket,copy
from pathlib import Path
from unittest.mock import patch,MagicMock
from cc_auditor.toolkit import network_v3 as net,proxy_adapters as adapters,profiles_v3 as profiles,preflight_v3 as core,mcp_v3
from cc_auditor.toolkit.safe_yaml_v3 import load
from cc_auditor.toolkit.consent_v3 import Broker
from cc_auditor.toolkit import route_correlation as route
from cc_auditor.toolkit.proxy_discovery import Runtime

class ConfigSafety(unittest.TestCase):
    def test_real_yaml_nested_groups_and_pipe(self):
        c=load('''mixed-port: 17431
external-controller-pipe: \\\\.\\pipe\\fixture-mihomo
secret: private-value
rules:
  - DOMAIN-SUFFIX,claude.ai,group
proxy-groups:
  - name: group
    type: select
    proxies: [upstream]
dns:
  enhanced-mode: fake-ip
tun:
  enable: true
''')
        self.assertTrue(c['tun']['enable']);self.assertEqual(c['proxy-groups'][0]['name'],'group')
    def test_unsafe_yaml_tag_and_cycle_rejected(self):
        for value in ('x: !!python/object/apply:os.system [bad]','x: &x [*x]','x: '+'['*65+'1'+']'*65):
            with self.assertRaises(ValueError):load(value)
    def test_shared_yaml_alias_dag_bounded(self):
        text='a0: &a0 [1, 2]\n'+''.join('a'+str(i)+': &a'+str(i)+' [*a'+str(i-1)+', *a'+str(i-1)+']\n' for i in range(1,35))
        self.assertIsInstance(load(text)['a34'],list)
    def test_xray_direct_tag_not_reserved(self):
        t=dict(surface='api',host='api.anthropic.com',process='',port=443,network='tcp')
        c={'routing':{},'outbounds':[{'tag':'DIRECT','protocol':'socks','proxySettings':{'tag':'up'}},{'tag':'up','protocol':'socks'}]}
        r=adapters.simulate(c,t,lambda x:'anon-'+x);self.assertEqual(r['configured_chain'],['anon-DIRECT','anon-up'])
    def test_mihomo_live_controller_selection(self):
        c={'rules':['MATCH,auto'],'proxy-groups':[{'name':'auto','_selected':'node'}],'proxies':[{'name':'node','type':'socks'}]}
        t=dict(surface='web',host='claude.ai',process='chrome.exe',port=443,network='tcp')
        self.assertEqual(adapters.simulate(c,t)['configured_chain'],['auto','node'])
    def test_rule_simulation_never_resolves(self):
        with patch.object(socket,'getaddrinfo',side_effect=AssertionError('no target DNS')):
            for core in ({'rules':['MATCH,DIRECT']},{'routing':{},'outbounds':[{'tag':'a','protocol':'freedom'}]},{'route':{'final':'d'},'outbounds':[{'tag':'d','type':'direct'}]}):
                adapters.simulate(core,dict(surface='desktop',host='claude.ai',process='claude.exe',process_path='',port=443,network='tcp'))

class EndpointSafety(unittest.TestCase):
    def test_windows_pipe_close_preserves_received_echo(self):
        context=MagicMock();parent=MagicMock();child=MagicMock();context.Pipe.return_value=(parent,child)
        process=context.Process.return_value;process.is_alive.return_value=False
        parent.poll.side_effect=[True,BrokenPipeError(109,'closed')]
        parent.recv.return_value=('ipv4',{'status':'observed','source':'generic_neutral_probe','ip':'8.8.8.8','request_sent':True})
        with patch('multiprocessing.get_context',return_value=context):result=net.checks()
        self.assertEqual(result[0]['status'],'observed');self.assertTrue(result[0]['request_sent'])
        self.assertTrue(all(x.get('request_sent') is None for x in result[1:]));parent.close.assert_called_once()
    def test_exact_hosts_and_paths(self):
        for h,p in [('claude.ai','/'),('api.anthropic.com','/'),('api4.ipify.org.evil.test','/?format=json'),('api4.ipify.org','//evil.test'),('stat.ripe.net','/arbitrary'),('localhost','/')]:
            with patch.object(socket,'getaddrinfo',side_effect=AssertionError('no DNS')),self.assertRaises(PermissionError):net._request(h,p,socket.AF_INET,True,{})
    def test_loopback_rebinding_rejected_even_if_tun(self):
        for ip in ('127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1'):
            with patch.object(socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]),patch.object(socket,'socket',side_effect=AssertionError('no socket')):
                with self.assertRaises(ValueError):net._request('api4.ipify.org','/?format=json',socket.AF_INET,True,{})
    def test_fakeip_without_observed_tun_rejected(self):
        with patch.object(socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('198.18.0.7',443))]),patch.object(socket,'socket',side_effect=AssertionError('no socket')):
            with self.assertRaises(ValueError):net._request('api4.ipify.org','/?format=json',socket.AF_INET,False,{})
    def test_pinned_iana_selects_authority(self):
        self.assertEqual(net.rir_for_ip('8.8.8.8'),'rdap.arin.net');self.assertEqual(net.rir_for_ip('1.1.1.1'),'rdap.apnic.net');self.assertIsNone(net.rir_for_ip('2001:4860:4860::8888'))
    def test_unapproved_controller_path_and_address(self):
        for endpoint,path in [('127.0.0.1:1','/restart'),('192.168.1.1:80','/rules'),('evil.test:80','/rules')]:
            with self.assertRaises(ValueError):route._read_controller(endpoint,'',path)

class AuthorizationAndProfileSafety(unittest.TestCase):
    def test_failed_collector_does_not_drop_report_or_claim_tls_pass(self):
        sid='e'*32;manifest={'source_build':core.source_build()};core.RUNS[sid]={'manifest':manifest,'profiles':{}}
        approved={'scan_id':sid,'source_build':manifest['source_build'],'scopes':['local_system','neutral_network'],'profiles':[]}
        with patch.object(core.BROKER,'approve_and_consume',return_value=approved),patch('cc_auditor.toolkit.local_environment.inspect_local_environment',side_effect=OSError('PRIVATE_TOKEN_PATH')),patch('cc_auditor.toolkit.local_environment.inspect_network_topology',return_value={'collector_state':'failed'}),patch.object(core.proxy_discovery,'discover',return_value=({'status':'failed','software':[]},None)),patch.object(net,'checks',side_effect=BrokenPipeError(109,'closed')),patch.object(core,'save',return_value={'json':'fixture'}) as save,patch('cc_auditor.toolkit.pdf_report_renderer.build_pdf_reports',return_value={'fixture':'fixture.pdf'}):
            result=core.run(sid);r=save.call_args.args[0]
            self.assertEqual(result['status'],'completed_with_limitations');self.assertEqual(len(r['collector_errors']),2)
            self.assertNotIn('PRIVATE',json.dumps(r));self.assertNotEqual(next(c for c in r['checks'] if c['id']=='tls_bypass')['state'],'passed')
        del core.RUNS[sid]
    def test_fabricated_profile_refused(self):
        b=Broker();m=b.prepare([],['browser_dynamic'])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':['browser_dynamic'],'profiles':['fabricated']}),self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
    def test_profile_requires_dynamic_scope(self):
        b=Broker();m=b.prepare([{'profile_key':'real'}],['browser_static'])
        with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value={'scopes':['browser_static'],'profiles':['real']}),self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])
    def test_static_preferences_actual_values_and_no_identity(self):
        with tempfile.TemporaryDirectory(dir='scratch') as d:
            p=Path(d);(p/'Preferences').write_text(json.dumps({'proxy':{'mode':'fixed_servers','server':'SECRET_ADDRESS'},'account_info':[{'email':'PRIVATE'}]}))
            r=profiles.static_profile({'public':{},'path':p})
            self.assertEqual(r['network_preferences']['proxy']['diagnostic_values']['mode'],'fixed_servers');self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('PRIVATE',json.dumps(r))
    def test_dynamic_does_not_erase_static_result(self):
        sid='f'*32;manifest={'source_build':core.source_build()};public={'profile_key':'real','browser_name':'Fixture','profile_alias':'Fixture','version':'1','browser_running':True,'static_profile_checked':False,'dynamic_profile_checked':False}
        core.RUNS[sid]={'manifest':manifest,'profiles':{'real':{'public':public}}}
        approved={'scan_id':sid,'source_build':manifest['source_build'],'scopes':['browser_static','browser_dynamic'],'profiles':['real']}
        static={**public,'static_profile_checked':True};dynamic={**public,'dynamic_profile_checked':True,'status':'observed'}
        with patch.object(core.BROKER,'approve_and_consume',return_value=approved),patch.object(profiles,'static_profile',return_value=static),patch.object(profiles,'dynamic_profile',return_value=dynamic),patch.object(core,'save',return_value={'json':'fixture'}),patch('cc_auditor.toolkit.pdf_report_renderer.build_pdf_reports',return_value={}),patch.object(core,'make_report',wraps=core.make_report) as make:
            core.run(sid);self.assertTrue(make.call_args.args[6][0]['static_profile_checked'])
        del core.RUNS[sid]
    def test_mcp_invalid_params_remain_protocol_error(self):
        for params in ('bad',[1]):
            out=mcp_v3.handle_jsonrpc_message({'jsonrpc':'2.0','id':1,'method':'initialize','params':params});self.assertEqual(out['error']['code'],-32602)
        for arguments in ([],False,''):
            with self.assertRaises(ValueError):mcp_v3.dispatch_mcp_tool('audit_capabilities',arguments)

if __name__=='__main__':unittest.main()
