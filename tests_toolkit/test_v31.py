"""行动等级和真实协议边界；所有网络响应为 fixture，不读取真实 Profile。"""
import copy
import ipaddress
import struct
import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch
from cc_auditor.toolkit.risk_v31 import assess
from cc_auditor.toolkit import deep_network_v31 as net,proxy_discovery as pd
from cc_auditor.toolkit.pdf_v31 import technical_html
from cc_auditor.toolkit import route_correlation as routes,profiles_v3 as profiles,proxy_adapters
from unittest.mock import MagicMock


def fixture():
    checks=[]
    def add(key,state,layer='L01',points=0):
        checks.append(dict(id=key,state=state,layer=layer,title=key,value=None,points=points,evidence_id='E'+str(len(checks)+1).zfill(3),issue_id=key,source='synthetic',scope='all',captured_at_utc='2026-10-18T10:29:30+00:00',criterion='fixture',reason=''))
    for k in ('os_desktop_compatible','os_cli_compatible','cli_ram_sufficient','disk_sufficient'):add(k,'passed')
    for i in range(13):add('pass_'+str(i),'passed')
    for i in range(27):add('reference_'+str(i),'reference')
    for k in ('desktop','web','cli','api'):add('target_egress_'+k,'unknown','L05')
    for k,l in (('dns_receiver','L04'),('ipv6_bypass','L03'),('webrtc_stun','L10')):add(k,'unknown',l)
    for i in range(13):add('unknown_'+str(i),'unknown')
    return dict(checks=checks,profiles=[dict(browser_name='Chrome',profile_key='chrome-profile-1',profile_alias='档案 1',dynamic_profile_checked=True),dict(browser_name='Edge',profile_key='edge-profile-1',profile_alias='档案 1',dynamic_profile_checked=False)],target_routes={},run_id='a'*32,created_at_utc='2026-10-18T10:29:30+00:00',version='3.0.0',synthetic=True,approval={'scopes':[]})


class Risk(unittest.TestCase):
    def test_real_baseline_counts_amber_not_44_passed(self):
        r=fixture();before=copy.deepcopy(r);a=assess(r)
        self.assertEqual(a['action_level'],'amber');self.assertEqual(a['headline'],'电脑基础正常，Claude 专用网络还需核实。')
        self.assertEqual(a['completeness'],{'total':64,'passed':17,'fault':0,'reference':27,'needs_verification':20,'observed':44,'percent':68.8})
        self.assertEqual(before,r)
    def test_missing_not_red(self):
        r=fixture()
        for c in r['checks']:c['state']='unknown'
        self.assertEqual(assess(r)['action_level'],'amber');self.assertEqual(assess(r)['confirmed_fault_count'],0)
    def test_confirmed_tls_fault_red_with_evidence(self):
        r=fixture();r['checks'][0].update(state='fault',id='tls_bypass',points=35)
        a=assess(r);self.assertEqual(a['action_level'],'red');self.assertEqual(a['basis'][0]['evidence_id'],'E001')
    def test_minor_confirmed_fault_amber(self):
        r=fixture();r['checks'][0].update(state='fault',points=10)
        self.assertEqual(assess(r)['action_level'],'amber')
    def test_low_only_after_all_critical_checks(self):
        r=fixture()
        for c in r['checks']:c['state']='passed'
        for p in r['profiles']:p['dynamic_profile_checked']=True
        r['target_routes']={'configs':[{'activation':'controller_rules_observed'}]}
        self.assertEqual(assess(r)['action_level'],'green')
    def test_reference_does_not_pass_target(self):
        r=fixture()
        for c in r['checks']:c['state']='reference'
        self.assertEqual(assess(r)['action_level'],'amber')
    def test_language_and_generic_hk_do_not_make_red(self):
        r=fixture();r['generic_probe_egress']=[{'country_code':'HK','vendor_score':99}]
        r['checks'][20]['value']={'language':'zh-CN','claude_process_count':16}
        self.assertEqual(assess(r)['action_level'],'amber');self.assertEqual(assess(r)['confirmed_fault_count'],0)
    def test_edge_not_covered_by_chrome(self):
        a=assess(fixture());g=next(x for x in a['critical_gaps'] if x['id']=='daily_profiles')
        self.assertIn('Edge',g['title']);self.assertNotIn('Chrome',g['title'])
    def test_full_report_keeps_every_id_and_no_raw_json(self):
        r=fixture();text=technical_html(r,'b'*64,assess(r))
        for c in r['checks']:self.assertIn(c['id'],text);self.assertIn(c['evidence_id'],text)
        self.assertNotIn('measured_subset_score',text)


class Protocol(unittest.TestCase):
    def test_pipe_failure_falls_back_to_pid_owned_tcp_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'config.json';p.write_text(json.dumps({'rules':['MATCH,Old'],'external-controller-pipe':'\\\\.\\pipe\\mihomo-stale','external-controller':'127.0.0.1:9191','secret':'PRIVATE_SECRET'}))
            runtime=pd.Runtime();public={'pid':99,'family':'mihomo','listeners':[{'host':'127.0.0.1','port':9191}]}
            runtime.processes=[{'public':public,'process':MagicMock(),'exe':'mihomo.exe'}]
            def read(endpoint,secret,path):
                return {'/version':{'version':'fixture'},'/rules':{'rules':[{'type':'DomainSuffix','payload':'claude.ai','proxy':'DIRECT'}]},'/configs':{'mode':'rule'},'/proxies':{'proxies':{}}}[path]
            with patch.object(routes,'config_candidates',return_value=[(p,'mihomo')]),patch.object(routes,'_read_controller',side_effect=read),patch('cc_auditor.toolkit.controller_pipe_v3.read',side_effect=ValueError('absent')),patch('cc_auditor.toolkit.controller_pipe_v3.discover_names',return_value=[]):
                r=routes.inspect_routes(runtime,{'software':[public]})
            self.assertEqual(r['configs'][0]['activation'],'controller_rules_observed');self.assertEqual(r['controllers'][0]['attempts'][-1]['transport'],'tcp')
            self.assertNotIn('PRIVATE_SECRET',str(r));self.assertIsNone(r['configs'][0]['runtime_rules'][0]['final_public_egress'])
    def test_controller_no_delay_or_healthcheck(self):
        for path in ('/proxies/X/delay','/providers/proxies/X/healthcheck','/configs?reload=true'):
            with self.assertRaises(ValueError):routes._read_controller('127.0.0.1:1','SECRET',path)
    def test_direct_mode_does_not_apply_rule_list(self):
        r=proxy_adapters.simulate({'rules':['MATCH,REJECT'],'mode':'direct'},dict(surface='web',host='claude.ai',process='chrome.exe',process_path='',port=443,network='tcp'))
        self.assertEqual(r['configured_chain'],['DIRECT']);self.assertIsNone(r['final_public_egress'])
    def test_fresh_visible_window_overrides_old_not_running_flag(self):
        record={'public':dict(browser_name='Edge',profile_key='edge-profile-1',profile_alias='档案',browser_running=False,engine='Chromium'),'exe':Path('edge.exe'),'root':Path('.'),'path':Path('Default')}
        session=MagicMock();session.run.return_value={'status':'ok','data':{'features':{}}}
        with patch.object(profiles,'has_visible_window',return_value=True),patch('cc_auditor.toolkit.browser_probe.ToolkitBrowserLoopbackSession',return_value=session):r=profiles.dynamic_profile(record)
        self.assertTrue(r['dynamic_profile_checked']);self.assertFalse(r['actual_profile_verified'])
    def test_os_denied_window_has_specific_next_step(self):
        record={'public':dict(browser_name='Edge',profile_key='edge-profile-1',profile_alias='档案',browser_running=True,engine='Chromium'),'exe':Path('edge.exe')}
        with patch.object(profiles,'has_visible_window',return_value=False):r=profiles.dynamic_profile(record)
        self.assertIn('普通空白页',r['reason']);self.assertFalse(r.get('dynamic_profile_checked',False))
    def test_unreadable_cwd_does_not_guess_relative_config(self):
        m=pd.parse_launch_args(['mihomo','-f','relative.yaml','-ext-ctl=127.0.0.1:9191'],'mihomo',None)
        self.assertFalse(m['files']);self.assertEqual(m['ext-ctl'],'127.0.0.1:9191')
    def test_mihomo_config_base64_not_path_and_equals_flags(self):
        m=pd.parse_launch_args(['mihomo','-config','a-secret-base64','-f=D:/example/current.yaml','-ext-ctl-pipe=\\\\.\\pipe\\mihomo','-secret','SECRET'],'mihomo','D:/example')
        self.assertEqual(len(m['files']),1);self.assertNotIn('a-secret-base64',str(m['files']));self.assertEqual(m['secret'],'SECRET')
    def test_xray_config_is_path(self):
        self.assertEqual(len(pd.parse_launch_args(['xray','run','-config','D:/example/a.json'],'xray','D:/example')['files']),1)
    def test_unc_config_not_acquired(self):
        self.assertFalse(pd.parse_launch_args(['mihomo','-f','\\\\server\\private.yaml'],'mihomo','D:/')['files'])
    def test_dns_accept_only_receiver_format(self):
        rows=net.parse_dns_txt(['FROM: 8.8.8.8#53 (UDP)','Cookie: SECRET','FROM: 127.0.0.1#53 (UDP)'])
        self.assertEqual(rows,[{'resolver_ip':'8.8.8.8','authoritative_transport':'UDP'}])
    def test_stun_xor_and_transaction_validation(self):
        tid=b'0123456789ab';ip=ipaddress.ip_address('8.8.4.4').packed
        xor=bytes(a^b for a,b in zip(ip,struct.pack('!I',0x2112a442)))
        packet=struct.pack('!HHI',0x0101,12,0x2112a442)+tid+struct.pack('!HHBBH',0x20,8,0,1,1234)+xor
        self.assertEqual(net.parse_stun(packet,tid),'8.8.4.4')
        with self.assertRaises(ValueError):net.parse_stun(packet,b'x'*12)
        with self.assertRaises(ValueError):net.parse_stun(packet[:-1],tid)
    def test_browser_network_sanitized_not_arbitrary_data(self):
        out=net.sanitize_browser({'cookie':'SECRET','stun':{'status':'observed','mapped_ip':'192.168.1.1'},'dns':{'status':'observed','resolver_ips':['8.8.8.8','127.0.0.1']},'tls':{'status':'observed','ja4':'t13d1234','headers':'SECRET'}})
        self.assertNotIn('SECRET',str(out));self.assertEqual(out['stun']['status'],'failed');self.assertEqual(out['dns']['resolver_ips'],['8.8.8.8'])
    def test_no_media_permissions_no_turn_no_claude_in_page(self):
        for forbidden in ('getUserMedia','turn:','claude.ai','anthropic.com','document.cookie'):
            self.assertNotIn(forbidden,net.BROWSER_JS)


if __name__=='__main__':unittest.main()
