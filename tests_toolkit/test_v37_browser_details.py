"""Synthetic collection, consent and coverage tests; no daily profile is opened."""
import copy
import http.client
import json
import shutil
import subprocess
import threading
import unittest
from unittest.mock import patch

from cc_auditor.toolkit import browser_details_v37 as details
from cc_auditor.toolkit.browser_probe import ToolkitBrowserLoopbackSession
from cc_auditor.toolkit.consent_v3 import Broker
from cc_auditor.toolkit.coverage_v37 import catalog, summary


def fixture():
    return {'contract':details.CONTRACT,
            'canvas':{'status':'observed','width':128,'height':32,'painted_pixels':0,'repeated_read_equal':False},
            'fonts':{'status':'observed','candidates':[{'name':name,'differs_from_fallback':[True,False,True]} for name in details.FONTS]},
            'emoji':{'status':'observed','sample':'grinning_face','painted_pixels':24,'color_pixels':12},
            'webgl':{'status':'observed','vendor':'fixture-vendor','renderer':'fixture-renderer','unmasked_extension':False,'extension_count':3,'max_texture_size':4096},
            'audio':{'status':'observed','frames':4096,'sample_rate':44100,'channels':1,'finite_samples':True,'signal_present':True},
            'permissions':{'status':'observed','values':dict(zip(details.PERMISSIONS,['prompt','denied','granted','unsupported','timeout']))}}


def report(value=None, scopes=None):
    return {'synthetic':True,'profiles':[{'profile_key':'fixture-a','dynamic_result':{
        'profile_binding':'user_attested_targeted_launch_only','checked_at_utc':'2026-10-31T12:00:00Z',
        'data':{'browser_details_v37':value} if value is not None else {}}}],
        'approval':{'profiles':['fixture-a'],'scopes':scopes if scopes is not None else ['browser_dynamic','browser_feature_details']}}


class BrowserDetailsTests(unittest.TestCase):
    def test_fixed_fields_and_no_identifier(self):
        f=fixture();f['stable_hash']='not retained';f['webgl']['unexpected']='not retained'
        out=details.sanitize(f)
        self.assertNotIn('stable_hash',out);self.assertNotIn('unexpected',out['webgl'])
        self.assertFalse(out['visitor_identifier_generated'])
        self.assertEqual(out['canvas']['painted_pixels'],0)
        self.assertFalse(out['canvas']['repeated_read_equal'])
        self.assertEqual(out['emoji']['os_attribution'],'not_inferred')

    def test_missing_and_failed_are_separate(self):
        f=fixture();f['canvas']={'status':'timeout'};f['audio']={'status':'unsupported'}
        out=details.sanitize(f)
        self.assertEqual(out['canvas'],{'status':'timeout'})
        self.assertEqual(out['audio'],{'status':'unsupported'})
        del f['audio']
        with self.assertRaises(ValueError):details.sanitize(f)

    def test_reject_unbounded_or_invalid_results(self):
        for group,key,value in [('webgl','renderer','x'*241),('webgl','vendor','x\n'),
                                ('canvas','painted_pixels',4097),('canvas','repeated_read_equal',1),
                                ('emoji','color_pixels',25),('audio','sample_rate',48000),('audio','channels',True)]:
            with self.subTest(group=group,key=key):
                f=fixture();f[group][key]=value
                with self.assertRaises(ValueError):details.sanitize(f)

    def test_fonts_are_fixed_not_user_supplied_enumeration(self):
        f=fixture();f['fonts']['candidates'][0]['name']='arbitrary-font'
        with self.assertRaises(ValueError):details.sanitize(f)

    def test_permissions_require_exact_names_and_known_states(self):
        for change in ('extra','bad-state'):
            f=fixture();f['permissions']['values']['extra' if change=='extra' else 'camera']='unknown'
            with self.assertRaises(ValueError):details.sanitize(f)
        self.assertEqual(details.sanitize(fixture())['permissions']['values']['notifications'],'denied')

    def test_catalog_all_50_ids_once_and_no_superset_claim(self):
        c=catalog();ids=[x for r in c['groups'] for x in r['envguard_ids']]
        self.assertEqual(len(ids),50);self.assertEqual(len(set(ids)),50)
        self.assertFalse(c['full_superset_claim'])
        self.assertEqual(next(r for r in c['groups'] if r['id']=='target_reachability')['implementation'],'excluded_zero_contact')

    def test_mcp_coverage_is_read_only_and_uses_same_catalog(self):
        from cc_auditor.toolkit.mcp_v3 import dispatch_mcp_tool
        capabilities=dispatch_mcp_tool('audit_capabilities')
        self.assertEqual(capabilities['capability_coverage']['envguard_reference']['configured_items'],50)
        with patch('cc_auditor.toolkit.mcp_v3.core.read',return_value=(report(fixture()),'fixture-digest')):
            out=dispatch_mcp_tool('get_preflight_evidence',{'scan_id':'a'*32,'view':'coverage'})
            self.assertEqual(out['groups'],catalog()['groups'])
            with self.assertRaises(ValueError):
                dispatch_mcp_tool('get_preflight_evidence',{'scan_id':'a'*32,'view':'coverage','compare_to_scan_id':'b'*32})

    def test_new_observations_leave_health_scores_unchanged(self):
        from tests_toolkit.test_v34_clean_preuse import clean_user
        from cc_auditor.toolkit.health_v35 import assess
        r=clean_user(True);r['version']='3.7.0-dev1'
        before=assess(r)
        r['profiles'][0]['dynamic_result']['data']['browser_details_v37']=fixture()
        after=assess(r)
        self.assertEqual({k:v['health_score'] for k,v in before['surface_assessments'].items()},
                         {k:v['health_score'] for k,v in after['surface_assessments'].items()})

    def test_status_view_does_not_leak_gpu_or_font_values(self):
        out=summary(report(fixture()))
        text=json.dumps(out)
        self.assertNotIn('fixture-renderer',text);self.assertNotIn('differs_from_fallback',text)
        self.assertEqual(out['browser_detail_attempts']['profiles'][0]['groups']['audio'],'observed')
        self.assertEqual(out['browser_detail_attempts']['profiles'][0]['permission_state_counts']['timeout_count'],1)
        # The report's privacy gate reserves "prompt" for conversation content.
        from cc_auditor.storage import bounded
        bounded(out)
        self.assertTrue(out['synthetic'])
        self.assertEqual(out['browser_detail_attempts']['profiles'][0]['profile_binding'],'user_attested_targeted_launch_only')

    def test_unapproved_results_never_become_measurements(self):
        for scopes in ([],['browser_dynamic'],['browser_feature_details']):
            states=details.summarize(report(fixture(),scopes))['profiles'][0]['groups']
            self.assertEqual(set(states.values()),{'not_authorized'})

    def test_absent_not_run_and_invalid_not_success(self):
        self.assertEqual(set(details.summarize(report())['profiles'][0]['groups'].values()),{'not_run'})
        self.assertEqual(set(details.summarize(report({}))['profiles'][0]['groups'].values()),{'invalid_evidence'})

    def test_native_scope_dependency_enforced(self):
        p=[{'profile_key':'fixture-a'}]
        for decision in ({'scopes':['browser_feature_details'],'profiles':[]},
                         {'scopes':['browser_dynamic','browser_feature_details'],'profiles':[]}):
            b=Broker();m=b.prepare(p)
            with patch('cc_auditor.toolkit.consent_v3._native_consent',return_value=decision):
                with self.assertRaises(PermissionError):b.approve_and_consume(m['scan_id'])

    def test_retry_uses_same_scope_and_keeps_original_attempt(self):
        from tests_toolkit.test_v34_clean_preuse import clean_user
        from cc_auditor.toolkit.evidence_completion_v33 import complete
        for state in ('failed','unsupported'):
            r=clean_user(True);r['version']='3.7.0-dev1'
            r['approval'].update(scopes=['browser_dynamic','browser_feature_details'],profiles=[r['profiles'][0]['profile_key']])
            p=r['profiles'][0];p['dynamic_profile_checked']=True
            f=fixture();f['audio']={'status':state};p['dynamic_result']['data']['browser_details_v37']=f
            f['permissions']['values']['local-fonts']='unsupported'
            retry=copy.deepcopy(p['dynamic_result']);retry.update(dynamic_profile_checked=True)
            retry['data']['browser_details_v37']=fixture()
            with patch('cc_auditor.toolkit.profiles_v3.dynamic_profile',return_value=retry) as dynamic:
                complete(r,None,None,None,r['program_context_v33'],{}, {p['profile_key']:{'public':{}}})
            self.assertEqual(dynamic.called,state=='failed')
            if dynamic.called:
                self.assertTrue(dynamic.call_args.kwargs['browser_feature_details'])
                self.assertFalse(dynamic.call_args.kwargs['independent_network'])
                self.assertEqual(p['v33_attempt_history'][0]['result']['data']['browser_details_v37']['audio']['status'],'failed')
                self.assertEqual(p['dynamic_result']['data']['browser_details_v37']['audio']['status'],'observed')

    def test_loopback_page_and_post_respect_scope(self):
        # Local HTTP only, synthetic payload; no external endpoint or browser.
        base={'family':'Chrome','version':'1','languages':['en-US'],'timezone':'UTC','offset_minutes':0,'features':{}}
        for enabled in (False,True):
            s=ToolkitBrowserLoopbackSession(browser_feature_details=enabled)
            worker=threading.Thread(target=lambda:s.run(lambda _:None,timeout=5),daemon=True);worker.start()
            try:
                c=http.client.HTTPConnection(s.authority,timeout=3)
                c.request('GET','/'+s.token);r=c.getresponse();page=r.read().decode()
                self.assertEqual('async function ccBrowserDetails' in page,enabled)
                self.assertNotIn('https://',r.getheader('Content-Security-Policy'))
                payload={**base,'browser_details_v37':fixture()}
                c.request('POST','/'+s.token,json.dumps(payload),{'Content-Type':'application/json','Origin':'http://'+s.authority,
                    'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty'})
                response=c.getresponse();response.read();self.assertEqual(response.status,200)
                self.assertEqual('browser_details_v37' in s.result,enabled)
                if enabled:self.assertEqual(s.result['request_fetch_metadata']['Sec-Fetch-Site'],'same-origin')
                c.close()
            finally:
                s.event.set();worker.join(5)

    @unittest.skipUnless(shutil.which('node'),'Node needed for isolated JS execution')
    def test_javascript_executes_with_synthetic_apis_and_no_network(self):
        harness=r'''
const vm=require('node:vm');
let network=0,access=0,disconnected=0,lost=0;
class Offline {
  constructor(ch,frames,rate){this.frames=frames;this.rate=rate;this.ch=ch;this.destination={};}
  createOscillator(){return {frequency:{},connect(){},start(){},disconnect(){disconnected++;}};}
  async startRendering(){return {length:this.frames,sampleRate:this.rate,numberOfChannels:this.ch,
    getChannelData(){return new Float32Array(4096).fill(0.5);}};}
}
const gl={VENDOR:1,RENDERER:2,MAX_TEXTURE_SIZE:3,
 getExtension(n){return n==='WEBGL_debug_renderer_info'?null:{loseContext(){lost++;}};},
 getParameter(n){return n===3?4096:'fixture-gpu';},getSupportedExtensions(){return ['fixture'];}};
const ctx={font:'',fillRect(){},fillText(){},measureText(){return {width:this.font.includes('"')?101:100};},
 getImageData(x,y,w,h){return {data:new Uint8ClampedArray(w*h*4).fill(128)};}};
const sandbox={setTimeout,clearTimeout,window:{OfflineAudioContext:Offline},
 navigator:{permissions:{async query({name}) {if(name==='local-fonts')throw new TypeError('unsupported');return {state:'prompt'};}},
   mediaDevices:{getUserMedia(){access++;throw Error('forbidden');}}},
 document:{createElement(){return {getContext(k){return k==='2d'?ctx:gl;}};}},
 fetch(){network++;throw Error('network forbidden');}};
vm.runInNewContext(SOURCE+';ccBrowserDetails()',sandbox).then(result=>{
 console.log(JSON.stringify({result,network,access,disconnected,lost}));
}).catch(e=>{console.error(e);process.exitCode=1;});
'''
        code='const SOURCE='+json.dumps(details.BROWSER_DETAILS_JS)+';\n'+harness
        proc=subprocess.run(['node','-e',code],text=True,capture_output=True,timeout=10,check=True)
        out=json.loads(proc.stdout);result=details.sanitize(out['result'])
        self.assertEqual({r['status'] for k,r in result.items() if k in details.GROUPS},{'observed'})
        self.assertEqual((out['network'],out['access'],out['disconnected'],out['lost']),(0,0,1,1))
        self.assertEqual(result['permissions']['values']['local-fonts'],'unsupported')
        # No APIs yields unsupported, not false or fabricated fingerprint values.
        altered=code.replace('window:{OfflineAudioContext:Offline}','window:{}').replace("return k==='2d'?ctx:gl;","return null;")
        proc=subprocess.run(['node','-e',altered],text=True,capture_output=True,timeout=10,check=True)
        result=details.sanitize(json.loads(proc.stdout)['result'])
        self.assertEqual(result['audio'],{'status':'unsupported'})
        self.assertEqual(result['canvas'],{'status':'unsupported'})


if __name__=='__main__':unittest.main()
