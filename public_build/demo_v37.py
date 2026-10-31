"""Run a fully synthetic upgrade preview; no network or environment collectors."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import secrets
import sys
from unittest.mock import patch


def main():
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    from tests_toolkit.test_v34_clean_preuse import clean_user
    from tests_toolkit.test_v37_evidence import observation, NOW, LATER
    from tests_toolkit.test_v37_browser_details import fixture as browser_fixture
    from cc_auditor.toolkit.browser_details_v37 import sanitize as sanitize_details
    from cc_auditor.toolkit.evidence_completion_v33 import attach
    from cc_auditor.toolkit.preflight_v3 import save, VERSION
    from cc_auditor.toolkit.evidence_v37 import analyze
    from cc_auditor.toolkit.review_v37 import export_review
    from cc_auditor.toolkit.pdf_report_renderer import build_pdf_reports
    root = Path(__file__).resolve().parents[1] / 'scratch' / ('v37-demo-' + secrets.token_hex(4))
    root.mkdir(parents=True)
    before = clean_user(True)
    before.update(version=VERSION, run_id='a'*32, created_at_utc=NOW, synthetic=True,
                  diagnostic_context_v37={'device_session':'fixture-device','execution_origin':'synthetic',
                                          'network_context_id':'fixture-egress-a','policy_snapshot_id':'fixture-intent-v1'})
    for p in before['profiles']:
        p.update(profile_session_binding='fixture-profile-a', checked_at_utc=NOW)
        p['dynamic_result'].update(checked_at_utc=NOW, profile_binding='user_attested_targeted_launch_browser_pid')
    before['approval']['scopes'] = list(set(before['approval']['scopes']) | {'independent_network'})
    before['approval']['profiles'] = [p['profile_key'] for p in before['profiles']]
    before['approval']['scopes'] = list(set(before['approval']['scopes']) | {'browser_dynamic','browser_feature_details'})
    for p in before['profiles']:
        value=browser_fixture();value['audio']={'status':'unsupported'}
        p['dynamic_result']['data']['browser_details_v37']=sanitize_details(value)
    dns = observation('dns', id='profile-a-dns', data={'authoritative_receipt': True, 'policy_bound': True,
                       'expected_resolver_regions':['US'], 'observed_resolver_regions':['US','CN']})
    before['diagnostic_observations_v37'] = [dns,
        observation('ice', id='profile-a-ice', data={'candidates':[{'address':'198.18.0.1','type':'host'}], 'gathering_complete':True}),
        observation('external_score', id='external-score', data={'score':90}),
        observation('failure_state', id='core-down', data={'configured_protection':True}),
        observation('dns', id='profile-b-dns', state='not_run', scope={**dns['scope'],'profile_key':'chrome-profile-2','profile_binding':'fixture-profile-b'})]
    attach(before, before['program_context_v33'], attempts=[])
    for c in before['checks']: c['captured_at_utc'] = NOW
    before['diagnostics_v37'] = analyze(before)
    after = copy.deepcopy(before)
    after.update(run_id='b'*32, created_at_utc=LATER)
    after['diagnostic_observations_v37'][0]['data']['observed_resolver_regions'] = ['US']
    after['diagnostic_observations_v37'][0]['runtime_sha256'] = '2'*64
    after['diagnostic_observations_v37'][2]['data'] = {'probe_error': True}
    for r in after['diagnostic_observations_v37']: r['captured_at_utc'] = LATER
    for c in after['checks']: c['captured_at_utc'] = LATER
    for p in after['profiles']:
        p['checked_at_utc']=LATER;p['dynamic_result']['checked_at_utc']=LATER
    after['diagnostics_v37'] = analyze(after)
    # Guard the whole authoring run against accidental network or app launch.
    with patch('socket.socket', side_effect=AssertionError('offline demo forbids networking')), patch('subprocess.Popen', side_effect=AssertionError('offline demo forbids application launch')):
        a = save(before, root/'before')['json']; b = save(after, root/'after')['json']
        first = export_review(a); second = export_review(b,a)
        pdfs = build_pdf_reports(b)
    receipt = {'version': VERSION, 'synthetic': True, 'network_and_process_launch_blocked': True,
               'before': first, 'after': second, 'pdfs': pdfs,
               'note_zh': '示例变化由合成输入构造；没有扫描或修复当前电脑。'}
    path = root/'demo-receipt.json';path.write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({**receipt, 'receipt':str(path)},ensure_ascii=False,indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
