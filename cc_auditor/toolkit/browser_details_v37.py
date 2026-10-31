"""Opt-in, bounded tool-origin rendering observations; no visitor identifiers."""
from __future__ import annotations

CONTRACT = '3.7.browser-details.1'
FONTS = ('Arial', 'Times New Roman', 'Consolas', 'Segoe UI', 'Microsoft YaHei',
         'SimSun', 'SimHei', 'PingFang SC', 'Hiragino Sans GB', 'Noto Sans CJK SC',
         'Roboto', 'Segoe UI Emoji')
PERMISSIONS = ('geolocation', 'notifications', 'camera', 'microphone', 'local-fonts')
GROUPS = ('canvas', 'fonts', 'emoji', 'webgl', 'audio', 'permissions')
STATES = ('observed', 'unsupported', 'failed', 'timeout')

BROWSER_DETAILS_JS = r"""
async function ccBrowserDetails() {
  const out = {contract: '3.7.browser-details.1'};
  const timed = async (fn, ms) => {
    let timer;
    try { return await Promise.race([Promise.resolve().then(fn), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('cc_timeout')), ms);
    })]); } finally { clearTimeout(timer); }
  };
  const run = async (name, fn) => {
    try { out[name] = await timed(fn, 1200); }
    catch (e) { out[name] = {status: e.message === 'cc_timeout' ? 'timeout' : 'failed'}; }
  };
  await run('canvas', () => {
    const c = document.createElement('canvas'); c.width = 128; c.height = 32;
    const x = c.getContext('2d'); if (!x) return {status:'unsupported'};
    x.fillStyle = '#137f87'; x.fillRect(0,0,128,32);
    x.font = '18px sans-serif'; x.fillStyle = '#ffba43'; x.fillText('CC Aa 123', 2,24);
    const a = x.getImageData(0,0,128,32).data, b = x.getImageData(0,0,128,32).data;
    let nonzero = 0, same = a.length === b.length;
    for (let i=0;i<a.length;i++) { if (a[i] !== b[i]) same=false; if (i%4===3 && a[i]) nonzero++; }
    return {status:'observed', width:128, height:32, painted_pixels:nonzero, repeated_read_equal:same};
  });
  await run('fonts', () => {
    const x = document.createElement('canvas').getContext('2d'); if (!x) return {status:'unsupported'};
    const candidates = ['Arial','Times New Roman','Consolas','Segoe UI','Microsoft YaHei','SimSun',
      'SimHei','PingFang SC','Hiragino Sans GB','Noto Sans CJK SC','Roboto','Segoe UI Emoji'];
    const sample = 'mmmmWWii123\u6d4b\u8bd5', bases=['monospace','sans-serif','serif'];
    const widths = bases.map(b => {x.font='24px '+b; return x.measureText(sample).width;});
    return {status:'observed', candidates:candidates.map(name => ({name,
      differs_from_fallback:bases.map((b,i) => {x.font='24px "'+name+'", '+b;
        return Math.abs(x.measureText(sample).width-widths[i]) > 0.01;})}))};
  });
  await run('emoji', () => {
    const c=document.createElement('canvas'); c.width=64;c.height=64;
    const x=c.getContext('2d');if (!x) return {status:'unsupported'};
    x.font='40px sans-serif';x.fillText('\ud83d\ude00',4,48);
    const a=x.getImageData(0,0,64,64).data;let painted=0,color=0;
    for(let i=0;i<a.length;i+=4) if(a[i+3]) {painted++;if(Math.max(a[i],a[i+1],a[i+2])-Math.min(a[i],a[i+1],a[i+2])>16) color++;}
    return {status:'observed',sample:'grinning_face',painted_pixels:painted,color_pixels:color};
  });
  await run('webgl', () => {
    const c=document.createElement('canvas'), g=c.getContext('webgl');if(!g) return {status:'unsupported'};
    try {
      const d=g.getExtension('WEBGL_debug_renderer_info');
      return {status:'observed',vendor:String(g.getParameter(d?d.UNMASKED_VENDOR_WEBGL:g.VENDOR)||'').slice(0,160),
        renderer:String(g.getParameter(d?d.UNMASKED_RENDERER_WEBGL:g.RENDERER)||'').slice(0,240),
        unmasked_extension:d!==null,extension_count:(g.getSupportedExtensions()||[]).length,
        max_texture_size:g.getParameter(g.MAX_TEXTURE_SIZE)};
    } finally { const loss=g.getExtension('WEBGL_lose_context');if(loss) loss.loseContext(); }
  });
  await run('audio', async () => {
    const C=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(!C) return {status:'unsupported'};
    const c=new C(1,4096,44100), oscillator=c.createOscillator();
    try {
      oscillator.type='sine';oscillator.frequency.value=440;oscillator.connect(c.destination);oscillator.start(0);
      const b=await c.startRendering(), a=b.getChannelData(0);
      let finite=true, signal=false;
      for(let i=0;i<a.length;i++) {if(!Number.isFinite(a[i])) finite=false;if(Math.abs(a[i])>0.001) signal=true;}
      return {status:'observed',frames:b.length,sample_rate:b.sampleRate,channels:b.numberOfChannels,
        finite_samples:finite,signal_present:signal};
    } finally {oscillator.disconnect();}
  });
  await run('permissions', async () => {
    if(!navigator.permissions || !navigator.permissions.query) return {status:'unsupported'};
    const values={};
    await Promise.all(['geolocation','notifications','camera','microphone','local-fonts'].map(async name => {
      try { values[name]=(await timed(() => navigator.permissions.query({name}),800)).state; }
      catch(e) {values[name]=e.message==='cc_timeout'?'timeout':e.name==='TypeError'?'unsupported':'failed';}
    }));
    return {status:'observed',values};
  });
  return out;
}
"""


def sanitize(value):
    """Only fixed observation fields survive. Missing is not success/zero."""
    if not isinstance(value, dict) or value.get('contract') != CONTRACT:
        raise ValueError('invalid_browser_details_contract')
    out = {'contract': CONTRACT, 'vantage': 'browser_tool_loopback_origin',
           'visitor_identifier_generated': False,
           'interpretation_zh': '自有临时 origin 的特征观察；不是安装字体清单、系统归属、跨站指纹、真人或服务端评分证明。'}

    def integer(v, maximum):
        if type(v) is not int or not 0 <= v <= maximum:
            raise ValueError('invalid_browser_detail_number')
        return v

    def flag(v):
        if type(v) is not bool:
            raise ValueError('invalid_browser_detail_flag')
        return v

    for name in GROUPS:
        node = value.get(name)
        if not isinstance(node, dict) or node.get('status') not in STATES:
            raise ValueError('invalid_browser_detail_state')
        row = {'status': node['status']}
        if row['status'] == 'observed':
            if name == 'canvas':
                if integer(node.get('width'),128) != 128 or integer(node.get('height'),32) != 32:
                    raise ValueError('invalid_canvas_dimensions')
                row.update(width=128, height=32, painted_pixels=integer(node.get('painted_pixels'),4096),
                           repeated_read_equal=flag(node.get('repeated_read_equal')))
            elif name == 'fonts':
                candidates = node.get('candidates')
                if not isinstance(candidates, list) or len(candidates) != len(FONTS):
                    raise ValueError('invalid_font_candidates')
                rows = []
                for expected, c in zip(FONTS, candidates):
                    if not isinstance(c,dict) or c.get('name') != expected:
                        raise ValueError('invalid_font_candidate')
                    flags = c.get('differs_from_fallback')
                    if not isinstance(flags,list) or len(flags)!=3:
                        raise ValueError('invalid_font_metrics')
                    rows.append({'name':expected,'differs_from_fallback':[flag(f) for f in flags]})
                row.update(candidates=rows, meaning='metric_difference_only_not_installation_or_geography')
            elif name == 'emoji':
                if node.get('sample') != 'grinning_face':raise ValueError('invalid_emoji_sample')
                painted=integer(node.get('painted_pixels'),4096)
                row.update(sample='grinning_face', painted_pixels=painted,
                           color_pixels=integer(node.get('color_pixels'),painted), os_attribution='not_inferred')
            elif name == 'webgl':
                for k, limit in (('vendor',160),('renderer',240)):
                    v=node.get(k)
                    if not isinstance(v,str) or len(v)>limit or any(ord(c)<32 for c in v):
                        raise ValueError('invalid_webgl_text')
                    row[k]=v
                row.update(unmasked_extension=flag(node.get('unmasked_extension')),
                           extension_count=integer(node.get('extension_count'),512),
                           max_texture_size=integer(node.get('max_texture_size'),1048576))
            elif name == 'audio':
                if tuple(integer(node.get(k),n) for k,n in (('frames',4096),('sample_rate',44100),('channels',1))) != (4096,44100,1):
                    raise ValueError('invalid_audio_dimensions')
                row.update(frames=4096,sample_rate=44100,channels=1,finite_samples=flag(node.get('finite_samples')),
                           signal_present=flag(node.get('signal_present')))
            else:
                values=node.get('values')
                if not isinstance(values,dict) or set(values)!=set(PERMISSIONS):
                    raise ValueError('invalid_permission_names')
                if any(v not in ('granted','denied','prompt','unsupported','failed','timeout') for v in values.values()):
                    raise ValueError('invalid_permission_state')
                row.update(values={k:values[k] for k in PERMISSIONS}, scope='this_temporary_origin_only', access_requested=False)
        out[name]=row
    return out


def summarize(report):
    """Model/report view of recorded attempts, without detailed GPU/font values."""
    result=[]
    approval=report.get('approval') or {}
    for p in report.get('profiles',[])[:24]:
        authorized=('browser_feature_details' in approval.get('scopes',[]) and
                    'browser_dynamic' in approval.get('scopes',[]) and p.get('profile_key') in approval.get('profiles',[]))
        data=((p.get('dynamic_result') or {}).get('data') or {}).get('browser_details_v37')
        if not authorized:
            states={k:'not_authorized' for k in GROUPS}
        elif data is None:
            states={k:'not_run' for k in GROUPS}
        else:
            try:states={k:v['status'] for k,v in sanitize(data).items() if k in GROUPS}
            except (ValueError,TypeError):states={k:'invalid_evidence' for k in GROUPS}
        row={'profile_key':p['profile_key'],'synthetic':report.get('synthetic') is True,
                       'profile_binding':(p.get('dynamic_result') or {}).get('profile_binding','unverified'),
                       'captured_at_utc':(p.get('dynamic_result') or {}).get('checked_at_utc'), 'groups':states}
        if authorized and states.get('permissions')=='observed':
            from collections import Counter
            row['permission_state_counts']={k+'_count':v for k,v in Counter(sanitize(data)['permissions']['values'].values()).items()}
        result.append(row)
    return {'contract':CONTRACT,'profiles':result,'total_profiles':len(report.get('profiles',[])),
            'omitted_profiles':max(0,len(report.get('profiles',[]))-len(result)), 'health_score_changed':False}
