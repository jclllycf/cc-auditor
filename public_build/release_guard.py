"""公开源树和压缩包的确定性边界检查。命中仅输出规则名和文件名。"""
from __future__ import annotations
import argparse, hashlib, json, re, stat, zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN = {'.git','.venv','scratch','output','data','reports','release','__pycache__','claude-web-helper','browser-bridge'}
PATTERNS = {
    'private_key': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{40,}',
    'provider_key': rb'(?:sk-ant-api\d\d-|ghp_|github_pat_)[A-Za-z0-9_-]{20,}',
    'credential_url': rb'https?://[^\s/\"\x27:]+:[^\s/\"\x27@]+@',
    'aws_access_id': rb'(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])',
    'bearer_value': rb'(?i)Bearer[ \t]+[A-Za-z0-9._~-]{24,}',
    'jwt_value': rb'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'proxy_subscription_uri': rb'(?:vmess|vless|trojan|ss)://[A-Za-z0-9/+_=-]{24,}',
    'private_home': rb'(?i)[A-Z]:[\\/](?:Users[\\/](?!Public(?:[\\/]|\b)|example(?:[\\/]|\b)|USERNAME\b|<)[^\\/\s\"\x27]+)',
}

def sha(raw): return hashlib.sha256(raw).hexdigest()

def safe_name(name):
    p=PurePosixPath(name)
    if not name or '\\' in name or ':' in name or p.is_absolute() or any(x in ('..','.') for x in name.split('/')):
        raise ValueError('unsafe_member_name')
    if any(x.lower() in FORBIDDEN for x in p.parts) or p.name.lower()=='agents.md' or p.name.upper().startswith('CODEX_'):
        raise ValueError('private_member_name:'+name)

def content_findings(name,raw):
    findings=[]
    # UTF-16LE 和 UTF-8/ASCII 均扫描；不回显匹配值。
    views=[raw,raw.replace(b'\x00',b'')]
    for rule,pattern in PATTERNS.items():
        if any(re.search(pattern,v) for v in views):findings.append({'rule':rule,'path':name})
    return findings

def files(root):
    for p in sorted(root.rglob('*')):
        s=p.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&1024:
            raise ValueError('reparse_member_rejected')
        if p.is_file():
            if s.st_nlink!=1:raise ValueError('hardlink_member_rejected')
            yield p

def exceptions(root):
    policy=Path(root)/'licenses/upstream-string-exceptions.json'
    if not policy.is_file():return {}
    return {x['path']:x for x in json.loads(policy.read_text('utf-8'))['files']}

def reviewed_findings(name,raw,policy):
    found=content_findings(name,raw);entry=policy.get(name)
    if entry and entry['sha256']==sha(raw):
        # 仅允许审核过的固定上游二进制内构建路径；真实密钥规则永不豁免。
        found=[x for x in found if not (x['rule']=='private_home' and 'private_home' in entry['rules'])]
    return found

def audit_tree(root,manifest=None,git_checkout=False):
    root=Path(root).resolve();seen={};lower=set();findings=[];policy=exceptions(root)
    for p in files(root):
        name=p.relative_to(root).as_posix()
        if git_checkout and name.split('/')[0]=='.git':continue
        safe_name(name)
        if name.lower() in lower:raise ValueError('case_collision')
        lower.add(name.lower());raw=p.read_bytes();seen[name]=sha(raw);findings.extend(reviewed_findings(name,raw,policy))
    if findings:raise ValueError(json.dumps(findings,ensure_ascii=False))
    if manifest is not None:
        expected={x['path']:x['sha256'] for x in manifest['files']}
        # 清单无法包含自身 hash；唯一允许的非清单文件是清单本身。
        actual={k:v for k,v in seen.items() if k!='public-manifest.json'}
        if actual!=expected:raise ValueError('public_manifest_mismatch')
    return {'status':'passed','file_count':len(seen),'content_rules':list(PATTERNS),'files':seen}

def audit_zip(path):
    seen=set();findings=[]
    with zipfile.ZipFile(path) as z:
        if z.testzip():raise ValueError('zip_crc_failure')
        policies=[n for n in z.namelist() if n.endswith('/licenses/upstream-string-exceptions.json') or n=='licenses/upstream-string-exceptions.json']
        if len(policies)>1:raise ValueError('ambiguous_exception_policy')
        policy={x['path']:x for x in json.loads(z.read(policies[0]))['files']} if policies else {}
        for i in z.infolist():
            if i.is_dir():continue
            safe_name(i.filename)
            if i.filename.lower() in seen:raise ValueError('duplicate_zip_member')
            seen.add(i.filename.lower())
            if stat.S_ISLNK(i.external_attr>>16):raise ValueError('zip_symlink')
            relative=i.filename.split('/',1)[1] if '/' in i.filename else i.filename
            findings.extend(reviewed_findings(relative,z.read(i),policy))
    if findings:raise ValueError(json.dumps(findings,ensure_ascii=False))
    return {'status':'passed','members':len(seen),'sha256':sha(Path(path).read_bytes())}

def main():
    p=argparse.ArgumentParser();p.add_argument('path',type=Path);p.add_argument('--git-checkout',action='store_true');a=p.parse_args()
    result=audit_zip(a.path) if a.path.is_file() else audit_tree(a.path,json.loads((a.path/'public-manifest.json').read_text('utf-8')),git_checkout=a.git_checkout)
    result.pop('files',None);print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
