"""检查自建 PyInstaller 归档的压缩代码、常量及源文件名；不执行其中代码。"""
from __future__ import annotations
import argparse,json,marshal,re,types,zipfile
from pathlib import Path
from public_build.release_guard import audit_tree,content_findings,sha

def code_findings(code,label,counts):
    if not isinstance(code,types.CodeType):return []
    counts['code_objects']+=1;out=[]
    if re.match(r'^(?:[A-Za-z]:|/|\\\\)',code.co_filename):out.append({'rule':'absolute_co_filename','path':label})
    out.extend(content_findings(label,code.co_filename.encode('utf-8')))
    for value in code.co_consts:
        if isinstance(value,types.CodeType):out.extend(code_findings(value,label,counts))
        elif isinstance(value,(str,bytes)):out.extend(content_findings(label,value.encode('utf-8',errors='surrogatepass') if isinstance(value,str) else value))
    return out

def audit(exe):
    from PyInstaller.archive.readers import CArchiveReader
    exe=Path(exe);tree=audit_tree(exe.parent);archive=CArchiveReader(str(exe));counts={'code_objects':0,'pyz_modules':0,'base_library_modules':0};findings=[];modules=[]
    policy_file=exe.parent/'licenses/upstream-string-exceptions.json'
    policy=json.loads(policy_file.read_text('utf-8')) if policy_file.is_file() else {}
    code_exceptions={x['module']:x for x in policy.get('code_modules',[])}
    def inspect(code,label,raw):
        found=code_findings(code,label,counts);entry=code_exceptions.get(label)
        if entry and not label.startswith('cc_auditor') and entry['sha256']==sha(raw):
            found=[x for x in found if x['rule']!='private_home']
        return found
    for name,item in archive.toc.items():
        if item[-1]=='z':
            pyz=archive.open_embedded_archive(name)
            for module in pyz.toc:
                modules.append(module);counts['pyz_modules']+=1
                findings.extend(inspect(pyz.extract(module),module,pyz.extract(module,raw=True)))
        elif item[-1] in ('s','m','M'):findings.extend(code_findings(marshal.loads(archive.extract(name)),name,counts))
        else:findings.extend(content_findings(name,archive.extract(name)))
    for path in exe.parent.rglob('*.zip'):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                raw=z.read(n)
                if n.endswith('.pyc'):
                    counts['base_library_modules']+=1;findings.extend(inspect(marshal.loads(raw[16:]),n,raw[16:]))
                else:findings.extend(content_findings(n,raw))
    if any(m in ('cc_auditor.toolkit.mcp_server','cc_auditor.__main__','cc_auditor.web_account','cc_auditor.toolkit.report_builder') for m in modules):raise ValueError('legacy_module_collected')
    if findings:raise ValueError(json.dumps(findings,ensure_ascii=False))
    return {'status':'passed','exe_sha256':sha(exe.read_bytes()),'files':tree['file_count'],**counts,'legacy_entrypoints_absent':True,'scope':'archive_names_all_file_bytes_decompressed_code_constants_and_co_filename_not_a_security_guarantee'}

def main():
    p=argparse.ArgumentParser();p.add_argument('exe',type=Path);a=p.parse_args();print(json.dumps(audit(a.exe),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
