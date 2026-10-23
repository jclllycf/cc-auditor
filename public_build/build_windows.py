"""从公开树构建 Windows 便携程序；隔离 PATH，不复制开发者环境。"""
from pathlib import Path
import json,os,shutil,subprocess,sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    from public_build.release_guard import audit_tree
    audit_tree(ROOT,json.loads((ROOT/'public-manifest.json').read_text('utf-8')),git_checkout=(ROOT/'.git').exists())
    from cc_auditor.toolkit.preflight_v3 import source_build
    output=ROOT/'dist';work=ROOT/'build';target=output/'CC_Auditor'
    if output.exists() or work.exists():raise FileExistsError('use_fresh_build_tree')
    work.mkdir();(work/'v3-source-manifest.json').write_text(json.dumps(source_build(),ensure_ascii=False,indent=2),encoding='utf-8')
    env=dict(os.environ)
    base=Path(sys.base_prefix);system=Path(env.get('SystemRoot','C:/Windows'))
    env['PATH']=os.pathsep.join(map(str,[Path(sys.executable).parent,base,base/'DLLs',system/'System32',system,system/'System32/WindowsPowerShell/v1.0']))
    env.pop('PYTHONPATH',None);env.pop('QT_PLUGIN_PATH',None);env.pop('QT_QPA_PLATFORM_PLUGIN_PATH',None)
    env['PYTHONIOENCODING']='utf-8';env['PYTHONDONTWRITEBYTECODE']='1'
    args=[sys.executable,'-m','PyInstaller','--noconfirm','--onedir','--console','--name','CC_Auditor',
          '--paths',str(ROOT/'cc_auditor/_vendor_pdf'),'--paths',str(ROOT/'cc_auditor/_vendor_reportlab'),
          '--distpath',str(output),'--workpath',str(work),'--specpath',str(work),
          '--exclude-module','PySide6.QtSvg','--exclude-module','PySide6.QtOpenGL',
          '--exclude-module','PySide6.QtQuick','--exclude-module','PySide6.QtQml']
    data=[(work/'v3-source-manifest.json','.'),
          (ROOT/'cc_auditor/toolkit/rdap_ipv4_bootstrap.json','cc_auditor/toolkit'),
          (ROOT/'cc_auditor/toolkit/rdap_bootstrap_provenance.json','cc_auditor/toolkit')]
    data += [(ROOT/'assets/report-fonts'/n,'assets/report-fonts') for n in ('CCAuditorSansSC-Regular.ttf','CCAuditorSansSC-Bold.ttf','OFL.txt','PROVENANCE.json')]
    for src,dest in data:args+=['--add-data',str(src)+';'+dest]
    args.append(str(ROOT/'preflight_entry_v3.py'))
    subprocess.run(args,cwd=ROOT,env=env,check=True)
    # 只移除明确不使用的可选 Qt 软件 OpenGL 后端；产品使用普通 QWidget 和 CPU PDF 渲染。
    removals=[target/'_internal/PySide6/opengl32sw.dll',target/'_internal/opengl32sw.dll',target/'_internal/PySide6/Qt6Svg.dll']
    plugins=target/'_internal/PySide6/plugins'
    # 此程序不加载用户图片或 SVG。Qt hook 自动吸收的图片插件和额外平台后端
    # 不属于产品需要；排除它们同时缩小可加载二进制与对应许可范围。
    for folder in ('imageformats','iconengines'):
        removals.extend((plugins/folder).glob('*.dll'))
    removals.extend(p for p in (plugins/'platforms').glob('*.dll') if p.name!='qwindows.dll')
    # Microsoft 运行库由用户从 Microsoft 官方单独取得，避免将安装依赖的
    # DLL 再分发权利误当成 Qt/Python 开源许可的一部分。
    removals.extend(p for p in target.rglob('*.dll') if p.name.upper().startswith(('VCRUNTIME','MSVCP','CONCRT','VCAMP','VCOMP','VCCORLIB')))
    for p in removals:
        if not p.resolve().is_relative_to(target.resolve()):raise ValueError('invalid_optional_binary_path')
        if p.is_file():p.unlink()
    for n in ('LICENSE','README.md','README.en.md','INSTALL_WINDOWS_ZH.md','MCP_CONFIGURATION_ZH.md','PRIVACY_ZH.md','SECURITY.md','SUPPORT_MATRIX_ZH.md','CHANGELOG.md','NOTICES.md','DEPENDENCY_SOURCE_AND_REPLACEMENT_ZH.md'):
        shutil.copyfile(ROOT/n,target/n)
    shutil.copytree(ROOT/'skills',target/'skills');shutil.copytree(ROOT/'licenses',target/'licenses')
    shutil.copyfile(ROOT/'start-preflight.cmd',target/'启动预检.cmd')
    print('Build complete; native acceptance and licensing gates still required.')
if __name__=='__main__':main()
