"""本机候选运行时元数据，不运行 Claude/SDK、不读取目标进程环境或密钥。"""
import os,shutil,platform
from pathlib import Path
from ..collectors import file_version
from .zero_contact_guard import utc_now


def collect():
    candidates=[]
    for name in ('python.exe','python3.exe','node.exe','pwsh.exe','powershell.exe','cmd.exe','bash.exe','claude.exe','claude.cmd'):
        path=shutil.which(name)
        if path:
            candidates.append({'command':name,'present_on_collector_path':True,'file_version':file_version(Path(path)) or None,
                'executed':False,'candidate_only':True})
    commands={r['command'] for r in candidates}
    return {'captured_at_utc':utc_now(),'source':'collector_host_PATH_metadata','candidates':candidates,
        'collector_python_version':platform.python_version(),'target_process_environment_read':False,'api_credentials_read':False,
        'cli':{'shell_available':bool(commands & {'pwsh.exe','powershell.exe','cmd.exe','bash.exe'}),'cli_on_path':bool(commands & {'claude.exe','claude.cmd'}),
            'claude_executed':False,'target_host_bound':False,'meaning':'本机候选；未安装 CLI 属于正常使用前状态，不能推及 WSL/容器/远端。'},
        'api':{'runtime_candidate_found':bool(commands & {'python.exe','python3.exe','node.exe'}),'python_candidate_found':bool(commands & {'python.exe','python3.exe'}),'node_candidate_found':'node.exe' in commands,
            'target_host_bound':False,'meaning':'没有指定具体应用、SDK/虚拟环境或远端；检测器自身 Python 不作为实际 API 应用的证据。'},
        'terminal_context':{'windows_terminal_marker_present':bool(os.environ.get('WT_SESSION')),'ssh_marker_present':bool(os.environ.get('SSH_CONNECTION')),'wsl_marker_present':bool(os.environ.get('WSL_DISTRO_NAME')),
            'meaning':'仅检测器继承环境中的标记存在性；不代表用户计划使用的终端。'}}
