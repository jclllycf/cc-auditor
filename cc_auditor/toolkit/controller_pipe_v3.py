"""Windows 已配置命名管道上的有界只读 HTTP；验证服务端 PID，不猜测管道名。"""
import http.client
import json
import os
import re
import io

PATHS=('/version','/rules','/proxies','/connections','/configs','/providers/rules')


def discover_names(kernels):
    """仅列名称元数据并过滤已发现内核；连接后仍须验证 server PID 才能发请求。"""
    if os.name!='nt':return []
    patterns=[]
    if 'mihomo' in kernels:patterns+=['mihomo','clash']
    if 'sing-box' in kernels:patterns+=['sing-box','singbox']
    try:
        return ['\\\\.\\pipe\\'+n for n in os.listdir('\\\\.\\pipe\\')[:4096]
                if any(x in n.casefold() for x in patterns) and re.fullmatch(r'[\w .-]{1,120}',n)][:8]
    except OSError:return []


def _worker(sender,name,path,secret,pids):
    import ctypes,msvcrt
    from ctypes import wintypes
    try:
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.WaitNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD]
        api.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        api.CreateFileW.restype=wintypes.HANDLE
        api.GetNamedPipeServerProcessId.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.ULONG)]
        api.CloseHandle.argtypes=[wintypes.HANDLE]
        if not api.WaitNamedPipeW(name,500):raise ValueError('pipe_unavailable')
        handle=api.CreateFileW(name,0xc0000000,0,None,3,0,None)
        if handle==ctypes.c_void_p(-1).value:raise ValueError('pipe_open_failed')
        pid=wintypes.ULONG()
        if not api.GetNamedPipeServerProcessId(handle,ctypes.byref(pid)) or pid.value not in pids:
            api.CloseHandle(handle);raise ValueError('pipe_owner_not_attributed')
        fd=msvcrt.open_osfhandle(int(handle),os.O_RDWR|os.O_BINARY)
        with os.fdopen(fd,'r+b',buffering=0) as stream:
            if '\r' in secret or '\n' in secret:raise ValueError('invalid_controller_secret')
            auth='Authorization: Bearer '+secret+'\r\n' if secret else ''
            stream.write(('GET '+path+' HTTP/1.1\r\nHost: localhost\r\n'+auth+'Connection: close\r\n\r\n').encode('utf-8'))
            class Wrapped:
                def makefile(self,*args,**kwargs):return io.BufferedReader(stream,65536)
            response=http.client.HTTPResponse(Wrapped());response.begin()
            if response.status!=200:raise ValueError('pipe_http_unavailable')
            data=response.read(2*1024*1024+1)
            if len(data)>2*1024*1024:raise ValueError('pipe_response_limit')
            sender.send({'value':json.loads(data),'server_pid':pid.value})
    except Exception:sender.send({'error':'configured_pipe_unavailable_or_untrusted'})
    finally:sender.close()


def read(name,path,secret,pids):
    if os.name!='nt' or path not in PATHS or not re.fullmatch(r'\\\\\.\\pipe\\[\w .-]{1,120}',name):raise ValueError('unsafe_pipe_target')
    import multiprocessing as mp
    context=mp.get_context('spawn');recv,send=context.Pipe(False)
    child=context.Process(target=_worker,args=(send,name,path,secret,list(pids)),daemon=True);child.start();send.close()
    try:
        if not recv.poll(3):raise ValueError('pipe_timeout')
        result=recv.recv()
        if 'error' in result:raise ValueError('pipe_unavailable')
        return result['value']
    finally:
        if child.is_alive():child.terminate()
        child.join(1);recv.close()
