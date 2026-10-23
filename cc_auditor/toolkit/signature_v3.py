"""WinVerifyTrust 仅缓存验证：禁止为签名验证下载 CRL / 证书。"""
import ctypes as c
import sys
from ctypes import wintypes as w

def verify_offline(path):
    if sys.platform!='win32':return 'unsupported'
    class GUID(c.Structure):_fields_=[('a',w.DWORD),('b',w.WORD),('d',w.WORD),('e',c.c_ubyte*8)]
    class FILE(c.Structure):_fields_=[('size',w.DWORD),('path',w.LPCWSTR),('handle',w.HANDLE),('subject',c.c_void_p)]
    class DATA(c.Structure):_fields_=[('size',w.DWORD),('policy',c.c_void_p),('sip',c.c_void_p),('ui',w.DWORD),('revocation',w.DWORD),('choice',w.DWORD),('file',c.POINTER(FILE)),('action',w.DWORD),('state',w.HANDLE),('url',w.LPCWSTR),('flags',w.DWORD),('context',w.DWORD),('settings',c.c_void_p)]
    try:
        guid=GUID(0x00aac56b,0xcd44,0x11d0,(c.c_ubyte*8)(0x8c,0xc2,0,0xc0,0x4f,0xc2,0x95,0xee))
        f=FILE(c.sizeof(FILE),str(path),None,None);data=DATA();data.size=c.sizeof(DATA);data.ui=2;data.choice=1;data.file=c.pointer(f);data.action=1;data.flags=0x1000|0x10
        api=c.WinDLL('wintrust').WinVerifyTrust;api.argtypes=[w.HWND,c.POINTER(GUID),c.c_void_p];api.restype=w.LONG
        code=api(w.HWND(-1),c.byref(guid),c.byref(data)) & 0xffffffff
        data.action=2;api(w.HWND(-1),c.byref(guid),c.byref(data))
        return 'valid_cached_trust_not_publisher_identity' if code==0 else 'unsigned' if code in (0x800b0100,0x800b0003) else 'not_verified_offline'
    except (OSError,ValueError):return 'unavailable'
