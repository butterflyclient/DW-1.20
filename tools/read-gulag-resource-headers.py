"""Read only 24-byte headers of the already identified native resource registry."""
import ctypes as c
from ctypes import wintypes as w
import hashlib,json,struct
from pathlib import Path
source=json.loads(Path(r'E:\DW\IW8\data\gpu-live-gulag-resources.json').read_bytes())
k=c.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]; k.OpenProcess.restype=w.HANDLE
k.CloseHandle.argtypes=[w.HANDLE]
k.ReadProcessMemory.argtypes=[w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)]
k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
h=k.OpenProcess(0x410,False,source['pid'])
if not h: raise c.WinError(c.get_last_error())
try:
    path=c.create_unicode_buffer(32768); length=w.DWORD(len(path))
    assert k.QueryFullProcessImageNameW(h,0,path,c.byref(length))
    with Path(path.value).open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
    assert digest==source['executable_sha256']
    rows=[]
    for resource in source['resources']:
        data=c.create_string_buffer(24); received=c.c_size_t()
        assert k.ReadProcessMemory(h,int(resource['source_data'],16),data,24,c.byref(received)) and received.value==24
        rows.append(dict(index=resource['index'],resource_bytes=resource['data_size'],hex=data.raw.hex(),dwords=struct.unpack('<6I',data.raw)))
    result=dict(pid=source['pid'],read_only=True,bytes_read=384,sha256=digest,resources=rows)
    Path(r'E:\DW\IW8\data\gpu-live-gulag-resource-headers.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
finally:k.CloseHandle(h)
