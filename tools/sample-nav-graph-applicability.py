"""Read-only live portal layout applicability; no calls, writes, injection or suspension."""
import ctypes as c
from ctypes import wintypes as w
import hashlib,json,struct,collections
from pathlib import Path
REPORT=Path(r'E:\DW\IW8\data\dw-client\jobs\1792275307683495200\publication\build-report.json')
PID=30200
report=json.loads(REPORT.read_bytes()); symbols=report['symbols']
k=c.WinDLL('kernel32',use_last_error=True); p=c.WinDLL('psapi',use_last_error=True)
k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]; k.OpenProcess.restype=w.HANDLE
k.ReadProcessMemory.argtypes=[w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)]
k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
k.CloseHandle.argtypes=[w.HANDLE]
p.EnumProcessModulesEx.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),w.DWORD]
h=k.OpenProcess(0x410,False,PID)
if not h: raise c.WinError(c.get_last_error())
try:
    name=c.create_unicode_buffer(32768); length=w.DWORD(len(name))
    assert k.QueryFullProcessImageNameW(h,0,name,c.byref(length))
    with Path(name.value).open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
    assert digest==report['sha256']
    modules=(w.HMODULE*1024)(); needed=w.DWORD()
    assert p.EnumProcessModulesEx(h,modules,c.sizeof(modules),c.byref(needed),3)
    base=modules[0]
    def read(at,n):
        b=c.create_string_buffer(n); done=c.c_size_t()
        if not k.ReadProcessMemory(h,at,b,n,c.byref(done)) or done.value!=n: raise OSError(hex(at))
        return b.raw
    def val(at,fmt='<Q'): return struct.unpack(fmt,read(at,struct.calcsize(fmt)))[0]
    count=val(base+symbols['SVHS_ClientCount'],'<I')
    rows=[]; seeds=[]
    for slot in range(min(count,200)):
        client=val(base+symbols['SVHS_Clients']+slot*8)
        if not client: continue
        try:
            kind=val(client+214756,'<i')
            if kind!=2: continue
            nav=val(client+1368+360)
            if not nav: continue
            ref,space=struct.unpack('<QQ',read(nav+1364,16)); area=val(ref) if ref else 0
            row=dict(slot=slot,area=hex(area),space=hex(space))
            if area:
                b=read(area,72); child,links=struct.unpack_from('<QQ',b,8); shape,flags=struct.unpack_from('<II',b,52)
                row.update(usage=shape,shape=flags,child=hex(child),links=hex(links),childCount=val(child,'<i') if child else None)
                row['supported']=not child and not links and not flags&0x20000000 and flags&127>=3
                seeds.append(area)
            rows.append(row)
        except OSError as e: rows.append(dict(slot=slot,error=str(e)))
    visited={}; queue=collections.deque(seeds[:1]); errors=[]
    while queue and len(visited)<2048:
        area=queue.popleft()
        if area in visited: continue
        try:
            b=read(area,72); child,links=struct.unpack_from('<QQ',b,8); usage,shape=struct.unpack_from('<II',b,52)
            n=shape&127
            visited[area]=dict(child=bool(child),childCount=val(child,'<i') if child else None,links=bool(links),obstacle=bool(shape&0x20000000),edges=n)
            if n:
                edges=read(area+72,32*n)
                queue.extend(struct.unpack_from('<Q',edges,i*32)[0] for i in range(n) if struct.unpack_from('<Q',edges,i*32)[0])
        except OSError as e: errors.append(str(e))
    summary=dict(sampled=len(visited),supported=sum(not r['child'] and not r['links'] and not r['obstacle'] and r['edges']>=3 for r in visited.values()),
                 child=sum(r['child'] for r in visited.values()),emptyChild=sum(r['child'] and r['childCount']==0 for r in visited.values()),
                 specialLinks=sum(r['links'] for r in visited.values()),obstacle=sum(r['obstacle'] for r in visited.values()))
    result=dict(pid=PID,sha256=digest,read_only=True,atomic_snapshot=False,clientCount=count,botAreas=rows,adjacencySample=summary,errors=errors,
                limitation='Live sequential memory reads; applicability estimate only, not coherent graph capture or GPU runtime proof.')
    Path(r'E:\DW\IW8\data\gpu-nav-live-applicability.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
finally: k.CloseHandle(h)
