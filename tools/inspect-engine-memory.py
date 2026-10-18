"""Read-only, hash-bound memory/queue/GC observations. Never trim or collect."""
import argparse
import collections
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import re
import struct
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=15)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    symbols = report["symbols"]
    kernel = c.WinDLL("kernel32", use_last_error=True)
    psapi = c.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD,w.BOOL,w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.ReadProcessMemory.argtypes = [w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)]
    kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
    psapi.EnumProcessModulesEx.argtypes = [w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),w.DWORD]
    class Counters(c.Structure):
        _fields_ = [("cb",w.DWORD),("PageFaultCount",w.DWORD)] + [(n,c.c_size_t) for n in (
            "PeakWorkingSetSize","WorkingSetSize","QuotaPeakPagedPoolUsage","QuotaPagedPoolUsage",
            "QuotaPeakNonPagedPoolUsage","QuotaNonPagedPoolUsage","PagefileUsage","PeakPagefileUsage","PrivateUsage")]
    class Region(c.Structure):
        _fields_ = [("base",c.c_void_p),("allocation",c.c_void_p),("allocation_protect",w.DWORD),
                    ("partition",w.WORD),("size",c.c_size_t),("state",w.DWORD),("protect",w.DWORD),("type",w.DWORD)]
    psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE,c.POINTER(Counters),w.DWORD]
    kernel.VirtualQueryEx.argtypes = [w.HANDLE,c.c_void_p,c.POINTER(Region),c.c_size_t]
    kernel.VirtualQueryEx.restype = c.c_size_t
    process = kernel.OpenProcess(0x410,False,args.pid)
    if not process: raise c.WinError(c.get_last_error())
    try:
        path = c.create_unicode_buffer(32768); length = w.DWORD(len(path))
        assert kernel.QueryFullProcessImageNameW(process,0,path,c.byref(length))
        with Path(path.value).open('rb') as file:
            assert hashlib.file_digest(file,'sha256').hexdigest() == report['sha256']
        modules = (w.HMODULE*1024)(); needed = w.DWORD()
        assert psapi.EnumProcessModulesEx(process,modules,c.sizeof(modules),c.byref(needed),3)
        base = modules[0]
        def read(address,length):
            data = c.create_string_buffer(length); received = c.c_size_t()
            if not kernel.ReadProcessMemory(process,address,data,length,c.byref(received)) or received.value!=length:
                raise c.WinError(c.get_last_error())
            return data.raw
        def value(address,fmt):return struct.unpack(fmt,read(address,struct.calcsize(fmt)))[0]
        def global_value(name,fmt):return value(base+symbols[name],fmt)
        aliases = dict(re.findall(r'\{"([^"]+)", "([^"]+)"\}',
                                  (ROOT/'integration/replay/con_dvar_names.h').read_text()))
        dvars = {}
        pool_address = base+symbols['gl_14E37EE30']
        pool = read(pool_address,7000*112)
        for offset in range(0,len(pool),112):
            pointer = struct.unpack_from('<Q',pool,offset)[0]
            if not pointer:continue
            try: name=read(pointer,128).split(b'\0')[0].decode(errors='replace')
            except OSError:continue
            name=aliases.get(name,name)
            if name in ('mapname','ui_mapname','com_maxfps','com_optimized','sv_maxclients') or name.startswith('lui_gc_'):
                kind=pool[offset+29];address=pool_address+offset+40
                if kind in (0,1,5,8):dvars[name]=value(address,'<?' if kind==0 else '<f' if kind==1 else '<i')
                elif kind==9:
                    p=value(address,'<Q');dvars[name]=read(p,256).split(b'\0')[0].decode(errors='replace') if p else ''
        snapshots=[]
        for index in range(args.samples):
            counts=Counters();counts.cb=c.sizeof(counts)
            assert psapi.GetProcessMemoryInfo(process,c.byref(counts),counts.cb)
            queues=read(base+symbols['gl_14D53F300'],192*147)
            rows=[]
            for kind in range(147):
                offset=kind*192;incoming,outgoing,size=struct.unpack_from('<iii',queues,offset+16)
                capacity=struct.unpack_from('<i',queues,offset+64)[0]
                rows.append(dict(type=kind,in_size=incoming,out_size=outgoing,command_bytes=size,capacity_bytes=capacity))
            lua=global_value('gl_151868880','<Q')
            lua_global=value(lua+16,'<Q') if lua else 0
            snapshots.append(dict(time=time.time(),working_set=counts.WorkingSetSize,
                private_commit=counts.PrivateUsage,peak_working_set=counts.PeakWorkingSetSize,
                mode=global_value('s_comOptimizedMode','<I'),
                worker_count=global_value('gl_14D57EE4C','<I'),
                minimum_queue=global_value('gl_14D57EE44','<i'),
                lua_heap_bytes=value(lua_global+48,'<Q') if lua_global else None,
                queue_capacity_bytes=sum(max(0,r['capacity_bytes']) for r in rows),
                pending_queues=[r for r in rows if r['in_size'] or r['out_size']]))
            if index+1<args.samples:time.sleep(2)
        allocations=collections.defaultdict(lambda:dict(committed=0,reserved=0,types=set()))
        cursor=0
        while True:
            region=Region()
            if kernel.VirtualQueryEx(process,cursor,c.byref(region),c.sizeof(region))!=c.sizeof(region):break
            if region.allocation:
                row=allocations[region.allocation];row['types'].add(region.type)
                if region.state==0x1000:row['committed']+=region.size
                elif region.state==0x2000:row['reserved']+=region.size
            next_address=(region.base or 0)+region.size
            if next_address<=cursor:break
            cursor=next_address
        largest=sorted([dict(address=hex(address),committed=row['committed'],reserved=row['reserved'],types=list(row['types']))
            for address,row in allocations.items()],key=lambda r:-r['committed'])[:20]
        result=dict(pid=args.pid,executable_sha256=report['sha256'],read_only=True,dvars=dvars,snapshots=snapshots,largest_allocations=largest)
        args.output.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(dvars=dvars,first=snapshots[0],last=snapshots[-1],largest=largest[:6]),indent=2))
    finally:kernel.CloseHandle(process)


if __name__=='__main__':main()
