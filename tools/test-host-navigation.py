"""Differential native/compiled navigation instructions; no game launch."""
import argparse
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import struct
import subprocess
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("Scr_GetClosestReachablePointOnNavmesh", "Bfx_ClosestReachableTreeStep",
           "Bfx_ClosestReachableSearchStep", "Bfx_IncrementalSearchToIsland", "SV_HostScaleNavigation",
           "Bfx_GetClosestArea")


class Runner:
    def __init__(self, snapshot, build):
        self.snapshot = snapshot
        self.proof = json.loads((snapshot / "generated/host-scale-integration.json").read_bytes())
        self.original = pefile.PE(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe", fast_load=True)
        self.base = self.original.OPTIONAL_HEADER.ImageBase
        self.original_symbols = {r["name"]: self.base+r["original_rva"] for r in self.proof["bindings"]}
        self.original_entries = {r["symbol"]: self.base+r["original_rva"] for r in self.proof["replacements"]}
        self.report = None
        if build:
            self.report = json.loads((build / "build-report.json").read_bytes())
            exe = Path(self.report["executable"])
            assert hashlib.sha256(exe.read_bytes()).hexdigest() == self.report["sha256"]
            self.linked = pefile.PE(str(exe), fast_load=True)
            self.linked.parse_data_directories(directories=[1])
            self.ranges = self.report["rva_map"]["ranges"]
            self.starts = [r["begin"] for r in self.ranges]
        else:
            spec = importlib.util.spec_from_file_location("coff", snapshot / "tools/coff.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.objects = []
            folder = snapshot / "navigation-test-objects"
            folder.mkdir(exist_ok=True)
            for name in SOURCES:
                target = folder / (name + ".obj")
                subprocess.run([r"C:\Program Files\LLVM\bin\clang++.exe",
                    "--target=x86_64-pc-windows-msvc", "-c", str(snapshot / "src" / (name + ".cpp")),
                    "-o", str(target), "-O2", "-std=c++20", "-ffreestanding", "-fno-stack-protector",
                    "-fno-exceptions", "-fno-rtti", "-funwind-tables", "-ffunction-sections",
                    "-fdata-sections", "-Wall", "-Wextra", "-Werror", "-I"+str(snapshot / "src")], check=True)
                self.objects.append(module.read(target))

    def machine(self, edited, mode=0, population=150):
        vm = Machine()
        pe = self.linked if edited and self.report else self.original
        vm.image = pe
        vm.base = self.base
        symbols = dict(self.original_symbols)
        entries = dict(self.original_entries)
        if edited and self.report:
            def mapped(address):
                rva = address-self.base
                row = self.ranges[bisect.bisect_right(self.starts, rva)-1]
                return self.base+row["mapped_begin"]+rva-row["begin"]
            symbols = {k: mapped(v) for k,v in symbols.items()}
            entries = {k: self.base+self.report["symbols"][k] for k in entries}
            entries.update({k:self.base+v for k,v in self.report["symbols"].items()
                            if k.startswith("SV_HostNav_")})
        vm.symbols = symbols
        vm.entries = entries
        hooks = {symbols[r["name"]]:r["name"] for r in self.proof["bindings"] if r["kind"] == "function"}
        common = {"?Enabled@HostScale@@YA_NXZ":"mode", "?Population@HostScale@@YAIXZ":"population",
                  "Com_Optimized_IsEnabled":"mode", "Com_Printf":"print", "memcpy":"memcpy",
                  "memset":"memset", "GetCurrentThreadId":"thread-id", "__security_check_cookie":"cookie"}
        if edited and self.report:
            for name, alias in common.items():
                if name in self.report["symbols"]:
                    hooks[self.base+self.report["symbols"][name]] = alias
            for desc in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in desc.imports:
                    if imp.name == b"GetCurrentThreadId":
                        vm.put(imp.address, 0x180ff1000, "<Q")
                        hooks[0x180ff1000] = "thread-id"
        elif edited:
            externals = dict(symbols)
            section_addresses = {}
            cursor = 0x180000000
            for index,obj in enumerate(self.objects):
                for section in obj["sections"]:
                    section_addresses[index,section["number"]] = cursor
                    cursor += max(0x10000, (len(section["data"])+65535)&-65536)
                for symbol in obj["symbols"].values():
                    if symbol["section"] > 0 and symbol["storage"] == 2:
                        externals[symbol["name"]] = section_addresses[index,symbol["section"]]+symbol["value"]
            for name,alias in common.items():
                if name not in externals:
                    externals[name] = cursor
                    hooks[cursor] = alias
                    cursor += 32
            externals["__imp_GetCurrentThreadId"] = cursor
            vm.put(cursor, externals["GetCurrentThreadId"], "<Q")
            externals["_fltused"] = cursor+16
            for index,obj in enumerate(self.objects):
                addresses = {i:section_addresses[index,s["section"]]+s["value"] if s["section"] > 0
                             else externals[s["name"]] if s["section"] == 0 else s["value"]
                             for i,s in obj["symbols"].items()}
                for section in obj["sections"]:
                    start = section_addresses[index,section["number"]]
                    data = bytearray(section["data"])
                    for offset,number,kind in section["relocations"]:
                        target = addresses[number]
                        if 4 <= kind <= 9:
                            value = struct.unpack_from("<i",data,offset)[0]+target-start-offset-4-(kind-4)
                            struct.pack_into("<i",data,offset,value)
                        elif kind == 1:
                            struct.pack_into("<Q",data,offset,struct.unpack_from("<Q",data,offset)[0]+target)
                        elif kind == 3:
                            struct.pack_into("<I",data,offset,(target-0x180000000)&0xffffffff)
                        else:
                            raise AssertionError(kind)
                    if data:
                        vm.put(start,bytes(data))
            entries.update({k:v for k,v in externals.items() if k in SOURCES or k.startswith("SV_HostNav_")})
        vm.hooks = hooks
        vm.mode,vm.population = mode,population
        vm.put(symbols["SVHS_LevelTime"],0,"<i")
        vm.put(symbols["SVHS_FrameDuration"],16,"<i")
        vm.put(symbols["SVHS_ClientCount"],population,"<I")
        # Both native originals end through the same target-build cookie routine.
        cookie = self.base+0x21ccf60
        if edited and self.report:
            cookie = mapped(cookie)
        hooks[cookie] = "cookie"
        return vm


class Machine:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86,UC_MODE_64)
        self.pages = set()
        self.events = []
        self.allocations = []
        self.thread = 7
        self.heap = 0x60000000
        self.scope = False
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing)
        self.uc.hook_add(UC_HOOK_CODE,self.boundary)

    def page(self,address):
        at = address & -4096
        if at not in self.pages:
            self.uc.mem_map(at,4096)
            if hasattr(self,"image") and self.base <= at < self.base+self.image.OPTIONAL_HEADER.SizeOfImage:
                data = self.image.get_data(at-self.base,4096)
                if data:self.uc.mem_write(at,data)
            self.pages.add(at)

    def put(self,address,value,fmt=None):
        data = struct.pack(fmt,value) if fmt else value
        for at in range(address&-4096,(address+len(data)+4095)&-4096,4096):self.page(at)
        self.uc.mem_write(address,data)

    def get(self,address,fmt):
        return struct.unpack(fmt,self.uc.mem_read(address,struct.calcsize(fmt)))[0]

    def missing(self,machine,access,address,size,value,user):
        if not self.base <= address < self.base+self.image.OPTIONAL_HEADER.SizeOfImage:
            raise AssertionError(f"Unexpected memory access {address:x}, PC {self.uc.reg_read(UC_X86_REG_RIP):x}")
        self.page(address);self.page(address+size-1)
        return True

    def ret(self,value=0):
        sp = self.uc.reg_read(UC_X86_REG_RSP)
        self.uc.reg_write(UC_X86_REG_RIP,self.get(sp,"<Q"))
        self.uc.reg_write(UC_X86_REG_RSP,sp+8)
        self.uc.reg_write(UC_X86_REG_RAX,value)

    def call(self,name,*args):
        stack,stop = 0x70080008,0x190000000
        self.put(stack-0x20000,bytes(0x22000));self.put(stack,stop,"<Q");self.page(stop)
        for address in self.hooks:
            self.page(address)
        self.uc.reg_write(UC_X86_REG_RSP,stack)
        for reg,value in zip((UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9),args):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(self.entries[name],stop,count=3000000)
        assert self.uc.reg_read(UC_X86_REG_RIP)==stop,name
        return self.uc.reg_read(UC_X86_REG_RAX)

    def boundary(self,machine,address,size,user):
        kind = self.hooks.get(address)
        if kind is None:return
        a,b,c,d = (self.uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9))
        if kind=="thread-id":self.ret(self.thread)
        elif kind=="mode":self.ret(self.mode!=0)
        elif kind=="population":self.ret(self.population)
        elif kind in ("cookie","print"):self.ret()
        elif kind in ("memcpy","SVHS_NavMemmove"):
            self.put(a,bytes(self.uc.mem_read(b,c)));self.ret(a)
        elif kind=="memset":self.put(a,bytes([b&255])*c);self.ret(a)
        elif kind=="SVHS_NavCollectArea":
            self.events.append(("collect",b,bytes(self.uc.mem_read(c,12)).hex()));self.ret()
        elif kind in ("SVHS_NavMalloc","allocator"):
            result=self.heap;self.heap+=(b+4095)&-4096
            self.put(result,bytes(b));self.allocations.append(b);self.ret(result)
        elif kind in ("SVHS_NavFree","free"):
            self.events.append(("free",b));self.ret()
        elif kind=="SVHS_ScriptEntity":self.ret(0x51000000)
        elif kind=="SVHS_Navigator":self.ret(0x51100000)
        elif kind=="SVHS_ScriptGetVector":self.put(c,struct.pack("<fff",*self.request));self.ret()
        elif kind=="SVHS_ScriptAddVector":self.output=bytes(self.uc.mem_read(b,12));self.ret()
        elif kind=="SVHS_IsBotEntity":self.ret(self.bot)
        elif kind in ("SVHS_Nav2DClosest","other-navigator"):
            self.put(c,struct.pack("<fff",91.,92.,93.));self.events.append(("native",));self.ret()
        elif kind=="SVHS_NavClosestArea":
            self.events.append(("closest",));self.put(a,struct.pack("<QQ",0x51400000,0x51500000) if self.found else bytes(16));self.ret()
        elif kind=="SVHS_NavProjectArea":
            chosen=self.get(a,"<Q")==0x51400000
            self.put(b,struct.pack("<fff",*(self.request if chosen else (1.,2.,3.))));self.ret()
        elif kind=="SVHS_NavDestroyArea":self.events.append(("destroy",self.get(a,"<Q")));self.ret()
        elif kind=="SVHS_NavGetClosestAreas":
            maximum=struct.unpack('<f',struct.pack('<I',self.uc.reg_read(UC_X86_REG_XMM3)&0xffffffff))[0]
            sp=self.uc.reg_read(UC_X86_REG_RSP)
            assert self.get(sp+40,'<I')==1
            output=self.get(sp+48,'<Q')
            self.events.append(('closest-areas',maximum))
            eligible=[(distance,index) for index,distance in enumerate(self.distances) if distance<=maximum]
            selected=min(eligible)[1] if eligible else None
            items=self.heap;self.heap+=4096
            self.put(items,0 if selected is None else 0x560000000+selected*128,'<Q')
            self.put(output,items,'<Q');self.put(output+8,int(selected is not None),'<I')
            self.put(output+12,1,'<I');self.ret()
        else:raise AssertionError(kind)


def graph(vm,count,blocked=False,tracked=True):
    search,generation,table,table_pointer,queue,spec,storage = (0x50000000,0x50001000,0x50002000,
        0x50003000,0x50004000,0x50005000,0x53000000)
    vm.put(generation,7,"<I");vm.put(table_pointer,table,"<Q")
    vm.put(search,struct.pack("<QQQ",generation,table_pointer,queue))
    vm.put(table,struct.pack("<"+"Q"*count,*[0x51000000+i*64 for i in range(count)]))
    vm.put(0x51000000,bytes(count*64));vm.put(0x52000000,bytes(count*32))
    for i in range(count):
        at=0x51000000+i*64
        vm.put(at+8,7 if i==0 else 0,"<I")
        vm.put(at+20,1 if blocked and i==count//2 else 0,"<I")
        vm.put(at+24,2,"<I")
        edges=0x52000000+i*32
        vm.put(at+32,edges,"<Q");vm.put(at+40,int(i+1<count),"<i")
        if i+1<count:vm.put(edges,struct.pack("<QB3xI",at+64,1,1))
    vm.put(spec,struct.pack("<IIIII",0,1,2,0,1))
    vm.put(storage,struct.pack("<QQ",0x51000000,0))
    vm.put(queue,struct.pack("<QQQQQQ",generation,2,storage,storage,storage+8,spec))
    vm.put(vm.symbols["SVHS_NavSystem"],0x5f000000,"<Q")
    vm.put(vm.symbols["SVHS_NavAllocationTag"],4,"<I")
    vm.put(0x5f000000,bytes(0x4000));vm.put(0x5f000008,0x5f001000,"<Q")
    vm.put(0x5f001010,0 if tracked==2 else 0x5f002000,"<Q")
    vm.put(0x5f00103c,int(tracked),"<I")
    vm.put(0x5f002000,0x5f003000,"<Q")
    vm.put(0x5f003000,0x180fa0000,"<Q");vm.put(0x5f003010,0x180fa0020,"<Q")
    vm.hooks[0x180fa0000]="allocator";vm.hooks[0x180fa0020]="free"
    result=vm.call("Bfx_IncrementalSearchToIsland",search,count-1)
    return dict(visited=[vm.get(0x51000000+i*64+8,"<I") for i in range(count)],
        capacity=vm.get(queue+8,"<Q"),read=vm.get(queue+24,"<Q")-vm.get(queue+16,"<Q"),
        write=vm.get(queue+32,"<Q")-vm.get(queue+16,"<Q"),allocations=vm.allocations)


def spatial(vm,seed,loose=0,children=0):
    rng=random.Random(seed)
    step,resource,collector,nodes,areas=0x50000000,0x50002000,0x50003000,0x51000000,0x52000000
    vm.put(step,bytes(8192));vm.put(resource,bytes(128));vm.put(collector,bytes(128))
    vm.put(collector+8,1000.,"<f");vm.put(collector+56,resource,"<Q");vm.put(resource+24,areas,"<Q")
    vm.put(nodes,bytes(8192));vm.put(areas,bytes(8192))
    vm.put(step,struct.pack("<QQQ",resource,step+24,collector));walk=step+24
    vm.put(walk,struct.pack("<ffffff",0.,0.,0.,1.,2.,3.));vm.put(walk+32,collector,"<Q")
    leaves=0
    def node(at,depth):
        nonlocal leaves
        if depth==0:
            offset=leaves*128;leaves+=1
            vm.put(at,0x80000000|offset,"<I")
            if children:
                child=0x54000000+offset*100
                vm.put(child,bytes(28+children*96));vm.put(child,children,"<I")
                vm.put(areas+offset+8,child,"<Q")
            return at+12
        after=node(at+12,depth-1)
        vm.put(at,struct.pack("<Iff",(rng.randrange(3)<<28)|(after-at),rng.uniform(-10,10),rng.uniform(-10,10)))
        return node(after,depth-1)
    node(nodes,3 if not children else 0)
    vm.put(walk+24,walk+56,"<Q");vm.put(walk+40,struct.pack("<Qff",nodes,0.,0.))
    vm.put(step+4160,0x55000000,"<Q");vm.put(0x55000000,struct.pack("<Qii",0x55001000,loose,0))
    if loose:
        vm.put(0x56000000,bytes(loose*128))
        vm.put(0x55001000,struct.pack("<"+"Q"*loose,*[0x56000000+i*128 for i in range(loose)]))
    result=vm.call("Bfx_ClosestReachableSearchStep",step,0x7fffffff)
    return dict(result=result,events=vm.events,top=vm.get(walk+24,"<Q"),index=vm.get(step+4168,"<i"))


def script(vm,bot=True,other=False):
    entity,navigator,vtable=0x51000000,0x51100000,0x51200000
    vm.put(entity,bytes(1440));vm.put(entity+336,0x54000000,"<Q")
    vm.put(navigator,bytes(1384));vm.put(navigator,vtable,"<Q");vm.put(vtable,bytes(400))
    target=vm.symbols["SVHS_Nav2DClosest"]
    if other:target=0x180fa0040;vm.hooks[target]="other-navigator"
    vm.put(vtable+360,target,"<Q")
    vm.put(navigator+1364,struct.pack("<QQ",0x51300000,0x51500000))
    vm.put(0x51300000,0x51300100,"<Q");vm.put(0x51400000,0x51400100,"<Q")
    vm.bot,vm.request,vm.found=bot,(10.,20.,30.),True


def closest(vm,distances,layer=0,present=True,tracked=True):
    vm.distances=distances
    vm.put(0x50000000,bytes(512))
    if present and layer<32:
        vm.put(0x50000020+layer*8,0x50001000,'<Q')
    vm.put(vm.symbols['SVHS_NavSystem'],0x5f000000,'<Q')
    vm.put(vm.symbols['SVHS_NavAllocationTag'],5,'<I')
    vm.put(0x5f000000,bytes(0x4000));vm.put(0x5f000008,0x5f001000,'<Q')
    vm.put(0x5f001010,0x5f002000,'<Q');vm.put(0x5f00103c,int(tracked),'<I')
    vm.put(0x5f002000,0x5f003000,'<Q');vm.put(0x5f003010,0x180fa0020,'<Q')
    vm.hooks[0x180fa0020]='free'
    result=vm.call('Bfx_GetClosestArea',0x50000000,0x50002000,layer,0x50003000)
    queries=[x[1] for x in vm.events if x[0]=='closest-areas']
    released=[x[1] for x in vm.events if x[0]=='free']
    assert len(queries)==len(released) and len(released)==len(set(released)), 'Native result-array ownership changed'
    return result,queries


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot",type=Path,required=True)
    parser.add_argument("--build",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();runner=Runner(args.snapshot,args.build);total=0
    for count in (1,2,7,65):
        for blocked in (False,True):
            for tracked in (False,True,2):
                original=graph(runner.machine(False),count,blocked,tracked)
                compiled=graph(runner.machine(True),count,blocked,tracked)
                assert compiled==original,(count,blocked,tracked,compiled,original)
                total+=1
    print("PASS native graph filters, queue growth and ownership",total,flush=True)
    for seed in range(12):
        original=spatial(runner.machine(False),seed,loose=seed%4,children=seed%3 if seed%2 else 0)
        compiled=spatial(runner.machine(True),seed,loose=seed%4,children=seed%3 if seed%2 else 0)
        assert compiled==original,(seed,compiled,original)
        total+=1
    print("PASS native spatial ordering and list progress",total,flush=True)
    vm=runner.machine(True,mode=1);assert vm.call("SV_HostNav_Begin",0,150)==1
    reduced=graph(vm,5000);assert sum(n==7 for n in reduced["visited"])==2049;vm.call("SV_HostNav_End",0);total+=1
    for loose,children in ((5000,0),(0,5000)):
        vm=runner.machine(True,mode=1);assert vm.call("SV_HostNav_Begin",0,150)==1
        reduced=spatial(vm,1,loose,children);assert len(reduced["events"])<=512,reduced
        vm.call("SV_HostNav_End",0);total+=1
    vm=runner.machine(True,mode=1);vm.call("SV_HostNav_Begin",0,150);vm.thread=8
    independent=graph(vm,2200);assert all(n==7 for n in independent["visited"]);total+=1
    for mode,population,bot,other in ((0,150,True,False),(1,20,True,False),(1,150,False,False),(1,150,True,True)):
        vm=runner.machine(True,mode,population);script(vm,bot,other)
        vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
        assert struct.unpack("<fff",vm.output)==(91.,92.,93.);total+=1
    vm=runner.machine(True,1,150);script(vm)
    vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
    assert struct.unpack("<fff",vm.output)==vm.request
    vm.put(vm.symbols["SVHS_LevelTime"],16,"<i")
    vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
    assert struct.unpack("<fff",vm.output)==vm.request and vm.events.count(("closest",))==1
    vm.request=(50.,60.,70.)
    vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
    assert struct.unpack("<fff",vm.output)==(1.,2.,3.)
    vm.put(vm.symbols["SVHS_LevelTime"],160,"<i");vm.found=False
    vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
    assert struct.unpack("<fff",vm.output)==(1.,2.,3.);total+=4
    # All 150 occupied ordinals receive a turn, with no more than 15 per frame.
    vm=runner.machine(True,1,150);seen=[]
    for frame in range(10):
        vm.put(vm.symbols["SVHS_LevelTime"],frame*16,"<i");admitted=[]
        for ordinal in range(150):
            if vm.call("SV_HostNav_Begin",ordinal,150)==1:admitted.append(ordinal)
            vm.call("SV_HostNav_End",0)
        assert len(admitted)==15;seen+=admitted
    assert sorted(seen)==list(range(150));total+=1
    for distances in ([],[0.],[1023.5],[1024.],[1024.5],[100000.],[900.,12.,1025.],[1024.,1024.,1025.]):
        for tracked in (False,True):
            native,original_queries=closest(runner.machine(False),distances,tracked=tracked)
            off,off_queries=closest(runner.machine(True,0),distances,tracked=tracked)
            on,queries=closest(runner.machine(True,1),distances,tracked=tracked)
            assert (off,off_queries)==(native,original_queries)
            assert on==native
            assert queries[0]==1024.
            assert len(queries)==(1 if distances and min(distances)<=1024 else 2)
            total+=1
    for layer,present in ((32,True),(0xffffffff,True),(0,False)):
        assert closest(runner.machine(True,1),[1.],layer,present)==(0,[])
        total+=1
    receipt=dict(passed=True,cases=total,scope=__doc__,live_game_tested=False,
        linked_executable_sha256=runner.report["sha256"] if runner.report else None,
        graph_budget=2048,spatial_budget=512,occupied_slots_fairness=150)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n")
    print("PASS",total,"navigation instruction cases",flush=True)


if __name__=="__main__":main()
