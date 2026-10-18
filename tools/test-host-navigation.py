"""Differential native/compiled navigation instructions; no game launch."""
import argparse
import bisect
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import random
import struct
import subprocess
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("Scr_GetClosestReachablePointOnNavmesh", "Bfx_ClosestReachableTreeStep",
           "Bfx_ClosestReachableSearchStep", "Bfx_IncrementalSearchToIsland", "SV_HostScaleNavigation",
           "Bfx_GetClosestArea", "Bfx_ClosestAreaTreeStep", "Bfx_ClosestAreaCollect",
           "Bot_UpdateMove_OffPathGrid", "Sentient_NearestTacPoint")


class Runner:
    def __init__(self, snapshot, build):
        self.snapshot = snapshot
        self.proof = json.loads((snapshot / "generated/host-scale-integration.json").read_bytes())
        original_path = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
        assert hashlib.file_digest(original_path.open('rb'), 'sha256').hexdigest() == self.proof['image_sha256']
        self.original = pefile.PE(str(original_path), fast_load=True)
        self.base = self.original.OPTIONAL_HEADER.ImageBase
        catalog = json.loads((snapshot / 'generated/function-catalog.json').read_bytes())
        goal_row = next(row for row in catalog['functions'] if row['id'] == 'fn_8e3f1a92f87cbed1')
        goal_bytes = self.original.get_data(goal_row['rva'], 686)
        goal_hash = '988c6a94990c66fcd7b50ebd32fd9297736e3cfae8567a6cb03fb65b8479da09'
        assert hashlib.sha256(goal_bytes).hexdigest() == goal_hash
        goal_instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(goal_bytes, self.base + goal_row['rva']))
        assert any(row.mnemonic == 'mov' and row.op_str == 'eax, dword ptr [rcx + 0x204]' for row in goal_instructions)
        assert any(row.mnemonic == 'mov' and row.op_str == 'dword ptr [rbx + 0x204], ebp' for row in goal_instructions)
        self.goal_type_proof = dict(function_id=goal_row['id'], original_rva=goal_row['rva'],
            bytes=686, sha256=goal_hash, type_offset=516, script_position_offset=472, native_route_goal_offset=536)
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
                            if k.startswith(("SV_HostNav_", "SV_HostScale_", "SV_HostBot_UpdateTravelUrgency", "?RecordBotFrame"))})
        vm.symbols = symbols
        vm.entries = entries
        hooks = {symbols[r["name"]]:r["name"] for r in self.proof["bindings"] if r["kind"] == "function"}
        common = {"?Enabled@HostScale@@YA_NXZ":"mode", "?Population@HostScale@@YAIXZ":"population",
                  "Com_Optimized_IsEnabled":"mode", "Com_Printf":"print", "memcpy":"memcpy",
                  "memset":"memset", "GetCurrentThreadId":"thread-id", "__security_check_cookie":"cookie",
                  "QueryPerformanceCounter":"qpc", "QueryPerformanceFrequency":"qpf",
                  "Sys_IsMainThread":"main-thread", "Cmd_AddCommandInternal":"register-command",
                  "SV_HostNav_PrintStatus":"print", "SV_HostBot_GetLootGoal":"loot-goal",
                  "SV_HostBot_InGulag":"gulag", "SVHBE_WeaponMap":"weapon-map",
                  "DW_BotPolicy_ProfileSeed":"mapped-profile"}
        common["sqrtf"] = "sqrtf"
        common.update({"SV_HostBot_GasEvacuationRequired":"gas-required",
                       "SV_HostBot_GetGasGoal":"gas-goal", "SV_HostBot_GetGasState":"gas-state"})
        planner_names = self.report["symbols"] if self.report else {
            symbol["name"] for obj in self.objects for symbol in obj["symbols"].values()
        } if edited else ()
        for name in planner_names:
            if "@HostBotPlanner@@" in name:
                common[name] = "planner-" + name.split("@", 1)[0][1:].lower()
        if not self.report:
            # Object-only navigation fixtures model the equipment boundary.
            # A linked fixture executes the actual compiled read-only helper.
            common["SV_HostBot_EquipmentActionActive"] = "equipment-active"
        if edited and self.report:
            for name, alias in common.items():
                if name in self.report["symbols"]:
                    hooks[self.base+self.report["symbols"][name]] = alias
            for desc in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in desc.imports:
                    if imp.name in (b"GetCurrentThreadId", b"QueryPerformanceCounter", b"QueryPerformanceFrequency"):
                        slot = (b"GetCurrentThreadId", b"QueryPerformanceCounter", b"QueryPerformanceFrequency").index(imp.name)
                        target = 0x180ff1000 + slot * 32
                        vm.put(imp.address, target, "<Q")
                        hooks[target] = common[imp.name.decode()]
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
            for name in ("GetCurrentThreadId", "QueryPerformanceCounter", "QueryPerformanceFrequency"):
                externals["__imp_" + name] = cursor
                vm.put(cursor, externals[name], "<Q")
                cursor += 16
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
            entries.update({k:v for k,v in externals.items() if k in SOURCES or k.startswith(("SV_HostNav_", "SV_HostScale_", "SV_HostBot_UpdateTravelUrgency", "?RecordBotFrame"))})
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
        elif kind == 'sqrtf':
            value = struct.unpack('<f', struct.pack('<I', self.uc.reg_read(UC_X86_REG_XMM0) & 0xffffffff))[0]
            bits = struct.unpack('<I', struct.pack('<f', math.sqrt(value)))[0]
            self.uc.reg_write(UC_X86_REG_XMM0, bits);self.ret()
        elif kind.startswith('planner-'):
            action = kind.removeprefix('planner-')
            if action == 'enabled':self.ret(getattr(self, 'gpu_enabled', False))
            elif action == 'pending':self.ret(getattr(self, 'gpu_state', 0) != 0)
            elif action == 'take':
                state = getattr(self, 'gpu_state', 0) if getattr(self, 'gpu_enabled', False) else 0
                if state == 2:
                    output = self.get(self.uc.reg_read(UC_X86_REG_RSP) + 64, '<Q')
                    self.put(output, struct.pack('<3f', *self.gpu_waypoint)); self.gpu_state = 0
                self.ret(state)
            elif action == 'queue':
                enabled = getattr(self, 'gpu_enabled', False)
                if enabled:self.gpu_queues = getattr(self, 'gpu_queues', 0) + 1
                accepted = enabled and getattr(self, 'gpu_queue_accept', False)
                if accepted:self.gpu_state = 1
                self.ret(accepted)
            elif action == 'cancel':self.gpu_state = 0;self.ret()
            else:self.ret()
        elif kind == "cookie":self.ret(self.uc.reg_read(UC_X86_REG_RAX))
        elif kind == "print":self.ret()
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
        elif kind=="SVHS_IsBotEntity":self.ret(getattr(self, 'bot', True))
        elif kind=="SVHS_IsBotPlaying":self.ret(getattr(self, 'playing_bot', True))
        elif kind=="mapped-profile":
            self.put(b, 120, '<Q');self.ret(getattr(self, 'mapped_profile', True))
        elif kind in ("SVHS_Nav2DClosest","other-navigator"):
            self.put(c,struct.pack("<fff",91.,92.,93.));self.events.append(("native",));self.ret()
        elif kind=="SVHS_NavClosestArea":
            self.project_request = struct.unpack('<3f', self.uc.mem_read(b, 12))
            self.events.append(("closest",));self.put(a,struct.pack("<QQ",0x51400000,0x51500000) if self.found else bytes(16));self.ret()
        elif kind=="SVHS_NavProjectArea":
            chosen=self.get(a,"<Q")==0x51400000
            self.put(b,struct.pack("<fff",*(self.project_request if chosen else (1.,2.,3.))));self.ret()
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
        elif kind=="SVHS_NavCollectClosest":
            point=struct.unpack('<fff',self.uc.mem_read(c,12))
            center=struct.unpack('<fff',self.uc.mem_read(b+32,12))
            distance=float32(math.sqrt(sum((x-y)**2 for x,y in zip(point,center))))
            self.events.append(('candidate',b))
            if not getattr(self, 'reject_nearest', False) and distance<=self.get(a+8,'<f'):
                self.closest_selected=b
                self.put(a+8,distance,'<f')
                self.put(a+24,1,'<i')
            self.ret()
        elif kind=="SVHS_NavProjectClosest":
            self.events.append(('project',b))
            self.put(a,struct.pack('<fff',*self.projection));self.ret()
        elif kind=="SVHS_NavInsertClosest":
            distance=struct.unpack('<f',struct.pack('<I',self.uc.reg_read(UC_X86_REG_XMM2)&0xffffffff))[0]
            self.events.append(('insert',self.get(b,'<Q'),struct.pack('<f',distance).hex()))
            self.put(a+8,1,'<i');self.ret()
        elif kind=="SVHS_NavFarthestClosest":
            self.uc.reg_write(UC_X86_REG_XMM0,struct.unpack('<I',struct.pack('<f',self.farthest))[0]);self.ret()
        elif kind == 'SVHS_BotCanFire':self.ret(getattr(self, 'can_fire', False))
        elif kind in ('weapon-map', 'SVHBE_WeaponMap'):self.ret(0x5f000000)
        elif kind == 'SVHS_SprintLeftRaw':
            assert a == 0x5f000000 and b == 0x5b030000
            self.ret(getattr(self, 'sprint_left', 0))
        elif kind == 'SVHS_BotUpdateSprinting':
            assert a == 0x5b000000
            if getattr(self, 'approve_sprint', True):self.put(b, self.get(b, '<Q') | 2, '<Q')
            self.ret()
        elif kind == 'loot-goal':
            goal = getattr(self, 'loot_goal', None)
            if goal is not None:self.put(b, struct.pack('<3f', *goal))
            self.ret(goal is not None)
        elif kind == 'gas-required':self.ret(getattr(self, 'gas_required', False))
        elif kind == 'gas-goal':
            goal = getattr(self, 'gas_goal', None) if getattr(self, 'gas_required', False) else None
            if goal is not None:self.put(b, struct.pack('<3f', *goal))
            self.ret(goal is not None)
        elif kind == 'gas-state':
            valid = getattr(self, 'gas_required', False)
            if valid:
                self.put(a, struct.pack('<3f3fffiiBBxx', *getattr(self, 'gas_center', (0., 0., 0.)),
                    *getattr(self, 'gas_center', (0., 0., 0.)), getattr(self, 'gas_radius', 1000.),
                    getattr(self, 'gas_radius', 1000.), 1000, 1, False, True))
            self.ret(valid)
        elif kind == 'gulag':self.ret(getattr(self, 'gulag', False))
        elif kind == 'equipment-active':
            self.ret(bool(a and self.get(a + 448, '<Q') and self.get(a + 28068, '<I') & 3))
        elif kind == 'SVHS_NavHasPath':self.ret(getattr(self, 'path_exists', False))
        elif kind == 'SVHS_BotYawVectors':
            self.put(b,struct.pack('<3f',1.,0.,0.));self.put(c,struct.pack('<3f',0.,-1.,0.));self.ret()
        elif kind == 'SVHS_BotPathToGoal':
            self.events.append(('path-request',struct.unpack('<3f',self.uc.mem_read(b,12))))
            self.put(a + 536, bytes(self.uc.mem_read(b, 12)))
            self.path_exists=getattr(self, 'route_success', True);self.ret(self.path_exists)
        elif kind == 'SVHS_BotMovePathing':
            self.events.append(('follow-path',));self.put(b+156,struct.pack('<bb',90,35));self.ret(1)
        elif kind == 'SVHS_BotSteerPath':
            self.events.append(('steer-path',c));self.put(b+156,struct.pack('<bb',40,110));self.ret()
        elif kind == 'SVHS_EnemyTeamFlags':
            flags = bytearray([255] * 20)
            if b:
                word = struct.unpack_from('<I', flags, (b >> 5) * 4)[0]
                struct.pack_into('<I', flags, (b >> 5) * 4, word & ~(0x80000000 >> (b & 31)))
            self.put(a, bytes(flags));self.ret()
        elif kind == 'SVHS_TacSetReference':
            self.tac_selected=b;self.put(a,bytes(4));self.events.append(('set-tactical',b));self.ret()
        elif kind == 'SVHS_TacGetReference':self.ret(getattr(self,'tac_selected',0))
        elif kind == 'SVHS_NavConstructArea':self.put(a,bytes(16));self.ret()
        elif kind == 'SVHS_NavClosestVerticalDefault':
            self.events.append(('vertical-search',));self.put(b,struct.pack('<3f',0.,0.,0.));self.ret(1)
        elif kind == 'SVHS_TacClosestWithLos':self.ret(getattr(self,'tac_point',0))
        elif kind == 'SVHS_TacClosest':self.ret(getattr(self,'tac_fallback',0))
        elif kind == 'SVHS_PathNodePosition':self.put(b,struct.pack('<3f',*self.node_position));self.ret()
        elif kind == 'SVHS_TacPointForNode':self.ret(getattr(self,'node_tac',0))
        elif kind == 'navigator-tactical':self.ret(getattr(self,'navigator_tac',0))
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


def float32(value):
    return struct.unpack('<f',struct.pack('<f',value))[0]


def nearest_tree(vm,seed,count=256,point=(150.,-220.,-8000.),steps=0x7fffffff,maximum=9.2233715e18,
                 coordinates=None,offset=(0.,0.,0.),axes=(0,1,2),rotation=0.):
    rng=random.Random(seed)
    points=[tuple(float32(rng.uniform(-50000.,50000.)) for _ in range(2))+
            (float32(rng.uniform(-1000.,1000.)),) for _ in range(count)]
    # Include a known ground point beneath the request and ties at its distance.
    if count>=3:points[:3]=[(point[0],point[1],20.),(point[0],point[1],20.),(point[0],point[1],40.)]
    if coordinates is not None:
        points=[tuple(float32(v) for v in row) for row in coordinates]
        count=len(points)
    def world(position):
        cosine,sine=math.cos(rotation),math.sin(rotation)
        return (float32(position[0]*cosine-position[1]*sine+offset[0]),
                float32(position[0]*sine+position[1]*cosine+offset[1]),float32(position[2]+offset[2]))
    world_point=world(point)
    walk,collector,resource,areas,nodes=0x57000000,0x57002000,0x57003000,0x58000000,0x59000000
    vm.put(walk,bytes(4136));vm.put(collector,bytes(64));vm.put(resource,bytes(32))
    vm.put(collector+8,maximum,'<f');vm.put(collector+56,resource,'<Q');vm.put(resource+24,areas,'<Q')
    vm.put(walk,struct.pack('<ffffff',*point,*world_point));vm.put(walk+32,collector,'<Q')
    for index,center in enumerate(points):
        vm.put(areas+index*96,bytes(96));vm.put(areas+index*96+32,struct.pack('<fff',*world(center)))
    raw=bytearray()
    def node(indices,depth):
        at=len(raw);raw.extend(bytes(12))
        if len(indices)==1:
            struct.pack_into('<I',raw,at,0x80000000|indices[0]*96)
            return at
        axis=axes[depth%3]
        indices=sorted(indices,key=lambda index:points[index][axis])
        middle=len(indices)//2;left,right=indices[:middle],indices[middle:]
        assert node(left,depth+1)==at+12
        offset=node(right,depth+1)-at
        struct.pack_into('<Iff',raw,at,(axis<<28)|offset,max(points[i][axis] for i in left),min(points[i][axis] for i in right))
        return at
    if count:
        node(list(range(count)),0);vm.put(nodes,bytes(raw))
        vm.put(walk+40,struct.pack('<QfI',nodes,0.,0));vm.put(walk+24,walk+56,'<Q')
    else:vm.put(walk+24,walk+40,'<Q')
    vm.closest_selected=0
    calls=0
    if not count:assert vm.call('Bfx_ClosestAreaTreeStep',walk,steps)==0
    while vm.get(walk+24,'<Q')>walk+40:
        vm.call('Bfx_ClosestAreaTreeStep',walk,steps);calls+=1
        assert calls<=len(points)*4+1,'Tree failed to make progress'
    return dict(selected=vm.closest_selected,maximum=vm.get(collector+8,'<f'),
                events=vm.events,top=vm.get(walk+24,'<Q'),calls=calls)


def nearest_collector(vm,case):
    collector,area,point,spec=0x57002000,0x58000000,0x58001000,0x58002000
    vm.put(collector,bytes(64));vm.put(area,bytes(96));vm.put(point,struct.pack('<fff',*case['point']))
    vm.put(spec,struct.pack('<5I',case.get('obstacle_mode',0),case.get('obstacle_mask',7),case.get('area_mask',2),0,0))
    vm.put(collector,spec,'<Q');vm.put(collector+8,case.get('maximum',100.),'<f')
    vm.put(collector+40,1,'<i')
    vm.put(area+32,struct.pack('<fff',*case.get('center',(0.,0.,0.))))
    vm.put(area+44,case.get('radius',0.),'<f');vm.put(area+52,case.get('area_flags',2),'<I')
    vm.put(area+56,case.get('shape_flags',0),'<I');vm.put(area+68,case.get('obstacle_flags',0),'<I')
    vm.projection=case.get('projection',(0.,0.,0.));vm.farthest=case.get('farthest',12.)
    # Tree fixtures model the collector boundary; this fixture executes the
    # actual native/recompiled collector rather than that tree boundary model.
    vm.hooks.pop(vm.entries['Bfx_ClosestAreaCollect'],None)
    vm.call('Bfx_ClosestAreaCollect',collector,area,point)
    return dict(events=vm.events,maximum=bytes(vm.uc.mem_read(collector+8,4)).hex(),count=vm.get(collector+24,'<i'))


def mesh_bot(vm, mode_case, targets=(), target_handle=None, teams=(), command_bytes=None,
             goal_type=0, native_goal=None, existing_path=False, route_goal=None):
    bot, entity, sentient, player = 0x5b000000, 0x5b010000, 0x5b020000, 0x5b030000
    nav, vtable, command, area = 0x5b040000, 0x5b050000, 0x5b060000, 0x5b070000
    vm.put(bot, bytes(28152));vm.put(entity, bytes(1440));vm.put(sentient, bytes(184))
    # Allocate the complete prefix consumed by shared movement/equipment views,
    # including skydiving state12072 and BR game-extra flags22336. The native
    # player allocation contains these bytes; a one-page model falsely faults.
    vm.put(player, bytes(22340));vm.put(nav, bytes(1400));vm.put(vtable, bytes(512))
    vm.put(command, command_bytes or bytes(264));vm.put(area, 0x5b071000, '<Q')
    vm.put(0x51400000, 0x51400100, '<Q'); vm.found = mode_case != 'unreachable'
    for at,value in ((bot,entity),(bot+8,sentient),(bot+360,nav),(bot+448,player),
                     (entity+336,player),(entity+344,sentient),(nav,vtable),
                     (vtable+45*8,vm.symbols['SVHS_Nav2DClosest']),
                     (nav+1364,area),(nav+1372,0x5b080000)):
        vm.put(at,value,'<Q')
    vm.put(entity+440,100,'<i');vm.put(bot+8984,0x1000000,'<I')
    vm.put(sentient+16, 2, '<I')
    vm.put(player+626,2046,'<H');vm.put(vm.symbols['SVHS_LevelTime'],1000,'<i')
    vm.put(vm.symbols['SVHS_ClientCount'],0,'<I')
    if targets:
        vm.put(vm.symbols['SVHS_Clients'], bytes(1600))
        vm.put(vm.symbols['SVHS_ClientCount'], len(targets) + 1, '<I')
        for slot, xyz in enumerate(targets, 1):
            client = 0x5e000000 + slot * 0x10000
            target_entity, target_sentient = client + 0x1000, client + 0x2000
            vm.put(client, bytes(0x3000))
            vm.put(vm.symbols['SVHS_Clients'] + slot * 8, client, '<Q')
            vm.put(client + 8, 5, '<B'); vm.put(client + 280, target_entity, '<Q')
            vm.put(target_entity, slot, '<H'); vm.put(target_entity + 344, target_sentient, '<Q')
            vm.put(target_entity + 440, 100, '<i')
            vm.put(target_sentient + 16, teams[slot - 1] if teams else 1, '<I')
            vm.put(target_entity + 304, struct.pack('<3f', *xyz))
        vm.put(sentient + 72, 2 if target_handle is None else target_handle, '<H')
    vm.put(bot+640,1,'<i');vm.put(bot+28136,struct.pack('<3f',0.5,0.25,0.))
    vm.put(bot+516,goal_type,'<I')
    if native_goal is not None:
        # The script setter owns position472; routeGoal536 may still belong to
        # an older route. Critical repair must use the requested script position.
        vm.put(bot+472,struct.pack('<3f',*native_goal))
        vm.put(bot+536,struct.pack('<3f',*(route_goal if route_goal is not None else native_goal)))
    if existing_path:
        vm.path_exists = True
        vm.put(bot+640,0,'<i')
    if mode_case in ('tactical', 'tactical-no-path'):
        vm.put(sentient+150,1,'<B')
        vm.path_exists = mode_case == 'tactical'
    if mode_case=='locked':vm.put(player+364,0x20,'<I')
    if mode_case=='airborne':vm.put(player+626,2047,'<H')
    if mode_case=='no-area':vm.put(nav+1364,0,'<Q')
    if mode_case=='failed':vm.route_success=False
    result=vm.call('Bot_UpdateMove_OffPathGrid',bot,command)
    return dict(result=result,movement=bytes(vm.uc.mem_read(command+156,2)).hex(),events=vm.events)


def install_bot_tls(vm):
    teb, slots, tls = 0x5d000000, 0x5d001000, 0x5d002000
    for at in (teb, slots, tls):
        vm.put(at, bytes(128))
    vm.put(teb + 0x58, slots, '<Q'); vm.put(slots, tls, '<Q')
    vm.uc.reg_write(UC_X86_REG_GS_BASE, teb)
    vm.put(vm.symbols['SVHS_BotTlsIndex'], 0, '<I')
    vm.put(vm.symbols['SVHS_GameStatics'], 0x5d003000, '<Q')
    vm.put(tls + 16, 0x5d004000, '<Q')
    return tls


def map_mesh_bot(vm):
    bot, entity = 0x5b000000, 0x5b010000
    client = bot - 1368
    vm.put(client, bytes(1368));vm.put(client + 280, entity, '<Q')
    vm.put(client + 214756, 2, '<i')
    vm.put(vm.symbols['SVHS_Clients'], client, '<Q')
    vm.put(vm.symbols['SVHS_ClientCount'], 1, '<I')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot",type=Path,required=True)
    parser.add_argument("--build",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();runner=Runner(args.snapshot,args.build);total=0
    urgency_cases = 0
    for mode, population in ((0, 20), (1, 20), (2, 150)):
        for denial in ('none', 'fire', 'ads-button', 'use', 'armor', 'ads-fraction', 'up-required',
                       'grenade-button', 'tactical-button', 'equipment-cook', 'equipment-script',
                       'skydiving', 'ladder',
                       'downed', 'dead', 'airborne', 'locked', 'gulag', 'no-path', 'short',
                       'no-meter', 'native-denied', 'tac-disabled', 'medium-route',
                       'boundary-route', 'human', 'unmapped', 'stale-slot', 'stale-player',
                       'stale-sentient', 'native-not-playing'):
            vm = runner.machine(True, mode, population)
            mesh_bot(vm, 'normal'); tls = install_bot_tls(vm)
            bot, entity, player, cmd = 0x5b000000, 0x5b010000, 0x5b030000, 0x5b060000
            client = bot - 1368
            vm.put(client, bytes(1368)); vm.put(client + 280, entity, '<Q')
            vm.put(client + 214756, 2, '<i')
            vm.put(vm.symbols['SVHS_Clients'], client, '<Q')
            vm.put(vm.symbols['SVHS_ClientCount'], 1, '<I')
            vm.put(cmd + 12, 1000, '<i'); vm.sprint_left = 1500
            if denial == 'fire':vm.put(cmd, 1, '<Q')
            elif denial == 'ads-button':vm.put(cmd, 0x200, '<Q')
            elif denial == 'use':vm.put(cmd, 8, '<Q')
            elif denial == 'armor':vm.put(player + 1796, 1 << 42, '<Q')
            elif denial == 'ads-fraction':vm.put(player + 1804, 0.5, '<f')
            elif denial == 'up-required':vm.put(player + 796, 1, '<i')
            elif denial == 'grenade-button':vm.put(cmd, 0x1000, '<Q')
            elif denial == 'tactical-button':vm.put(cmd, 0x2000, '<Q')
            elif denial == 'equipment-cook':vm.put(bot + 28068, 1, '<I')
            elif denial == 'equipment-script':vm.put(bot + 28068, 2, '<I')
            elif denial == 'skydiving':vm.put(player + 12072, 1, '<B')
            elif denial == 'ladder':vm.put(player + 20, 1 << 5, '<Q')
            elif denial == 'downed':vm.put(player + 28, 0x800, '<Q')
            elif denial == 'dead':vm.put(entity + 440, 0, '<i')
            elif denial == 'airborne':vm.put(player + 626, 2047, '<H')
            elif denial == 'locked':vm.put(player + 364, 0x20, '<I')
            elif denial == 'gulag':vm.gulag = True
            elif denial == 'no-path':vm.path_exists = False
            elif denial == 'short':vm.put(bot + 536, struct.pack('<3f', 255., 0., 0.))
            elif denial == 'medium-route':vm.put(bot + 536, struct.pack('<3f', 500., 0., 0.))
            elif denial == 'boundary-route':vm.put(bot + 536, struct.pack('<3f', 256., 0., 0.))
            elif denial == 'human':vm.put(client + 214756, 1, '<i')
            elif denial == 'unmapped':vm.mapped_profile = False
            elif denial == 'stale-slot':vm.put(vm.symbols['SVHS_Clients'], client + 8, '<Q')
            elif denial == 'stale-player':vm.put(bot + 448, player + 8, '<Q')
            elif denial == 'stale-sentient':vm.put(bot + 8, 0x5b020008, '<Q')
            elif denial == 'native-not-playing':vm.playing_bot = False
            elif denial == 'no-meter':vm.sprint_left = 500
            elif denial == 'native-denied':vm.approve_sprint = False
            elif denial == 'tac-disabled':vm.put(player + 20, 1 << 53, '<Q')
            before = bytes(vm.uc.mem_read(cmd, 264))
            vm.call('SV_HostBot_UpdateTravelUrgency', bot, cmd, 0)
            after = bytes(vm.uc.mem_read(cmd, 264))
            expected = 0 if not mode or denial not in ('none', 'tac-disabled', 'medium-route', 'boundary-route') else (
                2 if denial == 'tac-disabled' else 2 | 0x800000000000)
            assert vm.get(cmd, '<Q') == struct.unpack_from('<Q', before)[0] | expected, (mode, population, denial)
            assert after[8:] == before[8:] and vm.get(tls + 16, '<Q') == 0x5d004000
            if mode and denial == 'none':
                # Reusing a command carrying only our additions must remove
                # those additions before a newly arrived ADS or plate action.
                vm.put(cmd, vm.get(cmd, '<Q') | 0x200, '<Q')
                vm.call('SV_HostBot_UpdateTravelUrgency', bot, cmd, 1)
                assert vm.get(cmd, '<Q') == 0x200
            urgency_cases += 1
    total += urgency_cases
    for mode in (1, 2):
        vm = runner.machine(True, mode); mesh_bot(vm, 'normal')
        vm.put(vm.symbols['SVHS_LevelTime'], 1749, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert sum(e[0] == 'path-request' for e in vm.events) == 1
        vm.put(vm.symbols['SVHS_LevelTime'], 1750, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        requests = [e[1] for e in vm.events if e[0] == 'path-request']
        assert len(requests) == 2 and requests[1] != requests[0], '750ms stuck escape did not replan'
        vm = runner.machine(True, mode); mesh_bot(vm, 'normal')
        vm.put(0x5b010000 + 304, struct.pack('<3f', 700., 0., 0.))
        for now in (1016, 1032):
            vm.put(vm.symbols['SVHS_LevelTime'], now, '<i')
            vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert sum(e[0] == 'path-request' for e in vm.events) == 2, 'Reached goal waited for the old route cooldown'
        total += 2
    for case in ('normal','tactical','locked','airborne','no-area'):
        native=mesh_bot(runner.machine(False),case)
        off=mesh_bot(runner.machine(True,0),case)
        assert off==native,('off-grid baseline',case,off,native)
        if case!='normal':assert mesh_bot(runner.machine(True,1),case)==native
        total+=1
    # Gulag cold entry must not replay an exterior patrol or blindly strafe.
    # Only movement may change; the complete native command remains intact.
    command = bytes((i * 31 + 7) & 255 for i in range(264))
    for case in ('normal', 'tactical', 'locked', 'no-area'):
        native_vm, off_vm = runner.machine(False), runner.machine(True, 0)
        native_vm.gulag = off_vm.gulag = True
        assert mesh_bot(native_vm, case, command_bytes=command) == mesh_bot(off_vm, case, command_bytes=command)
        total += 1
    for mode in (1, 2):
        for case, firing in (('normal', False), ('no-area', False), ('tactical', False),
                             ('locked', False), ('normal', True)):
            vm = runner.machine(True, mode); vm.gulag = True; vm.can_fire = firing
            result = mesh_bot(vm, case, command_bytes=command)
            after = bytes(vm.uc.mem_read(0x5b060000, 264))
            stopped = case in ('normal', 'no-area') and not firing
            expected = command[:156] + bytes(2) + command[158:] if stopped else command
            assert after == expected, ('Gulag command preservation', mode, case, firing)
            assert result['result'] == int(stopped), (mode, case, firing)
            assert not any(e[0] in ('path-request', 'follow-path', 'steer-path') for e in vm.events)
            total += 1
        vm = runner.machine(True, mode); vm.gulag = True
        mesh_bot(vm, 'tactical', command_bytes=command)
        tls = install_bot_tls(vm); before = len(vm.events)
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == [('steer-path', 127)]
        assert vm.get(tls + 16, '<Q') == 0x5d004000
        # Readiness requires both live handle components, even with a path.
        for offset in (1364, 1372):
            previous = vm.get(0x5b040000 + offset, '<Q')
            vm.put(0x5b040000 + offset, 0, '<Q'); before = len(vm.events)
            vm.put(0x5b060000, command)
            vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
            assert len(vm.events) == before and bytes(vm.uc.mem_read(0x5b060000, 264)) == command
            assert vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000) == 1
            assert bytes(vm.uc.mem_read(0x5b060000, 264)) == command[:156] + bytes(2) + command[158:]
            vm.put(0x5b040000 + offset, previous, '<Q')
            total += 1
        vm.can_fire = True; before = len(vm.events)
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert len(vm.events) == before
        vm.can_fire = False; vm.put(0x5b030000 + 364, 0x20, '<I')
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert len(vm.events) == before
        total += 3
        # Entering Gulag releases only fallback ownership, retaining its native
        # path. Leaving again must not revive the earlier exterior request.
        vm = runner.machine(True, mode); mesh_bot(vm, 'normal'); install_bot_tls(vm)
        vm.gulag = True; before = len(vm.events)
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == [('steer-path', 127)]
        vm.gulag = False; vm.path_exists = False; before = len(vm.events)
        vm.put(0x5b060000, command)
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert len(vm.events) == before and bytes(vm.uc.mem_read(0x5b060000, 264)) == command
        total += 2
    for mode in (1,2):
        success=mesh_bot(runner.machine(True,mode),'normal')
        assert success['movement']=='5a23' and success['events'][-1]==('follow-path',)
        assert any(e[0]=='path-request' for e in success['events'])
        tactical = mesh_bot(runner.machine(True, mode), 'tactical-no-path')
        assert tactical['movement'] == '5a23'
        assert any(event[0] == 'path-request' for event in tactical['events'])
        total += 1
        failed=mesh_bot(runner.machine(True,mode),'failed')
        assert failed['movement'] == mesh_bot(runner.machine(False), 'failed')['movement']
        assert all(e[0]!='follow-path' for e in failed['events'])
        unreachable = mesh_bot(runner.machine(True, mode), 'unreachable')
        assert unreachable['movement'] == mesh_bot(runner.machine(False), 'unreachable')['movement']
        assert all(e[0] not in ('path-request', 'follow-path') for e in unreachable['events'])
        total += 1
        total+=2
        # Execute the actual compiled movement entry with modeled authoritative
        # circle data. Escape outranks a pre-existing tactical route and combat.
        vm = runner.machine(True, mode)
        vm.gas_required = vm.can_fire = True
        vm.gas_center = vm.gas_goal = (2000., 0., 0.)
        vm.loot_goal = (-2000., 0., 0.)
        gas_route = mesh_bot(vm, 'normal', goal_type=5,
                             native_goal=(-2000., 0., 0.), existing_path=True)
        assert next(e[1] for e in gas_route['events'] if e[0] == 'path-request') == vm.gas_goal
        assert gas_route['events'][-1] == ('steer-path', 127)
        assert gas_route['movement'] == '286e'
        assert getattr(vm, 'gpu_queues', 0) == 0
        total += 1
        vm = runner.machine(True, mode)
        mesh_bot(vm, 'normal');map_mesh_bot(vm)
        vm.gpu_enabled = True;vm.gpu_state = 1
        before = len(vm.events)
        vm.put(vm.symbols['SVHS_LevelTime'], 1016, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == [('follow-path',)], 'Pending GPU work erased an existing native route'
        assert getattr(vm, 'gpu_queues', 0) == 0
        vm.gpu_state = 2;vm.gpu_waypoint = (320., 0., 0.)
        before = len(vm.events)
        vm.put(vm.symbols['SVHS_LevelTime'], 1032, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert next(e[1] for e in vm.events[before:] if e[0] == 'path-request') == vm.gpu_waypoint
        assert vm.events[-1] == ('follow-path',)
        # A completed patrol search must not replace a newly authored critical
        # script destination. The native critical route retains ownership.
        vm.gpu_state = 2
        vm.put(0x5b000000 + 516, 5, '<I')
        vm.put(0x5b000000 + 472, struct.pack('<3f', -1500., 400., 0.))
        vm.put(vm.symbols['SVHS_LevelTime'], 1048, '<i')
        before = len(vm.events)
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert not any(e[0] == 'path-request' for e in vm.events[before:])
        assert vm.gpu_state == 0, 'Stale GPU patrol survived a changed critical script goal'
        total += 3
        vm = runner.machine(True, mode)
        mesh_bot(vm, 'normal')
        # A cached decision must steer again without replanning or rescanning
        # every friendly client, with the same TLS contract as native BotThink.
        teb, slots, tls = 0x5d000000, 0x5d001000, 0x5d002000
        vm.put(teb, bytes(128)); vm.put(slots, bytes(128)); vm.put(tls, bytes(128))
        vm.put(teb + 0x58, slots, '<Q'); vm.put(slots, tls, '<Q')
        vm.uc.reg_write(UC_X86_REG_GS_BASE, teb)
        vm.put(vm.symbols['SVHS_BotTlsIndex'], 0, '<I')
        vm.put(vm.symbols['SVHS_GameStatics'], 0x5d003000, '<Q')
        vm.put(tls + 16, 0x5d004000, '<Q')
        before = len(vm.events)
        vm.put(vm.symbols['SVHS_LevelTime'], 1016, '<i')
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == [('steer-path', 127)]
        assert bytes(vm.uc.mem_read(0x5b060000 + 156, 2)) == bytes([40, 110])
        assert vm.get(tls + 16, '<Q') == 0x5d004000
        vm.path_exists = False
        before = len(vm.events)
        previous_command = bytes(vm.uc.mem_read(0x5b060000, 264))
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == []
        assert bytes(vm.uc.mem_read(0x5b060000, 264)) == previous_command
        total += 2
        # Native routes also need fresh corner steering between full decisions.
        vm = runner.machine(True, mode)
        mesh_bot(vm, 'tactical')
        vm.put(teb, bytes(128)); vm.put(slots, bytes(128)); vm.put(tls, bytes(128))
        vm.put(teb + 0x58, slots, '<Q'); vm.put(slots, tls, '<Q')
        vm.uc.reg_write(UC_X86_REG_GS_BASE, teb)
        vm.put(vm.symbols['SVHS_BotTlsIndex'], 0, '<I')
        vm.put(vm.symbols['SVHS_GameStatics'], 0x5d003000, '<Q')
        vm.put(tls + 16, 0x5d004000, '<Q')
        before = len(vm.events)
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == [('steer-path', 127)]
        assert vm.get(tls + 16, '<Q') == 0x5d004000
        vm.can_fire = True
        before = len(vm.events)
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == []
        vm.can_fire = False
        vm.put(0x5b030000 + 364, 0x20, '<I')
        vm.call('SV_HostNav_RefreshBotMovement', 0x5b000000, 0x5b060000)
        assert vm.events[before:] == []
        total += 3
        vm = runner.machine(True, mode)
        mesh_bot(vm, 'normal', targets=((700., 0., 0.), (750., 0., 0.)))
        first_goal = next(event[1] for event in vm.events if event[0] == 'path-request')
        # The second opponent becomes marginally closer while the bot makes
        # progress. Losing the route must not rotate the offset or flip targets.
        vm.put(0x5e021000 + 304, struct.pack('<3f', 690., 0., 0.))
        vm.put(0x5b010000 + 304, struct.pack('<3f', 100., 0., 0.))
        vm.put(vm.symbols['SVHS_LevelTime'], 2400, '<i'); vm.path_exists = False
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        vm.put(vm.symbols['SVHS_LevelTime'], 2416, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert [event[1] for event in vm.events if event[0] == 'path-request'] == [first_goal, first_goal]
        total += 1
        # Fire-ready combat must yield to native movement, including a route
        # previously owned by the fallback. The target may be another bot.
        vm = runner.machine(True, mode)
        vm.can_fire = True
        combat = mesh_bot(vm, 'normal', targets=((100., 0., 0.),))
        assert combat['result'] == 0
        assert not any(e[0] in ('path-request', 'follow-path') for e in combat['events'])
        # Unseen hostile players are not omniscient patrol destinations; nearby
        # squadmates should not become an endpoint that causes circling.
        for teams in ((1,), (2,)):
            vm = runner.machine(True, mode)
            route = mesh_bot(vm, 'normal', targets=((100., 0., 0.),), target_handle=0, teams=teams)
            goal = next(e[1] for e in route['events'] if e[0] == 'path-request')
            assert goal == (768., 0., 0.), (teams, goal)
        # Loot is an explicit local native-use goal; a failed route tries a
        # different short escape, and a dead target does not retain its route.
        vm = runner.machine(True, mode)
        vm.loot_goal = (200., 100., 0.)
        route = mesh_bot(vm, 'normal')
        assert next(e[1] for e in route['events'] if e[0] == 'path-request') == vm.loot_goal
        # Ordinary hunt type1 may choose a nearby native loot destination even
        # with a different native hunt path. Critical type5 keeps its route or
        # repairs that exact destination when the native path is absent.
        vm = runner.machine(True, mode); vm.loot_goal = (200., 100., 0.)
        route = mesh_bot(vm, 'normal', goal_type=1, native_goal=(900., 0., 0.), existing_path=True)
        assert next(e[1] for e in route['events'] if e[0] == 'path-request') == vm.loot_goal
        vm = runner.machine(True, mode); vm.loot_goal = (200., 100., 0.)
        command = bytes((i * 17 + 11) & 255 for i in range(264))
        critical = (1100., 240., 20.)
        route = mesh_bot(vm, 'normal', goal_type=5, native_goal=critical,
                         existing_path=True, command_bytes=command)
        assert route['result'] == 0 and not any(e[0] == 'path-request' for e in route['events'])
        assert bytes(vm.uc.mem_read(0x5b060000,264)) == command
        vm = runner.machine(True, mode); vm.loot_goal = (200., 100., 0.)
        route = mesh_bot(vm, 'normal', goal_type=5, native_goal=critical,
                         route_goal=(-700., -200., 0.))
        assert next(e[1] for e in route['events'] if e[0] == 'path-request') == critical
        assert vm.get(0x5b000000+516,'<I') == 5
        total += 3
        vm = runner.machine(True, mode)
        mesh_bot(vm, 'normal', targets=((700., 0., 0.),))
        first = next(e[1] for e in vm.events if e[0] == 'path-request')
        vm.put(0x5e011000 + 440, 0, '<i')
        vm.put(vm.symbols['SVHS_LevelTime'], 1016, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        vm.put(vm.symbols['SVHS_LevelTime'], 1032, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        assert [e[1] for e in vm.events if e[0] == 'path-request'][-1] != first
        vm = runner.machine(True, mode)
        mesh_bot(vm, 'normal')
        vm.put(vm.symbols['SVHS_LevelTime'], 2600, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        vm.put(vm.symbols['SVHS_LevelTime'], 2616, '<i')
        vm.call('Bot_UpdateMove_OffPathGrid', 0x5b000000, 0x5b060000)
        escape = [e[1] for e in vm.events if e[0] == 'path-request'][-1]
        assert abs(escape[0]) <= 256 and abs(escape[1]) <= 256
        total += 6
    for graphs in (0,1):
        for point in (0,0x5c020000):
            results=[]
            for edited,mode in ((False,0),(True,0),(True,1)):
                vm=runner.machine(edited,mode);sentient,entity=0x5c000000,0x5c010000
                vm.put(sentient,bytes(184));vm.put(entity,bytes(1440));vm.put(sentient,entity,'<Q')
                vm.put(vm.symbols['SVHS_TacGraphCount'],graphs,'<i');vm.tac_point=point
                result=vm.call('Sentient_NearestTacPoint',sentient)
                results.append((result,vm.events,bytes(vm.uc.mem_read(sentient+152,2))))
            assert results[0]==results[1],('tactical baseline',graphs,point,results)
            if graphs:assert results[2]==results[0]
            else:assert results[2]==(0,[('set-tactical',0)],bytes([0,1]))
            total+=1
    for path in ('cached','near-node','far-node','navigator'):
        results=[]
        for edited,mode in ((False,0),(True,0),(True,1)):
            vm=runner.machine(edited,mode)
            sentient,entity,ai,nav,table=0x5c000000,0x5c010000,0x5c030000,0x5c040000,0x5c050000
            for at,size in ((sentient,184),(entity,1440),(ai,400),(nav,1400),(table,512)):
                vm.put(at,bytes(size))
            vm.put(sentient,entity,'<Q');vm.put(vm.symbols['SVHS_TacGraphCount'],1,'<i')
            vm.tac_selected=0x5c020000;vm.node_tac=0x5c020100;vm.navigator_tac=0x5c020200
            if path=='cached':vm.put(sentient+152,1,'<B')
            elif path.endswith('node'):
                vm.put(sentient+112,0x5c070000,'<Q')
                vm.node_position=(10.,0.,0.) if path=='near-node' else (100.,0.,0.)
            else:
                vm.put(sentient+8,ai,'<Q');vm.put(ai+360,nav,'<Q');vm.put(nav,table,'<Q')
                vm.put(table+384,0x5c080000,'<Q');vm.hooks[0x5c080000]='navigator-tactical'
            result=vm.call('Sentient_NearestTacPoint',sentient)
            results.append((result,vm.events,bytes(vm.uc.mem_read(sentient+152,2))))
        assert results[0]==results[1]==results[2],('populated tactical graph',path,results)
        total+=1
    vm = runner.machine(True, 1)
    sentient, entity = 0x5c000000, 0x5c010000
    vm.put(sentient, bytes(184)); vm.put(entity, bytes(1440)); vm.put(sentient, entity, '<Q')
    vm.put(vm.symbols['SVHS_TacGraphCount'], 1, '<i')
    assert vm.call('SV_HostNav_BeginBot') == 1
    assert vm.call('Sentient_NearestTacPoint', sentient) == 0
    before = len(vm.events)
    vm.put(vm.symbols['SVHS_LevelTime'], 200, '<i')
    assert vm.call('Sentient_NearestTacPoint', sentient) == 0 and len(vm.events) == before
    vm.put(vm.symbols['SVHS_LevelTime'], 250, '<i')
    vm.call('Sentient_NearestTacPoint', sentient)
    assert len(vm.events) > before
    before = len(vm.events)
    vm.put(entity + 304, 65., '<f')
    vm.call('Sentient_NearestTacPoint', sentient)
    assert len(vm.events) > before
    vm.call('SV_HostNav_EndBot')
    before = len(vm.events)
    vm.call('Sentient_NearestTacPoint', sentient)
    assert len(vm.events) > before  # No negative cache outside the owning bot thread.
    total += 4
    print('PASS mesh-only routing, failed-path native movement preservation and empty tactical-graph fast return',total,flush=True)
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
    previous_request=vm.request
    vm.request=(50.,60.,70.)
    vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
    assert struct.unpack("<fff",vm.output)==previous_request
    vm.request=(500.,600.,700.)
    vm.put(vm.symbols["SVHS_LevelTime"],160,"<i");vm.found=False
    vm.call("Scr_GetClosestReachablePointOnNavmesh",0x58000000,0)
    assert struct.unpack("<fff",vm.output)==(1.,2.,3.);total+=4
    # All 150 occupied ordinals receive a turn, with at most four per frame.
    vm=runner.machine(True,1,150);seen=[]
    for frame in range(38):
        vm.put(vm.symbols["SVHS_LevelTime"],frame*16,"<i");admitted=[]
        for ordinal in range(150):
            if vm.call("SV_HostNav_Begin",ordinal,150)==1:admitted.append(ordinal)
            vm.call("SV_HostNav_End",0)
        assert 0 < len(admitted)<=4;seen+=admitted
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
    work=[]
    for seed in range(12):
        for point in ((150.,-220.,-8000.),(150.,-220.,40.)):
            original=nearest_tree(runner.machine(False),seed,point=point)
            off=nearest_tree(runner.machine(True,0),seed,point=point)
            on=nearest_tree(runner.machine(True,1),seed,point=point)
            assert off==original,('nearest tree baseline',seed,point)
            assert (on['selected'],on['maximum'],on['top'])==(original['selected'],original['maximum'],original['top']),('nearest tree result',seed,point,on,original)
            assert len(on['events'])<=len(original['events'])
            work.append(dict(seed=seed,point=point,native_candidates=len(original['events']),optimized_candidates=len(on['events'])))
            total+=1
    for count,steps,maximum in ((0,1,1.),(1,1,9.2233715e18),(64,1,9.2233715e18),
                                 (64,7,9.2233715e18),(512,0x7fffffff,1024.),(4096,0x7fffffff,9.2233715e18)):
        original=nearest_tree(runner.machine(False),7,count=count,steps=steps,maximum=maximum)
        on=nearest_tree(runner.machine(True,1),7,count=count,steps=steps,maximum=maximum)
        assert (on['selected'],on['maximum'],on['top'])==(original['selected'],original['maximum'],original['top'])
        work.append(dict(count=count,steps=steps,native_candidates=len(original['events']),optimized_candidates=len(on['events'])))
        total+=1
    for extra in (dict(offset=(100000.,-230000.,45000.),rotation=1.2345),
                  dict(offset=(1.e8,1.e8,0.),point=(0.,0.,0.),axes=(1,0,2),
                       coordinates=[(7.9,0.,1.),(3.9,7.9,0.),(-100.,8.,0.)])):
        original=nearest_tree(runner.machine(False),11,**extra)
        for mode in (0,1,2):
            on=nearest_tree(runner.machine(True,mode),11,**extra)
            assert (on['selected'],on['maximum'],on['top'])==(original['selected'],original['maximum'],original['top']),('World transform precision',extra,mode,on,original)
        total+=1
    for count in (0,0xffffffff):
        vm=runner.machine(True,1);walk=0x57000000
        vm.put(walk,bytes(4136));vm.put(walk+24,walk+40,'<Q')
        assert vm.call('Bfx_ClosestAreaTreeStep',walk,count)==0
        total+=1
    for reject in (False, True):
        vm = runner.machine(True, 1)
        budget = 0x5a000000
        vm.put(budget, bytes(8))
        assert vm.call('SV_HostNav_SetClosestBudget', budget) == 0
        assert vm.call('SV_HostNav_GetClosestBudget') == 0
        assert vm.call('SV_HostNav_BeginBot') == 1
        assert vm.call('SV_HostNav_BeginBot') == 0
        assert vm.call('SV_HostNav_SetClosestBudget', budget) == 0
        vm.reject_nearest = reject
        bounded = nearest_tree(vm, 3, count=16384, point=(150., -220., -80000.), axes=(0, 1, 0))
        assert vm.get(budget, '<I') == (4096 if reject else 512)
        assert vm.get(budget + 4, '<B') == 1
        assert bool(bounded['selected']) == (not reject)
        assert len(bounded['events']) < (4096 if reject else 512)
        nested = budget + 16
        vm.put(nested, bytes(8))
        assert vm.call('SV_HostNav_SetClosestBudget', nested) == budget
        assert vm.call('SV_HostNav_SetClosestBudget', budget) == nested
        assert vm.call('SV_HostNav_SuspendClosest', 1) == 0
        assert vm.call('SV_HostNav_GetClosestBudget') == 0
        assert vm.call('SV_HostNav_SetClosestBudget', nested) == 0
        assert vm.call('SV_HostNav_SuspendClosest', 0) == 1
        assert vm.call('SV_HostNav_GetClosestBudget') == budget
        vm.thread += 1
        assert vm.call('SV_HostNav_GetClosestBudget') == 0
        vm.call('SV_HostNav_EndBot')
        vm.thread -= 1
        assert vm.call('SV_HostNav_GetClosestBudget') == budget
        vm.call('SV_HostNav_EndBot')
        assert vm.call('SV_HostNav_GetClosestBudget') == 0
        total += 1
    # A rejected dynamic candidate still consumes work, even outside the KD tree.
    vm = runner.machine(True, 1)
    budget = 0x5a000000
    vm.put(budget, struct.pack('<IB3x', 4096, 0))
    vm.call('SV_HostNav_BeginBot')
    vm.call('SV_HostNav_SetClosestBudget', budget)
    exhausted = nearest_collector(vm, dict(point=(0., 0., 0.)))
    assert not exhausted['events'] and vm.get(budget+4, '<B') == 1
    vm.call('SV_HostNav_EndBot')
    total += 1
    for obstacle_mode in (0,1):
        for obstacle_flags in (0,1,7):
            for area_flags in (0,1,2):
                for point in ((5.,6.,7.),(200.,0.,0.)):
                    case=dict(obstacle_mode=obstacle_mode,obstacle_flags=obstacle_flags,
                              shape_flags=0x20000000,area_flags=area_flags,point=point)
                    original=nearest_collector(runner.machine(False),case)
                    for mode in (0,1):
                        assert nearest_collector(runner.machine(True,mode),case)==original,('nearest collector',case,mode)
                    total+=1
    for case in (dict(point=(float('nan'),0.,0.)),dict(point=(float('inf'),0.,0.)),
                 dict(point=(100.,0.,0.),maximum=100.),dict(point=(1.,0.,0.),farthest=200.),
                 dict(point=(1.,0.,0.),farthest=float('nan'))):
        original=nearest_collector(runner.machine(False),case)
        for mode in (0,1):assert nearest_collector(runner.machine(True,mode),case)==original,(case,mode)
        total+=1
    receipt=dict(passed=True,cases=total,scope=__doc__,live_game_tested=False,
        script_goal_type_proof=runner.goal_type_proof,
        linked_executable_sha256=runner.report["sha256"] if runner.report else None,
        graph_budget=2048,spatial_budget=512,occupied_slots_fairness=150,nearest_tree_work=work)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n")
    print("PASS",total,"navigation instruction cases",flush=True)


if __name__=="__main__":main()
