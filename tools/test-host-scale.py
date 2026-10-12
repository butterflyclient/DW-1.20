"""Execute original and rebuilt host routines with modeled engine boundaries.

This is instruction/ABI regression evidence, not a live 150-player benchmark.
The test never starts the game or connects to the Demonware server.
"""
import argparse
import bisect
import hashlib
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


class Runner:
    def __init__(self, snapshot, build=None):
        self.snapshot = snapshot
        self.proof = json.loads((snapshot / "generated/host-scale-integration.json").read_bytes())
        self.original = pefile.PE(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe", fast_load=True)
        self.base = self.original.OPTIONAL_HEADER.ImageBase
        self.native = json.loads((snapshot / "generated/native-symbols.json").read_bytes())
        self.imports = {r["name"]: self.base + r["original_rva"] for r in self.proof["bindings"]}
        self.entries = {r["symbol"]: self.base + r["original_rva"] for r in self.proof["replacements"]}
        self.objects = {}
        self.report = None
        if build:
            self.report = json.loads((build / "build-report.json").read_bytes())
            path = Path(self.report["executable"])
            assert hashlib.sha256(path.read_bytes()).hexdigest() == self.report["sha256"]
            assert self.report["unresolved_symbols"] == 0
            self.linked = pefile.PE(str(path), fast_load=True)
            self.ranges = self.report["rva_map"]["ranges"]
            self.starts = [r["begin"] for r in self.ranges]
        else:
            sys.path.insert(0, str(snapshot / "tools"))
            from coff import read as read_coff
            destination = snapshot / "host-scale-test-objects"
            destination.mkdir(exist_ok=True)
            for symbol in self.entries:
                source = ROOT / "integration/host-scale" / (symbol + ".cpp")
                obj = destination / (symbol + ".obj")
                subprocess.run([r"C:\Program Files\LLVM\bin\clang++.exe",
                    "--target=x86_64-pc-windows-msvc", "-c", str(source), "-o", str(obj),
                    "-O2", "-std=c++20", "-ffreestanding", "-fno-stack-protector",
                    "-fno-exceptions", "-fno-rtti", "-funwind-tables", "-ffunction-sections",
                    "-fdata-sections", "-Wall", "-Wextra", "-Werror",
                    "-I" + str(snapshot / "src")], check=True)
                self.objects[symbol] = read_coff(obj)

    def run(self, routine, edited, case):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        pe = self.linked if edited and self.report else self.original
        pages = set()

        def page(address):
            address &= -4096
            if address in pages:
                return
            vm.mem_map(address, 4096)
            if self.base <= address < self.base + pe.OPTIONAL_HEADER.SizeOfImage:
                data = pe.get_data(address - self.base, 4096)
                if data:
                    vm.mem_write(address, data)
            pages.add(address)

        def put(address, data, fmt=None):
            if fmt:
                data = struct.pack(fmt, data)
            for at in range(address & -4096, (address + len(data) + 4095) & -4096, 4096):
                page(at)
            vm.mem_write(address, data)

        def get(address, fmt):
            size = struct.calcsize(fmt)
            page(address); page(address + size - 1)
            return struct.unpack(fmt, vm.mem_read(address, size))[0]

        def mapped(address):
            if edited and self.report:
                rva = address - self.base
                row = self.ranges[bisect.bisect_right(self.starts, rva) - 1]
                return self.base + row["mapped_begin"] + rva - row["begin"]
            return address

        symbols = {n: mapped(a) for n, a in self.imports.items()}
        hooks = {a: n for n, a in symbols.items() if n in {
            r["name"] for r in self.proof["bindings"] if r["kind"] == "function"}}
        helpers = ("?Enabled@HostScale@@YA_NXZ", "?Population@HostScale@@YAIXZ",
                   "?RecordSight@HostScale@@YAXIII@Z", "?RecordMovement@HostScale@@YAXII@Z",
                   "?RecordBackpressure@HostScale@@YAXXZ", "?Clock@HostScale@@YA_KXZ",
                   "?RecordBotFrame@HostScale@@YAXII_K0@Z",
                   "SV_HostNav_Begin", "SV_HostNav_End", "SV_HostNav_SpatialWork",
                   "SV_HostNav_GraphWork", "SV_HostNav_HasWork",
                   "DW_LocalBackend_GetAuthAddress", "SV_HostNav_RecordClosest",
                   "SV_HostNav_BeginBot", "SV_HostNav_EndBot", "SV_HostNav_RefreshBotMovement",
                   "SV_HostBot_PrepareEquipment", "SV_HostBot_UpdateLoot", "SV_HostBot_FaceLoot",
                   "SV_HostBot_InGulag", "SV_HostBot_UpdateTravelUrgency")
        if edited and self.report:
            entry = self.base + self.report["symbols"][routine]
            for name in helpers:
                if (name.startswith("?Record") or name.startswith("?Clock")) and name in self.report["symbols"]:
                    hooks[self.base + self.report["symbols"][name]] = name
            hooks[self.base + self.report["symbols"]["Com_Optimized_IsEnabled"]] = "optimized-policy"
            for name in ("SV_HostNav_BeginBot", "SV_HostNav_EndBot", "SV_HostNav_RefreshBotMovement",
                         "SV_HostBot_PrepareEquipment", "SV_HostBot_UpdateLoot", "SV_HostBot_FaceLoot",
                         "SV_HostBot_InGulag", "SV_HostBot_UpdateTravelUrgency"):
                hooks[self.base + self.report["symbols"][name]] = name
            for name in ("memcpy", "memcmp", "memset", "__chkstk", "__security_check_cookie"):
                if name in self.report["symbols"]:
                    hooks[self.base + self.report["symbols"][name]] = name
            if routine in ("SV_BotApplyCommands", "SV_BotUpdateBots"):
                hooks[self.base + self.report["symbols"]["SV_UserMoveWorkersMP_TryQueueClientThinkCmd"]] = "queue-bot"
        elif edited:
            obj = self.objects[routine]
            section_addresses = {}
            section_base = 0x180000000
            for section in obj["sections"]:
                section_addresses[section["number"]] = section_base
                # Large bot arrays exceed 64 KiB. Keep their COFF sections
                # disjoint just as the real linker does, including zero data.
                size = max(len(section["data"]), section.get("aux", {}).get("length", 0))
                section_base += max(0x10000, (size + 0xffff) & ~0xffff)
            externals = dict(symbols)
            externals.update(self.entries)
            for name in (*helpers, "memcpy", "memcmp", "memset", "__chkstk", "_fltused", "SV_UserMoveWorkersMP_TryQueueClientThinkCmd"):
                address = 0x180D00000 + len(externals) * 32
                externals[name] = address
                hooks[address] = "queue-bot" if name == "SV_UserMoveWorkersMP_TryQueueClientThinkCmd" else name
            addresses = {i: section_addresses[s["section"]] + s["value"] if s["section"] > 0
                         else externals[s["name"]] if s["section"] == 0 else s["value"]
                         for i, s in obj["symbols"].items()}
            for section in obj["sections"]:
                start = section_addresses[section["number"]]
                data = bytearray(section["data"])
                for offset, index, kind in section["relocations"]:
                    target = addresses[index]
                    if 4 <= kind <= 9:
                        add = struct.unpack_from("<i", data, offset)[0]
                        struct.pack_into("<i", data, offset, add + target - start - offset - 4 - (kind - 4))
                    elif kind == 1:
                        struct.pack_into("<Q", data, offset, struct.unpack_from("<Q", data, offset)[0] + target)
                    elif kind == 3:
                        struct.pack_into("<I", data, offset, (target - 0x180000000) & 0xffffffff)
                    else:
                        raise AssertionError((section["name"], kind))
                if data:
                    put(start, bytes(data))
            entry = next(addresses[i] for i, s in obj["symbols"].items() if s["name"] == routine)
        else:
            entry = self.entries[routine]
        for name in ("__security_check_cookie", "__chkstk", "_alloca_probe"):
            if name in self.native:
                hooks[mapped(self.base + self.native[name])] = "__chkstk" if "probe" in name else name
        # Original stack probe has an exact call target but different aliases in
        # historical catalogs. It touches only stack pages that the VM owns.
        hooks[mapped(self.base + 0x21ccef0)] = "__chkstk"
        hooks[mapped(self.base + 0x21ccf60)] = "__security_check_cookie"

        stop, stack = 0x190000000, 0x70080008
        for at in range(stack - 0x20000, stack + 0x1000, 4096):
            page(at)
        page(stop)
        put(stack, stop, "<Q")
        vm.reg_write(UC_X86_REG_RSP, stack)
        put(symbols["SVHS_ClientCount"], case.get("population", 20), "<I")
        put(symbols["SVHS_LevelTime"], case.get("time", 10000), "<i")
        put(symbols["SVHS_FrameDuration"], 50, "<i")
        put(symbols["SVHS_WorkersEnabled"], case.get("workers", 1), "<B")
        events, observed, queued, stats = [], [], [], []
        scopes = []
        urgency = []
        entities, sentients, info, ai, interface, vtable = (0x51000000, 0x52000000, 0x53000000,
                                                         0x54000000, 0x54100000, 0x54200000)
        clients, players, commands, queues = 0x55000000, 0x5A000000, 0x5B000000, 0x5C000000
        count = case.get("count", case.get("population", 20))
        now = case.get("time", 10000)
        visibility_events, threat_events, perfect_events = [], [], []
        is_collision = routine.startswith("CL_TransientsCollisionMP_")
        # Linked tests execute the real population cache and optimization gate.
        for i in range(min(case.get("population", 20), 200)):
            client = clients + i * 321192
            put(symbols["SVHS_Clients"] + i * 8, client, "<Q")
            put(client + 8, 5, "<B")
        if is_collision:
            tile = case.get("tile", 560)
            count = case.get("tiles", tile + 1)
            mask = 0x80000000 >> (tile & 31)
            word = tile >> 5
            for name in ("SVHS_TileLoadRequested", "SVHS_TileLoaded", "SVHS_TileSetupRequested", "SVHS_TileSetup"):
                put(symbols[name], bytes(128))
            for name in ("SVHS_WorldTileSetup", "SVHS_StaticTileSetup"):
                put(symbols[name], bytes(640))
            for prefix, world_mask in (("World", case.get("worlds", 31)), ("Static", case.get("models", 31))):
                for world in range(5):
                    if world_mask & (1 << world):
                        put(symbols["SVHS_" + prefix + "TileSetup"] + world * 128 + word * 4, mask, "<I")
            for name, selected in (("SVHS_TileLoadRequested", case.get("load_requested", True)),
                                   ("SVHS_TileSetupRequested", case.get("requested", True)),
                                   ("SVHS_TileSetup", case.get("setup", False))):
                put(symbols[name] + word * 4, mask if selected else 0, "<I")
            put(symbols["SVHS_TileFileIndices"], bytes(2048))
            put(symbols["SVHS_TileFileIndices"] + tile * 2, 17 if case.get("file", True) else 0, "<H")
            put(symbols["SVHS_AllTilesFileIndex"], 18 if case.get("file", True) else 0, "<H")
            put(symbols["SVHS_CollisionTileCount"], count, "<I")
            for name, value in (("SVHS_AllTilesLoadRequested", case.get("load_requested", True)),
                                ("SVHS_AllTilesLoaded", False),
                                ("SVHS_AllTilesSetupRequested", case.get("requested", True)),
                                ("SVHS_AllTilesSetup", case.get("setup", False))):
                put(symbols[name], int(value), "<B")
            vm.reg_write(UC_X86_REG_RCX, int(case.get("force", True)) if routine.endswith("_UpdateTransientFlags") else tile)
            vm.reg_write(UC_X86_REG_RDX, int(case.get("force", True)))
        elif routine == "AICommon_UpdateSight":
            put(symbols["SVHS_TeamMode"], int(case.get("ffa", False)), "<i")
            put(symbols["SVHS_Sentients"], sentients, "<Q")
            put(interface, struct.pack("<QQ", vtable, ai))
            put(ai, bytes(448))
            put(ai, entities, "<Q"); put(ai + 8, sentients, "<Q"); put(ai + 16, info, "<Q")
            put(ai + 88, case.get("awareness", 0.0), "<f")
            put(ai + 164, 268435456.0, "<f"); put(ai + 176, 100, "<i")
            for index, name in ((60, "fov-z"), (59, "fov"), (26, "perfect-info")):
                address = 0x180F00000 + index * 32
                put(vtable + index * 8, address, "<Q"); hooks[address] = name
            rng = random.Random(case.get("seed", 120))
            for i in range(count):
                ent, sent = entities + i * 1440, sentients + i * 184
                put(ent, bytes(1440)); put(sent, bytes(184)); put(info + i * 64, bytes(64))
                put(ent, i, "<h"); put(ent + 8, 1, "<H"); put(ent + 440, 100, "<i")
                xyz = (0.0, 0.0, 0.0) if i == 0 else (
                    rng.uniform(-200.0, 200.0), rng.uniform(-200.0, 200.0), rng.uniform(1.0, 20.0))
                if case.get("far") and i:
                    xyz = (2000.0 + i * 5, 1000.0, 0.0)
                if case.get("zero_distance") and i == 1:
                    xyz = (0.0, 0.0, 0.0)
                put(ent + 304, struct.pack("<fff", *xyz)); put(sent, ent, "<Q")
                put(sent + 16, 2 if i == 0 else 1, "<I")
                put(info + i * 64 + 4, now if case.get("cached") else 100 + i * 3, "<i")
                if case.get("mixed") and i and i % 9 == 0:
                    put(ent + 440, 0, "<i")
                if case.get("mixed") and i and i % 11 == 0:
                    put(ent + 8, 5, "<H")
            put(sentients + 72, case.get("target", 0), "<H")
            put(sentients + 156, int(case.get("neutral", False)), "<B")
            vm.reg_write(UC_X86_REG_RCX, interface)
        else:
            rng = random.Random(120)
            for i in range(count):
                client, ent, player = clients + i * 321192, entities + i * 1440, players + i * 0x8000
                put(symbols["SVHS_Clients"] + i * 8, client, "<Q")
                put(client + 8, 5, "<B"); put(client + 280, ent, "<Q")
                put(client + 214756, 2, "<i"); put(client + 28, 100, "<i")
                put(ent, bytes(1440)); put(ent, i, "<h"); put(ent + 336, player, "<Q")
                put(ent + 440, 100, "<i"); put(ent + 344, sentients + i * 184, "<Q")
                put(ent + 304, struct.pack('<fff', float(case.get('bot_distance', 0)), 0., 0.))
                if i == case.get('target', 0) - 1 and 'enemy_distance' in case:
                    put(ent + 304, struct.pack('<fff', -float(case['enemy_distance']), 0., 0.))
                put(sentients + i * 184, bytes(184))
                put(sentients + i * 184 + 72, case.get("target", 0), "<H")
                put(client + 1368 + 8988, 0, "<I")
                put(player, bytes(25000)); put(player + 21368, 2, "<i")
                put(player + 448, i, "<i")
                data = bytearray(rng.randbytes(264)); struct.pack_into("<iii", data, 12, now, now, now)
                put(commands + i * 264, bytes(data))
                if case.get("mixed"):
                    if i % 7 == 0:
                        put(client + 214756, 1, "<i")
                    elif i % 7 == 1:
                        put(client + 8, 3, "<B")
                    elif i % 7 == 2:
                        put(player + 21372, 2, "<i")
                    elif i % 7 == 3:
                        put(client + 28, now, "<i")
                    elif i % 7 == 4:
                        put(player + 448, 900, "<i")
                if i == case.get('human_slot'):
                    put(client + 214756, 1, '<i')
                    put(ent + 304, bytes(12))
            vm.reg_write(UC_X86_REG_RCX, commands)
            if routine == "SV_BotUpdateBots":
                put(symbols["SVHS_ServerGlobals"], 0x5F000000, "<Q")
                put(0x5F000000, bytes(64))
                put(0x5F000000 + 28, now, "<i")
                for name in ("SVHS_BotSystemAllocated", "SVHS_LevelClientsAllocated"):
                    put(symbols[name], int(case.get("loaded", True)), "<I")
                put(symbols["SVHS_ActiveBotCount"], 0, "<I")
                put(symbols["SVHS_BotPingAnchor"] - 8, struct.pack('<iiIi', -1, 0, 0, -1) * 32)
                put(symbols["SVHS_BotPingAnchor"] - 8, struct.pack('<iiIi', 2, now - 4000, 123, 1))
            if routine == "SV_UserMoveWorkersMP_TryQueueClientThinkCmd":
                put(symbols["SVHS_ThinkQueues"], queues, "<Q")
                put(queues, b'\xa5' * (count * 1600 + 128))
                selected = case.get("slot", count - 1)
                put(queues + selected * 1600 + 1584, case.get("write", 0), "<I")
                put(queues + selected * 1600 + 1592, case.get("pending", 0), "<i")
                vm.reg_write(UC_X86_REG_RCX, selected)
                vm.reg_write(UC_X86_REG_RDX, commands + selected * 264)

        def returned(value=0, floating=None):
            sp = vm.reg_read(UC_X86_REG_RSP)
            target = get(sp, "<Q")
            vm.reg_write(UC_X86_REG_RAX, int(value) & 0xffffffffffffffff)
            if floating is not None:
                vm.reg_write(UC_X86_REG_XMM0, struct.unpack("<I", struct.pack("<f", floating))[0])
            vm.reg_write(UC_X86_REG_RSP, sp + 8); vm.reg_write(UC_X86_REG_RIP, target)

        def do_think(client, command):
            slot = (client - clients) // 321192
            data = bytes(vm.mem_read(command, 264))
            put(client + 16, data)
            observed.append((slot, hashlib.sha256(data).hexdigest()))
            if routine == "SV_BotUpdateBots":
                assert struct.unpack_from('<iii', data, 12) == (now, now, now), "Movement command lost current tick time"

        def boundary(machine, address, size, context):
            kind = hooks.get(address)
            if kind is None:
                return
            a, b, c, d = (vm.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9))
            if kind == "__chkstk":
                returned(vm.reg_read(UC_X86_REG_RAX)); return
            if kind == "__security_check_cookie":
                returned(); return
            if kind in ("?Enabled@HostScale@@YA_NXZ", "optimized-policy"):
                returned(case.get("mode", 0) != 0); return
            if kind == "?Population@HostScale@@YAIXZ":
                returned(case.get("population", 20)); return
            if kind.startswith("?Record"):
                stats.append((kind, a & 0xffffffff, b & 0xffffffff, c & 0xffffffff))
                returned(); return
            if kind.startswith("?Clock"):
                returned(len(events) * 100); return
            if kind in ("SV_HostNav_BeginBot", "SV_HostNav_EndBot", "SV_HostNav_RefreshBotMovement"):
                if kind != "SV_HostNav_RefreshBotMovement":
                    scopes.append((kind, now))
                returned(kind == "SV_HostNav_BeginBot"); return
            if kind == "SV_HostBot_InGulag":
                slot = (a - clients - 1368) // 321192
                returned(bool(get(players + slot * 0x8000 + 22336, '<I') & 0x600)); return
            if kind == "SV_HostBot_UpdateTravelUrgency":
                assert get(b + 12, '<i') == now
                if case.get('mode', 0):urgency.append(((a - clients - 1368) // 321192, now, bool(c & 255)))
                returned(); return
            if kind in ("SV_HostBot_PrepareEquipment", "SV_HostBot_UpdateLoot", "SV_HostBot_FaceLoot"):
                returned(); return
            if kind == "SVHS_TransientFileLoaded":
                events.append(("file-loaded", a)); returned(case.get("loaded", True)); return
            if kind in ("SVHS_WorldTileReady", "SVHS_StaticTileReady"):
                prefix = "World" if kind == "SVHS_WorldTileReady" else "Static"
                full = all(get(symbols["SVHS_" + prefix + "TileSetup"] + i * 128 + (a >> 5) * 4, '<I') &
                           (0x80000000 >> (a & 31)) for i in range(5))
                returned(full); return
            if kind in ("SVHS_IsBotPlaying", "SVHS_IsBotSpectator"):
                ent = get(a + 280, '<Q'); player = get(ent + 336, '<Q')
                eligible = get(a + 8, '<B') >= 5 and get(player + 21368, '<i') == 2
                if kind == "SVHS_IsBotPlaying":
                    eligible &= get(player + 21372, '<i') == 0 and get(player + 448, '<i') == get(ent, '<h')
                else:
                    eligible &= get(player + 21372, '<i') == 2
                returned(eligible); return
            if kind == "SVHS_BotThink":
                slot = (a - clients) // 321192
                data = bytearray(vm.mem_read(commands + slot * 264, 264))
                struct.pack_into('<iii', data, 12, now, now, now)
                put(b, bytes(data)); events.append(("decision", slot, now)); returned(); return
            if kind == "SVHS_AdvanceBotPriority":
                events.append(("priority", a)); returned(); return
            if kind == "SVHS_BotScriptActions":
                events.append(("script", (a - 1368 - clients) // 321192)); returned(); return
            if kind == "SVHS_ReleaseBotPing":
                events.append(("release-ping", a)); returned(); return
            if kind == "memcpy":
                put(a, bytes(vm.mem_read(b, c))); returned(a); return
            if kind == "memcmp":
                left, right = bytes(vm.mem_read(a, c)), bytes(vm.mem_read(b, c))
                returned((left > right) - (left < right)); return
            if kind == "memset":
                put(a, bytes([b & 255]) * c); returned(a); return
            if kind == "SVHS_SupportsFeature":
                returned(case.get("feature", True) if a == 2 else case.get("sp", False)); return
            if kind in ("SVHS_AllCombatTeamsSP", "SVHS_AllTeamsMP"):
                put(0x54300000, b'\xff' * 20); returned(0x54300000); return
            if kind == "SVHS_EnemyTeamFlags":
                put(a, bytes(20) if case.get("empty_teams") else b'\xff' * 20); returned(); return
            if kind == "SVHS_FirstSentient":
                returned(sentients if count else 0); return
            if kind == "SVHS_NextSentient":
                i = (a - sentients) // 184 + 1
                returned(sentients + i * 184 if i < count else 0); return
            if kind == "SVHS_SentientOrigin":
                put(b, bytes(vm.mem_read(get(a, "<Q") + 304, 12))); returned(); return
            if kind == "SVHS_UpdateThreatSight":
                i = (b - info) // 64
                distance = vm.reg_read(UC_X86_REG_XMM2) & 0xffffffff
                threat_events.append((i, distance)); returned(); return
            if kind == "SVHS_Sort":
                rows = [bytes(vm.mem_read(a + i * 16, 16)) for i in range(b)]
                rows.sort(key=lambda data: struct.unpack_from("<I", data, 8)[0], reverse=True)
                put(a, b''.join(rows)); returned(); return
            if kind == "SVHS_IsBotEntity":
                returned(case.get("bot", True)); return
            if kind in ("fov", "fov-z"):
                returned(floating=0.5 if kind == "fov" else 0.7); return
            if kind == "SVHS_CanSeeEntity":
                i = (b - entities) // 1440
                visibility_events.append(i)
                put(info + i * 64, 1, "<B"); put(info + i * 64 + 4, now, "<i")
                put(ai + 444, get(ai + 444, "<I") + (0 if case.get("no_rays") else 1), "<I")
                returned(1); return
            if kind == "perfect-info":
                assert c & 255 == 18
                perfect_events.append((b - sentients) // 184); returned(); return
            if kind == "SVHS_AcknowledgeBotCommands":
                events.append(("ack", (a - clients) // 321192)); returned(); return
            if kind == "SVHS_ClientThink":
                do_think(a, b); returned(); return
            if kind == "SVHS_GetUsercmd":
                put(b, bytes(vm.mem_read(clients + a * 321192 + 16, 264)))
                events.append(("spectator", a)); returned(); return
            if kind == "queue-bot":
                # Queue ownership copies the complete command before returning.
                temp = 0x5D000000 + a * 264
                put(temp, bytes(vm.mem_read(b, 264)))
                put(clients + a * 321192 + 16, bytes(vm.mem_read(b, 264)))
                queued.append((clients + a * 321192, temp)); returned(1); return
            if kind == "SVHS_FinishClientThinkCmds":
                for client, cmd in reversed(queued):
                    do_think(client, cmd)
                queued.clear(); events.append(("join",)); returned(); return
            if kind == "SVHS_UserMoveBegin":
                events.append(("begin",)); returned(); return
            if kind == "SVHS_ClientPreThink":
                if case.get("reject"):
                    returned(0)
                else:
                    put(a + 16, bytes(vm.mem_read(b, 264))); returned(1)
                return
            if kind in ("SVHS_WaitWorkerType", "SVHS_Sleep"):
                events.append(("assist" if kind == "SVHS_WaitWorkerType" else "sleep", a))
                put(queues + selected * 1600 + 1592, 0, "<i"); returned(); return
            if kind == "SVHS_AddWorker":
                events.append(("enqueue", a, get(b, "<I"))); returned(); return
            raise AssertionError(kind)

        def missing(machine, access, address, size, value, context):
            page(address); page(address + size - 1); return True

        missing_hook = vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        callback = vm.hook_add(UC_HOOK_CODE, boundary)
        try:
            for frame in range(case.get("frames", 1)):
                if routine == "SV_BotUpdateBots":
                    now = case.get("time", 10000) + frame * case.get("frame_ms", 16)
                    if frame >= case.get("rewind_at", 1000000):
                        now -= 1000
                    put(symbols["SVHS_LevelTime"], now, '<i')
                    put(symbols["SVHS_FrameDuration"], case.get("frame_ms", 16), '<i')
                    put(0x5F000000 + 28, now, '<i')
                    if frame == case.get("damage_at"):
                        for i in range(count):
                            put(entities + i * 1440 + 440, 50, '<i')
                    if frame == case.get("target_at"):
                        for i in range(count):
                            put(sentients + i * 184 + 72, 2, '<H')
                    if frame == case.get("script_at"):
                        for i in range(count):
                            put(clients + i * 321192 + 1368 + 8988, 8, '<I')
                    if frame == case.get("equipment_at"):
                        for i in range(count):
                            put(players + i * 0x8000 + 1784, 17, '<I')
                    if frame == case.get("gulag_at"):
                        for i in range(count):
                            put(players + i * 0x8000 + 22336, 0x200, '<I')
                    if frame == case.get("teleport_at"):
                        for i in range(count):
                            put(entities + i * 1440 + 304, struct.pack('<3f', 300., 0., 0.))
                    if frame == case.get("target_died_at"):
                        put(entities + 1440 + 440, 0, '<i')
                vm.reg_write(UC_X86_REG_RSP, stack)
                put(stack, stop, '<Q')
                vm.emu_start(entry, stop, count=8000000)
                assert vm.reg_read(UC_X86_REG_RIP) == stop, (routine, edited, case)
            assert not queued, "Bot workers escaped the apply-command fence"
            if is_collision:
                return dict(setup=bool(get(symbols['SVHS_TileSetup'] + word * 4, '<I') & mask),
                            loaded=bool(get(symbols['SVHS_TileLoaded'] + word * 4, '<I') & mask),
                            all_setup=bool(get(symbols['SVHS_AllTilesSetup'], '<B')), events=events)
            if routine == "SV_BotUpdateBots":
                return dict(events=events, observed=observed, stats=stats, scopes=scopes, urgency=urgency,
                            active=get(symbols['SVHS_ActiveBotCount'], '<I'),
                            pings=bytes(vm.mem_read(symbols['SVHS_BotPingAnchor'] - 8, 512)).hex())
            if routine == "AICommon_UpdateSight":
                return dict(threat=threat_events, vision=visibility_events, perfect=perfect_events, stats=stats)
            if routine == "SV_BotApplyCommands":
                state = [hashlib.sha256(bytes(vm.mem_read(clients + i * 321192 + 16, 264)) +
                                        bytes(vm.mem_read(players + i * 0x8000, 25000))).hexdigest()
                         for i in range(count)]
                return dict(state=state, observed=sorted(observed), events=events, stats=stats)
            return dict(result=vm.reg_read(UC_X86_REG_RAX) & 255,
                        queue=hashlib.sha256(bytes(vm.mem_read(queues, count * 1600 + 128))).hexdigest(),
                        events=events, stats=stats)
        finally:
            vm.hook_del(callback)
            vm.hook_del(missing_hook)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runner = Runner(args.snapshot, args.build)
    total, reductions = 0, []
    sight_cases = [dict(count=n, population=min(n, 200), seed=n)
                   for n in (1, 2, 20, 21, 64, 65, 100, 101, 150, 200, 272)]
    sight_cases += [dict(count=150, population=150, **extra) for extra in (
        {"cached":True}, {"bot":False}, {"far":True}, {"mixed":True},
        {"ffa":True}, {"ffa":True,"sp":True}, {"neutral":True}, {"empty_teams":True},
        {"zero_distance":True}, {"target":150}, {"awareness":512.0}, {"no_rays":True})]
    for case in sight_cases:
        original = runner.run("AICommon_UpdateSight", False, case)
        off = runner.run("AICommon_UpdateSight", True, {**case, "mode":0})
        for key in ("threat", "vision", "perfect"):
            assert off[key] == original[key], ("sight baseline", case, key, off[key], original[key])
        total += 1
        for mode in (1, 2):
            edited = runner.run("AICommon_UpdateSight", True, {**case, "mode":mode})
            assert edited["threat"] == original["threat"] and edited["perfect"] == original["perfect"], case
            if case["population"] <= 20 or not case.get("bot", True):
                assert edited["vision"] == original["vision"], case
            else:
                limit = (4 if case["population"] > 100 else 6 if case["population"] > 64 else 8)
                assert len(edited["vision"]) <= limit + bool(case.get("target")), case
                if case.get("target"):
                    assert case["target"] - 1 in edited["vision"], case
            if case.get("population") == 150 and len(original["vision"]) >= 100:
                reductions.append(dict(case=case, mode=mode, original=len(original["vision"]),
                                       optimized=len(edited["vision"])))
            total += 1
    print("PASS sight", total, flush=True)
    for population in (1, 20, 21, 64, 150, 200):
        for mixed in (False, True):
            for workers in (0, 1):
                case = dict(count=population, population=population, mixed=mixed, workers=workers)
                original = runner.run("SV_BotApplyCommands", False, case)
                for mode in (0, 1, 2):
                    edited = runner.run("SV_BotApplyCommands", True, {**case, "mode":mode})
                    assert edited["state"] == original["state"], ("bot state", case, mode)
                    assert edited["observed"] == original["observed"], ("bot commands", case, mode)
                    assert [e for e in edited["events"] if e[0] != "join"] == original["events"], case
                    if mode and population > 20 and workers and edited["observed"]:
                        assert edited["events"][-1] == ("join",), case
                    total += 1
    print("PASS bot command ownership and fence", total, flush=True)
    for population in (20, 21, 150):
        for pending in (0, 2, 6):
            for write in (0, 5):
                for mode in (0, 1, 2):
                    case = dict(population=population, count=population, pending=pending, write=write, mode=mode)
                    original = runner.run("SV_UserMoveWorkersMP_TryQueueClientThinkCmd", False, case)
                    edited = runner.run("SV_UserMoveWorkersMP_TryQueueClientThinkCmd", True, case)
                    assert (edited["result"], edited["queue"]) == (original["result"], original["queue"]), case
                    expected = [("assist",128) if e[0]=="sleep" and mode and population>20 else e
                                for e in original["events"]]
                    assert edited["events"] == expected, (case, edited, original)
                    total += 1
    for extra in ({"workers":0}, {"reject":True}):
        case = dict(population=150, count=150, mode=1, **extra)
        original = runner.run("SV_UserMoveWorkersMP_TryQueueClientThinkCmd", False, case)
        edited = runner.run("SV_UserMoveWorkersMP_TryQueueClientThinkCmd", True, case)
        assert edited == original, (case, edited, original)
        total += 1
    scheduling = []
    for population, extra in ((20, {}), (42, {}), (100, {}), (150, {}),
                              (150, {"target":2}), (150, {"mixed":True}),
                              (150, {"frame_ms":50}), (42, {"damage_at":5}),
                              (42, {"target_at":5}), (42, {"script_at":5}),
                              (42, {"equipment_at":5}), (42, {"gulag_at":5}),
                              (42, {"teleport_at":5}), (42, {"gulag_at":3, "teleport_at":5}),
                              (42, {"target_died_at":5, "target":2}),
                              (42, {"rewind_at":5}), (42, {"loaded":False}),
                              (81, {'human_slot':0, 'bot_distance':800, 'target':2}),
                              (150, {'human_slot':0, 'bot_distance':8000, 'enemy_distance':8000, 'target':2}),
                              (150, {'human_slot':0, 'bot_distance':100, 'target':2}),
                              (150, {'human_slot':0, 'bot_distance':8000, 'target':1})):
        case = dict(population=population, count=population, frames=12, **extra)
        original = runner.run('SV_BotUpdateBots', False, case)
        off = runner.run('SV_BotUpdateBots', True, {**case, 'mode':0})
        for key in ('events', 'active', 'pings'):
            assert off[key] == original[key], ('bot-frame baseline', case, key)
        assert off['observed'] == original['observed'], ('baseline movement', case)
        total += 1
        for mode in (1, 2):
            on = runner.run('SV_BotUpdateBots', True, {**case, 'mode':mode})
            assert on['active'] == original['active'] and on['pings'] == original['pings'], case
            assert len(on['observed']) == len(original['observed']), ('movement tick lost', case)
            original_thinks = sum(e[0] == 'decision' for e in original['events'])
            thinks = sum(e[0] == 'decision' for e in on['events'])
            assert len(on['urgency']) == original_thinks, ('Travel urgency skipped a playing bot command', case)
            assert sum(not entry[2] for entry in on['urgency']) == thinks
            if population <= 20:
                assert on['observed'] == original['observed'] and thinks == original_thinks, case
            elif not extra:
                assert thinks < original_thinks / 2, (case, thinks, original_thinks)
            for trigger in ('damage_at', 'target_at', 'script_at', 'rewind_at',
                            'equipment_at', 'gulag_at', 'target_died_at', 'teleport_at'):
                if trigger in case:
                    instant = 10000 + case[trigger] * 16 - (1000 if trigger == 'rewind_at' else 0)
                    assert sum(e[0] == 'decision' and e[2] == instant for e in on['events']) == population, (case, trigger)
            if 'gulag_at' in case:
                instant = 10000 + case['gulag_at'] * 16
                assert sum(e[0] == 'decision' and e[2] >= instant for e in on['events']) == population * (12 - case['gulag_at']), case
                assert all(e[1] < instant for e in on['scopes']), ('Gulag used approximate navigation scope', case)
            scheduling.append(dict(population=population, mode=mode, extra=extra,
                                   original_decisions=original_thinks, scheduled_decisions=thinks,
                                   movement_commands=len(on['observed'])))
            total += 1
    for mode in (1, 2):
        human_cases = {
            (row['extra'].get('bot_distance'), row['extra'].get('target')): row['scheduled_decisions']
            for row in scheduling if row['mode'] == mode and row['population'] == 150
            and row['extra'].get('human_slot') == 0
        }
        assert 0 < human_cases[8000, 2] < human_cases[100, 2], 'Nearby combat lost priority'
        assert human_cases[8000, 1] == human_cases[100, 2], 'Distant human target lost priority'
    print('PASS bot decision cadence and command continuity', total, flush=True)
    for tile in (0, 31, 32, 560, 1023):
        for worlds, models in ((0, 0), (31, 31), (3, 0), (1, 0), (0, 1), (16, 31), (31, 16)):
            for requested in (True, False):
                case = dict(tile=tile, worlds=worlds, models=models, requested=requested)
                original = runner.run('CL_TransientsCollisionMP_UpdateTransientTileFlags', False, case)
                compiled = runner.run('CL_TransientsCollisionMP_UpdateTransientTileFlags', True, case)
                assert compiled['loaded'] == original['loaded'], case
                expected = worlds == 31 and models == 31 if requested else bool(worlds | models)
                assert compiled['setup'] == expected, (case, compiled)
                if requested:
                    assert compiled == original, ('collision setup changed', case)
                total += 1
    for requested in (True, False):
        for worlds, models in ((0, 0), (31, 31), (3, 0), (0, 4)):
            for tiles in (0, 1, 3):
                case = dict(tile=0, tiles=tiles, worlds=worlds, models=models, requested=requested)
                compiled = runner.run('CL_TransientsCollisionMP_UpdateTransientFlags', True, case)
                expected = tiles == 1 and worlds == 31 and models == 31 if requested else bool(worlds | models)
                assert compiled['all_setup'] == expected, (case, compiled)
                total += 1
    print('PASS individual/combined collision release acknowledgements', total, flush=True)
    receipt = dict(passed=True, cases=total, original_image_sha256=runner.proof["image_sha256"],
                   linked_executable_sha256=runner.report["sha256"] if runner.report else None,
                   modeled_150_client_visibility_evaluations=reductions,
                   modeled_bot_decision_cadence=scheduling,
                   scope=__doc__, live_game_tested=False)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS", total, "native/compiled instruction cases; no game launched")


if __name__ == "__main__":
    main()
