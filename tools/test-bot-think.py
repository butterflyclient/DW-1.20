"""Execute native and compiled Bot_Think with modeled native call boundaries.

This focused harness executes the hash-verified original instructions. It proves
branch/order/ABI behavior against stubs, not native leaf or live-game behavior.
"""
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
import tempfile

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *

ROOT = Path(__file__).resolve().parents[1]


class Runner:
    def __init__(self, snapshot, build=None):
        self.snapshot = snapshot
        self.proof = json.loads((snapshot / "generated/bot-think-integration.json").read_bytes())
        self.pe = pefile.PE(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe", fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        code = self.pe.get_data(self.proof["original_rva"], self.proof["original_bytes"])
        assert hashlib.sha256(code).hexdigest() == self.proof["original_sha256"]
        host = json.loads((snapshot / "generated/host-scale-integration.json").read_bytes())
        self.symbols = {r["name"]: self.base + r["original_rva"] for r in host["bindings"] + self.proof["bindings"]}
        self.hooks = {self.symbols[r["name"]]: r["name"] for r in self.proof["bindings"] if r["kind"] == "function"}
        spec = importlib.util.spec_from_file_location("bot_think_signatures", ROOT / "tools/prepare-bot-think-integration.py")
        definitions = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(definitions)
        self.parameters = {"BT_" + name: params.split(", ") if params else []
                           for ordinal, name, result, params in definitions.CALLS + definitions.POLICY_CALLS + definitions.POLICY_DIRECT_CALLS}
        self.fire = next(r for r in self.proof["combat_policy_proofs"] if r["symbol"] == "Bot_CombatStateFire")
        fire_code = self.pe.get_data(self.fire["original_rva"], self.fire["original_bytes"])
        assert hashlib.sha256(fire_code).hexdigest() == self.fire["original_sha256"]
        self.fire_calls = [int(i.op_str, 16) for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(fire_code, self.base + self.fire["original_rva"])
                           if i.mnemonic == "call"]
        combat = next(r for r in self.proof["combat_policy_proofs"] if r["symbol"] == "Bot_UpdateCombat")
        combat_code = self.pe.get_data(combat["original_rva"], combat["original_bytes"])
        assert hashlib.sha256(combat_code).hexdigest() == combat["original_sha256"]
        self.combat_calls = [int(i.op_str, 16) for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(combat_code, self.base + combat["original_rva"])
                             if i.mnemonic == "call"]
        self.report = None
        self.build_path = build
        self.source = snapshot / self.proof["source"]
        assert hashlib.sha256(self.source.read_bytes()).hexdigest() == self.proof["source_sha256"]
        if build:
            self.report = json.loads((build / "build-report.json").read_bytes())
            path = Path(self.report["executable"])
            assert hashlib.sha256(path.read_bytes()).hexdigest() == self.report["sha256"]
            assert self.report["unresolved_symbols"] == 0
            self.linked = pefile.PE(str(path), fast_load=True)
            assert self.linked.OPTIONAL_HEADER.ImageBase == self.base
            self.ranges = self.report["rva_map"]["ranges"]
            self.starts = [r["begin"] for r in self.ranges]
            assert "Bot_Think" in self.report["symbols"]
            return
        # Isolated compilation never creates files in the supplied snapshot.
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(snapshot / "tools"))
        from coff import read
        with tempfile.TemporaryDirectory(prefix="bot-think-test-", dir=ROOT / "data") as temporary:
            obj = Path(temporary) / "Bot_Think.obj"
            subprocess.run([r"C:\Program Files\LLVM\bin\clang++.exe", "--target=x86_64-pc-windows-msvc",
                            "-c", str(self.source), "-o", str(obj),
                            "-O2", "-std=c++20", "-ffreestanding", "-fno-stack-protector", "-fno-exceptions",
                            "-fno-rtti", "-funwind-tables", "-ffunction-sections", "-fdata-sections",
                            "-Wall", "-Wextra", "-Werror", "-I" + str(snapshot / "src")], check=True)
            self.object = read(obj)

    def run(self, edited, case):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        pe = self.linked if edited and self.report else self.pe
        symbols = dict(self.symbols)
        if edited and self.report:
            def mapped(address):
                rva = address - self.base
                row = self.ranges[bisect.bisect_right(self.starts, rva) - 1]
                assert row["begin"] <= rva < row["end"], (address, row)
                return self.base + row["mapped_begin"] + rva - row["begin"]
            symbols = {name: mapped(address) for name, address in symbols.items()}
        pages = set()
        def page(at):
            at &= -4096
            if at in pages:
                return
            vm.mem_map(at, 4096)
            if self.base <= at < self.base + pe.OPTIONAL_HEADER.SizeOfImage:
                data = pe.get_data(at - self.base, 4096)
                if data:
                    vm.mem_write(at, data)
            pages.add(at)
        def put(at, data, fmt=None):
            if fmt:
                data = struct.pack(fmt, data)
            for address in range(at & -4096, (at + len(data) + 4095) & -4096, 4096):
                page(address)
            vm.mem_write(at, data)
        def get(at, fmt):
            size = struct.calcsize(fmt)
            page(at); page(at + size - 1)
            return struct.unpack(fmt, vm.mem_read(at, size))[0]
        hooks = {symbols[r["name"]]: r["name"] for r in self.proof["bindings"] if r["kind"] == "function"}
        enabled = 0x180e00000
        hooks[enabled] = "enabled"
        memcpy = 0x180e00020
        hooks[memcpy] = "memcpy"
        br_policy = 0x180e00040
        hooks[br_policy] = "br-policy"
        hooks[symbols["SVHS_EnemyTeamFlags"]] = "enemy-team-flags"
        fire_entry = self.base + self.fire["original_rva"]
        if edited and self.report:
            fire_entry = mapped(fire_entry)
        if case.get("native_fire"):
            fire_aliases = {4: "NF_hand", 5: "NF_weaponstate", 6: "NF_dual", 8: "NF_overlay",
                            12: "NF_recoil", 18: "NF_boltaction", 19: "NF_boltstate", 20: "NF_clip",
                            23: "NF_firetime", 24: "NF_usingalternate", 26: "NF_delay"}
            for ordinal, name in fire_aliases.items():
                address = self.fire_calls[ordinal]
                hooks[mapped(address) if edited and self.report else address] = name
            combat_aliases = {0: "NF_blind", 1: "NF_grenade_allowed", 4: "NF_melee_react", 5: "NF_melee_allowed",
                              8: "NF_melee_range", 11: "NF_melee_preferred", 13: "NF_grenade_action",
                              14: "NF_offhand_fire", 17: "NF_ammo", 18: "NF_corner_combat",
                              19: "NF_should_fire", 20: "NF_fire_wait"}
            for ordinal, name in combat_aliases.items():
                address = self.combat_calls[ordinal]
                hooks[mapped(address) if edited and self.report else address] = name
        if edited and self.report:
            entry = self.base + self.report["symbols"]["Bot_Think"]
            for name, alias in (("?Enabled@HostScale@@YA_NXZ", "enabled"),
                                ("Com_Optimized_IsEnabled", "enabled"), ("memcpy", "memcpy"),
                                ("DW_BotPolicy_IsBattleRoyale", "br-policy")):
                if name in self.report["symbols"]:
                    hooks[self.base + self.report["symbols"][name]] = alias
        elif edited:
            obj = self.object
            section_addresses = {i + 1: 0x180000000 + i * 0x10000 for i in range(len(obj["sections"]))}
            externals = dict(symbols)
            externals.update({"?Enabled@HostScale@@YA_NXZ": enabled, "memcpy": memcpy, "_fltused": 0x180e00100,
                              "DW_BotPolicy_IsBattleRoyale": br_policy})
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
                        raise AssertionError(kind)
                if data:
                    put(start, bytes(data))
            entry = next(addresses[i] for i, s in obj["symbols"].items() if s["name"] == "Bot_Think")
        else:
            entry = self.base + self.proof["original_rva"]
        client, ent, sentient, player, command, last, nav, vtable, area, area_value = (
            0x51000000, 0x52000000, 0x52100000, 0x53000000, 0x54000000, 0x54100000,
            0x55000000, 0x55100000, 0x55200000, 0x55210000)
        bot = client + 1368
        for address, size in ((client, 36000), (ent, 1440 * 4), (sentient, 184), (player, 25000),
                              (nav, 1400), (vtable, 400), (area, 16)):
            put(address, bytes(size))
        put(client + 1368, 0 if case.get("no_entity") else ent, "<Q")
        put(bot + 8, sentient, "<Q"); put(bot + 360, nav if case.get("navigator", True) else 0, "<Q")
        put(bot + 448, player, "<Q"); put(bot + 456, last, "<Q")
        put(bot + 464, case.get("bot_flags", 0), "<I")
        put(bot + 8984, 0x1000000 if case.get("mesh", False) else 0, "<I")
        put(client + 10355, int(case.get("mesh", False)), "<B")
        put(client + 1988, case.get("traversal", 0), "<i")
        put(client + 30568, case.get("radar_time", 10000), "<i")
        put(client + 30576, 9950 if case.get("ads") and not case.get("native_fire") else 0, "<i")
        put(client + 10492, 9000, "<i")
        put(client + 34032, 0.75, "<f")
        put(bot + 32484, case.get("match_flags", 0x10), "<I")
        put(bot + 32688, case.get("burst_type", 1), "<I")
        put(bot + 27864, case.get("burst_start", 20000), "<i")
        put(bot + 27868, 30000, "<i")
        put(bot + 27872, case.get("semi_delay", 0), "<i")
        put(bot + 27884, case.get("offhand_delay", 0), "<i")
        put(bot + 32516, case.get("ads_delay", 0.0), "<f")
        put(player + 1796, case.get("weapon_flags", 0), "<I")
        put(player + 1804, case.get("ads_fraction", 1.0), "<f")
        put(player + 1872, 1, "<I")
        put(player + 12072, case.get("skydive", 0), "<B")
        put(player + 24016, case.get("client_flags", 0), "<I")
        put(player + 22336, case.get("gulag_phase", 0), "<I")
        put(player + 20, case.get("pm_flags", 0), "<I")
        put(player + 144, 1, "<h")
        if case.get("remote"):
            put(player + 20, 0x10000000, "<I")
            put(ent + 1440 + 8, 4, "<H"); put(ent + 1440 + 492, 0x80, "<B")
        put(ent, 3, "<h"); put(ent + 336, player, "<Q"); put(ent + 344, sentient, "<Q")
        put(ent + 440, case.get("health", 100), "<i"); put(ent + 304, struct.pack("<fff", 2000.0, 0.0, 0.0))
        put(sentient, ent, "<Q"); put(sentient + 16, case.get("team", 1), "<I")
        put(nav, vtable, "<Q"); put(vtable + 45 * 8, symbols["SVHS_Nav2DClosest"] if case.get("nav_type", True) else 0, "<Q")
        put(nav + 1364, area if case.get("area_handle", True) else 0, "<Q")
        put(nav + 1372, area_value if case.get("area_space", True) else 0, "<Q")
        put(area, area_value if case.get("area_value", True) else 0, "<Q")
        rng = random.Random(case.get("seed", 120))
        cmd = bytearray(rng.randbytes(264)); struct.pack_into("<Q", cmd, 0, case.get("last_buttons", 0xC8))
        put(last, bytes(cmd)); put(command, b"\xa5" * 264)
        put(symbols["BT_ClientBase"], client - 3 * 321192, "<Q")
        put(symbols["BT_Entities"], ent, "<Q")
        put(symbols["SVHS_LevelTime"], 10000, "<i")
        for name in ("BT_PausedDvar", "BT_DisableRepulsorsDvar", "BT_RadarDvar"):
            dvar = 0x56000000 + list(("BT_PausedDvar", "BT_DisableRepulsorsDvar", "BT_RadarDvar")).index(name) * 4096
            put(dvar, bytes(64)); put(symbols[name], dvar, "<Q")
            if name == "BT_PausedDvar":
                put(dvar + 40, int(case.get("paused", False)), "<I")
        put(symbols["BT_DisableNearest"], 0, "<B")
        put(symbols["BT_Persistent"], 0x56300000, "<Q"); put(0x56300000 + 28, 10000, "<i")
        put(symbols["BT_RadarEntities"], struct.pack("<h", 2047) * 64)
        put(symbols["BT_EntityInUse"], 0x56400000, "<Q"); put(0x56400000, bytes(2048))
        if case.get("native_fire"):
            put(ent + 1440 + 440, case.get("enemy_health", 100), "<i")
            put(ent + 1440 + 344, sentient + 184, "<Q")
            put(sentient + 184 + 16, 2, "<I")
            put(0x56400000 + 1, 1, "<B")
        if case.get("radar_entity"):
            put(symbols["BT_RadarEntities"], 3, "<h"); put(0x56400000 + 3, 1, "<B")
            put(ent + 1440 * 3, 3, "<h"); put(ent + 1440 * 3 + 336, player, "<Q")
            put(player + 364, 0x200000, "<I")
        put(0x56002000 + 40, int(case.get("radar", False)), "<B")
        put(symbols["SVHS_BotTlsIndex"], 2, "<I"); put(symbols["SVHS_GameStatics"], 0x56500000, "<Q")
        vm.reg_write(UC_X86_REG_GS_BASE, 0x56600000)
        put(0x56600000 + 0x58, 0x56700000, "<Q"); put(0x56700000 + 16, 0x56800000, "<Q")
        put(0x56800000 + 16, 0, "<Q")
        stop, stack = 0x190000000, 0x70080008
        for address in range(stack - 0x20000, stack + 0x1000, 4096):
            page(address)
        page(stop); put(stack, stop, "<Q")
        vm.reg_write(UC_X86_REG_RSP, stack); vm.reg_write(UC_X86_REG_RCX, client); vm.reg_write(UC_X86_REG_RDX, command)
        events, arguments = [], []
        def returned(value=0, floating=None):
            sp = vm.reg_read(UC_X86_REG_RSP)
            vm.reg_write(UC_X86_REG_RAX, value & 0xffffffffffffffff)
            if floating is not None:
                vm.reg_write(UC_X86_REG_XMM0, struct.unpack("<I", struct.pack("<f", floating))[0])
            vm.reg_write(UC_X86_REG_RSP, sp + 8); vm.reg_write(UC_X86_REG_RIP, get(sp, "<Q"))
        def boundary(machine, address, size, context):
            name = hooks.get(address)
            if name is None:
                return
            a, b, c = (vm.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8))
            if name == "enabled":
                returned(int(case.get("enabled", True))); return
            if name == "memcpy":
                put(a, bytes(vm.mem_read(b, c))); returned(a); return
            if name == "br-policy":
                returned(int(case.get("br_policy", False))); return
            if name == "enemy-team-flags":
                put(a, bytes(20) if case.get("friendly") else b"\xff" * 20); returned(); return
            if name and name.startswith("NF_"):
                if name == "NF_weaponstate":
                    returned(case.get("weapon_state", 0))
                elif name == "NF_clip":
                    returned(30)
                elif name == "NF_ammo":
                    returned(0 if case.get("no_ammo") else 30)
                elif name == "NF_should_fire":
                    returned(int(case.get("fire", False) and case.get("enemy_health", 100) > 0 and not case.get("friendly")))
                elif name in ("NF_melee_react", "NF_melee_allowed"):
                    returned(int(case.get("native_melee", False)))
                elif name == "NF_melee_range":
                    returned(floating=3000.0 if case.get("native_melee") else 0.0)
                elif name == "NF_dual":
                    returned(int(case.get("native_dual", False)))
                elif name == "NF_fire_wait":
                    returned(int(case.get("aim_wait", False)))
                elif name == "NF_grenade_action" and case.get("grenade_action"):
                    put(b, get(b, "<Q") | 0x1000, "<Q"); returned(1)
                elif name in ("NF_firetime", "NF_delay"):
                    returned(100)
                else:
                    returned()
                return
            events.append(name)
            assert name.startswith("BT_")
            observed = []
            for index, type_ in enumerate(self.parameters[name]):
                if type_ == "...":
                    break
                if type_ == "float":
                    value = vm.reg_read((UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3)[index]) & 0xffffffff
                elif index < 4:
                    value = vm.reg_read((UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)[index])
                else:
                    value = get(vm.reg_read(UC_X86_REG_RSP) + 40 + (index - 4) * 8, "<Q")
                if type_ in ("bool", "uint8_t"):
                    value &= 0xff
                elif type_ in ("int", "unsigned"):
                    value &= 0xffffffff
                elif name == "BT_PrintError" and index == 1:
                    data = bytearray()
                    while get(value + len(data), "<B"):
                        data.append(get(value + len(data), "<B"))
                    value = data.decode()
                observed.append(value)
            arguments.append((name, observed))
            if name in ("BT_XRay", "BT_Sight", "BT_Threat", "BT_Combat", "BT_OffGridMove"):
                assert get(0x56800000 + 16, "<Q") == 0x56500000, (name, "game statics missing")
            if name == "BT_PlayerState":
                assert a == 3; returned(player); return
            if name == "BT_EntityData":
                returned(bot); return
            if name == "BT_ViewWeapon" or name == "BT_MapViewWeapon":
                put(0x56900000, case.get("weapon", 1), "<H"); returned(0x56900000); return
            if name == "BT_WeaponNone":
                returned(int(not get(a, "<H"))); return
            if name == "BT_NearestNode":
                returned(0x56a00000 if case.get("node", True) else 0); return
            if name == "BT_NearestTac":
                returned(0x56b00000 if case.get("tac", True) else 0); return
            if name == "BT_ArchiveTime":
                returned(case.get("archive", 0)); return
            if name == "BT_LocalPaused":
                returned(int(case.get("local_paused", False))); return
            if name == "BT_ScriptedScene":
                returned(int(case.get("scripted_scene", False))); return
            if name == "BT_Sight":
                if case.get("acquire"):
                    put(sentient + 72, 2, "<H")
                returned(); return
            if name == "BT_Combat":
                if case.get("native_fire"):
                    # Execute both complete native Combat and Fire bodies;
                    # their leaf boundaries model visibility, weapon facts,
                    # grenade requests and reaction timing.
                    return
                if get(sentient + 72, "<H"):
                    put(command, get(command, "<Q") | 1, "<Q")
                returned(); return
            if name == "BT_IsFiring":
                returned(int(bool(get(command, "<Q") & 1))); return
            if name == "BT_ClearWeapon":
                put(a + 36, bytes(60)); returned(); return
            if name == "BT_Compare":
                returned(int(bytes(vm.mem_read(a, c)) != bytes(vm.mem_read(b, c)))); return
            if name in ("BT_RandomInt", "BT_BreathTime"):
                if name == "BT_RandomInt":
                    events[-1] += f":{a & 0xffffffff}:{b & 0xffffffff}"
                returned(100); return
            if name in ("BT_RandomFloat", "BT_WeaponRange", "BT_NodeDistance"):
                returned(floating=0.25 if name == "BT_RandomFloat" else 100.0); return
            if name in ("BT_Gesture", "BT_WeaponMap"):
                returned(0x56c00000); return
            if name == "BT_Reload":
                returned(int(not case.get("underbarrel"))); return
            if name == "BT_Underbarrel":
                returned(int(case.get("underbarrel", False))); return
            if name == "BT_WeaponFireType":
                returned(case.get("fire_type", 0)); return
            if name == "BT_IsWeaponClass":
                returned(int(c == 6 and case.get("grenade", False))); return
            if name == "BT_IsRanged":
                returned(int(not case.get("melee", False))); return
            if name == "BT_ADSAllowed" and case.get("native_fire"):
                returned(int(case.get("ads_allowed", True) and not case.get("native_dual") and bool(get(bot + 32484, "<I") & 2))); return
            mapping = {"BT_PressADS": "ads", "BT_CanHoldBreath": "breath", "BT_VariableZoom": "zoom",
                       "BT_InADS": "in_ads", "BT_IsSkydiving": "sky", "BT_DualWield": "dual",
                       "BT_GesturePlaying": "gesture", "BT_CanFire": "fire", "BT_ADSDesire": "ads_desire",
                       "BT_ADSAllowed": "ads_allowed", "BT_ActiveUnderbarrel": "alternate"}
            returned(int(case.get(mapping[name], False)) if name in mapping else int(name == "BT_Feature"))
        vm.hook_add(UC_HOOK_CODE, boundary)
        def unmapped(machine, access, address, size, value, context):
            page(address); page(address + size - 1); return True
        vm.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)
        vm.emu_start(entry, stop, count=1000000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        return dict(command=bytes(vm.mem_read(command, 264)).hex(), client=bytes(vm.mem_read(client, 36000)).hex(),
                    events=events, arguments=arguments, statics=get(0x56800000 + 16, "<Q"),
                    tactical=bytes(vm.mem_read(sentient + 148, 6)).hex())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot_positional", type=Path, nargs="?")
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    snapshot = args.snapshot or args.snapshot_positional
    if snapshot is None:
        parser.error("a snapshot path is required")
    if args.snapshot and args.snapshot_positional:
        parser.error("supply either --snapshot or positional snapshot")
    runner = Runner(snapshot.resolve(), args.build.resolve() if args.build else None)
    baselines = [dict(), dict(mesh=True), dict(mesh=True, tac=False, enabled=False),
                 dict(node=False), dict(mesh=True, tac=False, area_value=False),
                 dict(mesh=True, tac=False, nav_type=False), dict(mesh=True, tac=False, navigator=False),
                 dict(mesh=True, tac=False, area_handle=False), dict(mesh=True, tac=False, area_space=False),
                 dict(no_entity=True), dict(team=0), dict(team=153),
                 dict(paused=True), dict(local_paused=True), dict(health=0), dict(archive=500), dict(pm_flags=0x8000),
                 dict(client_flags=4), dict(client_flags=0x404, weapon=0), dict(skydive=2),
                 dict(ads=True, breath=True), dict(ads=True, breath=True, ads_fraction=0.5),
                 dict(zoom=True), dict(zoom=True, in_ads=True), dict(underbarrel=True),
                 dict(dual=True, weapon_flags=0x8000000), dict(gesture=True),
                 dict(ads_desire=True, ads_allowed=True, fire=True), dict(radar_time=0),
                 dict(acquire=True, bot_flags=8), dict(node=False, scripted_scene=True), dict(remote=True),
                 dict(radar_time=0, radar_entity=True), dict(radar_time=0, radar=True)]
    for index, case in enumerate(baselines):
        native, edited = runner.run(False, case), runner.run(True, case)
        assert native == edited, (index, case, native["events"], edited["events"])
    case = dict(mesh=True, tac=False, node=False, acquire=True, fire=True)
    native, edited = runner.run(False, case), runner.run(True, case)
    assert "BT_OffGridMove" in native["events"] and "BT_Sight" not in native["events"]
    stages = ("BT_XRay", "BT_Sight", "BT_Threat", "BT_EnemyTrack", "BT_WeaponUpdate", "BT_Movement", "BT_Combat", "BT_MeleeCharge")
    assert all(stage in edited["events"] for stage in stages)
    assert "BT_OffGridMove" not in edited["events"]
    assert struct.unpack_from("<Q", bytes.fromhex(edited["command"]))[0] & 1
    assert native["tactical"] == edited["tactical"] == bytes(6).hex()
    assert native["statics"] == edited["statics"] == 0
    policy_cases = [
        ("full-auto", {}, True, True),
        ("beam", {"fire_type": 5}, True, True),
        ("semi-auto cadence", {"fire_type": 1, "burst_type": 0, "semi_delay": 20000}, False, True),
        ("offhand delay", {"offhand_delay": 20000}, False, True),
        ("disallowed weapon state", {"weapon_state": 12}, False, True),
        ("blocked sight", {"fire": False}, False, False),
        ("dead target", {"enemy_health": 0}, False, False),
        ("friendly target", {"friendly": True}, False, False),
        ("grenade class", {"grenade": True}, False, False),
        ("melee weapon", {"melee": True}, False, False),
        ("native close melee", {"melee": True, "native_melee": True}, False, False),
        ("native dual wield", {"native_dual": True}, True, False),
        ("Gulag jail", {"gulag_phase": 0x200}, False, False),
        ("skydive", {"sky": True, "skydive": 2}, False, False),
        ("ADS unsupported", {"ads_allowed": False}, True, False),
        ("native ADS transition wait", {"match_flags": 0x14, "ads_fraction": 0.5, "ads_delay": 100.0}, False, True),
        ("empty ammunition", {"no_ammo": True}, False, False),
        ("native aim wait", {"aim_wait": True}, False, False),
        ("native grenade action", {"grenade_action": True}, False, False),
        ("BR policy disabled", {"enabled": False}, False, False),
        ("outside BR", {"br_policy": False}, False, False),
    ]
    for label, options, shooting, aiming in policy_cases:
        case = dict(native_fire=True, br_policy=True, acquire=True, fire=True, ads=True)
        case.update(options)
        native, edited = runner.run(False, case), runner.run(True, case)
        buttons = struct.unpack_from("<Q", bytes.fromhex(edited["command"]))[0]
        assert bool(buttons & 1) == shooting, (label, "fire", hex(buttons), edited["events"])
        assert bool(buttons & 0x200) == aiming, (label, "ADS", hex(buttons), edited["events"])
        state = bytes.fromhex(edited["client"])
        assert struct.unpack_from("<I", state, 1368 + 32484)[0] == case.get("match_flags", 0x10), (label, "match flags not restored")
        assert struct.unpack_from("<I", state, 1368 + 32688)[0] == case.get("burst_type", 1), (label, "burst policy not restored")
        if label in ("full-auto", "beam"):
            assert not struct.unpack_from("<Q", bytes.fromhex(native["command"]))[0] & 1, (label, "original must retain burst pause")
        if label == "native grenade action":
            assert buttons & 0x1000, "Native grenade command was lost"
        if label == "native close melee":
            assert buttons & 4, "Native melee command was lost"
            assert native["command"] == edited["command"]
        if label == "native dual wield":
            assert buttons & 0x20000, "Native second-hand fire command was lost"
        if label in ("BR policy disabled", "outside BR"):
            assert native == edited, (label, "policy changed baseline")
    report = dict(schema=1, baseline_cases=len(baselines), mesh_continuation_cases=1,
                  native_fire_policy_cases=len(policy_cases),
                  native_fire_body_sha256=runner.fire["original_sha256"],
                  native_body_sha256=runner.proof["original_sha256"],
                  source_sha256=hashlib.sha256(runner.source.read_bytes()).hexdigest(),
                  build_report=str(runner.build_path / "build-report.json") if runner.build_path else None,
                  linked_image_sha256=runner.report["sha256"] if runner.report else None,
                  exact_linked_image=bool(runner.report),
                  passed=True, game_run_performed=False)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
