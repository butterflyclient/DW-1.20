"""Execute exact linked Replay unlock getters and original Lua consumers without a game."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sqlite3
import sys

import pefile
import unicorn
import unicorn.x86_const as x

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/unlock-lua-runtime"))
from lupa import LuaRuntime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lua-source", type=Path)
    args = parser.parse_args()
    report_path = args.build / "build-report.json" if args.build.is_dir() else args.build
    report = json.loads(report_path.read_bytes())
    image = Path(report["executable"])
    raw = image.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == report["sha256"]
    assert report["input_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    symbols = {name: base + rva for name, rva in report["symbols"].items()}
    roots = ["func_1410592B0", "func_141059360", "func_141059410",
             "func_141059500", "func_141059A80", "func_140F58C60"]
    for name in roots:
        assert name in symbols
        assert any(r["symbol"] == name and "DW_Unlocks" in r["source"]
                   for r in report["replacements"])
    vm = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for section in pe.sections:
        length = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & -4096
        if length:
            vm.mem_map(base + section.VirtualAddress, length)
            vm.mem_write(base + section.VirtualAddress, section.get_data())
    arena = 0x100000000
    vm.mem_map(arena, 0x20000)
    stack, stop, reference_address = arena + 0x10000 - 8, arena + 0x1F000, arena + 0x18000
    state = dict(provider=True, enabled=False, count=1, controller=0, season=0,
                 number=True, reference="", value=None, table={})
    calls = {}

    def return_value(value=0):
        rsp = vm.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack("<Q", vm.mem_read(rsp, 8))[0]
        vm.reg_write(x.UC_X86_REG_RAX, value)
        vm.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(x.UC_X86_REG_RIP, target)

    def string(address):
        return bytes(vm.mem_read(address, 256)).split(b"\0")[0].decode()

    boundaries = {symbols[name]: name for name in (
        "DW_LocalBackend_IsEnabled", "DW_LocalConfig_UnlockAll", "func_1420838B0",
        "func_1420839E0", "func_142083A30", "func_1419CE9B0", "func_142084950",
        "func_142084100", "func_1420833B0", "func_1419CE4F0", "func_142089FB0",
        "func_140D66C20")}
    receipt_path = report_path.parent.parent.parent / "source-receipt.json"
    source_receipt = json.loads(receipt_path.read_bytes())
    for binding in source_receipt["bindings"]:
        if binding["kind"] == "import" and binding["symbol"] in boundaries.values():
            boundaries[base + binding["original_rva"]] = binding["symbol"]

    def boundary(machine, address, size, userdata):
        name = boundaries.get(address)
        if name is None:
            return
        calls[name] = calls.get(name, 0) + 1
        if name == "DW_LocalBackend_IsEnabled": return_value(int(state["provider"]))
        elif name == "DW_LocalConfig_UnlockAll": return_value(int(state["enabled"]))
        elif name == "func_1420838B0": return_value(state["count"])
        elif name == "func_1420839E0": return_value(int(state["number"]))
        elif name == "func_142083A30": return_value(int(bool(state["reference"])))
        elif name == "func_1419CE9B0":
            return_value(state["controller"] if vm.reg_read(x.UC_X86_REG_RDX) == 1 else state["season"])
        elif name == "func_142084950": return_value(reference_address)
        elif name == "func_142084100":
            bits = vm.reg_read(x.UC_X86_REG_XMM1) & ((1 << 64) - 1)
            state["value"] = struct.unpack("<d", struct.pack("<Q", bits))[0]
            return_value()
        elif name == "func_1420833B0": state["table"] = {}; return_value()
        elif name == "func_1419CE4F0":
            state["table"][string(vm.reg_read(x.UC_X86_REG_RCX))] = vm.reg_read(x.UC_X86_REG_RDX)
            return_value()
        elif name == "func_142089FB0": raise AssertionError("Compiled getter rejected fixture arguments")
        elif name == "func_140D66C20": return_value(state["controller"])
    vm.hook_add(unicorn.UC_HOOK_CODE, boundary)

    def invoke(name, address=None):
        address = symbols[name] if address is None else address
        vm.mem_write(stack, struct.pack("<Q", stop))
        vm.reg_write(x.UC_X86_REG_RSP, stack)
        vm.reg_write(x.UC_X86_REG_RCX, arena)
        vm.reg_write(x.UC_X86_REG_RIP, address)
        vm.emu_start(address, stop, count=500000)
        assert vm.reg_read(x.UC_X86_REG_RIP) == stop, name
        return vm.reg_read(x.UC_X86_REG_RAX)

    # Execute the actual original singleton getter, including its linked data
    # reference. It is deliberately excluded from modeled native boundaries.
    progression = invoke("func_14105BC30")
    assert base <= progression < base + pe.OPTIONAL_HEADER.SizeOfImage
    weapons = symbols["gl_14414CC80"]
    lifetime = symbols["gl_1444879C8"]
    values = [1000 + index * 37 for index in range(120)]
    vm.mem_write(progression + 64, struct.pack("<120Q", *values))
    vm.mem_write(lifetime, struct.pack("<16Q", *range(16)))
    saved_player = bytes(vm.mem_read(progression, 1024))
    saved_lifetime = bytes(vm.mem_read(lifetime, 128))
    normal_cases = 0
    normal_errors = []

    def player(kind, controller=0, season=0):
        state.update(count=2 if kind in (2, 3) else 1, controller=controller,
                     season=season, value=None)
        assert invoke(roots[kind]) == 1
        return state["value"]

    for controller in range(8):
        assert player(0, controller) == values[2 * controller]
        assert player(1, controller) == values[2 * controller + 1]
        if player(4, controller) != 2 * controller:
            normal_errors.append(("compiled lifetime stride", controller, state["value"], 2 * controller))
        normal_cases += 3
        for season in range(7):
            assert player(2, controller, season) == values[2 * (1 + 7 * controller + season)]
            assert player(3, controller, season) == values[2 * (1 + 7 * controller + season) + 1]
            normal_cases += 2
    assert bytes(vm.mem_read(progression, 1024)) == saved_player
    assert bytes(vm.mem_read(lifetime, 128)) == saved_lifetime
    # Independently execute the pinned original getter instructions with the
    # identical values and compare every controller/season result, rather than
    # treating an arithmetic restatement of the layout as the only oracle.
    original_image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    original_raw = original_image.read_bytes()
    assert hashlib.sha256(original_raw).hexdigest() == report["input_sha256"]
    original_pe = pefile.PE(data=original_raw, fast_load=True)
    original_data = base + 0x4483CE0
    vm.mem_write(original_data + 64, struct.pack("<120Q", *values))
    vm.mem_write(base + 0x44879C8, struct.pack("<16Q", *range(16)))
    original_cases = 0
    database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        for kind, binding in enumerate([next(b for b in source_receipt["bindings"]
                                              if b["symbol"] == name) for name in roots[:5]]):
            address = base + binding["original_rva"]
            size = db.execute("select size from functions where address=?", (str(address),)).fetchone()[0]
            saved_code = bytes(vm.mem_read(address, size))
            vm.mem_write(address, original_pe.get_data(binding["original_rva"], size))
            vm.ctl_remove_cache(address, address + size)
            try:
                for controller in range(8):
                    for season in (range(7) if kind in (2, 3) else [0]):
                        state.update(count=2 if kind in (2, 3) else 1,
                                     controller=controller, season=season, value=None)
                        assert invoke(roots[kind], address) == 1
                        expected = 2 * controller if kind == 4 else values[
                            2 * (1 + 7 * controller + season) + (kind == 3)
                            if kind in (2, 3) else 2 * controller + (kind == 1)]
                        assert state["value"] == expected, ("original", kind, controller, season, state["value"], expected)
                        original_cases += 1
            finally:
                vm.mem_write(address, saved_code)
                vm.ctl_remove_cache(address, address + size)
    assert original_cases == normal_cases
    target = json.loads((ROOT / "validation/20261011-unlock-progression-target.json").read_bytes())
    caps = target["weapon_caps"]
    weapon_cases = 0

    def weapon(reference, controller=0):
        encoded = reference.encode() + b"\0"
        vm.mem_write(reference_address, encoded)
        for client in range(2):
            vm.mem_write(weapons + 64 + 2056 * client, struct.pack(
                "<4Q", reference_address, 2000001, 1334 + client * 100, 3 + client))
            vm.mem_write(weapons + 2112 + 2056 * client, struct.pack("<i", 1))
        before = bytes(vm.mem_read(weapons, 4176))
        state.update(count=2, reference=reference, controller=controller, table={})
        assert invoke(roots[5]) == 1
        assert bytes(vm.mem_read(weapons, 4176)) == before
        return dict(state["table"])

    for controller in range(2):
        for cap in caps:
            state["enabled"] = True
            assert weapon(cap["reference"], controller) == {"xp": cap["xp"], "rank": cap["rank"]}, (controller, cap)
            state["enabled"] = False
            assert weapon(cap["reference"], controller) == {"xp": 1334 + controller * 100, "rank": 3 + controller}
            state.update(enabled=True, provider=False)
            assert weapon(cap["reference"], controller) == {"xp": 1334 + controller * 100, "rank": 3 + controller}
            state["provider"] = True
            weapon_cases += 3
    assert not normal_errors, normal_errors

    lua_source = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all"
                      r"\ui\utils\progressionutils.lua.2223.lua")
    assets = json.loads((ROOT / "validation/20261007-weapon-progression-assets.json").read_bytes())
    expected_lua_hash = assets["inputs"][str(lua_source)]
    lua_source = args.lua_source or lua_source
    lua_hash = hashlib.sha256(lua_source.read_bytes()).hexdigest()
    assert lua_hash == expected_lua_hash
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.execute("""
LUI={clamp=function(v,a,b) return math.max(a,math.min(b,v)) end}
SEASON={GetCurrentSeason=function() return 6 end}
CSV={MPRank={file='rank',cols={index=0,maxXP=7}},
elderProgressionTable={GetFile=function(s) return 'season'..s end,cols={rank=0,maxXP=2,minXP=1}},
gunsmithProgressionTable={GetFile=function(_,w) return w end,cols={level=0}}}
OnlineProgression={}; Gunsmith={}; StringTable={}
""")
    for name, kind in [("CBJHJGIGDA", 0), ("BDHJABHDDC", 1), ("DFDGDCIAHI", 2),
                       ("CFEDCBACGI", 3), ("DABCDDIHDG", 4)]:
        lua.globals().OnlineProgression[name] = lambda controller, season=0, kind=kind: player(
            kind, int(controller), int(season))
    lua.globals().Gunsmith.BEDFIJHAB = lambda controller, reference: lua.table_from(weapon(reference, int(controller)))
    cap_lookup = {cap["reference"]: cap["rank"] for cap in caps}

    def lookup(file, column, key, output):
        if file == "rank": return {"maxrank": 54, "maxelder": 100}.get(str(key), 960000)
        return target["season_maximum_xp"][int(file[6:])]
    lua.globals().StringTable.DIFCHIGDFB = lookup
    lua.globals().StringTable.BFHCAIIDA = lambda file: 0
    lua.globals().StringTable.CBGJCDIHCE = lambda file, row, column: str(cap_lookup[file])
    lua.execute(lua_source.read_text(encoding="utf-8-sig"))
    p = lua.globals().PROGRESSION
    state.update(enabled=True, provider=True)
    assert p.IsElder(0) is True and p.GetPlayerRank(0) == 154 and p.GetPlayerDisplayLevel(0) == 155
    assert p.IsPlayerLifeTimeRankMax(0) is True and p.IsPlayerLifeTimeXPMax(0) is True
    for controller in range(2):
        for cap in caps:
            assert p.GetWeaponLevel(controller, cap["reference"]) == cap["rank"] + 1
            assert p.IsWeaponMaxLevel(controller, cap["reference"]) is True
            assert p.GetWeaponXP(controller, cap["reference"]) == cap["xp"]
    assert bytes(vm.mem_read(progression, 1024)) == saved_player
    assert bytes(vm.mem_read(lifetime, 128)) == saved_lifetime
    # Genuine native awards arrive while the maximum projection is enabled.
    vm.mem_write(progression + 64, struct.pack("<QQ", 18200, 4))
    for season in range(7): vm.mem_write(progression + 80 + 16 * season, bytes(16))
    vm.mem_write(lifetime, bytes(8))
    state["enabled"] = False
    assert p.IsElder(0) is False and p.GetPlayerXP(0) == 18200
    assert p.GetPlayerRank(0) == 4 and p.GetPlayerDisplayLevel(0) == 5
    for controller in range(2):
        for cap in caps:
            assert p.GetWeaponXP(controller, cap["reference"]) == 1334 + controller * 100
            assert p.GetWeaponLevel(controller, cap["reference"]) == 4 + controller
    result = dict(schema=1, passed=True, executable=str(image), sha256=report["sha256"],
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  original_lua_sha256=lua_hash, native_singleton_pointer=hex(progression),
                  original_controller_equivalence_cases=normal_cases, weapon_getter_cases=weapon_cases,
                  original_instruction_oracle_cases=original_cases,
                  canonical_weapons=len(caps), maximum_display_level=155,
                  native_storage_unchanged=True, earned_progress_preserved=True,
                  modeled_boundaries=calls, game_launched=False,
                  scope="Exact linked getter instruction execution and original Lua consumers; Lua/native calls modeled")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: exact-image getters, eight-controller native equivalence, original Lua level155 and 51 reversible weapon caps")


if __name__ == "__main__":
    main()
