"""Exercise linked DW lobby controls at their original engine ABI boundaries."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_XMM1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    image = Path(report["executable"])
    if not image.is_absolute():
        image = args.build / image
    assert hashlib.sha256(image.read_bytes()).hexdigest() == report["sha256"]
    verification = json.loads((args.build / "verification-report.json").read_bytes())
    assert verification["sha256"] == report["sha256"] and not verification["unresolved_symbols"]
    pe = pefile.PE(str(image), fast_load=True)
    base, symbols = pe.OPTIONAL_HEADER.ImageBase, report["symbols"]
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, arena, halt = 0x10000000, 0x11000000, 0x12000000
    for address in (stack, arena, halt):
        vm.mem_map(address, 0x10000)
    pages = set()

    def page(address):
        page = address & ~4095
        assert base <= page < base + pe.OPTIONAL_HEADER.SizeOfImage
        if page not in pages:
            vm.mem_map(page, 4096)
            raw = pe.get_data(page - base, 4096)
            if raw:
                vm.mem_write(page, raw)
            pages.add(page)

    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True

    def write(address, value, fmt="<i"):
        if base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            page(address)
        vm.mem_write(address, struct.pack(fmt, value))

    def read(address, fmt="<i"):
        return struct.unpack(fmt, vm.mem_read(address, struct.calcsize(fmt)))[0]

    def string(address):
        result = bytearray()
        for offset in range(256):
            if base <= address + offset < base + pe.OPTIONAL_HEADER.SizeOfImage:
                page(address + offset)
            value = vm.mem_read(address + offset, 1)[0]
            if not value:
                return result.decode()
            result.append(value)
        raise AssertionError("Unbounded control string")

    def returned(value=0):
        rsp = vm.reg_read(UC_X86_REG_RSP)
        vm.reg_write(UC_X86_REG_RAX, value)
        vm.reg_write(UC_X86_REG_RIP, read(rsp, "<Q"))
        vm.reg_write(UC_X86_REG_RSP, rsp + 8)

    dvars = {}
    for i, name in enumerate(("gl_14D386820", "gl_14D386948", "gl_14D386840", "gl_14C796328", "DVARBOOL_onlinegame")):
        pointer = arena + 0x1000 + i * 0x100
        dvars[name] = pointer
        write(base + symbols[name], pointer, "<Q")
        write(pointer + 29, 5, "<B")
    write(dvars["DVARBOOL_onlinegame"] + 40, 1)
    write(dvars["gl_14C796328"] + 40, 2)
    settings = dict(enabled=True, main=True, frontend=True, lobby=True, host=True, systemlink=False, controller=0, playlist_bots=False, mode=2, slots=152, humans=2, allies=1, axis=1)
    calls, registered, checks = [], {}, []
    lua = dict(top=2, locked=False, limits={}, now=10000)
    names = ("DW_LocalBackend_IsEnabled", "Sys_IsMainThread", "Com_FrontEndScene_IsActive", "Com_GameMode_GetActiveGameMode", "Dvar_BeginPermanentRegistration", "Dvar_EndPermanentRegistration", "Dvar_RegisterInt", "Dvar_SetVariant", "Dvar_FindVarByName", "Com_Printf", "replay_rva_01187fa0", "replay_rva_01187ee0", "replay_rva_01189120", "replay_rva_0118dd00", "replay_rva_0119cfa0", "replay_rva_0119a5a0", "replay_rva_00ca2370", "replay_rva_00ca1d20", "replay_rva_01119b40", "replay_rva_0118ab60", "replay_rva_0118ad10", "replay_rva_00ca2110", "replay_rva_01528420", "replay_rva_00ca1c50", "replay_rva_010cd460", "replay_rva_010cc6f0", "replay_rva_019bdad0", "replay_rva_019bedb0", "replay_rva_020838b0", "replay_rva_020836e0", "replay_rva_02084ac0", "replay_rva_02084100", "replay_rva_02084510", "replay_rva_02084790", "replay_rva_0148fce0")
    names += ("func_142083A30", "func_1420839E0", "func_142084950", "func_1419B78C0", "func_142089FB0", "func_1413E33E0", "func_1413E2BA0", "func_142084120", "func_1419CDD30")
    store = dict(active=False, top=4, table="loot/bundle_ids.csv", column=10, price="500", exists=True, result=None)

    def resolve(name):
        canonical = f"func_{0x140000000 + int(name.removeprefix('replay_rva_'), 16):X}" if name.startswith("replay_rva_") else name
        return base + symbols[name if name in symbols else canonical]

    boundaries = {resolve(name): name for name in (*names, "replay_rva_0118c7d0", "replay_rva_011916c0")}

    def boundary(machine, address, size, context):
        name = boundaries.get(address)
        if not name:
            return
        values = [machine.reg_read(reg) for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        boolean = {"DW_LocalBackend_IsEnabled": "enabled", "Sys_IsMainThread": "main", "Com_FrontEndScene_IsActive": "frontend", "replay_rva_01187fa0": "lobby", "replay_rva_01189120": "host", "replay_rva_0118dd00": "lobby", "replay_rva_01528420": "systemlink", "replay_rva_010cc6f0": "playlist_bots"}
        if name in boolean:
            returned(int(settings[boolean[name]]))
        elif name == "Com_GameMode_GetActiveGameMode":
            returned(settings["mode"])
        elif name == "replay_rva_01187ee0":
            returned(arena + 0x8000)
        elif name == "replay_rva_00ca1c50":
            returned(settings["controller"] & 0xFFFFFFFF)
        elif name == "replay_rva_010cd460":
            returned(3)
        elif name == "replay_rva_0118c7d0":
            assert values[0] == arena + 0x8000
            returned(settings["slots"])
        elif name == "replay_rva_011916c0":
            assert values[0] == arena + 0x8000 and values[1] == 200
            settings["slots"] = values[1]
            returned()
        elif name == "Dvar_RegisterInt":
            key = string(values[0])
            assert key in ("replay_dw_forceStart", "replay_dw_fillBots", "replay_dw_botCount") and values[1:4] == [0, 0, 199 if key == "replay_dw_botCount" else 1]
            assert key not in registered
            pointer = arena + 0x2000 + len(registered) * 0x100
            write(pointer + 29, 5, "<B")
            registered[key] = pointer
            returned(pointer)
        elif name == "Dvar_SetVariant":
            machine.mem_write(values[0] + 40, bytes(machine.mem_read(values[1], 16)))
            returned()
        elif name == "Dvar_FindVarByName":
            assert string(values[0]) == "br_minplayers"
            returned(arena + 0x3000)
        elif name == "replay_rva_0148fce0":
            returned(lua["now"])
        elif name == "replay_rva_019bdad0":
            assert not lua["locked"]
            lua["locked"] = True
            returned()
        elif name == "replay_rva_019bedb0":
            assert lua["locked"] and lua["top"] == 2
            lua["locked"] = False
            returned()
        elif name == "replay_rva_020838b0" and store["active"]:
            returned(store["top"])
        elif name == "replay_rva_020838b0":
            assert lua["locked"]
            returned(lua["top"])
        elif name == "replay_rva_020836e0":
            assert lua["locked"] and values[1] & 0xFFFFFFFF == (-10002 & 0xFFFFFFFF) and string(values[2]) == "Lobby"
            lua["top"] += 1
            returned()
        elif name == "replay_rva_02084ac0":
            assert lua["locked"] and values[1] & 0xFFFFFFFF == 0xFFFFFFFF
            returned(5)
        elif name == "replay_rva_02084100":
            raw = (machine.reg_read(UC_X86_REG_XMM1) & ((1 << 64) - 1)).to_bytes(8, "little")
            assert lua["locked"] and struct.unpack("<d", raw)[0] == 200.0
            lua["top"] += 1
            returned()
        elif name == "replay_rva_02084510":
            key = string(values[2])
            assert lua["locked"] and values[1] & 0xFFFFFFFF == 0xFFFFFFFE
            assert key in ("BotLimit", "BotLimitForSplitScreen")
            lua["limits"][key] = 200
            lua["top"] -= 1
            returned()
        elif name == "replay_rva_02084790":
            assert lua["locked"] and values[1] == 2
            lua["top"] = 2
            returned()
        elif name == "replay_rva_00ca2370":
            assert values[:2] == [settings["humans"] + 7, 0 if read(dvars["gl_14C796328"] + 40) == 0 else 2]
            returned()
        elif name == "replay_rva_0118ab60":
            assert values[1] == 1
            returned(settings["humans"])
        elif name == "replay_rva_0118ad10":
            assert values[2] == 1
            returned(settings["allies"] if values[1] == 2 else settings["axis"])
        elif name == "replay_rva_01119b40":
            assert values[0] in (0, 1) and 1 <= values[1] <= 200
            returned()
        elif name == "replay_rva_00ca1d20":
            assert read(dvars["gl_14D386840"] + 40) == 152 and settings["slots"] == 152
            assert read(dvars["gl_14C796328"] + 40) in (0, 2)
            calls.append("bots")
            returned()
        elif name == "replay_rva_0119cfa0":
            assert values[0] == arena + 0x8000 and values[1] & 255 == 1
            calls.append("start")
            returned()
        elif name in ("replay_rva_00ca2110", "replay_rva_0119a5a0"):
            calls.append(name)
            returned()
        elif name in ("func_142083A30", "func_1420839E0"):
            returned(1)
        elif name == "func_142084950":
            pointer = arena + (0x6000 if values[1] == 1 else 0x6100)
            machine.mem_write(pointer, (store["table"] if values[1] == 1 else "400061").encode() + b"\0")
            assert values[2] == 0
            returned(pointer)
        elif name == "func_1419B78C0":
            returned(0 if values[1] == 2 else store["column"])
        elif name == "func_1413E33E0":
            assert string(values[0]) == store["table"]
            write(values[1], arena + 0x7000, "<Q")
            returned(int(store["exists"]))
        elif name == "func_1413E2BA0":
            assert values[0] == arena + 0x7000 and values[1] == 0 and string(values[2]) == "400061"
            assert values[3] == store["column"]
            machine.mem_write(arena + 0x6200, store["price"].encode() + b"\0")
            returned(arena + 0x6200)
        elif name == "func_142084120":
            store["result"] = string(values[1]); store["top"] += 1
            returned()
        elif name == "func_142089FB0":
            returned(0xFFFFFFFF)
        elif name == "func_1419CDD30":
            assert "Table not found" in string(values[0])
            returned()
        else:
            returned()

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    vm.hook_add(UC_HOOK_CODE, boundary)

    def run(name):
        rsp = stack + 0x8000 - 8
        write(rsp, halt, "<Q")
        vm.reg_write(UC_X86_REG_RSP, rsp)
        vm.emu_start(base + symbols[name], halt, count=100000)
        assert vm.reg_read(UC_X86_REG_RIP) == halt
        return vm.reg_read(UC_X86_REG_RAX) & 255

    write(arena + 0x3000 + 29, 5, "<B")
    write(arena + 0x3000 + 40, 150)
    run("DW_LobbyControls_Frame")
    assert read(arena + 0x3000 + 40) == 2
    write(dvars["gl_14D386840"] + 40, 152)
    write(registered["replay_dw_botCount"] + 40, 7)
    write(registered["replay_dw_forceStart"] + 40, 1)
    for key in ("main", "frontend", "host", "lobby", "enabled"):
        settings[key] = False
        run("DW_LobbyControls_Frame")
        assert not calls
        settings[key] = True
    checks.append("Only the DW main-thread frontend lobby host can create bots or start a match")
    write(dvars["gl_14C796328"] + 40, 200)
    run("DW_LobbyControls_Frame")
    assert calls == ["bots", "replay_rva_00ca2110", "replay_rva_0119a5a0", "start"]
    assert read(dvars["gl_14C796328"] + 40) == 200
    assert read(dvars["gl_14D386840"] + 40) == 152 and settings["slots"] == 152
    run("DW_LobbyControls_Frame")
    assert len(calls) == 4
    checks.append("BR prepares seven requested bots, retains its 152-slot capacity, restores squad count and requests native start once")
    assert run("func_140CA1C80") == 1
    for key, value in (("systemlink", True), ("controller", -1), ("mode", 3)):
        old = settings[key]
        settings[key] = value
        assert run("func_140CA1C80") == 0
        settings[key] = old
    for name in ("gl_14D386820", "DVARBOOL_onlinegame"):
        old = read(dvars[name] + 40)
        write(dvars[name] + 40, 1 if name == "gl_14D386820" else 0)
        assert run("func_140CA1C80") == 0
        write(dvars[name] + 40, old)
    write(registered["replay_dw_botCount"] + 40, 0)
    write(registered["replay_dw_forceStart"] + 40, 0)
    assert run("func_140CA1C80") == 0
    settings["playlist_bots"] = True
    assert run("func_140CA1C80") == 1
    checks.append("Bot eligibility preserves native online, platform, mode, controller and playlist checks")
    run("DW_LobbyControls_Frame")
    write(registered["replay_dw_forceStart"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert calls[-1] == "start" and len(calls) == 5
    checks.append("A new round's cleared controls permit another start without duplicate bot setup")
    write(base + symbols["gl_151868880"], arena + 0x9000, "<Q")
    lua["now"] += 1000
    write(dvars["gl_14D386820"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert read(dvars["gl_14D386840"] + 40) == 200
    assert settings["slots"] == 200
    assert lua["limits"] == dict(BotLimit=200, BotLimitForSplitScreen=200)
    assert not lua["locked"] and lua["top"] == 2
    checks.append("Custom setup uses the full native slot capacity; Lua table updates preserve the VM stack and native LUI locking")
    write(arena + 0x3000 + 29, 9, "<B")
    write(arena + 0x3000 + 24, 256)
    vm.mem_write(arena + 0x4000, b"12\0")
    write(arena + 0x3000 + 40, arena + 0x4000, "<Q")
    lua["now"] += 1000
    run("DW_LobbyControls_Frame")
    pointer = read(arena + 0x3000 + 40, "<Q")
    page(pointer)
    assert string(pointer) == "2" and read(arena + 0x3000 + 24) == 256
    checks.append("BR's actual script-created STRING type receives value 2 without changing its registration or flags")
    store["active"] = True
    for table, column, value, enabled, exists, expected in (
        ("loot/bundle_ids.csv", 10, "500", True, True, "0"),
        ("loot/bundle_ids.csv", 11, "200", True, True, "0"),
        ("loot/bundle_ids.csv", 36, "100", True, True, "0"),
        ("loot/bundle_ids.csv", 14, "123", True, True, "123"),
        ("loot/bundle_ids.csv", 10, "", True, True, ""),
        ("loot/bundle_ids.csv", 10, "500", False, True, "500"),
        ("other.csv", 10, "500", True, True, "500"),
        ("loot/bundle_ids.csv", 10, "500", True, False, ""),
    ):
        store.update(top=4, table=table, column=column, price=value, exists=exists, result=None)
        settings["enabled"] = enabled
        assert run("func_1419BA320") == 1
        assert store["result"] == expected and store["top"] == 5
    store["top"] = 3
    assert run("func_1419BA320") == 255
    checks.append("Native bundle price binding zeros regular, sale and smart costs only for DW; other columns/tables, missing rows, non-DW calls and Lua arity retain their original behavior")
    args.output.write_text(json.dumps(dict(schema=1, passed=True, game_sha256=report["sha256"], checks=checks, native_game_verified=False), indent=2) + "\n")
    print(f"PASS: {len(checks)} linked native control groups")


if __name__ == "__main__":
    main()
