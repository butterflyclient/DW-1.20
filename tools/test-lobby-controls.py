"""Exercise linked DW lobby controls at their original engine ABI boundaries."""

import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import collections
import subprocess
import sys
import tempfile

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_XMM1,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--controls-source", type=Path,
                        help="Compile/link only this controls owner into the offline VM")
    parser.add_argument("--compiler-source", type=Path,
                        help="Frozen compiler source and complete native headers for the focused owner")
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    image = Path(report["executable"])
    if not image.is_absolute():
        image = args.build / image
    assert hashlib.sha256(image.read_bytes()).hexdigest() == report["sha256"]
    verification = json.loads((args.build / "verification-report.json").read_bytes())
    assert verification["sha256"] == report["sha256"] and not verification["unresolved_symbols"]
    pe = pefile.PE(str(image), fast_load=True)
    base, symbols = pe.OPTIONAL_HEADER.ImageBase, dict(report["symbols"])
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, arena, halt = 0x10000000, 0x11000000, 0x12000000
    for address in (stack, arena, halt):
        vm.mem_map(address, 0x80000 if address == arena else 0x10000)
    pages = set()

    def page(address):
        page = address & ~4095
        if page in pages:
            return
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

    owner_proof = None
    if args.controls_source:
        assert args.compiler_source, "Focused compilation requires the frozen compiler/headers"
        sys.path.insert(0, str(args.compiler_source / "tools"))
        import coff
        import build as compiler_linker
        source_hash = hashlib.sha256(args.controls_source.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="lobby-owner-", dir=Path(__file__).resolve().parents[1] / "data") as folder:
            obj_path = Path(folder) / "controls.obj"
            subprocess.run([str(compiler_linker.LLVM / "clang++.exe"),
                "--target=x86_64-pc-windows-msvc", "-std=c++20", "-O2", "-ffreestanding",
                "-fno-stack-protector", "-fno-exceptions", "-fno-rtti", "-funwind-tables",
                "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror",
                "-I" + str(args.compiler_source / "src"), "-c", str(args.controls_source),
                "-o", str(obj_path)], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            obj = coff.read(obj_path)
            owner_proof = dict(source_sha256=source_hash, object_sha256=hashlib.sha256(obj_path.read_bytes()).hexdigest())
        assert hashlib.sha256(args.controls_source.read_bytes()).hexdigest() == source_hash
        at = (pe.OPTIONAL_HEADER.SizeOfImage + 65535) & -65536
        start = at
        for section in obj["sections"]:
            section["rva"] = at
            at = coff.align(at + len(section["data"]), 16)
        vm.mem_map(base + start, coff.align(at - start, 4096))
        pages.update(range(base + start, base + start + coff.align(at - start, 4096), 4096))
        original = dict(symbols)
        for symbol in obj["symbols"].values():
            if symbol["section"] > 0 and symbol["storage"] == 2:
                symbols[symbol["name"]] = obj["sections"][symbol["section"] - 1]["rva"] + symbol["value"]
            elif symbol["section"] == 0 and symbol["name"].startswith("replay_rva_"):
                rva = int(symbol["name"][11:], 16)
                symbol["name"] = f"func_{0x140000000 + rva:X}" if symbol["name"] not in symbols else symbol["name"]
                if rva == 0x0C27E4B0:
                    symbol["name"] = "gl_14C27E4B0"
        statistics = collections.Counter()
        manifest = dict(image_base=base, replacements=[], optional=dict(SizeOfImage=at))
        for section in obj["sections"]:
            if section["data"]:
                vm.mem_write(base + section["rva"], bytes(compiler_linker.relocate(
                    obj, section, symbols, manifest, statistics, set())))
        # Recovered SDK wrappers still call their original linked controls entry.
        # Redirect those VM-only entries to the freshly linked owner object.
        for name, rva in symbols.items():
            if name in original and rva != original[name]:
                address = base + original[name]
                page(address); page(address + 11)
                vm.mem_write(address, b"\x48\xb8" + struct.pack("<Q", base + rva) + b"\xff\xe0")
        owner_proof.update(compiler_relocator_sha256=hashlib.sha256((args.compiler_source / "tools/build.py").read_bytes()).hexdigest(),
                           relocation_counts=dict(statistics), vm_only=True, full_game_compiled=False)

    dvars = {}
    for i, name in enumerate(
        ("gl_14D386820", "gl_14D386948", "gl_14D386840", "gl_14C796328", "DVARBOOL_onlinegame")
    ):
        pointer = arena + 0x1000 + i * 0x100
        dvars[name] = pointer
        write(base + symbols[name], pointer, "<Q")
        write(pointer + 29, 5, "<B")
    write(dvars["DVARBOOL_onlinegame"] + 40, 1)
    write(dvars["gl_14C796328"] + 40, 2)
    settings = dict(
        enabled=True,
        main=True,
        frontend=True,
        lobby=True,
        host=True,
        systemlink=False,
        map_eligible=False,  # Existing controls groups isolate the native private-party exclusion.
        controller=0,
        playlist_bots=False,
        mode=2,
        slots=152,
        humans=2,
        allies=1,
        axis=1,
        requested=7,
        initialized=False,
        bots=0,
    )
    command = dict(callback=None, argc=2)
    calls, registered, checks, pool_calls, map_calls = [], {}, [], [], []
    lua = dict(top=2, locked=False, limits={}, now=10000)
    names = (
        "DW_LocalBackend_IsEnabled",
        "Sys_IsMainThread",
        "Com_FrontEndScene_IsActive",
        "Com_GameMode_GetActiveGameMode",
        "Dvar_BeginPermanentRegistration",
        "Dvar_EndPermanentRegistration",
        "Dvar_RegisterInt",
        "Dvar_RegisterBool",
        "DW_BotPolicy_Register",
        "DW_BotPolicy_Prepare",
        "DW_BotPolicy_ResetRoster",
        "DW_BotPolicy_CaptureRoster",
        "DW_MatchmakingAssignments_PrepareLaunch",
        "DW_PlaylistUI_Frame",
        "DW_LobbyControls_StartMatchInternalNative",
        "DW_LobbyControls_ReadyToLaunchNative",
        "Dvar_SetVariant",
        "Dvar_FindVarByName",
        "Com_Printf",
        "replay_rva_01187fa0",
        "replay_rva_01187ee0",
        "replay_rva_01189120",
        "replay_rva_0118dd00",
        "replay_rva_0119cfa0",
        "replay_rva_0119a5a0",
        "replay_rva_00ca2370",
        "replay_rva_00ca1d20",
        "replay_rva_01119b40",
        "replay_rva_0118ab60",
        "replay_rva_0118ad10",
        "replay_rva_00ca2110",
        "replay_rva_01528420",
        "replay_rva_00ca1c50",
        "replay_rva_010cd460",
        "replay_rva_010cc6f0",
        "replay_rva_019bdad0",
        "replay_rva_019bedb0",
        "replay_rva_020838b0",
        "replay_rva_020836e0",
        "replay_rva_02084ac0",
        "replay_rva_02084100",
        "replay_rva_02084510",
        "replay_rva_02084790",
        "replay_rva_0148fce0",
    )
    names += (
        "func_142083A30",
        "func_1420839E0",
        "func_142084950",
        "func_1419B78C0",
        "func_142089FB0",
        "func_1413E33E0",
        "func_1413E2BA0",
        "func_1413E2B40",
        "func_142084120",
        "func_1419CDD30",
    )
    names += (
        "Cmd_AddCommandInternal",
        "Cmd_Argc",
        "Cmd_Argv",
        "replay_rva_00ca2250",
        "replay_rva_00ca2270",
        "replay_rva_0118e020",
    )
    names += ("replay_rva_00ca2070", "DW_BotPolicy_BuildRoster", "Com_sprintf")
    names += ("replay_rva_00f6eb20", "replay_rva_021367b0")
    names += ("replay_rva_0118e960", "replay_rva_0118fdc0", "replay_rva_01191980",
              "replay_rva_010d23e0", "replay_rva_0118cf60")
    map_integer_domains = {
        "replay_dw_mapVoteCycle": 0x7FFFFFFF,
        "replay_dw_mapVoteRemainingMs": 30000,
        "replay_dw_mapVoteChoiceCount": 3,
        "replay_dw_mapVoteWinner": 2,
        **{"replay_dw_mapVoteEntry" + choice: 19 for choice in "ABC"},
        **{"replay_dw_mapVoteVotes" + choice: 200 for choice in "ABC"},
        **{"replay_dw_mapVoteLobby" + str(part): 65535 for part in range(4)},
    }
    map_boolean_names = ("replay_dw_mapVoteActive", "replay_dw_mapVoteComplete",
                         *["replay_dw_mapVoteSelect" + choice for choice in "ABC"])
    store = dict(
        active=False,
        top=4,
        table="loot/bundle_ids.csv",
        column=10,
        price="500",
        exists=True,
        result=None,
    )

    def resolve(name):
        canonical = (
            f"func_{0x140000000 + int(name.removeprefix('replay_rva_'), 16):X}"
            if name.startswith("replay_rva_")
            else name
        )
        return base + symbols[name if name in symbols else canonical]

    boundaries = {
        resolve(name): name for name in (*names, "replay_rva_0118c7d0", "replay_rva_011916c0")
    }
    boundaries[arena + 0xFD00] = "sdk_ready"

    def boundary(machine, address, size, context):
        name = boundaries.get(address)
        if not name:
            return
        values = [
            machine.reg_read(reg)
            for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
        ]
        boolean = {
            "DW_LocalBackend_IsEnabled": "enabled",
            "Sys_IsMainThread": "main",
            "Com_FrontEndScene_IsActive": "frontend",
            "replay_rva_01187fa0": "lobby",
            "replay_rva_01189120": "host",
            "replay_rva_0118dd00": "lobby",
            "replay_rva_01528420": "systemlink",
            "replay_rva_010cc6f0": "playlist_bots",
        }
        if name == "sdk_ready":
            assert values[0] == arena + 0xC200
            returned(1)
        elif name == "replay_rva_00f6eb20":
            assert values[0] == arena + 0xC400 + 904
            returned(arena + 0xC700)
        elif name == "replay_rva_021367b0":
            assert values[:4] == [arena + 0xC700, arena + 0xC900,
                                  read(lobby_identity, "<Q"),
                                  base + symbols["gl_14C27E4B0"] + 131864]
            rsp = machine.reg_read(UC_X86_REG_RSP)
            assert read(rsp + 40, "<Q") == 123
            document = string(read(rsp + 48, "<Q"))
            assert read(rsp + 56, "<Q") == len(document) + 1
            command["submitted"] = json.loads(document)
            write(values[1], arena + 0xC800, "<Q")
            returned(values[1])
        elif name in boolean:
            returned(int(settings[boolean[name]]))
        elif name == "replay_rva_0118e960":
            assert values[0] == arena + 0x8000
            returned(int(not settings["map_eligible"]))
        elif name == "replay_rva_0118fdc0":
            assert values[0] == arena + 0x8000 and values[1] <= 3
            write(values[0] + 311148, values[1], "<I")
            map_calls.append(("vote", values[1]))
            returned()
        elif name == "replay_rva_01191980":
            assert all(entry < 20 for entry in values[:3])
            map_calls.append(("entries", *values[:3]))
            returned()
        elif name == "replay_rva_010d23e0":
            assert values[0] == 0 and values[1] < 20
            map_calls.append(("rules", values[1]))
            returned()
        elif name == "replay_rva_0118cf60":
            assert values[1] == arena + 0x8000 and values[2] < 200
            write(values[0], 100 + values[2], "<Q")
            returned(values[0])
        elif name == "Cmd_AddCommandInternal":
            assert string(values[0]) == "fill_lobby" and command["callback"] is None
            command["callback"] = values[1]
            returned()
        elif name == "Cmd_Argc":
            returned(command["argc"])
        elif name == "Cmd_Argv":
            assert values[0] == 1
            returned(arena + 0x5000)
        elif name == "replay_rva_00ca2250":
            returned(int(settings["initialized"]))
        elif name == "replay_rva_00ca2270":
            returned(int(values[0] < settings["humans"] + settings["bots"]))
        elif name == "replay_rva_0118e020":
            returned(int(values[1] < settings["humans"]))
        elif name == "replay_rva_00ca2070":
            pool_calls.append("clear")
            settings.update(initialized=False, bots=0)
            returned()
        elif name == "DW_BotPolicy_BuildRoster":
            pool_calls.append("build")
            assert values[:3] == [arena + 0x8000, settings["slots"], settings["requested"]]
            returned()
        elif name == "DW_MatchmakingAssignments_PrepareLaunch":
            assert values[0] == arena + 0x8000
            returned()
        elif name == "Com_sprintf":
            format = string(values[2])
            assert format in (',"dw_bot_count":%u}',
                ',"dw_bot_count":%u,"dw_auto_fill_bots":%s,"dw_auto_fill_complete":%s,"dw_auto_fill_request":%u}',
                ',"dw_map_vote":{"version":1,"entry":%u,"votes":{', '%s"%llu":%u', '}}}')
            argument = iter([values[3], *[read(machine.reg_read(UC_X86_REG_RSP) + 40 + i * 8, "<Q")
                                          for i in range(4)]])
            def substitute(match):
                value = next(argument)
                return string(value) if match[0] == "%s" else str(value if match[0] == "%llu" else value & 0xFFFFFFFF)
            body = re.sub(r"%llu|%s|%u", substitute, format).encode()
            assert len(body) + 1 <= values[1]
            vm.mem_write(values[0], body + b"\0")
            returned(len(body))
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
            domains = {
                "replay_dw_forceStart": 1, "replay_dw_fillBots": 1,
                "replay_dw_botCount": 199, "replay_dw_autoFillBotTarget": 199,
                "replay_dw_autoFillRevision": 0x7FFFFFFF, "replay_dw_autoFillAck": 0x7FFFFFFF,
                **map_integer_domains,
            }
            assert key in domains and values[1:4] == [0, 0, domains[key]]
            assert key not in registered
            pointer = arena + 0x70000 + len(registered) * 0x100
            write(pointer + 29, 5, "<B")
            registered[key] = pointer
            returned(pointer)
        elif name == "Dvar_RegisterBool":
            key = string(values[0])
            assert key in (
                *map_boolean_names,
                "replay_dw_autoFillBots", "replay_dw_autoFillBotsActive", "replay_dw_autoFillBotsComplete",
                "lui_dwIntroVideos", "lui_dwTutorialPrompts")
            assert values[1:3] == [0, 0] and key not in registered
            pointer = arena + 0x70000 + len(registered) * 0x100
            write(pointer + 29, 0, "<B")
            registered[key] = pointer
            returned(pointer)
        elif name in ("DW_BotPolicy_ResetRoster", "DW_BotPolicy_CaptureRoster", "DW_PlaylistUI_Frame"):
            if name != "DW_PlaylistUI_Frame":
                pool_calls.append(name)
            returned()
        elif name == "DW_LobbyControls_ReadyToLaunchNative":
            returned(1)
        elif name == "DW_LobbyControls_StartMatchInternalNative":
            calls.append("native-start-body")
            returned(7)
        elif name == "Dvar_SetVariant":
            machine.mem_write(values[0] + 40, bytes(machine.mem_read(values[1], 16)))
            returned()
        elif name == "Dvar_FindVarByName":
            key = string(values[0])
            assert key in ("br_minplayers", "lui_battlepass_tier_sale_price")
            returned(arena + 0x3000 if key == "br_minplayers" else 0)
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
            assert (
                lua["locked"]
                and values[1] & 0xFFFFFFFF == (-10002 & 0xFFFFFFFF)
                and string(values[2]) in ("Lobby", "BATTLEPASS")
            )
            lua["table"] = string(values[2])
            lua["top"] += 1
            returned()
        elif name == "replay_rva_02084ac0":
            assert lua["locked"] and values[1] & 0xFFFFFFFF == 0xFFFFFFFF
            returned(5)
        elif name == "replay_rva_02084100":
            raw = (machine.reg_read(UC_X86_REG_XMM1) & ((1 << 64) - 1)).to_bytes(8, "little")
            assert lua["locked"] and struct.unpack("<d", raw)[0] == (
                200.0 if lua["table"] == "Lobby" else 0.0
            )
            lua["top"] += 1
            returned()
        elif name == "replay_rva_02084510":
            key = string(values[2])
            assert lua["locked"] and values[1] & 0xFFFFFFFF == 0xFFFFFFFE
            assert key in ("BotLimit", "BotLimitForSplitScreen", "SINGLE_TIER_COST")
            lua["limits"][key] = 0 if key == "SINGLE_TIER_COST" else 200
            lua["top"] -= 1
            returned()
        elif name == "replay_rva_02084790":
            assert lua["locked"] and values[1] == 2
            lua["top"] = 2
            returned()
        elif name == "replay_rva_00ca2370":
            assert values[:2] == [
                settings["humans"] + settings["requested"],
                0 if read(dvars["gl_14C796328"] + 40) == 0 else 2,
            ]
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
            settings.update(initialized=True, bots=settings["requested"])
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
            machine.mem_write(
                pointer, (store["table"] if values[1] == 1 else "400061").encode() + b"\0"
            )
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
        elif name == "func_1413E2B40":
            assert values[:3] == [arena + 0x7000, 0, store["column"]]
            machine.mem_write(arena + 0x6200, store["price"].encode() + b"\0")
            returned(arena + 0x6200)
        elif name == "func_142084120":
            store["result"] = string(values[1])
            store["top"] += 1
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

    def run(name, *arguments):
        rsp = stack + 0x8000 - 8
        write(rsp, halt, "<Q")
        vm.reg_write(UC_X86_REG_RSP, rsp)
        for register, value in zip(
            (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), arguments
        ):
            vm.reg_write(register, value)
        for index, value in enumerate(arguments[4:]):
            write(rsp + 40 + index * 8, value, "<Q")
        vm.emu_start(name if isinstance(name, int) else base + symbols[name], halt, count=100000)
        assert vm.reg_read(UC_X86_REG_RIP) == halt
        return vm.reg_read(UC_X86_REG_RAX) & 255

    write(arena + 0x3000 + 29, 5, "<B")
    write(arena + 0x3000 + 40, 150)
    lobby_identity = base + symbols["gl_14C27E4B0"] + 79656
    write(lobby_identity, 1, "<Q")
    write(base + symbols["gl_14C27E4B0"] + 80128, 1, "<B")
    run("DW_LobbyControls_Frame")
    for key in ("lui_dwIntroVideos", "lui_dwTutorialPrompts"):
        assert key in registered
        assert read(registered[key] + 29, "<B") == 0
        assert read(registered[key] + 40, "<B") == 0
    checks.append("Intro videos and automatic Warzone tutorial prompts register as native booleans disabled by default")
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
    checks.append(
        "BR prepares seven requested bots, retains its 152-slot capacity, restores squad count and requests native start once"
    )
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
    checks.append(
        "Bot eligibility preserves native online, platform, mode, controller and playlist checks"
    )
    run("DW_LobbyControls_Frame")
    write(registered["replay_dw_forceStart"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert calls[-1] == "start" and len(calls) == 5
    checks.append("A new round's cleared controls permit another start without duplicate bot setup")
    write(registered["replay_dw_forceStart"] + 40, 0)
    write(lobby_identity, 2, "<Q")
    settings.update(initialized=False, bots=0)
    run("DW_LobbyControls_Frame")
    assert command["callback"] is not None
    for text in ("0", "-1", "+2", "1.5", "200", "199x", "999999999999"):
        vm.mem_write(arena + 0x5000, text.encode() + b"\0")
        run(command["callback"])
        assert read(registered["replay_dw_botCount"] + 40) == 0
    vm.mem_write(arena + 0x5000, b"4\0")
    for key in ("main", "frontend", "host", "lobby", "enabled"):
        settings[key] = False
        run(command["callback"])
        assert read(registered["replay_dw_botCount"] + 40) == 0
        settings[key] = True
    run(command["callback"])
    assert read(registered["replay_dw_botCount"] + 40) == 0

    def submitted(expected):
        body = b'{"test":1}\0'
        vm.mem_write(arena + 0x6300, body)
        write(arena + 0x6200, arena + 0x6300, "<Q")
        write(arena + 0x6220, len(body))
        run(
            "DW_LobbyControls_HostDocument",
            read(lobby_identity, "<Q"),
            base + symbols["gl_14C27E4B0"] + 131864,
            arena + 0x6200,
            arena + 0x6220,
        )
        assert json.loads(string(read(arena + 0x6200, "<Q"))) == {
            "test": 1,
            "dw_bot_count": expected,
        }
        write(arena + 0xC200, arena + 0xC600, "<Q")
        write(arena + 0xC600, arena + 0xFD00, "<Q")
        write(arena + 0xC208, arena + 0xC400, "<Q")
        run("func_140F77B40", arena + 0xC200, arena + 0xC900,
            read(lobby_identity, "<Q"), base + symbols["gl_14C27E4B0"] + 131864,
            arena + 0x6300, len(body), 123)
        assert command["submitted"] == {"test": 1, "dw_bot_count": expected}
        assert read(arena + 0xC900, "<Q") == arena + 0xC800
        # The native backend update publishes this only after accepting the task.
        write(registered["replay_dw_botCount"] + 40, expected)

    submitted(4)
    settings["requested"] = 4
    run("DW_LobbyControls_Frame")
    assert settings["bots"] == 4
    vm.mem_write(arena + 0x5000, b"199\0")
    run(command["callback"])
    assert read(registered["replay_dw_botCount"] + 40) == 4
    submitted(150)
    settings["requested"] = 150
    run("DW_LobbyControls_Frame")
    assert settings["bots"] == 150 and settings["slots"] == 152
    assert read(dvars["gl_14C796328"] + 40) == 200
    assert read(dvars["gl_14D386840"] + 40) == 152
    checks.append(
        "Linked fill_lobby command rejects invalid counts and non-host contexts, adds to the native pool and clamps at the original playlist capacity"
    )
    write(lobby_identity, 3, "<Q")
    write(registered["replay_dw_botCount"] + 40, 0)  # new backend round's document
    run("DW_LobbyControls_Frame")
    assert read(registered["replay_dw_botCount"] + 40) == 0
    checks.append(
        "A command-owned bot request is cleared when native matchmaking changes lobby identity"
    )
    # New public allocation: native pooled bots stay empty until the 30-second
    # delay, then grow through authenticated host documents and exact token ACKs.
    write(lobby_identity, 4, "<Q")
    settings.update(initialized=False, bots=0, humans=2, slots=152, requested=0)
    write(registered["replay_dw_botCount"] + 40, 0)
    write(registered["replay_dw_autoFillBots"] + 40, 1)
    lua["now"] = 100000
    run("DW_LobbyControls_Frame")

    def auto_document(count, complete=False, active=True):
        body = b'{"test":1}\0'
        vm.mem_write(arena + 0x6300, body)
        command["submitted"] = None
        run("func_140F77B40", arena + 0xC200, arena + 0xC900,
            read(lobby_identity, "<Q"), base + symbols["gl_14C27E4B0"] + 131864,
            arena + 0x6300, len(body), 123)
        doc = command["submitted"]
        assert doc["dw_bot_count"] == count
        assert doc["dw_auto_fill_bots"] is active and doc["dw_auto_fill_complete"] is complete
        assert type(doc["dw_auto_fill_request"]) is int and doc["dw_auto_fill_request"] > 0
        return doc["dw_auto_fill_request"]

    def auto_ack(token, count, complete=False, active=True):
        write(registered["replay_dw_autoFillAck"] + 40, token)
        write(registered["replay_dw_autoFillBotsActive"] + 40, int(active))
        write(registered["replay_dw_autoFillBotsComplete"] + 40, int(complete))
        write(registered["replay_dw_botCount"] + 40, count)
        settings["requested"] = count
        run("DW_LobbyControls_Frame")

    token = auto_document(0)
    write(registered["replay_dw_autoFillBotTarget"] + 40, 148)
    auto_ack(token, 0)
    assert settings["bots"] == 0
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 0
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    lua["now"] = 129999
    run("DW_LobbyControls_Frame")
    assert settings["bots"] == 0
    lua["now"] = 135000
    run("DW_LobbyControls_Frame")
    token = auto_document(49)
    # An unrelated publication revision must not falsely acknowledge a request.
    write(registered["replay_dw_autoFillRevision"] + 40, 123)
    run("DW_LobbyControls_Frame")
    assert auto_document(49) == token
    auto_ack(token, 48)  # server clock skew can clamp the accepted count
    assert settings["bots"] == 48
    token = auto_document(49)
    auto_ack(token, 49)
    assert settings["bots"] == 49
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    lua["now"] = 145000
    run("DW_LobbyControls_Frame")
    token = auto_document(148)
    auto_ack(token, 148)
    assert settings["bots"] == 148 and settings["slots"] == 152
    run("DW_LobbyControls_Frame")
    token = auto_document(148, complete=True)
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    auto_ack(token, 148, complete=True)
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 1
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 7
    settings["bots"] = 147
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    settings["bots"] = 148
    settings["humans"] = 3
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    write(registered["replay_dw_autoFillBots"] + 40, 0)
    run("DW_LobbyControls_Frame")
    token = auto_document(0, active=False)
    write(registered["replay_dw_autoFillBotsActive"] + 40, 0)
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    auto_ack(token, 0, active=False)
    assert settings["bots"] == 0
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 7
    checks.append(
        "Linked 30/15-second automatic fill uses authenticated token ACKs, native pooled presence and authoritative No Fill target; both native launch entry points stay gated until completion and restore on disable"
    )

    def no_auto_document():
        body = b'{"test":1}\0'
        vm.mem_write(arena + 0x6300, body)
        command["submitted"] = None
        run("func_140F77B40", arena + 0xC200, arena + 0xC900,
            read(lobby_identity, "<Q"), base + symbols["gl_14C27E4B0"] + 131864,
            arena + 0x6300, len(body), 123)
        assert command["submitted"] == {"test": 1}

    # A guest has no local checkbox preference for the old host's active fill.
    # Takeover inherits that accepted policy, rather than publishing a disable.
    settings.update(host=False, initialized=True, bots=49, humans=2, requested=49)
    write(lobby_identity, 5, "<Q")
    write(registered["replay_dw_autoFillBots"] + 40, 0)
    write(registered["replay_dw_autoFillBotsActive"] + 40, 1)
    write(registered["replay_dw_autoFillBotsComplete"] + 40, 0)
    write(registered["replay_dw_autoFillAck"] + 40, 127)
    write(registered["replay_dw_autoFillBotTarget"] + 40, 148)
    write(registered["replay_dw_botCount"] + 40, 49)
    lua["now"] = 200000
    before = len(pool_calls)
    run("DW_LobbyControls_Frame")
    assert read(registered["replay_dw_autoFillBots"] + 40) == 0 and len(pool_calls) == before
    no_auto_document()
    settings["host"] = True
    run("DW_LobbyControls_Frame")
    assert read(registered["replay_dw_autoFillBots"] + 40) == 1 and settings["bots"] == 49
    assert auto_document(0) == 128
    # A revision or a previous host's ACK cannot apply the new zero-count arm.
    write(registered["replay_dw_autoFillRevision"] + 40, 999)
    run("DW_LobbyControls_Frame")
    assert auto_document(0) == 128 and settings["bots"] == 49
    auto_ack(128, 0)
    assert settings["bots"] == 0
    no_auto_document()
    lua["now"] = 229999
    run("DW_LobbyControls_Frame")
    assert settings["bots"] == 0
    no_auto_document()
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    write(registered["replay_dw_autoFillBots"] + 40, 0)
    run("DW_LobbyControls_Frame")
    assert auto_document(0, active=False) == 129
    auto_ack(129, 0, active=False)
    no_auto_document()
    run("DW_LobbyControls_Frame")
    assert read(registered["replay_dw_autoFillBots"] + 40) == 0
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 7
    checks.append("Guest submits no automatic controls; incomplete takeover adopts active checkbox, arms with token 128 above ACK 127, honors acknowledged zero-count delay and accepts later explicit off token 129")

    # Completed takeover needs neither a clear nor a fresh 45-second fill.
    settings.update(host=False, initialized=True, bots=148, requested=148)
    write(lobby_identity, 6, "<Q")
    write(registered["replay_dw_autoFillBots"] + 40, 0)
    write(registered["replay_dw_autoFillBotsActive"] + 40, 1)
    write(registered["replay_dw_autoFillBotsComplete"] + 40, 1)
    write(registered["replay_dw_autoFillAck"] + 40, 200)
    write(registered["replay_dw_botCount"] + 40, 148)
    lua["now"] = 300000
    run("DW_LobbyControls_Frame")
    before = len(pool_calls)
    settings["host"] = True
    run("DW_LobbyControls_Frame")
    # SyncLobby resets managed metadata for the new lobby; it must not rebuild
    # or clear an already complete native pool during host acquisition.
    assert pool_calls[before:] == ["DW_BotPolicy_ResetRoster"] and settings["bots"] == 148
    no_auto_document()
    assert read(registered["replay_dw_autoFillBots"] + 40) == 1
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 1
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 7
    lua["now"] += 1000
    run("DW_LobbyControls_Frame")
    assert pool_calls[before:] == ["DW_BotPolicy_ResetRoster"]
    no_auto_document()
    checks.append("Completed authoritative takeover preserves the native pool and immediate launch eligibility without sending a new arm/clear or restarting fill")

    # Missing local native data rebuilds through the existing roster lifecycle,
    # without lowering the backend's completed count or losing completion.
    settings["host"] = False
    run("DW_LobbyControls_Frame")
    settings.update(host=True, initialized=False, bots=0)
    before = len(pool_calls)
    run("DW_LobbyControls_Frame")
    assert pool_calls[before:] == ["DW_BotPolicy_CaptureRoster", "clear", "build"]
    assert settings["bots"] == 148
    no_auto_document()
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 7
    # A larger token published by the previous host is observed before a later
    # explicit user edit, independently of our process's smaller local counter.
    write(registered["replay_dw_autoFillAck"] + 40, 255)
    write(registered["replay_dw_autoFillBots"] + 40, 0)
    run("DW_LobbyControls_Frame")
    assert auto_document(0, active=False) == 256
    auto_ack(256, 0, active=False)
    checks.append("Completed takeover repairs a missing native pool through capture/clear/build without publishing incomplete state; later off stays monotonic above a newly observed accepted ACK")

    write(base + symbols["gl_151868880"], arena + 0x9000, "<Q")
    lua["now"] += 1000
    write(dvars["gl_14D386820"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert read(dvars["gl_14D386840"] + 40) == 200
    assert settings["slots"] == 200
    assert lua["limits"] == dict(BotLimit=200, BotLimitForSplitScreen=200, SINGLE_TIER_COST=0)
    assert not lua["locked"] and lua["top"] == 2
    checks.append(
        "Custom setup uses the full native slot capacity; Lua table updates preserve the VM stack and native LUI locking"
    )
    write(arena + 0x3000 + 29, 9, "<B")
    write(arena + 0x3000 + 24, 256)
    vm.mem_write(arena + 0x4000, b"12\0")
    write(arena + 0x3000 + 40, arena + 0x4000, "<Q")
    lua["now"] += 1000
    run("DW_LobbyControls_Frame")
    pointer = read(arena + 0x3000 + 40, "<Q")
    page(pointer)
    assert string(pointer) == "2" and read(arena + 0x3000 + 24) == 256
    checks.append(
        "BR's actual script-created STRING type receives value 2 without changing its registration or flags"
    )
    store["active"] = True
    for table, column, value, enabled, exists, expected in (
        ("loot/bundle_ids.csv", 10, "500", True, True, "0"),
        ("loot/bundle_ids.csv", 11, "200", True, True, "0"),
        ("loot/bundle_ids.csv", 36, "100", True, True, "0"),
        ("loot/bundle_ids.csv", 14, "123", True, True, "123"),
        ("loot/battlepass_ids.csv", 8, "1000", True, True, "0"),
        ("loot/battlepass_ids.csv", 9, "750", True, True, "0"),
        ("loot/battlepass_ids.csv", 6, "3002001", True, True, "3002001"),
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
    for column, expected in ((8, "0"), (9, "0"), (6, "1000")):
        store.update(
            top=3,
            table="loot/battlepass_ids.csv",
            column=column,
            price="1000",
            exists=True,
            result=None,
        )
        settings["enabled"] = True
        assert run("func_1419BA610") == 1 and store["result"] == expected and store["top"] == 4
    checks.append(
        "Both native keyed and row CSV readers expose free Battle Pass prices while preserving IDs and Lua stack/arity"
    )
    checks.append(
        "Native bundle price binding zeros regular, sale and smart costs only for DW; other columns/tables, missing rows, non-DW calls and Lua arity retain their original behavior"
    )
    assert set(map_integer_domains) | set(map_boolean_names) <= set(registered)
    for key in map_integer_domains:
        assert read(registered[key] + 29, "<B") == 5 and read(registered[key] + 40) == 0
    for key in map_boolean_names:
        assert read(registered[key] + 29, "<B") == 0 and read(registered[key] + 40, "<B") == 0
    checks.append("Map-vote registration retains exact native bool/int types, defaults and bounded entry/count/time/identity domains")

    # The prior controls cases exercise the real private-party ballot exclusion,
    # not a stub of Pending or Frame. Public contexts now execute the linked
    # ballot bridge and both original launch wrappers against its real dvars.
    settings.update(enabled=True, main=True, frontend=True, lobby=True, host=True,
                    systemlink=False, mode=2, map_eligible=True, requested=0, bots=0)
    write(dvars["gl_14D386820"] + 40, 0)
    write(dvars["DVARBOOL_onlinegame"] + 40, 1)
    write(registered["replay_dw_autoFillBots"] + 40, 0)
    write(registered["replay_dw_autoFillBotsActive"] + 40, 0)
    write(registered["replay_dw_forceStart"] + 40, 0)
    write(registered["replay_dw_botCount"] + 40, 0)
    write(lobby_identity, 7, "<Q")
    run("DW_LobbyControls_Frame")
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 0
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    for part in range(4):
        write(registered["replay_dw_mapVoteLobby" + str(part)] + 40, 7 if part == 0 else 0)
    for choice, entry in zip("ABC", (0, 1, 2)):
        write(registered["replay_dw_mapVoteEntry" + choice] + 40, entry)
    write(registered["replay_dw_mapVoteChoiceCount"] + 40, 3)
    write(registered["replay_dw_mapVoteActive"] + 40, 1)
    write(registered["replay_dw_mapVoteWinner"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert ("entries", 0, 1, 2) in map_calls
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 0
    write(registered["replay_dw_mapVoteComplete"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert ("rules", 1) in map_calls
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 1
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 7
    body = b'{"test":1}\0'
    vm.mem_write(arena + 0x6300, body)
    write(arena + 0x6200, arena + 0x6300, "<Q")
    write(arena + 0x6220, len(body))
    run("DW_LobbyControls_HostDocument", 7,
        base + symbols["gl_14C27E4B0"] + 131864, arena + 0x6200, arena + 0x6220)
    assert json.loads(string(read(arena + 0x6200, "<Q"))) == {
        "test": 1, "dw_map_vote": {"version": 1, "entry": 1, "votes": {}}}
    checks.append("Actual public launch wrappers deny initial/unfrozen ballots, apply the acknowledged native winner, and append the versioned native host handshake")
    write(registered["replay_dw_mapVoteSelectA"] + 40, 1)
    write(lobby_identity, 8, "<Q")
    run("DW_LobbyControls_Frame")
    assert read(registered["replay_dw_mapVoteSelectA"] + 40) == 0
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    write(registered["replay_dw_mapVoteLobby0"] + 40, 8)
    run("DW_LobbyControls_Frame")
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 1
    settings["frontend"] = False
    run("DW_LobbyControls_Frame")
    settings["frontend"] = True
    run("DW_LobbyControls_Frame")
    assert run("func_14119E3D0", arena + 0x8000, arena + 0x8100) == 0
    write(registered["replay_dw_mapVoteCycle"] + 40, 1)
    write(registered["replay_dw_mapVoteComplete"] + 40, 0)
    run("DW_LobbyControls_Frame")
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 0
    write(registered["replay_dw_mapVoteComplete"] + 40, 1)
    run("DW_LobbyControls_Frame")
    assert run("func_14119B0E0", arena + 0x8000, arena + 0x8100) == 1
    checks.append("Linked controls retire stale choices across allocation changes and hold the same allocation after frontend exit until its next ballot cycle freezes")
    args.output.write_text(
        json.dumps(
            dict(
                schema=1,
                passed=True,
                game_sha256=report["sha256"],
                checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                focused_owner=owner_proof,
                checks=checks,
                native_game_verified=False,
            ),
            indent=2,
        )
        + "\n"
    )
    print(f"PASS: {len(checks)} linked native control groups")


if __name__ == "__main__":
    main()
