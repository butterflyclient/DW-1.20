"""Execute linked Replay bot roster and ClientBegin replacements at engine boundaries."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import re

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
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--header-source", type=Path)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    executable = Path(report["executable"])
    if not executable.is_absolute():
        executable = args.build / executable
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == report["sha256"]
    pe = pefile.PE(str(executable), fast_load=True)
    base, symbols = pe.OPTIONAL_HEADER.ImageBase, report["symbols"]
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, arena, party, server_party, pool, halt = (
        0x10000000,
        0x11000000,
        0x13000000,
        0x13800000,
        0x14000000,
        0x15000000,
    )
    for address, size in [
        (stack, 0x400000),
        (arena, 0x10000),
        (party, 0x80000),
        (server_party, 0x80000),
        (pool, 0x10000),
        (halt, 4096),
    ]:
        vm.mem_map(address - 4096, size + 4096) if address == pool else vm.mem_map(address, size)
    pages = set()

    def mapped(address, size=1):
        if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            return
        for page in range(address & ~4095, (address + size - 1 & ~4095) + 4096, 4096):
            if page not in pages:
                vm.mem_map(page, 4096)
                vm.mem_write(page, pe.get_data(page - base, 4096))
                pages.add(page)

    misses = []

    def missing(machine, access, address, size, value, context):
        if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            rip = machine.reg_read(UC_X86_REG_RIP)
            nearest = sorted((v, n) for n, v in symbols.items() if v <= rip - base)[-1]
            misses.append(
                f"Unmodeled native boundary at {nearest[1]}+{rip-base-nearest[0]:x}; memory={address:x} access={access}"
            )
            return False
        mapped(address, size)
        return True

    def write(address, value, fmt="<i"):
        body = value if isinstance(value, bytes) else struct.pack(fmt, value)
        mapped(address, len(body))
        vm.mem_write(address, body)

    def read(address, fmt="<i"):
        mapped(address, struct.calcsize(fmt))
        return struct.unpack(fmt, vm.mem_read(address, struct.calcsize(fmt)))[0]

    def string(address):
        out = bytearray()
        for i in range(256):
            mapped(address + i)
            value = vm.mem_read(address + i, 1)[0]
            if not value:
                return out.decode()
            out.append(value)
        raise AssertionError("Unbounded engine string")

    def returned(value=0):
        rsp = vm.reg_read(UC_X86_REG_RSP)
        vm.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        vm.reg_write(UC_X86_REG_RIP, read(rsp, "<Q"))
        vm.reg_write(UC_X86_REG_RSP, rsp + 8)

    def member(address, index):
        return address + 2192 + 488 * index

    state = dict(enabled=True, lobby=True, server_bot=True, bot_count=12, local=0, eligible=True, initialized=True)
    registered, models, paths, human_calls = (
        {},
        {},
        {1: "members", 2: "squadMembers"},
        [],
    )
    for name, kind, value in [
        ("gl_14D386988", 0, 0),
        ("gl_14D386990", 5, 28),
        ("gl_14C796328", 5, 51),
    ]:
        ptr = arena + 0x1000 + len(registered) * 0x100
        registered[name] = ptr
        write(base + symbols[name], ptr, "<Q")
        write(ptr + 29, kind, "<B")
        write(ptr + 40, value)
    write(base + symbols["gl_14EEF12A4"], 1, "<B")
    write(base + symbols["gl_14EEF1288"], 0)
    server_pool = base + symbols["gl_14E183D00"]
    write(server_pool, b"\0" * (200 * 88))
    for address in (party, server_party):
        write(address + 311116, 1)
        for i in range(2):
            write(member(address, i) + 52, ("Human " + str(i)).encode() + b"\0")
            write(member(address, i) + 392, i + 1)
            write(member(address, i) + 396, i)
            write(member(address, i) + 402, 5, "<B")
            write(member(address, i) + 408, 42 + i, "<Q")
    for i in range(14):
        for address in (pool + 88 * i, server_pool + 88 * i):
            write(address, ("Bot " + str(i)).encode() + b"\0")
            write(address + 36, b"[^3Bot]\0")
            write(address + 48, i, "<H")
            write(address + 52, 70 + i)
            write(address + 56, 80 + i)
            write(address + 77, 20 + i, "<B")
            write(address + 80, 7, "<H")
            write(address + 84, 1, "<B")
            write(address + 85, int(i >= 2), "<B")
            write(address + 86, 44 + i - 2, "<B")
    # The profile boundary reads the actual native client table/count. These
    # allocations model current server ownership independently of bot pool rows.
    native_clients, native_entities, native_players = 0x17000000, 0x1C000000, 0x1D000000
    for address, size in ((native_clients, 200 * 321192), (native_entities, 200 * 1440),
                          (native_players, 200 * 64496)):
        vm.mem_map(address, (size + 4095) & ~4095)
    count_symbol = symbols.get("DW_Bot_ClientCount", symbols["SVHS_ClientCount"])
    clients_symbol = symbols.get("DW_Bot_Clients", symbols["SVHS_Clients"])
    write(base + count_symbol, 200, "<I")
    for slot in range(200):
        current_client = native_clients + slot * 321192
        current_entity = native_entities + slot * 1440
        current_player = native_players + slot * 64496
        write(base + clients_symbol + slot * 8, current_client, "<Q")
        write(current_client + 280, current_entity, "<Q")
        write(current_client + 214756, 2, "<i")
        write(current_entity, slot, "<h")
        write(current_entity + 336, current_player, "<Q")
        write(current_player + 448, slot, "<i")
    names = [
        "DW_LocalBackend_IsEnabled",
        "func_141187FA0",
        "func_141187EE0",
        "func_14118E1F0",
        "func_14118E020",
        "func_14118EE80",
        "func_14118E0E0",
        "func_140CA2250",
        "func_140CA1C80",
        "func_140CA2230",
        "func_140CA2210",
        "func_141359F90",
        "func_141371450",
        "DW_MatchmakingAssignments_PrepareLaunch",
        "func_14137D670",
        "func_14118CF60",
        "func_14118C070",
        "func_14118C110",
        "func_14107EA60",
        "func_1412B0570",
        "func_141B23610",
        "func_141B22140",
        "func_141528240",
        "func_140F22880",
        "func_140F23A00",
        "func_14118DDB0",
        "func_14118C7D0",
        "func_141B0D390",
        "func_141B0E150",
        "func_141B0E0B0",
        "func_141B0E280",
        "Com_sprintf",
        "DW_Bot_StringTableAsset",
        "DW_Bot_StringTableRows",
        "DW_Bot_StringTableColumn",
        "func_141B0D520",
        "func_141B0D710",
        "func_141B0D530",
        "func_141192AC0",
        "func_141192AA0",
        "Dvar_RegisterVariant",
        "Dvar_RegisterInt",
        "Dvar_GenerateChecksum",
        "Com_Printf",
    ]
    if "DW_BotRank_Apply" in symbols:
        names.append("DW_BotRank_Apply")
    boundaries = {base + symbols[name]: name for name in names}
    boundaries[base + symbols["sub_1421CCEF0"]] = "stack_probe"

    def boundary(machine, address, size, context):
        name = boundaries.get(address)
        if not name:
            return
        a = [
            machine.reg_read(r)
            for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
        ]
        rsp = machine.reg_read(UC_X86_REG_RSP)
        if name == "stack_probe":
            amount = machine.reg_read(UC_X86_REG_RAX)
            assert stack <= rsp - amount < rsp < stack + 0x400000
            returned(amount)
        elif name == "DW_LocalBackend_IsEnabled":
            returned(state["enabled"])
        elif name == "func_141187FA0":
            returned(state["lobby"])
        elif name == "func_141187EE0":
            returned(party)
        elif name in ("func_14118E1F0", "func_14118E020"):
            returned(a[1] < 200 and read(member(a[0], a[1]) + 402, "<B") >= 5)
        elif name == "func_14118EE80":
            returned(0)
        elif name == "func_14118E0E0":
            returned(a[1] == state["local"])
        elif name == "func_140CA2250":
            returned(state["initialized"])
        elif name == "func_140CA1C80":
            returned(state["eligible"])
        elif name in ("func_140CA2230", "func_140CA2210"):
            returned(pool + 88 * a[0])
        elif name == "DW_BotRank_Apply":
            returned(0)  # Actual rank handoff has its own full native/compiled gate.
        elif name == "func_141359F90":
            returned(state["server_bot"])
        elif name == "func_141371450":
            returned(not state["server_bot"])
        elif name == "DW_MatchmakingAssignments_PrepareLaunch":
            assert a[0] == server_party and not state["server_bot"]
            state["assignment_replays"] = state.get("assignment_replays", 0) + 1
            returned()
        elif name == "func_14137D670":
            returned(server_party)
        elif name == "func_14118CF60":
            write(a[0], 42 + a[2], "<Q")
            returned(a[0])
        elif name == "func_14118C070":
            returned(a[1] - 42)
        elif name == "func_14118C110":
            returned(a[1] - 41)
        elif name == "func_141B23610":
            write(a[1], struct.pack("<200i", *range(200)))
            returned()
        elif name == "func_141B22140":
            assert a[1] < 2, "Virtual bot dispatched to human identity binding"
            human_calls.append(a[1])
            models[paths[a[2]] + ".gamertag"] = "Human " + str(a[1])
            returned()
        elif name in ("func_141528240", "func_140F22880", "func_14118DDB0"):
            returned(0)
        elif name == "func_14118C7D0":
            returned(152)
        elif name == "func_141B0D390":
            path = paths.get(a[0], "global") + "." + string(a[1])
            handle = len(paths) + 10
            if path in paths.values():
                handle = next(i for i, p in paths.items() if p == path)
            else:
                paths[handle] = path
            returned(handle)
        elif name == "func_141B0E0B0":
            models[paths[a[0]]] = int(bool(a[1] & 255))
            returned()
        elif name == "func_141B0E150":
            models[paths[a[0]]] = a[1] if a[1] < 0x80000000 else a[1] - 0x100000000
            returned()
        elif name == "func_141B0E280":
            models[paths[a[0]]] = string(a[1])
            returned()
        elif name == "Com_sprintf":
            fmt = string(a[2])
            if fmt == "%llu":
                value = str(a[3])
            elif fmt == "%s%u":
                value = string(a[3]) + str(read(rsp + 40, "<I"))
            else:
                raise AssertionError(fmt)
            assert len(value.encode()) + 1 <= a[1]
            write(a[0], value.encode() + b"\0")
            returned(len(value))
        elif name == "DW_Bot_StringTableAsset":
            write(a[1], arena + 0x7000, "<Q")
            returned()
        elif name == "DW_Bot_StringTableRows":
            returned(200)
        elif name == "DW_Bot_StringTableColumn":
            write(arena + 0x7100, ("NativeBot" + str(a[1])).encode() + b"\0")
            returned(arena + 0x7100)
        elif name == "func_141B0D520":
            returned(3)
        elif name == "func_141B0D710":
            key = string(a[1])
            handle = 4 if key.endswith("friendlySquadIndex") else 5
            paths[handle] = "members." + key.rsplit(".", 1)[-1]
            returned(handle)
        elif name == "func_141B0D530":
            returned(models[paths[a[0]]])
        elif name in ("func_141192AC0", "func_141192AA0"):
            returned(1)
        elif name == "Dvar_GenerateChecksum":
            returned(123)
        elif name in ("Dvar_RegisterVariant", "Dvar_RegisterInt"):
            key = string(a[0])
            ptr = arena + 0x3000 + len(registered) * 0x100
            registered[key] = ptr
            if name == "Dvar_RegisterVariant":
                assert key == "replay_dw_reservedSquads" and a[2:4] == [9, 0]
                initial = read(read(rsp + 40, "<Q"), "<Q")
                write(ptr + 40, initial, "<Q")
                write(ptr + 29, 9, "<B")
            else:
                assert key == "replay_dw_squadSize" and a[1:4] == [0, 0, 200]
                write(ptr + 29, 5, "<B")
                write(ptr + 40, 0)
            returned(ptr)
        else:
            returned()

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    vm.hook_add(UC_HOOK_CODE, boundary)

    def run(name, *arguments):
        rsp = stack + 0x3FF000 - 8
        write(rsp, halt, "<Q")
        vm.reg_write(UC_X86_REG_RSP, rsp)
        for reg, value in zip(
            (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), arguments
        ):
            vm.reg_write(reg, value)
        try:
            vm.emu_start(base + symbols[name], halt, count=20000000)
        except Exception:
            print(
                "Native probe fault:",
                misses[-3:],
                "RIP",
                hex(vm.reg_read(UC_X86_REG_RIP)),
            )
            raise
        assert vm.reg_read(UC_X86_REG_RIP) == halt
        result = vm.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        return result if result < 0x80000000 else result - 0x100000000

    def policy(mask, size):
        write(arena + 0x6000, format(mask, "050x").encode() + b"\0")
        write(registered["replay_dw_reservedSquads"] + 40, arena + 0x6000, "<Q")
        write(registered["replay_dw_squadSize"] + 40, size)

    checks = []
    run("DW_BotPolicy_Register")
    policy(3, 3)
    before = bytes(vm.mem_read(party, 0x80000))
    run("func_141B21D50", party, 1)
    assert (
        human_calls == [0, 1]
        and models["members.memberCount"] == 14
        and models["members.maxCount"] == 152
    )
    assert models["members.count"] == 14
    for row in range(2, 14):
        assert (
            models[f"members.{row}.gamertag"] == f"Bot {row}"
            and models[f"members.{row}.isBot"] == 1
        ), (
            row,
            models.get(f"members.{row}.gamertag"),
            models.get(f"members.{row}.isBot"),
        )
        assert (
            models[f"members.{row}.xuid"] == str(0xB070000000000000 | row)
            and models[f"members.{row}.bodyWest"] == 80 + row
        )
        assert models[f"members.{row}.clanTag"] == "[^3Bot^7]"
        assert (
            len(models[f"members.{row}.clanTag"].replace("^3", "").replace("^7", ""))
            == 5
        )
    assert bytes(vm.mem_read(party, 0x80000)) == before
    assert run("func_14118ADD0", party) == 14
    run("func_141B22B40", party, 2)
    assert models["squadMembers.count"] == 1
    checks.append(
        "Native pregame includes twelve distinct bot display keys, record-owned operators and customized stock weapons; no human playercard boundary is called and No Fill preview excludes bot teammates"
    )
    keys = {models[f"members.{row}.xuid"] for row in range(2, 14)}
    assert len(keys) == 12
    weapon_loot = {models[f"members.{row}.weaponSetup.0.weaponLootID"] for row in range(2, 14)}
    assert len(weapon_loot) > 1
    # A weapon/style with no positive native Gunsmith tradeoff legitimately
    # remains stock. Validate the advertised selection rather than requiring
    # a cosmetic attachment regardless of the weapon's actual capabilities.
    source_root = Path(report["source_root"])
    style_header = source_root / "src/DW_BotStyleData.h"
    style_proof = json.loads((source_root / "generated/bot-style-data.json").read_bytes())
    assert style_proof["passed"] and style_proof["image_sha256"] == report["input_sha256"]
    assert hashlib.sha256(style_header.read_bytes()).hexdigest() == style_proof["generated_header_sha256"]
    roster_units = [unit for unit in report["cpp"] if unit["source"] == "src/DW_BotRoster.cpp"]
    assert len(roster_units) == 1
    compiled_headers = {Path(item["path"]).resolve(): item["sha256"]
                        for item in roster_units[0]["dependencies"]}
    assert compiled_headers[style_header.resolve()] == style_proof["generated_header_sha256"]
    style_text = style_header.read_text()
    styles = json.loads("[" + style_text.split("StyleNames[] = {", 1)[1].split("};", 1)[0] + "]")
    attachment_section = style_text.split("Attachment Attachments[] = {", 1)[1].split("};", 1)[0]
    attachment_rows = re.findall(
        r'\{"([^"]+)", "([^"]+)", (\d+), (\d+), (\d+), (\d+), (\d+), (\d+), \{([^{}]+)\}\}',
        attachment_section,
    )
    attachments = [dict(reference=row[0], category=int(row[5]), blocked=int(row[6]),
                        variant=int(row[7]), scores=[int(value) for value in row[8].split(",")])
                   for row in attachment_rows]
    weapon_section = style_text.split("Weapon Weapons[] = {", 1)[1].split("};", 1)[0]
    weapon_rows = re.findall(r'\{"([^"]+)", "([^"]+)", "([^"]+)", (\d+), (\d+), (\d+)\}', weapon_section)
    weapons = {int(row[5]): dict(reference=row[0], weapon_class=row[2], first=int(row[3]), count=int(row[4]))
               for row in weapon_rows}
    assert len(attachments) == style_proof["counts"]["attachments"]
    assert len(weapons) == style_proof["counts"]["weapons"]
    stock_selections = []
    selected_attachment_total = 0
    for row in range(2, 14):
        style_name = models[f"members.{row}.botLoadoutStyle"]
        style_index = styles.index(style_name)
        for slot in range(2):
            prefix = f"members.{row}.weaponSetup.{slot}"
            weapon = weapons[models[prefix + ".weaponLootID"]]
            assert (weapon["weapon_class"] == "weapon_pistol") == bool(slot)
            candidates = attachments[weapon["first"]:weapon["first"] + weapon["count"]]
            count = models[prefix + ".attachmentCount"]
            assert 0 <= count <= 5
            selected = []
            for index in range(5):
                reference = models[f"{prefix}.attachment.{index}.attachment"]
                variant = models[f"{prefix}.attachment.{index}.variant"]
                if index >= count:
                    assert reference == "" and variant == 0
                    continue
                matches = [item for item in candidates if item["reference"] == reference and item["variant"] == variant]
                assert len(matches) == 1, (row, slot, weapon["reference"], reference, variant)
                attachment = matches[0]
                assert attachment["scores"][style_index] > 0
                for previous in selected:
                    assert attachment["category"] != previous["category"]
                    assert not attachment["blocked"] or attachment["blocked"] != previous["category"]
                    assert not previous["blocked"] or previous["blocked"] != attachment["category"]
                selected.append(attachment)
            if not count:
                assert not any(item["scores"][style_index] > 0 for item in candidates)
                stock_selections.append(dict(row=row, slot=slot, weapon=weapon["reference"], style=style_name))
            selected_attachment_total += count
    assert selected_attachment_total > 0
    checks.append("Both displayed weapon slots use compatible native Gunsmith attachments, positive style tradeoffs and exact variants; unsupported stock-only selections and cleared unused slots are preserved")
    snapshot_models = dict(models)
    state["eligible"] = False
    state["local"] = 1
    models.clear()
    human_calls.clear()
    run("func_141B21D50", party, 1)
    for row in range(2, 14):
        for key in ("gamertag", "xuid", "headWest", "bodyWest", "weaponSetup.0.weaponLootID", "weaponSetup.0.weaponCamo"):
            assert models[f"members.{row}.{key}"] == snapshot_models[f"members.{row}.{key}"]
    assert models["members.memberCount"] == 14
    policy(0, 3)
    run("func_141B21D50", party, 1)
    run("func_141B22B40", party, 2)
    assert models["squadMembers.count"] == 3
    state["local"] = 0
    run("func_141B21D50", party, 1)
    run("func_141B22B40", party, 2)
    assert models["squadMembers.count"] == 3
    state["eligible"] = True
    policy(3, 3)
    checks.append("Both local member views show their synchronized team bots even with guest playlist eligibility false; all remote bot appearance and weapon choices agree")
    saved_pool = bytes(vm.mem_read(pool, 200 * 88))
    run("DW_BotPolicy_Prepare", party)
    expected = bytearray(saved_pool)
    for i in range(2, 14):
        expected[88 * i + 77] = 3 + (i - 2) // 3
        expected[88 * i + 36 : 88 * i + 47] = b"[^3Bot^7]\0\0"
    assert bytes(vm.mem_read(pool, 200 * 88)) == bytes(expected)
    checks.append(
        "Pregame preparation changes only native aiTeam and bot clan fields; all names, customization, unknown wire fields and human placeholders are preserved; the five-visible-character clan tag resets color before its closing bracket and fits its eleven-byte field"
    )
    teams = []
    for i in range(12):
        teams.append(run("func_141370860", 44 + i))
        assert run("func_1413707D0", 44 + i) == 2 + i // 3
    assert teams == [3 + i // 3 for i in range(12)] and len(set(teams)) == 4
    checks.append(
        "ClientBegin gives twelve bots four distinct BR combat teams and never uses either reserved human squad"
    )
    policy(1, 3)
    assert run("func_1413707D0", 44) == 1 and run("func_141370860", 44) == 2
    policy(0, 3)
    assert run("func_1413707D0", 44) == 0 and run("func_141370860", 44) == 1
    policy(3, 1)
    assert run("func_1413707D0", 44) == -1 and run("func_141370860", 44) == 3
    checks.append(
        "Mixed Fill On/Off allows only consenting squads; solos use independent teams without assigning a squad"
    )
    policy(3, 3)
    for i in range(2, 14):
        write(server_pool + 88 * i + 85, 0, "<B")
    for i in range(2, 14):
        assert run("func_14132ED80", 0) == i
    assert run("func_14132ED80", 0) == -1
    checks.append(
        "BR spawn selection consumes all native bot records once, including teams beyond axis/allies, while preserving human records"
    )
    state["server_bot"] = False
    write(native_clients + 321192 + 214756, 0, "<i")
    prior_replays = state.get("assignment_replays", 0)
    assert run("func_1413707D0", 1) == 1 and run("func_141370860", 1) == 2
    assert state["assignment_replays"] == prior_replays + 2
    state["enabled"] = False
    assert run("func_14118ADD0", party) == 2
    models.clear()
    human_calls.clear()
    run("func_141B21D50", party, 1)
    assert models["members.memberCount"] == 2 and human_calls == [0, 1]
    checks.append(
        "Human startup and non-DW roster behavior retain native assignment and identity consumers"
    )
    for i in range(200):
        write(member(party, i) + 402, int(i in (0, 103)) * 5, "<B")
        write(pool + 88 * i + 84, 1, "<B") # stale tail records must be erased
    state["enabled"] = True
    # Native registered package groups are the only external model lookup data.
    # Build report records source roots separately; the generated header's
    # matching model pairs are compiler inputs retained beside the job receipt.
    candidates = list(Path("E:/DW/IW8/data").glob("compiler-snapshot-*/src/DW_BotBindings.h"))
    matching = [p for p in candidates if hashlib.sha256((p.parent / "DW_BotRoster.cpp").read_bytes()).hexdigest()
                in {r["source_sha256"] for r in report["cpp"]}]
    assert matching or args.header_source
    selected_header = args.header_source or matching[-1]
    assert hashlib.sha256((selected_header.parent / "DW_BotRoster.cpp").read_bytes()).hexdigest() in {
        r["source_sha256"] for r in report["cpp"]}
    header_text = selected_header.read_text()
    section = header_text.split("DWBotOperatorSkins[] = {", 1)[1].split("};", 1)[0]
    skin_pairs = [(int(a), int(b)) for a, b in re.findall(r"\{(\d+), (\d+)\}", section)]
    groups = base + symbols["DW_Bot_CustomizationGroups"]
    packages = base + symbols["DW_Bot_CustomizationPackages"]
    write(base + symbols["DW_Bot_CustomizationEnabled"], 1)
    ids = [sorted({p[k] for p in skin_pairs}) for k in range(2)]
    first = 0
    for kind, selected_ids in enumerate(ids):
        write(groups + 16 * kind, struct.pack("<HHIII", first, 0, len(selected_ids), len(selected_ids), 0))
        for i, primary in enumerate(selected_ids):
            write(packages + 40 * (first + i), bytes(40))
            write(packages + 40 * (first + i) + 22, primary, "<H")
            write(packages + 40 * (first + i) + 28, 2)
        first += len(selected_ids)
    run("DW_BotPolicy_BuildRoster", party, 152, 9)
    present = [i for i in range(200) if read(pool + 88 * i + 84, "<B")]
    assert present == list(range(1, 10))
    selected_records = [bytes(vm.mem_read(pool + 88 * i, 88)) for i in present]
    assert len({r[:36].split(b"\0")[0] for r in selected_records}) == 9
    assert all((struct.unpack_from("<I", r, 52)[0], struct.unpack_from("<I", r, 56)[0]) in skin_pairs for r in selected_records)
    checks.append("Roster rebuilding assigns distinct list names and exact paired operator skin IDs from native registered packages, clears stale tail entries and respects noncontiguous human slots")
    run("DW_BotPolicy_CaptureRoster")
    for i in range(200):
        data = bytearray(88)
        struct.pack_into("<H", data, 48, i)
        struct.pack_into("<H", data, 78, 1000 + i)
        data[84] = 1
        write(pool + 88 * i, bytes(data))
    run("DW_BotPolicy_BuildRoster", party, 152, 17)
    assert all(bytes(vm.mem_read(pool + 88 * (i + 1), 88)) == record
               for i, record in enumerate(selected_records))
    prior = {i: bytes(vm.mem_read(pool + 88 * i, 88)) for i in range(1, 12)}
    run("DW_BotPolicy_CaptureRoster")
    run("DW_BotPolicy_BuildRoster", party, 152, 11)
    assert all(bytes(vm.mem_read(pool + 88 * i, 88)) == record for i, record in prior.items())
    assert not any(read(pool + 88 * i + 84, "<B") for i in range(12, 200))
    write(member(party, 5) + 402, 5, "<B")
    run("DW_BotPolicy_CaptureRoster")
    run("DW_BotPolicy_BuildRoster", party, 152, 11)
    assert not read(pool + 88 * 5 + 84, "<B")
    assert bytes(vm.mem_read(pool + 88 * 12, 88)) == prior[5]
    assert all(bytes(vm.mem_read(pool + 88 * i, 88)) == record
               for i, record in prior.items() if i != 5)
    write(member(party, 5) + 402, 0, "<B")
    checks.append("Gradual roster growth preserves all 88 bytes and prior slots; reduction removes excess records and a new human moves only its collided bot")
    # Expand the actual synchronized native 36-byte bot wire data on a guest.
    for record in selected_records:
        write(arena + 0x7200, record[48:84])
        write(arena + 0x7300, bytes(48))
        run("BG_GameStateInfo_ExpandBotData", arena + 0x7200, arena + 0x7300)
        assert bytes(vm.mem_read(arena + 0x7300, 36)).split(b"\0")[0] == record[:36].split(b"\0")[0]
    for i in range(200):
        write(member(party, i) + 402, int(i == 0) * 5, "<B")
        write(pool + 88 * i + 84, 1, "<B")
    run("DW_BotPolicy_BuildRoster", party, 200, 199)
    all_names = [string(pool + 88 * i) for i in range(1, 200)]
    assert len(set(n.casefold() for n in all_names)) == 199
    assert all(len(n) < 36 for n in all_names)
    name_corpus = selected_header.parent / "DW_BotNames.txt"
    supplied_names = set(name_corpus.read_text(encoding="utf-8").splitlines())
    assert len(supplied_names) == 100000 and all(name in supplied_names for name in all_names)
    # Case/color-normalized human collision must consume another unique name.
    write(member(party, 0) + 52, ("^3" + all_names[0].upper()).encode() + b"\0")
    run("DW_BotPolicy_BuildRoster", party, 200, 199)
    assert string(pool + 88) .casefold() != all_names[0].casefold()
    checks.append("Native wire name expansion agrees on guests; 199 requested bots use unique names from the supplied 100,000-name corpus and avoid case/color-normalized human name collisions")
    args.output.write_text(
        json.dumps(
            dict(
                schema=1,
                passed=True,
                game_sha256=report["sha256"],
                checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                bindings_header_sha256=hashlib.sha256(selected_header.read_bytes()).hexdigest(),
                bot_name_corpus_sha256=hashlib.sha256(name_corpus.read_bytes()).hexdigest(),
                gunsmith_data_sha256=style_proof["generated_header_sha256"],
                stock_weapon_style_selections=stock_selections,
                selected_attachment_total=selected_attachment_total,
                checks=checks,
                native_game_verified=False,
            ),
            indent=2,
        )
        + "\n"
    )
    print("PASS:", len(checks), "linked native bot roster/assignment groups")


if __name__ == "__main__":
    main()
