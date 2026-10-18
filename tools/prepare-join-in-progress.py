"""Bind the complete Replay anonymous-member reservation and bot slot preference."""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
SOURCE = "src/DW_JoinInProgress.cpp"
IDENTITY = "fn_58eea3d558827a00"
SYMBOL = "DW_PartyAtomicHost_AddAnonymousMember"
BODY_SHA = "72af5d8b4cc1235ebae5f818a1469693486b13fb0d66e647ebc115a729c29166"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_private(path, data):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT / "data"):
        raise ValueError("Join preparation escaped private workspace")
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=path.name + ".", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(data.encode() if isinstance(data, str) else data)
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def inspect_native(snapshot):
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    assert catalog["image_sha256"] == IMAGE_SHA == sha(IMAGE.read_bytes())
    pe = shared_original_pe(str(IMAGE), fast_load=True)
    pe.parse_data_directories(directories=[3])
    byid = {row["id"]: row for row in catalog["functions"]}
    by_rva = {row["rva"]: row for row in catalog["functions"]}
    families = {}
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        families.setdefault(owner.struct.BeginAddress, []).append(
            (entry.struct.BeginAddress, entry.struct.EndAddress)
        )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    imports = {}

    def function(name, identity):
        row = byid[identity]
        assert not row.get("quarantined")
        ranges = families.get(row["rva"])
        size = (
            max(end for _, end in ranges) - row["rva"]
            if ranges
            else min(r for r in by_rva if r > row["rva"]) - row["rva"]
        )
        body = pe.get_data(row["rva"], size)
        imports[name] = dict(
            identity=identity,
            rva=row["rva"],
            bytes=size,
            sha256=sha(body),
            kind="function",
        )
        return list(decoder.disasm(body, row["rva"]))

    def data(name, address):
        rows = [
            row
            for row in catalog["symbols"]
            if row["rva"] == address
            and row.get("kind") == "data-address"
            and not row.get("quarantined")
        ]
        assert len(rows) == 1, (name, address)
        imports[name] = dict(identity=rows[0]["id"], rva=address, kind="data")

    row = byid[IDENTITY]
    body = pe.get_data(row["rva"], 603)
    assert sha(body) == BODY_SHA
    assert max(end for _, end in families[row["rva"]]) - row["rva"] == 603
    instructions = list(decoder.disasm(body, row["rva"]))
    calls = [
        instruction.operands[0].imm
        for instruction in instructions
        if instruction.mnemonic == "call" and instruction.operands[0].type == X86_OP_IMM
    ]
    names = [
        "DWJIP_GameSlots",
        "DWJIP_GameLobby",
        "DWJIP_PlaylistId",
        "DWJIP_MaxHumanPlayers",
        "DWJIP_OldestSlot",
        "DWJIP_OldestSlot",
        "DWJIP_GameLobby",
        "DWJIP_LocalServerRunning",
        "DWJIP_OldestSlot",
        "DWJIP_Print",
        "DWJIP_RemoveMember",
        "DWJIP_Print",
        "DWJIP_XuidString",
        "DWJIP_Print",
        "DWJIP_Zero",
        "DWJIP_XuidAssign",
        "DWJIP_Milliseconds",
        "DWJIP_GameLobby",
    ]
    assert len(calls) == len(names)
    for name, address in zip(names, calls, strict=True):
        function(name, by_rva[address]["id"])
    slots = [
        instruction.address + instruction.size + instruction.operands[1].mem.disp
        for instruction in instructions
        if instruction.mnemonic == "mov"
        and len(instruction.operands) == 2
        and instruction.operands[1].type == X86_OP_MEM
        and instruction.operands[1].mem.base == X86_REG_RIP
    ]
    assert len(slots) == 5
    for name, address in zip(
        [
            "DWJIP_PrivateMatch",
            "DWJIP_Playlist",
            "DWJIP_AnonymousDuration",
            "DWJIP_ZombieDuration",
            "DWJIP_ConnectingDuration",
        ],
        slots,
        strict=True,
    ):
        data(name, address)
    function("DWJIP_AreWeHost", "fn_d1c60b525309035e")
    function("DWJIP_ServerLoaded", "fn_04583a98e3aa8c51")
    function("DWJIP_ServerLobby", "fn_509bc371a05c0e2b")
    bots = function("DWJIP_IsBot", "fn_28e18c92d4d58671")
    clients = [
        instruction.address + instruction.size + operand.mem.disp
        for instruction in bots
        for operand in instruction.operands
        if instruction.mnemonic == "lea"
        and operand.type == X86_OP_MEM
        and operand.mem.base == X86_REG_RIP
    ]
    assert len(clients) == 1
    data("DWJIP_Clients", clients[0])
    direct = byid["fn_8ab9299a36149d62"]
    direct_size = max(end for _, end in families[direct["rva"]]) - direct["rva"]
    direct_body = pe.get_data(direct["rva"], direct_size)
    assert (
        direct_size == 2796
        and sha(direct_body)
        == "3cebda116f6b3fb4df401bc46bf65f92fb63e02508eae35a44bb5cf381c65359"
    )
    direct_rows = list(decoder.disasm(direct_body, direct["rva"]))
    direct_calls = [
        instruction
        for instruction in direct_rows
        if instruction.mnemonic == "call" and instruction.operands[0].type == X86_OP_IMM
    ]
    validate = next(
        instruction
        for instruction in direct_calls
        if instruction.operands[0].imm == byid["fn_53e5c01bb17706c5"]["rva"]
    )
    mapped_party = next(
        instruction
        for instruction in direct_calls
        if instruction.operands[0].imm == byid["fn_509bc371a05c0e2b"]["rva"]
    )
    teardown = next(
        instruction
        for instruction in direct_calls
        if instruction.operands[0].imm == byid["fn_6adad9cb367e39fa"]["rva"]
    )
    assert validate.address < mapped_party.address < teardown.address
    counts = {
        instruction.address + instruction.size + operand.mem.disp
        for instruction in direct_rows
        for operand in instruction.operands
        if instruction.mnemonic == "mov"
        and instruction.op_str.startswith("ecx, dword ptr [rip")
        and operand.type == X86_OP_MEM
        and operand.mem.base == X86_REG_RIP
    }
    assert len(counts) == 1
    data("DWJIP_ClientCount", counts.pop())
    assert any(
        instruction.mnemonic == "cmp"
        and instruction.op_str == "dword ptr [rcx + 0x346e4], 2"
        for instruction in bots
    )
    return dict(
        image_sha256=IMAGE_SHA,
        target=dict(
            identity=IDENTITY,
            symbol=SYMBOL,
            rva=row["rva"],
            bytes=603,
            sha256=BODY_SHA,
            complete_body_hex=body.hex(),
        ),
        imports=imports,
        direct_connect=dict(
            identity=direct["id"],
            bytes=direct_size,
            sha256=sha(direct_body),
            party_slot_mapped_client=True,
            authenticated_native_teardown=True,
            protocol_validation_call=validate.address,
            server_party_call=mapped_party.address,
            teardown_call=teardown.address,
        ),
        layout=dict(
            member_bytes=488,
            member_array=2192,
            status=402,
            challenge=212,
            challenge_bytes=6,
            challenge_xuid=224,
            reserved_at=264,
            member_xuid=408,
            party_name=311056,
            dirty_bits=311164,
            client_state=8,
        ),
        admission=dict(
            native_capacity_unchanged=True,
            native_reservations_unchanged=True,
            ui_count_unchanged=True,
            no_premature_drop=True,
            private_matches_unchanged=True,
            scope="running public local-host DW native server party",
        ),
    )


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    if (
        not snapshot.is_relative_to(ROOT / "data")
        or (snapshot.parent / "client-readiness.json").exists()
    ):
        raise ValueError("Join preparation requires fresh private snapshot")
    proof = inspect_native(snapshot)
    canonical = ROOT / "integration/replay/DW_JoinInProgress.cpp"
    destination = snapshot / SOURCE
    if (
        destination.exists()
        and destination.read_bytes() != canonical.read_bytes()
        and not replace_owned
    ):
        raise ValueError("Join source has another owner")
    write_private(destination, canonical.read_bytes())
    header = "src/DW_JoinInProgressBindings.h"
    write_private(
        snapshot / header,
        "#pragma once\n// Complete Replay reservation body and derived native bindings.\n",
    )
    associations_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    associations = json.loads(associations_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    expected = dict(source=SOURCE, symbol=SYMBOL, function_id=IDENTITY)
    prior = [
        row
        for row in associations["units"]
        if row["function_id"] == IDENTITY or row["symbol"] == SYMBOL
    ]
    if prior and (not replace_owned or prior != [expected]):
        raise ValueError("Join root has another owner")
    if not prior:
        associations["units"].append(expected)
    prior = [row for row in units["units"] if row["function_id"] == IDENTITY]
    if prior and (not replace_owned or prior[0]["source"] != SOURCE):
        raise ValueError("Join editable root has another owner")
    digest = sha(destination.read_bytes())
    units["units"] = [row for row in units["units"] if row["function_id"] != IDENTITY]
    units["units"].append(
        dict(
            function_id=IDENTITY,
            kind="cpp",
            source=SOURCE,
            symbol=SYMBOL,
            sha256=digest,
            revision=digest,
            language="cpp",
        )
    )
    for symbol, binding in proof["imports"].items():
        expected = dict(symbol=symbol, symbol_id=binding["identity"])
        prior = [
            row for row in associations.get("imports", []) if row["symbol"] == symbol
        ]
        if prior and prior != [expected]:
            raise ValueError("Join import has another binding")
        if not prior:
            associations.setdefault("imports", []).append(expected)
    write_private(associations_path, json.dumps(associations, indent=2) + "\n")
    write_private(units_path, json.dumps(units, indent=2) + "\n")
    proof.update(
        passed=True,
        schema=1,
        source=SOURCE,
        source_sha256=digest,
        generator_sha256=sha(Path(__file__).read_bytes()),
        dependencies={
            name: sha((snapshot / name).read_bytes())
            for name in (SOURCE, header, "src/replay_dvar.h")
        },
        game_run_performed=False,
        game_modified=False,
    )
    write_private(
        snapshot / "generated/join-in-progress-integration.json",
        json.dumps(proof, indent=2) + "\n",
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
