"""Bind complete Replay team/squad updates and their native party setters."""

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
SOURCE = "src/DW_MatchmakingAssignments.cpp"
BODIES = (
    (
        "fn_e7efeaa28e8d76e1",
        "DW_Matchmaker_UpdateSquadAssignments",
        394,
        "5917af7b8f576d0adc1cfea0f3aa87c9eb27ebb1ec8c87b045bafc56298e6eca",
    ),
    (
        "fn_8818dff79f880518",
        "DW_Matchmaker_UpdateTeamAssignments",
        397,
        "bd4b941d0882031ec225009f1ad9922bdb65981f79d8894434602483519981be",
    ),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_private(path, data):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT / "data"):
        raise ValueError("Assignment preparation escaped the private workspace")
    payload = data.encode("utf-8") if isinstance(data, str) else data
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=path.name + ".", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def inspect_native(snapshot):
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    if catalog["image_sha256"] != IMAGE_SHA or sha(IMAGE.read_bytes()) != IMAGE_SHA:
        raise ValueError("Original Replay image binding changed")
    pe = pefile.PE(str(IMAGE), fast_load=True)
    pe.parse_data_directories(directories=[3])
    byid = {row["id"]: row for row in catalog["functions"] + catalog.get("symbols", [])}
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
    targets = []
    imports = {}
    calls_by_method = []
    for identity, symbol, size, expected in BODIES:
        row = byid[identity]
        assert not row.get("quarantined")
        ranges = [list(span) for span in sorted(families[row["rva"]])]
        assert ranges[0][0] == row["rva"] and ranges[-1][1] - row["rva"] == size
        body = pe.get_data(row["rva"], size)
        if sha(body) != expected:
            raise ValueError("Complete original assignment body changed: " + identity)
        instructions = list(decoder.disasm(body, row["rva"]))
        calls = [
            i.operands[0].imm
            for i in instructions
            if i.mnemonic in ("call", "jmp")
            and i.operands[0].type == X86_OP_IMM
            and not row["rva"] <= i.operands[0].imm < row["rva"] + size
        ]
        assert (
            len(calls) == 9
            and calls[0] == calls[4] == calls[8]
            and calls[3] == calls[6]
        )
        calls_by_method.append(calls)
        symbols = (
            "DWMA_Print",
            "DWMA_LobbyParty",
            "DWMA_XuidEqual",
            "DWMA_XuidString",
            "DWMA_Print",
            "DWMA_SetSquad" if identity == BODIES[0][0] else "DWMA_SetTeam",
            "DWMA_XuidString",
            "DWMA_Warning",
            "DWMA_Print",
        )
        for name, address in zip(symbols, calls, strict=True):
            native = by_rva[address]
            assert not native.get("quarantined")
            if name in imports:
                assert imports[name]["identity"] == native["id"]
            else:
                owned = families.get(address)
                native_size = (
                    max(end for _, end in owned) - address
                    if owned
                    else min(r for r in by_rva if r > address) - address
                )
                imports[name] = dict(
                    identity=native["id"],
                    rva=address,
                    bytes=native_size,
                    sha256=sha(pe.get_data(address, native_size)),
                    kind="function",
                )
        slots = [
            i.address + i.size + i.operands[1].mem.disp
            for i in instructions
            if i.mnemonic == "mov"
            and i.op_str.startswith("r8, qword ptr [rip")
            and i.operands[1].type == X86_OP_MEM
            and i.operands[1].mem.base == X86_REG_RIP
        ]
        assert len(slots) == 1
        globals_ = [
            r
            for r in catalog.get("symbols", [])
            if r["rva"] == slots[0]
            and r.get("kind") == "data-address"
            and not r.get("quarantined")
        ]
        assert len(globals_) == 1
        data_binding = dict(identity=globals_[0]["id"], rva=slots[0], kind="data")
        if "DWMA_UpdateAssignments" in imports:
            assert imports["DWMA_UpdateAssignments"] == data_binding
        imports["DWMA_UpdateAssignments"] = data_binding
        displacements = {
            o.mem.disp for i in instructions for o in i.operands if o.type == X86_OP_MEM
        }
        assert {
            6408,
            6416,
            46424,
            46432,
            16,
            24,
            196 if identity == BODIES[0][0] else 192,
        }.issubset(displacements)
        assert any(
            i.mnemonic == "add" and i.op_str == "rdx, 0x68" for i in instructions
        )
        targets.append(
            dict(
                identity=identity,
                symbol=symbol,
                rva=row["rva"],
                bytes=size,
                sha256=expected,
                unwind_family_ranges=ranges,
                complete_body_hex=body.hex(),
            )
        )
    assert all(
        a == b for i, (a, b) in enumerate(zip(*calls_by_method, strict=True)) if i != 5
    )
    setter_guards = {}
    for name, member_offset in (("DWMA_SetTeam", 2584), ("DWMA_SetSquad", 2588)):
        binding = imports[name]
        instructions = list(
            decoder.disasm(
                pe.get_data(binding["rva"], binding["bytes"]), binding["rva"]
            )
        )
        current_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.mnemonic == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[1].type == X86_OP_MEM
            and instruction.operands[1].mem.disp == member_offset
        )
        comparison, unchanged = instructions[current_index + 1 : current_index + 3]
        assert comparison.mnemonic == "cmp" and unchanged.mnemonic == "je"
        write = next(
            instruction
            for instruction in instructions[current_index + 3 :]
            if instruction.mnemonic == "mov"
            and instruction.operands[0].type == X86_OP_MEM
            and instruction.operands[0].mem.disp == member_offset
        )
        assert unchanged.operands[0].imm > write.address
        notify = [
            instruction
            for instruction in instructions
            if instruction.mnemonic == "call"
            and instruction.operands[0].type == X86_OP_IMM
            and write.address < instruction.address < unchanged.operands[0].imm
        ]
        assert notify
        setter_guards[name] = dict(
            member_absolute_offset=member_offset,
            compare_instruction_rva=comparison.address,
            equal_branch_rva=unchanged.address,
            equal_target_rva=unchanged.operands[0].imm,
            write_rva=write.address,
            unchanged_skips_party_write_and_notify=True,
        )
    lobby = byid["fn_0321d6b432abc45b"]
    lobby_body = pe.get_data(lobby["rva"], 8)
    assert lobby_body.hex() == "488b8128370100c3"
    imports["DWMA_LobbyIdentity"] = dict(
        identity=lobby["id"],
        rva=lobby["rva"],
        bytes=8,
        sha256=sha(lobby_body),
        kind="function",
    )
    owner = byid["fn_5c42c24c120e931c"]
    owner_size = max(end for _, end in families[owner["rva"]]) - owner["rva"]
    owner_body = pe.get_data(owner["rva"], owner_size)
    owner_instructions = list(decoder.disasm(owner_body, owner["rva"]))
    matchmaking = byid["fn_dc9af7b3d7e14cd5"]["rva"]
    receiver_sites = [
        owner_instructions[index - 1]
        for index, instruction in enumerate(owner_instructions)
        if instruction.mnemonic == "call"
        and instruction.operands[0].type == X86_OP_IMM
        and instruction.operands[0].imm == matchmaking
    ]
    assert len(receiver_sites) == 1
    receiver = receiver_sites[0]
    assert receiver.mnemonic == "lea" and receiver.op_str.startswith("rcx, [rip")
    address = receiver.address + receiver.size + receiver.operands[1].mem.disp
    globals_ = [
        r
        for r in catalog["symbols"]
        if r["rva"] == address
        and r.get("kind") == "data-address"
        and not r.get("quarantined")
    ]
    assert len(globals_) == 1
    imports["DWMA_CurrentMatchmaker"] = dict(
        identity=globals_[0]["id"], rva=address, kind="data"
    )
    return dict(
        image_sha256=IMAGE_SHA,
        targets=targets,
        imports=imports,
        setter_guards=setter_guards,
        cache_binding=dict(
            receiver_owner=owner["id"],
            owner_bytes=owner_size,
            owner_sha256=sha(owner_body),
            receiver_instruction=receiver.bytes.hex(),
            receiver_instruction_rva=receiver.address,
            lobby_identity_offset=79656,
        ),
    )


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    if (
        not snapshot.is_relative_to(ROOT / "data")
        or (snapshot.parent / "client-readiness.json").exists()
    ):
        raise ValueError("Assignment preparation requires a fresh private snapshot")
    proof = inspect_native(snapshot)
    source = ROOT / "integration/replay/DW_MatchmakingAssignments.cpp"
    staged = snapshot / SOURCE
    if (
        staged.exists()
        and not replace_owned
        and staged.read_bytes() != source.read_bytes()
    ):
        raise ValueError("Staged assignment source has another owner")
    write_private(staged, source.read_bytes())
    write_private(
        snapshot / "src/DW_MatchmakingAssignmentBindings.h",
        "#pragma once\n// Complete original Replay bodies, stable target imports and native party setters.\n",
    )
    associations_path = snapshot / "source-units.json"
    associations = json.loads(associations_path.read_bytes())
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    assert associations_path.stat().st_nlink == units_path.stat().st_nlink == 1
    digest = sha(staged.read_bytes())
    for target in proof["targets"]:
        identity, symbol = target["identity"], target["symbol"]
        expected = dict(source=SOURCE, symbol=symbol, function_id=identity)
        prior = [
            u
            for u in associations["units"]
            if u["function_id"] == identity or u["symbol"] == symbol
        ]
        if prior and (not replace_owned or prior != [expected]):
            raise ValueError("Assignment root already has another owner")
        if not prior:
            associations["units"].append(expected)
        prior = [u for u in units["units"] if u["function_id"] == identity]
        if prior and (not replace_owned or prior[0]["source"] != SOURCE):
            raise ValueError("Assignment editable source already has another owner")
        units["units"] = [u for u in units["units"] if u["function_id"] != identity]
        units["units"].append(
            dict(
                function_id=identity,
                kind="cpp",
                source=SOURCE,
                symbol=symbol,
                sha256=digest,
                revision=digest,
                language="cpp",
            )
        )
    for symbol, binding in proof["imports"].items():
        expected = dict(symbol=symbol, symbol_id=binding["identity"])
        prior = [u for u in associations.get("imports", []) if u["symbol"] == symbol]
        if prior and prior != [expected]:
            raise ValueError("Assignment native import has another binding")
        if not prior:
            associations.setdefault("imports", []).append(expected)
    write_private(associations_path, json.dumps(associations, indent=2) + "\n")
    write_private(units_path, json.dumps(units, indent=2) + "\n")
    proof.update(
        schema=1,
        passed=True,
        source=SOURCE,
        source_sha256=digest,
        generator_sha256=sha(Path(__file__).read_bytes()),
        assignment_list_bytes=6424,
        assignment_node_bytes=32,
        assignment_capacity=200,
        assignment_offsets=dict(
            free=6400, head_previous=6408, head_next=6416, xuid=16, value=24
        ),
        player_offsets=dict(
            head_previous=46424, head_next=46432, xuid=104, team=192, squad=196
        ),
        native_party_setter_guards_preserved=True,
        direct_party_member_writes=False,
        scope="DW battle royale with original update-party-assignment dvar enabled",
        replay_cache=dict(
            capacity_per_kind=200,
            current_receiver_only=True,
            nonzero_current_lobby_only=True,
            copies_values=True,
            native_party_only=True,
            invalid_epoch_clears=True,
            interlocked_lock=True,
            callbacks_outside_lock=True,
            bounded_owned_snapshot=True,
            revision_checked_before_callbacks=True,
        ),
        dependencies={
            name: sha((snapshot / name).read_bytes())
            for name in (
                SOURCE,
                "src/replay_dvar.h",
                "src/DW_MatchmakingAssignmentBindings.h",
            )
        },
        game_modified=False,
        game_run_performed=False,
    )
    write_private(
        snapshot / "generated/matchmaking-assignments-integration.json",
        json.dumps(proof, indent=2) + "\n",
    )
    return proof


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
