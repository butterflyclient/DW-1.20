"""Prepare the Replay inspection command and shared prediction owners.

Inspection is read-only with --inspect-only. Compilation of original fallback
owners is deferred until an authorized future canonical build calls prepare().
"""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import sys

import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
import pefile

ROOT = Path(__file__).resolve().parents[1]
INPUT_TOOL = ROOT / "tools/prepare-weapon-inspect-input.py"
HELPERS = runpy.run_path(str(INPUT_TOOL))
IMAGE = HELPERS["IMAGE"]
IMAGE_SHA = HELPERS["IMAGE_SHA"]
unwind_family = HELPERS["unwind_family"]
SOURCE = "src/DW_WeaponInspect.cpp"
OWNERS = (
    (
        0x1128160,
        "DW_WeaponInspect_UpdateSprint",
        "WIR_OriginalUpdateSprint",
        "uint8_t(DWInspectPmove *, void *)",
        977,
        "f2c575dfa3264723970cdf559d36dc7d7756441c4ad9e6e859b0679ab7de8f18",
    ),
    (
        0x1141160,
        "DW_WeaponInspect_PMove",
        "WIR_OriginalWeapon",
        "uint8_t(DWInspectPmove *, void *)",
        2570,
        "8d4d6445a0ebfdee27c75fd8ebdcb214fd3c0cb28bf2d56d2b1415d5fd1723b5",
    ),
)
FUNCTIONS = {
    "WIR_Milliseconds": (0x148FCE0, "uint32_t()"),
    "WIR_IsMainThread": (0x12CF280, "bool()"),
    "WIR_IsConnected": (0x15BCD30, "bool(uint32_t)"),
    "WIR_AddReliableCommand": (0x15E03E0, "void(void *, const char *)"),
    "WIR_ViewmodelWeapon": (
        0x1157430,
        "const DWInspectWeapon *(const void *, const DWInspectPlayerState *)",
    ),
    "WIR_RequestedWeapon": (
        0x113D610,
        "const DWInspectWeapon *(const DWInspectPmove *)",
    ),
    "WIR_WeaponCount": (0x1157390, "uint32_t()"),
    "WIR_LastHand": (0x11774B0, "int32_t(const void *, const DWInspectPlayerState *)"),
    "WIR_UsingAlternate": (0xCC5D70, "bool(const DWInspectPlayerState *)"),
    "WIR_IsSprinting": (0x1122830, "bool(const DWInspectPlayerState *)"),
    "WIR_IsSkydiving": (0xCE3C10, "bool(const DWInspectPlayerState *)"),
    "WIR_IsMounted": (0xCA5540, "bool(const DWInspectPlayerState *)"),
    "WIR_IsScriptedScene": (0x111BA00, "bool(const DWInspectPlayerState *)"),
    "WIR_AnimationIndex": (0x10F0F20, "bool(uint32_t, const char *, uint32_t *)"),
    "WIR_AnimationName": (0x10F1030, "bool(uint32_t, uint32_t, const char **)"),
    "WIR_PlayScripted": (
        0x113A4E0,
        "bool(const void *, DWInspectPlayerState *, uint32_t, int32_t, int32_t, uint32_t)",
    ),
    "WIR_WeaponIdle": (
        0x113A3F0,
        "void(DWInspectPlayerState *, void *, const void *, uint32_t)",
    ),
}
GLOBALS = {
    "WIR_WeaponDefinitions": (0xC6ED9A0, "const DWInspectWeaponDefinition *", "[]"),
    "WIR_MpFlagValue": (0xC5244C4, "uint32_t", ""),
    "WIR_ClientConnection": (0xEE85570, "void *", ""),
    "WIR_ConnectionType": (0xEE85578, "uint8_t", ""),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(snapshot, assets):
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    assert catalog["image_sha256"] == IMAGE_SHA
    raw = IMAGE.read_bytes()
    assert sha(raw) == IMAGE_SHA
    pe = shared_original_pe(data=raw, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    )
    functions = {row["rva"]: row for row in catalog["functions"]}
    data = {
        row["rva"]: row
        for row in catalog["symbols"]
        if row.get("kind") == "data-address" and not row.get("quarantined")
    }
    declarations, imports, native = [], {}, {}
    for rva, symbol, helper, signature, size, digest in OWNERS:
        row = functions[rva]
        assert not row.get("quarantined")
        records = unwind_family(pe, rva)
        code = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
        assert len(code) == size and sha(code) == digest
        native[symbol] = dict(
            identity=row["id"], rva=rva, bytes=size, sha256=digest, unwind=records
        )
        result, parameters = signature.split("(", 1)
        declarations.append(f"{result} {helper}({parameters};")
    for name, (rva, signature) in FUNCTIONS.items():
        assert not functions[rva].get("quarantined")
        imports[name] = functions[rva]["id"]
        result, parameters = signature.split("(", 1)
        declarations.append(f"{result} {name}({parameters};")
    for name, (rva, ctype, suffix) in GLOBALS.items():
        imports[name] = data[rva]["id"]
        declarations.append(f"extern {ctype} {name}{suffix};")

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    def operands(rva, size):
        return [
            o
            for instruction in decoder.disasm(pe.get_data(rva, size), rva)
            for o in instruction.operands
        ]

    def offset(body, value):
        return any(o.type == X86_OP_MEM and o.mem.disp == value for o in body)

    def immediate(body, value):
        return any(o.type == X86_OP_IMM and o.imm == value for o in body)

    setter = operands(0x113A4E0, 168)
    for value in (1252, 1256, 1312, 1328, 1800):
        assert offset(setter, value), value
    assert immediate(setter, 62) and immediate(setter, 70) and immediate(setter, 0x400)
    weapon = operands(0x1141160, 2570)
    for value in (8, 16, 52, 280, 840, 896, 1328, 1800):
        assert offset(weapon, value), value
    definitions = operands(0x172D2F0, 1000)
    assert offset(definitions, 144)
    count_instructions = list(decoder.disasm(pe.get_data(0x1157390, 9), 0x1157390))
    assert [(i.mnemonic, i.op_str) for i in count_instructions[1:]] == [
        ("inc", "eax"),
        ("ret", ""),
    ], "Native count must include the null weapon slot"
    ads = operands(0x113F180, 1800)
    assert offset(ads, 1804)

    # The local-index CL_Main_AddReliableCommand wrapper is inlined in Replay.
    # Its actual MP method retains the native (this, command) ABI. Confirm the
    # vtable slot and complete method body; the similarly named catalog entry
    # at 0x1198250 is unrelated party-presence code and must never be imported.
    reliable_body = pe.get_data(0x15E03E0, 96)
    assert (
        sha(reliable_body)
        == "b82fc77685d5f60b61ca2593c7abe11647a3a2d472ea7af7d01d1fac0bfafe82"
    )
    assert (
        struct.unpack("<Q", pe.get_data(0x24F3A28, 8))[0]
        == pe.OPTIONAL_HEADER.ImageBase + 0x15E03E0
    )
    reliable_instructions = list(decoder.disasm(reliable_body, 0x15E03E0))
    reliable_calls = [
        i.operands[0].imm
        for i in reliable_instructions
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    assert reliable_calls == [0x12DDBF0, 0x15E0440, 0x21CCF60]
    assert any(
        i.mnemonic == "xor" and i.op_str == "r9d, r9d" for i in reliable_instructions
    )
    connected_body = pe.get_data(0x15BCD30, 44)
    assert (
        sha(connected_body)
        == "888dbe1afd43223d0a232636b1e766085c3b85793e42b20e0b7b1b36a8feb633"
    )
    connected = operands(0x15BCD30, 44)
    assert offset(connected, 36) and offset(connected, 8)
    assert immediate(connected, 440) and immediate(connected, 9)
    player_event_body = pe.get_data(0x1109030, 361)
    assert (
        sha(player_event_body)
        == "20bb93df653b645821e85f14e4de3f703e66236a167cc7ebc63dfb3e4b946031"
    )
    assert offset(operands(0x1109030, 361), 448)

    manifest = json.loads((assets / "manifest.json").read_bytes())
    assert manifest["schema"] == "replay120-weapon-inspect-assets-v1"
    header_row = next(
        row for row in manifest["artifacts"] if row["path"] == "weapon-inspect-assets.h"
    )
    header = (assets / "weapon-inspect-assets.h").read_bytes()
    assert sha(header) == header_row["sha256"]
    assert len(manifest["packages"]) == len(
        {row["package"] for row in manifest["packages"]}
    )
    for package in manifest["packages"]:
        assert package["donor_inspect_slot"] == 433
        assert 0 < package["duration_ms"] < 32768
        assert package["animation"] in manifest["netconststrings"]["names"]
    proof = dict(
        passed=True,
        image_sha256=IMAGE_SHA,
        source=SOURCE,
        source_sha256=sha(
            (ROOT / "integration/replay/DW_WeaponInspect.cpp").read_bytes()
        ),
        source_header_sha256=sha(
            (ROOT / "integration/replay/DW_WeaponInspect.h").read_bytes()
        ),
        owners=native,
        imports=imports,
        assets_manifest_sha256=sha((assets / "manifest.json").read_bytes()),
        assets_header_sha256=sha(header),
        package_bindings=len(manifest["packages"]),
        clip_count=manifest["animations"],
        reliable_transport=dict(
            command="dw_inspect",
            client_method=dict(
                rva=0x15E03E0,
                identity=imports["WIR_AddReliableCommand"],
                signature="void(void *, const char *)",
                bytes=96,
                sha256=sha(reliable_body),
                vtable_slot_rva=0x24F3A28,
            ),
            connection_rva=0xEE85570,
            connection_pointer_bytes=8,
            supported_local_client=0,
            connection_type_rva=0xEE85578,
            mp_connection_type=2,
            connected_helper=dict(
                rva=0x15BCD30,
                bytes=44,
                sha256=sha(connected_body),
                state=9,
                frontend_scene=36,
                stride=440,
            ),
            server_entry="DW_WeaponInspect_ServerRequest",
            player_state_identity_proof=dict(
                rva=0x1109030,
                bytes=361,
                sha256=sha(player_event_body),
                client_number=448,
            ),
            queue_slots=200,
            queue_identity="authenticated server playerState pointer and client number",
            queue_synchronization="nonblocking atomic lock; paired pointer and timestamp",
            button_transport=False,
            finish_cmd_buttons_replaced=False,
            local_prediction="native scripted state arrives in server snapshots",
        ),
        sprint_cancellation=dict(
            owner_rva=0x1128160,
            flag_temporarily_lifted=0x400,
            decision="actual native sprint state after PM_UpdateSprint",
            failed_attempt="restore only owned script flag; retain native side effects",
            eligibility_probes_replaced=False,
            native_input_stance_stamina_and_auto_sprint_rules_preserved=True,
        ),
        completion_policy=dict(
            native_process_state_rva=0x114FA30,
            native_idle_rva=0x113A3F0,
            retained_fields=["scriptAnimation", "scriptStartTime"],
            reason="Match native scripted completion and retain outgoing XAnim tree pose",
        ),
        layout=dict(
            command_bytes=264,
            command_buttons=0,
            command_server_time=12,
            command_weapon=36,
            weapon_bytes=60,
            pm_ps=8,
            pm_cmd=16,
            pm_oldcmd=280,
            pm_handler=840,
            pm_weapon_map=896,
            ps_script_index=1252,
            ps_client_number=448,
            ps_script_start=1256,
            ps_hand_base=1288,
            hand_bytes=80,
            weapon_time=1312,
            weapon_delay=1316,
            weapon_state=1328,
            script_flag_word=1800,
            script_flag=0x400,
            ads_fraction=1804,
            package_pointer=144,
            scripted_state=62,
            scripted_anim=70,
            scripted_node=380,
            netconststrings_type=16,
            request_expiry_ms=250,
        ),
        limitations=[
            "One hand only; alternate and akimbo are rejected",
            "Exact native package identity required; unmapped packages are rejected",
            "Remote clients observe reliable-command and snapshot latency before playback",
            "Server dispatcher must authenticate sender and validate entity/living state before ServerRequest",
        ],
        cpp_compiled=False,
        game_runs_performed=False,
    )
    return pe, catalog, functions, declarations, proof


def prepare(snapshot, assets, *, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assets = Path(assets).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not any(
        (snapshot.parent / name).exists()
        for name in (
            "client-readiness.json",
            "readiness.json",
            "local-readiness.json",
            "source-receipt.json",
        )
    )
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    relatives = [
        "source-units.json",
        "source-workstation/units.json",
        SOURCE,
        "src/DW_WeaponInspect.h",
        "src/DW_WeaponInspectBindings.h",
        "src/DW_WeaponInspect_Native.cpp",
        "src/DW_WeaponInspectAssets.h",
    ]
    for relative in relatives:
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    pe, catalog, functions, declarations, proof = inspect(snapshot, assets)
    from replay_owned_clone import assemble

    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from coff import read

    output = snapshot / "generated/weapon-inspect"
    output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    clone_sources, clones = [], []
    for rva, symbol, helper, signature, size, digest in OWNERS:
        source, clone = assemble(
            workspace,
            pe,
            catalog,
            functions[rva],
            helper,
            output,
            Path(r"C:\Program Files\LLVM\bin"),
            read,
            gs_unwind=proof["owners"][symbol]["unwind"],
        )
        assert clone["bytes"] == size
        clone_sources.append(source)
        clones.append(clone)
        for fixup in clone["external_fixups"]:
            proof["imports"][fixup["stable_id"]] = fixup["stable_id"]
    for name in ("DW_WeaponInspect.cpp", "DW_WeaponInspect.h"):
        (snapshot / "src" / name).write_bytes(
            (ROOT / "integration/replay" / name).read_bytes()
        )
    (snapshot / "src/DW_WeaponInspectAssets.h").write_bytes(
        (assets / "weapon-inspect-assets.h").read_bytes()
    )
    header = '#pragma once\n#include "DW_WeaponInspect.h"\nextern "C" {\n'
    (snapshot / "src/DW_WeaponInspectBindings.h").write_text(
        header + "\n".join(declarations) + "\n}\n"
    )
    (snapshot / "src/DW_WeaponInspect_Native.cpp").write_text("\n".join(clone_sources))
    association_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    associations = json.loads(association_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    retired_identity = functions[0x15B8050]["id"]
    retired = [
        row
        for row in associations["units"]
        if row["function_id"] == retired_identity and row.get("source") == SOURCE
    ]
    if retired:
        assert replace_owned and retired == [
            dict(
                source=SOURCE,
                symbol="DW_WeaponInspect_FinishButtons",
                function_id=retired_identity,
            )
        ]
        associations["units"] = [
            row
            for row in associations["units"]
            if row["function_id"] != retired_identity
        ]
        units["units"] = [
            row
            for row in units["units"]
            if row["function_id"] != retired_identity or row.get("source") != SOURCE
        ]
    digest = sha((snapshot / SOURCE).read_bytes())
    for rva, symbol, helper, signature, size, body_digest in OWNERS:
        identity = functions[rva]["id"]
        wanted = dict(source=SOURCE, symbol=symbol, function_id=identity)
        prior = [row for row in associations["units"] if row["function_id"] == identity]
        assert not prior or (
            replace_owned and prior == [wanted]
        ), "Different root owner"
        if not prior:
            associations["units"].append(wanted)
        prior = [row for row in units["units"] if row["function_id"] == identity]
        assert not prior or (replace_owned and prior[0]["source"] == SOURCE)
        units["units"] = [
            row for row in units["units"] if row["function_id"] != identity
        ]
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
    for symbol, identity in proof["imports"].items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [
            row for row in associations.get("imports", []) if row["symbol"] == symbol
        ]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof.update(
        source=SOURCE,
        source_sha256=digest,
        clones=clones,
        original_bodies_assembled=True,
        generator_sha256=sha(Path(__file__).read_bytes()),
        helper_tool_sha256=sha(INPUT_TOOL.read_bytes()),
        clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
    )
    proof["dependencies"] = {
        relative: sha((snapshot / relative).read_bytes()) for relative in relatives[2:]
    }
    (snapshot / "generated/weapon-inspect-integration.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    if args.inspect_only:
        result = inspect(
            args.snapshot.resolve(strict=True), args.assets.resolve(strict=True)
        )[4]
    else:
        result = prepare(args.snapshot, args.assets, replace_owned=args.replace_owned)
    print(json.dumps(result, indent=2) + "\n")
