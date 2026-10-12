"""Bind profile receiver ownership to original Replay client count and table."""

import hashlib
import json
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
TARGET = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
MARKER = "// BEGIN DW native profile ownership\n"
HEADER = r"""// BEGIN DW native profile ownership
#include "sv_host_scale.h"

// Complete SvClientMP allocation. Only target-proven ownership fields are named.
struct DWBotNativeClient
{
    uint8_t opaque0[280];
    HostScale::Entity *entity;
    uint8_t opaque288[214468];
    int32_t clientType;
    uint8_t opaque214760[106432];
};
static_assert(sizeof(DWBotNativeClient) == 321192);
static_assert(offsetof(DWBotNativeClient, entity) == 280);
static_assert(offsetof(DWBotNativeClient, clientType) == 214756);
extern "C"
{
    extern uint32_t DW_Bot_ClientCount;
    extern DWBotNativeClient *DW_Bot_Clients[200];
}

inline DWBotNativeClient *DWBot_CurrentNativeClient(unsigned slot)
{
    if (DW_Bot_ClientCount > 200 || slot >= DW_Bot_ClientCount)
        return nullptr;
    auto *client = DW_Bot_Clients[slot];
    return client && client->clientType == 2 ? client : nullptr;
}

inline bool DWBot_IsCurrentEntity(unsigned slot, const HostScale::Entity *entity)
{
    const auto *client = DWBot_CurrentNativeClient(slot);
    return client && entity && client->entity == entity && entity->number == int(slot) &&
        entity->client && HostScale::Field<int32_t>(entity->client, 448) == int(slot);
}
// END DW native profile ownership
"""


def configure(snapshot):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not (snapshot.parent / "client-readiness.json").exists(), "Finished snapshot"
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    raw = IMAGE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == TARGET == catalog["image_sha256"]
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    by_id = {
        row["id"]: row for row in catalog["functions"] if not row.get("quarantined")
    }
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    evidence = []

    def body(identity, expected):
        row = by_id[identity]
        ranges = []
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            owner = entry
            while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
                owner = owner.unwindinfo._chained_entry
            if owner.struct.BeginAddress == row["rva"]:
                ranges.append((entry.struct.BeginAddress, entry.struct.EndAddress))
        ranges.sort()
        assert ranges and all(a[1] == b[0] for a, b in zip(ranges, ranges[1:]))
        code = pe.get_data(ranges[0][0], ranges[-1][1] - ranges[0][0])
        assert hashlib.sha256(code).hexdigest() == expected
        instructions = list(decoder.disasm(code, base + row["rva"]))
        assert sum(item.size for item in instructions) == len(code)
        evidence.append(
            dict(identity=identity, rva=row["rva"], bytes=len(code), sha256=expected)
        )
        return instructions

    bot = body(
        "fn_28e18c92d4d58671",
        "b1898a14441e3a2cc3fc5b970f9419a26e6c3ecde7bf79e80ed5a88a0efb5774",
    )
    apply = body(
        "fn_4a270f7cad270ed9",
        "57c5e7f6bcee351a0ec1c5e2bb84b35c99054eb216e255204068cf11e0bd127a",
    )
    assert any(
        row.mnemonic == "cmp" and row.op_str == "dword ptr [rcx + 0x346e4], 2"
        for row in bot
    )

    def rip(rows, mnemonic, prefix):
        values = {
            row.address + row.size + operand.mem.disp
            for row in rows
            if row.mnemonic == mnemonic and row.op_str.startswith(prefix)
            for operand in row.operands
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
        }
        assert len(values) == 1
        return values.pop()

    addresses = {
        "DW_Bot_Clients": rip(bot, "lea", "rcx,"),
        "DW_Bot_ClientCount": rip(apply, "cmp", "dword ptr [rip"),
    }
    assert addresses["DW_Bot_Clients"] == rip(apply, "lea", "r15,")
    path = snapshot / "source-units.json"
    units = json.loads(path.read_bytes())
    imports = []
    for alias, address in addresses.items():
        rows = [
            row
            for row in catalog["symbols"]
            if row["rva"] == address - base
            and row.get("kind") == "data-address"
            and not row.get("quarantined")
        ]
        assert len(rows) == 1
        imported = dict(symbol=alias, symbol_id=rows[0]["id"])
        old = [row for row in units.setdefault("imports", []) if row["symbol"] == alias]
        assert not old or old == [imported]
        if not old:
            units["imports"].append(imported)
        imports.append(
            dict(name=alias, identity=rows[0]["id"], original_rva=address - base)
        )
    path.write_text(json.dumps(units, indent=2) + "\n")
    header_path = snapshot / "src/DW_BotBindings.h"
    original = header_path.read_text().split(MARKER, 1)[0]
    header_path.write_text(original + HEADER)
    result = dict(
        passed=True,
        image_sha256=TARGET,
        original_instructions=evidence,
        imports=imports,
        header="src/DW_BotBindings.h",
        header_sha256=hashlib.sha256(header_path.read_bytes()).hexdigest(),
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        validates_actual_client_count=True,
        validates_current_entity=True,
        requires_playing=False,
        game_run_performed=False,
    )
    (snapshot / "generated/bot-profile-ownership.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    return result
