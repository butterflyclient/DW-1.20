"""Bind native killcam capture/composition to the pinned Replay renderer."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_R14, X86_REG_RCX, X86_REG_RIP
import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_owned_clone import assemble

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
SOURCE = "src/DW_AltKillcamRender.cpp"
LLVM = Path("C:/Program Files/LLVM/bin")

HEADER = r"""#pragma once
#include "DW_AltKillcamRender.h"
#include <stddef.h>

namespace DWAltKillcamNative
{
// Complete target RT pool record. Its image starts at24; remaining image and
// RT tracking fields retain their exact storage without invented semantics.
struct SurfaceRecord
{
    uint8_t opaque0[12];
    uint32_t externalFlags;
    uint32_t internalFlags;
    uint8_t opaque20[4];
    const char *imageName;
    uint8_t opaque32[8];
    uint32_t textureId;
    uint32_t format;
    uint8_t opaque48[12];
    uint16_t width;
    uint16_t height;
    uint8_t opaque64[440];
    void *Image() { return reinterpret_cast<uint8_t *>(this) + 24; }
};
static_assert(sizeof(SurfaceRecord) == 504);
static_assert(offsetof(SurfaceRecord, internalFlags) == 16);
static_assert(offsetof(SurfaceRecord, textureId) == 40);
static_assert(offsetof(SurfaceRecord, width) == 60);

struct TargetGroup
{
    uint8_t count;
    uint8_t opaque1;
    uint16_t colors[4];
    uint16_t depth;
    uint16_t opaque12;
};
static_assert(sizeof(TargetGroup) == 14);

// Complete native CmdBufSource allocation, initialized with memset0x2d60.
struct SourceState
{
    uint8_t opaque0[7920];
    void *inputImage;
    uint8_t opaque7928[3516];
    DWAltKillcamViewport viewport;
    uint8_t opaque11460[52];
    int32_t targetWidth;
    int32_t targetHeight;
    uint8_t opaque11520[96];
};
static_assert(sizeof(SourceState) == 11616);
static_assert(offsetof(SourceState, inputImage) == 7920);
static_assert(offsetof(SourceState, viewport) == 11444);

struct Context
{
    SourceState *source;
    void *state;
};
static_assert(sizeof(Context) == 16);

struct ViewInfo
{
    uint8_t opaque0[1200];
    DWAltKillcamViewport displayViewport;
    uint8_t opaque1216[10376];
    void *backend;
    uint32_t viewIndex;
    uint32_t localClient;
    uint8_t opaque11608[12120];
};
static_assert(sizeof(ViewInfo) == 23728);
static_assert(offsetof(ViewInfo, localClient) == 11604);
static_assert(offsetof(ViewInfo, backend) == 11592);
static_assert(offsetof(ViewInfo, viewIndex) == 11600);

// Exact88-byte field window consumed by the complete final task callback.
// Other task consumers may have a larger record; this is not a replacement.
struct FinalTaskInfo
{
    uint8_t opaque0[48];
    TargetGroup targets;
    uint8_t opaque62[18];
    const uint16_t *attachments;
};
static_assert(sizeof(FinalTaskInfo) == 88);
static_assert(offsetof(FinalTaskInfo, targets) == 48);
static_assert(offsetof(FinalTaskInfo, attachments) == 80);

extern "C"
{
extern SurfaceRecord *AKR_SurfacePool;
extern void *AKR_GraphScriptDvar;
extern uint8_t AKR_ImmediateQueue[];
extern void *AKR_CopyMaterial;
uint16_t *AKR_Create(uint16_t *, int32_t, uint32_t, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    const float *, uint32_t, const char *, uint16_t, void *, uint64_t, void *);
void AKR_Transition(void *, uint16_t, int32_t, uint32_t, uint32_t, uint32_t);
void AKR_FlushTransitions(void *);
void AKR_CopyBoundColor(Context *, void *, float, float, float, float);
void AKR_DrawRectangle(Context *, void *, int32_t, const DWAltKillcamViewport *,
    float, float, float, float, float, float, float, float);
void AKR_SetSourceViewport(SourceState *, const DWAltKillcamViewport *);
void AKR_SetViewportScissor(void *, const DWAltKillcamViewport *,
    const DWAltKillcamViewport *);
void AKR_DestroyPermanent(uint16_t);
void AKR_LockImmediate();
void AKR_UnlockImmediate();
uint64_t AKR_FlushImmediate();
void AKR_WaitFence(const uint64_t *, void *);
void AKR_SyncRenderThread();
float AKR_ResolutionScale();
void AKR_ClearTargets(void *, uint8_t, uint8_t);
void AKR_PostfxConstants(Context *, ViewInfo *, void *, bool, bool, bool, bool);
uint64_t AKR_PostfxApply(Context *, ViewInfo *, const DWAltKillcamViewport *,
    uint16_t, uint16_t, const uint16_t *, uint16_t, uint16_t);
uint64_t AKR_FinalCompositeNative(Context *, const FinalTaskInfo *, ViewInfo *, void *);
uint64_t AKR_DestroyGlobalTargetsNative();
}
}
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect_native(snapshot):
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    assert catalog["image_sha256"] == IMAGE_SHA
    raw = IMAGE.read_bytes()
    assert sha(raw) == IMAGE_SHA
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    by_id = {
        row["id"]: row for row in catalog["functions"] + catalog.get("symbols", [])
    }
    by_rva = {row["rva"]: row for row in catalog.get("symbols", [])}
    expected = json.loads((ROOT / "tools/alt_killcam_render_native.json").read_bytes())
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    bodies, native = {}, {}
    for role, binding in expected.items():
        row = by_id[binding["id"]]
        assert not row.get("quarantined")
        ranges = []
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            owner = entry
            while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
                owner = owner.unwindinfo._chained_entry
            if owner.struct.BeginAddress == row["rva"]:
                ranges.append((entry.struct.BeginAddress, entry.struct.EndAddress))
        ranges.sort()
        assert not ranges or all(a[1] == b[0] for a, b in zip(ranges, ranges[1:]))
        code = b"".join(pe.get_data(begin, end - begin) for begin, end in ranges)
        if not ranges:
            code = pe.get_data(row["rva"], binding["bytes"])
        assert len(code) == binding["bytes"] and sha(code) == binding["sha256"], role
        bodies[role] = list(decoder.disasm(code, base + row["rva"]))
        assert sum(instruction.size for instruction in bodies[role]) == len(code)
        native[role] = dict(
            binding, rva=row["rva"], ranges=[list(pair) for pair in ranges]
        )
        if role == "final":
            entry = next(
                entry
                for entry in pe.DIRECTORY_ENTRY_EXCEPTION
                if entry.struct.BeginAddress == row["rva"]
            )
            unwind_rva = entry.struct.UnwindData
            header = pe.get_data(unwind_rva, 4)
            header_size = 4 + ((header[2] + 1) & ~1) * 2
            blob = pe.get_data(unwind_rva, header_size + 8)
            assert header[0] >> 3 == 3
            handler = by_id["fn_3da1e16560231243"]
            assert struct.unpack_from("<I", blob, header_size)[0] == handler["rva"]
            assert (
                sha(pe.get_data(handler["rva"], 29))
                == "53989c4a3df823fa742c0bebda04d4729c810916a7f81899cc2b885ae9c8997c"
            )
            assert struct.unpack_from("<I", blob, header_size + 4)[0] == 128
            native[role]["unwind"] = [
                dict(
                    begin=entry.struct.BeginAddress,
                    end=entry.struct.EndAddress,
                    unwind_rva=unwind_rva,
                    bytes=blob.hex(),
                )
            ]
        elif role == "reset":
            records = []
            for begin, end in ranges:
                entry = next(
                    entry
                    for entry in pe.DIRECTORY_ENTRY_EXCEPTION
                    if entry.struct.BeginAddress == begin
                    and entry.struct.EndAddress == end
                )
                unwind_rva = entry.struct.UnwindData
                header = pe.get_data(unwind_rva, 4)
                flags = header[0] >> 3
                assert flags == (0 if not records else 4)
                size = 4 + ((header[2] + 1) & ~1) * 2 + (12 if flags == 4 else 0)
                records.append(
                    dict(
                        begin=begin,
                        end=end,
                        unwind_rva=unwind_rva,
                        bytes=pe.get_data(unwind_rva, size).hex(),
                    )
                )
            native[role]["unwind"] = records

    def rip_targets(role, mnemonic=None, destination=None):
        found = []
        for instruction in bodies[role]:
            if mnemonic and instruction.mnemonic != mnemonic:
                continue
            if destination and not instruction.op_str.startswith(destination + ","):
                continue
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    found.append(
                        (
                            instruction.address,
                            instruction.address
                            + instruction.size
                            + operand.mem.disp
                            - base,
                        )
                    )
        return found

    def has_offset(role, offset):
        return any(
            operand.type == X86_OP_MEM and operand.mem.disp == offset
            for instruction in bodies[role]
            for operand in instruction.operands
        )

    assert has_offset("bufferInitialization", 33256)
    # Native TLS recursion counters use a register carrying 0x190, rather than
    # an immediate memory displacement. Keep this assertion faithful to both
    # complete, hash-bound target bodies.
    assert all(
        any(
            operand.type == X86_OP_IMM and operand.imm == 400
            for instruction in bodies[role]
            for operand in instruction.operands
        )
        for role in ("lockRecursionEnter", "lockRecursionLeave")
    )
    assert all(has_offset("viewSetup", offset) for offset in (11592, 11604, 1200))
    assert all(
        has_offset("viewConstruction", offset)
        for offset in (33264, 33288, 11600, 11604)
    )
    assert has_offset("AKR_SetSourceViewport", 11444)
    assert all(has_offset("AKR_SetViewportScissor", offset) for offset in (4348, 4364))
    assert any(
        "0x2d60" in instruction.op_str for instruction in bodies["sourceInitialization"]
    )
    # The complete ordinary graph options builder keeps the input features in
    # RCX/R14 and reads only these four fields. Viewport type at0 participates
    # in camera history; changing it cannot select the offscreen graph.
    feature_offsets = {
        operand.mem.disp
        for instruction in bodies["graphOptions"]
        for operand in instruction.operands
        if operand.type == X86_OP_MEM and operand.mem.base in (X86_REG_RCX, X86_REG_R14)
    }
    assert feature_offsets == {24, 28, 40, 44}, feature_offsets
    table_calls = [
        operand.mem.disp
        for instruction in bodies["graphScriptSelection"]
        if instruction.mnemonic == "call"
        for operand in instruction.operands
        if operand.type == X86_OP_MEM and operand.mem.disp > 0
    ]
    assert len(table_calls) == 1
    graph_table = table_calls[0]
    assert struct.unpack("<QQ", pe.get_data(graph_table + 16, 16)) == (
        base + native["graphViewWrapper"]["rva"],
        base + native["graphOptions"]["rva"],
    )
    assert any(
        instruction.mnemonic == "call"
        and instruction.op_str == hex(base + native["graphFinalTask"]["rva"])
        for instruction in bodies["graphViewCommon"]
    )
    assert set(pair[1] for pair in rip_targets("graphFinalTask", "mov", "edx")) & set(
        pair[1] for pair in rip_targets("taskRegistration")
    )

    pools = rip_targets("AKR_Transition", "add", "rcx")
    queues = rip_targets("AKR_FlushImmediate", "lea", "rcx")
    materials = rip_targets("blur", "mov", "rdx")
    assert len(pools) == len(queues) == 1
    full_copy = next(
        row for row in catalog["functions"] if row["id"] == "fn_68556fe0b64c4a4c"
    )
    copy_calls = [
        instruction
        for instruction in bodies["blur"]
        if instruction.mnemonic == "call"
        and instruction.op_str == hex(base + full_copy["rva"])
    ]
    assert len(copy_calls) == 1
    material = max((pair for pair in materials if pair[0] < copy_calls[0].address))
    imports = {
        name: row["id"] for name, row in native.items() if name.startswith("AKR_")
    }
    derived = {}
    for alias, pair in (
        ("AKR_SurfacePool", pools[0]),
        ("AKR_ImmediateQueue", queues[0]),
        ("AKR_CopyMaterial", material),
        ("AKR_GraphScriptDvar", rip_targets("graphSelection", "mov", "rax")[-2]),
    ):
        row = by_rva[pair[1]]
        assert not row.get("quarantined")
        imports[alias] = row["id"]
        derived[alias] = dict(
            identity=row["id"], rva=row["rva"], instruction_rva=pair[0] - base
        )
    return pe, catalog, native, imports, derived


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not (snapshot.parent / "client-readiness.json").exists()
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from coff import read

    pe, catalog, native, imports, derived = inspect_native(snapshot)
    output = snapshot / "generated/alt-killcam-render"
    output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    clones, clone_source = [], []
    by_id = {row["id"]: row for row in catalog["functions"]}
    owners = (
        ("final", "DW_AltKillcamRender_FinalComposite", "AKR_FinalCompositeNative"),
        (
            "reset",
            "DW_AltKillcamRender_DestroyGlobalTargets",
            "AKR_DestroyGlobalTargetsNative",
        ),
    )
    for role, symbol, helper in owners:
        source, proof = assemble(
            workspace,
            pe,
            catalog,
            by_id[native[role]["id"]],
            helper,
            output,
            LLVM,
            read,
            gs_unwind=native[role].get("unwind"),
        )
        assert proof["bytes"] == native[role]["bytes"]
        clones.append(proof)
        clone_source.append(source)
        for fixup in proof["external_fixups"]:
            imports[fixup["stable_id"]] = fixup["stable_id"]

    for name in (
        "DW_AltKillcamRender.cpp",
        "DW_AltKillcamRender.h",
    ):
        (snapshot / "src" / name).write_bytes(
            (ROOT / "integration/replay" / name).read_bytes()
        )
    (snapshot / "src/DW_AltKillcamRenderBindings.h").write_text(HEADER)
    (snapshot / "src/DW_AltKillcamRender_Native.cpp").write_text(
        "\n".join(clone_source)
    )
    association_path = snapshot / "source-units.json"
    unit_path = snapshot / "source-workstation/units.json"
    assert association_path.stat().st_nlink == unit_path.stat().st_nlink == 1
    associations = json.loads(association_path.read_bytes())
    units = json.loads(unit_path.read_bytes())
    digest = sha((snapshot / SOURCE).read_bytes())
    for role, symbol, helper in owners:
        identity = native[role]["id"]
        expected = dict(source=SOURCE, symbol=symbol, function_id=identity)
        prior = [row for row in associations["units"] if row["function_id"] == identity]
        assert not prior or (
            replace_owned and prior == [expected]
        ), "Different native owner"
        if not prior:
            associations["units"].append(expected)
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
    for symbol, identity in imports.items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [
            row for row in associations.get("imports", []) if row["symbol"] == symbol
        ]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    unit_path.write_text(json.dumps(units, indent=2) + "\n")
    dependencies = {
        str(path.relative_to(snapshot)): sha(path.read_bytes())
        for path in (
            snapshot / SOURCE,
            snapshot / "src/DW_AltKillcamRender.h",
            snapshot / "src/DW_AltKillcamRenderBindings.h",
            snapshot / "src/DW_AltKillcamRender_Native.cpp",
        )
    }
    proof = dict(
        schema=1,
        passed=True,
        image_sha256=IMAGE_SHA,
        source=SOURCE,
        source_sha256=digest,
        native=native,
        derived_globals=derived,
        imports=imports,
        clones=clones,
        dependencies=dependencies,
        generator_sha256=sha(Path(__file__).read_bytes()),
        clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
        reference_sha256=sha(
            (ROOT / "tools/alt_killcam_render_reference.cpp").read_bytes()
        ),
        binding_table_sha256=sha(
            (ROOT / "tools/alt_killcam_render_native.json").read_bytes()
        ),
        layout_proof=dict(
            surface_stride=504,
            surface_count=4096,
            source_bytes=11616,
            view_bytes=23728,
            context_bytes=16,
            target_group_bytes=14,
            backend_frame_count=33256,
            backend_view_index=33264,
            backend_views=33288,
            view_backend=11592,
            view_index=11600,
            view_local_client=11604,
            source_input_image=7920,
            source_viewport=11444,
            state_viewport=4348,
            state_scissor=4364,
            state_target_group=4380,
        ),
        retained_capture_contract=dict(
            phase=3,
            token="last successful object capture in the same local killcam",
            validation="current stamped backend, view, frame, local, generation and owned RT",
            invalidation=["disarm", "reset", "resize", "missing stamp", "identity mismatch", "new object"],
            frontend_capture_reads=False,
        ),
        game_run_performed=False,
        full_engine_build_performed=False,
    )
    (snapshot / "generated/alt-killcam-render-integration.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
