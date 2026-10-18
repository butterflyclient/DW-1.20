"""Prepare an additive Replay Gulag NavMesh zone from audited real BFX resources.

Uses frozen workstation helpers and the original Replay loader offline. No game
process, existing zone, stock navigation asset, registration hook or deployment.
--format-fixture is explicitly non-production and never certifies real geometry.
"""

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
ACTS = Path(r"D:\mw124\atian-cod-tools\build-workstation\bin\Release\acts.exe")
ASSET_NAME = "maps/mp/dw_gulag.d3dbsp"
FOLLOW = 0xFFFFFFFFFFFFFFFE
REFERENCE = Path(
    r"D:\mw124\mw120rproxy\iw8-zonetool\src\zonetool\iw8\replay_navigation.cpp"
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def serialize_resource(payload, bounds, canonical_nav=None):
    # Reference EmitNavMesh/EmitRoot; every typed load is independently checked
    # against original Replay stream trace before a package becomes usable.
    payloads = payload if isinstance(payload, list) else [payload]
    minimum, maximum = bounds[:3], bounds[3:]
    half = [(maximum[i] - minimum[i]) / 2 for i in range(3)]
    mid = [(maximum[i] + minimum[i]) / 2 for i in range(3)]
    body = bytearray(struct.pack("<IIQIIQ", 0, 0, 0, 1, 0, FOLLOW))
    body.extend(struct.pack("<IIQ", 27, 0, FOLLOW))
    root = bytearray(168)
    exposure = 1
    if canonical_nav is not None:
        # These are map-global fields in Nav_ProcessPendingMeshes, not resource
        # bounds. Preserve the exact stock map values from its native export.
        half = canonical_nav["staticHalf"]
        mid = canonical_nav["staticMid"]
        exposure = canonical_nav["hasExposureData"]
    struct.pack_into("<QIII", root, 0, FOLLOW, 19, exposure, len(payloads))
    struct.pack_into("<Q", root, 24, FOLLOW)
    struct.pack_into("<3f", root, 144, *half)
    struct.pack_into("<3f", root, 156, *mid)
    root_at = len(body)
    body.extend(root)
    name = ASSET_NAME.encode("ascii") + b"\0"
    body.extend(name)
    virtual = 16 + len(name)
    virtual = (virtual + 7) & ~7
    record_at = len(body)
    for data in payloads:
        record = bytearray(112)
        struct.pack_into("<i", record, 4, -1)
        struct.pack_into("<I", record, 24, len(data))
        struct.pack_into("<Q", record, 96, FOLLOW)
        body.extend(record)
        virtual += 112
    payload_offsets = []
    for data in payloads:
        virtual = (virtual + 3) & ~3
        payload_offsets.append(len(body))
        body.extend(data)
        virtual += len(data)
    payload_at = payload_offsets[0]
    # The actual Replay Load_NavMeshDataPtr trace uses TEMP1 only. The
    # reference writer also reserves TEMP2 for its separate Preload/Postload
    # modes; this ordinary native Load package must match its exact high-water.
    streams = [0, 168, 0, 0, 0, virtual, 0, 0, 0, 0, 0]
    return (
        bytes(body),
        streams,
        dict(
            root_offset=root_at,
            resource_offset=record_at,
            payload_offset=payload_at,
            resource_count=len(payloads),
            payload_offsets=payload_offsets,
            root_bytes=168,
            resource_bytes=112,
            name=ASSET_NAME,
            type_id=27,
            model_index=-1,
            version=19,
        ),
    )


def native_owned_export(body, owner, begin, length):
    # Recover only bytes actually consumed by this asset's native Load_Stream
    # events; do not label a raw source slice as a loader-owned export.
    output = bytearray(length)
    coverage = bytearray(length)
    for span in owner["read_spans"]:
        start = span["archive_offset"]
        end = start + span["size"]
        low = max(start, begin)
        high = min(end, begin + length)
        if low >= high:
            continue
        for at in range(low, high):
            index = at - begin
            require(not coverage[index], "Native trace overlaps exported bytes")
            coverage[index] = 1
            output[index] = body[at]
    require(all(coverage), "Native trace did not consume the complete typed export")
    return bytes(output)


def render_header(packed, patch, empty_packed, empty_patch, proof):
    lines = [
        "#pragma once",
        '#include "DW_BotStyleScriptPackage.h"',
        "static_assert(sizeof(DWBotStyleScriptPackage)==96);",
        "namespace DWGulagNavPackage {",
    ]
    for name, data in [
        ("Fastfile", packed),
        ("Patch", patch),
        ("EmptyFastfile", empty_packed),
        ("EmptyPatch", empty_patch),
    ]:
        lines.append("inline const uint8_t " + name + "[] = {")
        lines.extend(
            "    " + ",".join(str(b) for b in data[i : i + 24]) + ","
            for i in range(0, len(data), 24)
        )
        lines.append("};")
    names = [
        row for row in proof["installation_manifest"] if row["name"].endswith(".ff")
    ]
    lines.append("inline const char *const InstallationNames[] = {")
    lines.extend("    " + json.dumps(row["name"][:-3]) + "," for row in names)
    lines.append("};")
    lines.append("inline const char *const InstallationDirectories[] = {")
    lines.extend("    " + json.dumps(row["directory"]) + "," for row in names)
    lines.append("};")
    lines.append(
        "inline const DWBotStyleScriptPackage Package = {"
        + json.dumps(proof["zone_name"])
        + ", Fastfile, sizeof(Fastfile), Patch, sizeof(Patch), EmptyFastfile, sizeof(EmptyFastfile), EmptyPatch, sizeof(EmptyPatch), InstallationNames, InstallationDirectories, sizeof(InstallationNames)/sizeof(*InstallationNames), 0};"
    )
    lines.append("}")
    return "\n".join(lines) + "\n"


def prepare(
    snapshot,
    resource,
    resource_report,
    output,
    format_fixture=False,
    canonical_nav=None,
):
    snapshot = Path(snapshot).resolve()
    output = Path(output).resolve()
    resources = [
        Path(path).resolve()
        for path in (resource if isinstance(resource, (list, tuple)) else [resource])
    ]
    reports = [
        Path(path).resolve()
        for path in (
            resource_report
            if isinstance(resource_report, (list, tuple))
            else [resource_report]
        )
    ]
    require(
        1 <= len(resources) <= 6 and len(resources) == len(reports),
        "Expected one to six resources with matching audit reports",
    )
    resource = resources[0]
    resource_report = reports[0]
    require(
        (snapshot / "tools/workstation_fastfiles.py").is_file(),
        "Frozen workstation helpers missing",
    )
    require(
        sha(IMAGE.read_bytes()) == IMAGE_SHA, "Original Replay image identity changed"
    )
    spec = importlib.util.spec_from_file_location(
        "gulag_bfx_validator", ROOT / "tools/generate-native-nav-resource.py"
    )
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    payloads = []
    audits = []
    validations = []
    geometry_inputs = []
    for path, report in zip(resources, reports):
        data = path.read_bytes()
        audit = json.loads(report.read_bytes())
        validation = validator.validate_resource(data)
        require(
            audit["resource_sha256"] == sha(data), "BFX report/resource hash mismatch"
        )
        require(
            audit.get("structural_validation") is True,
            "BFX structural validation absent",
        )
        if not format_fixture:
            provenance = audit.get("geometry_provenance", {})
            require(
                provenance.get("collision_complete") is True,
                "Real collision coverage must be explicitly audited complete",
            )
            require(
                not provenance.get("synthetic", False),
                "Synthetic geometry cannot become production navigation",
            )
            require(
                audit.get("research_candidate") is False,
                "Research candidates must be regenerated before production packaging",
            )
            require(
                audit.get("collision_fidelity", {}).get("sampled_checks_passed")
                is True,
                "BFX collision fidelity samples failed or absent",
            )
            require(
                audit.get("input") and Path(audit["input"]).is_file(),
                "Actual collision geometry input missing",
            )
            require(
                sha(Path(audit["input"]).read_bytes()) == audit["input_sha256"],
                "Collision input hash changed",
            )
            geometry = json.loads(Path(audit["input"]).read_bytes())
            require(
                geometry.get("collision_complete") is True
                and geometry.get("provenance") == provenance,
                "Collision audit does not describe the complete input geometry",
            )
        payloads.append(data)
        audits.append(audit)
        validations.append(validation)
        if audit.get("input") and Path(audit["input"]).is_file():
            geometry_path = Path(audit["input"]).resolve()
            require(
                file_sha(geometry_path) == audit["input_sha256"],
                "Collision input hash changed",
            )
            geometry_inputs.append(geometry_path)
    payload = payloads[0]
    audit = audits[0]
    validated = validations[0]
    canonical_data = None
    canonical_path = None
    canonical_sha = None
    canonical_source_files = []
    if canonical_nav is not None:
        canonical_path = Path(canonical_nav).resolve()
        canonical_raw = canonical_path.read_bytes()
        canonical_data = json.loads(canonical_raw)
        canonical_sha = sha(canonical_raw)
        require(
            canonical_data.get("asset") == "maps/mp/mp_donetsk.d3dbsp"
            and canonical_data.get("version") == 19,
            "Canonical map NavMesh identity/version mismatch",
        )
        require(
            canonical_data.get("native_export_complete") is True
            and canonical_data.get("native_export_failed") == 0,
            "Canonical stock navigation export is incomplete",
        )
        require(
            canonical_data.get("hasExposureData") in (0, 1)
            and len(canonical_data.get("staticHalf", [])) == 3
            and len(canonical_data.get("staticMid", [])) == 3,
            "Canonical map-global navigation fields are incomplete",
        )
        require(
            canonical_data.get("source_hashes")
            and all(
                len(row.get("sha256", "")) == 64
                for row in canonical_data["source_hashes"]
            ),
            "Canonical source FF/FP hashes are absent",
        )
        for entry in canonical_data["source_hashes"]:
            source_file = Path(entry["path"]).resolve()
            if source_file.exists():
                require(
                    file_sha(source_file) == entry["sha256"],
                    "Canonical source FF/FP hash changed",
                )
                canonical_source_files.append(source_file)
    require(
        format_fixture or canonical_data is not None,
        "Production requires pinned canonical mp_donetsk navigation metadata",
    )
    require(not output.exists(), "Package output must be a fresh directory")
    output.mkdir(parents=True)
    sys.path.insert(0, str(snapshot / "tools"))
    import workstation_fastfiles as ff
    import roundtrip_replay_fastfile as native_reader
    import workstation_trace_index as trace_index
    from workstation_trace_index import build_read_span_index
    import bot_style_paths as paths

    for module in (ff, native_reader, paths, trace_index):
        require(
            Path(module.__file__).resolve().is_relative_to(snapshot / "tools"),
            "Helper escaped frozen snapshot",
        )
    import pefile

    original = pefile.PE(str(IMAGE), fast_load=True)
    callback = struct.unpack("<Q", original.get_data(0x23FCFF0 + 27 * 8, 8))[0]
    require(callback == 0x140F5F020, "Replay XAsset27 registration callback differs")
    thunk = original.get_data(callback - original.OPTIONAL_HEADER.ImageBase, 5)
    require(
        thunk[0] == 0xE9
        and callback + 5 + struct.unpack_from("<i", thunk, 1)[0] == 0x1410E9750,
        "Replay NavMesh registration thunk no longer targets Nav_AddPendingMesh",
    )
    loaders = []
    for name, address, size in [
        ("Load_NavMeshData", 5383243920, 1412),
        ("Load_NavMeshDataPtr", 5383245344, 239),
        ("Load_nav_resource_s", 5383262976, 206),
        ("Nav_AddPendingMesh", 0x1410E9750, 209),
        ("Nav_ProcessPendingMeshes", 0x1410EB7D0, 854),
    ]:
        rva = address - original.OPTIONAL_HEADER.ImageBase
        loaders.append(
            dict(
                name=name,
                original_rva=rva,
                bytes=size,
                sha256=sha(original.get_data(rva, size)),
            )
        )
    bounds = [min(row["bounds"][i] for row in validations) for i in range(3)] + [
        max(row["bounds"][i] for row in validations) for i in range(3, 6)
    ]
    body, streams, layout = serialize_resource(payloads, bounds, canonical_data)
    packed = ff.pack_replay_uncompressed(body, streams)
    require(
        ff.unpack_replay_uncompressed(packed) == body, "FF physical roundtrip differs"
    )
    template = bytearray(0x148)
    template[:8] = b"IWffd100"
    struct.pack_into("<II", template, 8, 6, 4)
    patch = ff.make_replay_header_only_patch(bytes(template), packed)
    empty_body = bytes(32)
    empty_packed = ff.pack_replay_uncompressed(empty_body, [0] * 11)
    empty_patch = ff.make_replay_header_only_patch(bytes(template), empty_packed)
    bundle_hash = sha(packed + patch + empty_packed + empty_patch)
    zone = (
        "dw_gulag_nav_fixture_" if format_fixture else "dw_gulag_nav_"
    ) + bundle_hash[:16]
    (output / (zone + ".ff")).write_bytes(packed)
    (output / (zone + ".fp")).write_bytes(patch)
    native = native_reader.verify_native(
        output / (zone + ".ff"),
        body,
        output / (zone + ".ff"),
        ACTS,
        IMAGE,
        output / "native-reread",
        60,
        trace=True,
    )
    manifest = Path(native["manifest_path"])
    index = build_read_span_index(
        manifest.parent / "stream-trace.jsonl", manifest, len(body)
    )
    journal = [
        json.loads(line)
        for line in (manifest.parent / "assets.jsonl").read_text().splitlines()
        if line.strip()
    ]
    require(
        [(row["type_id"], row["name"]) for row in journal] == [(27, ASSET_NAME)],
        "Native asset identities differ from additive-only recipe",
    )
    require(len(index["assets"]) == 1, "Unexpected native assets")
    owner = index["assets"][0]
    root_export = native_owned_export(body, owner, layout["root_offset"], 168)
    record_export = native_owned_export(
        body, owner, layout["resource_offset"], 112 * len(payloads)
    )
    exports = [
        native_owned_export(body, owner, at, len(data))
        for at, data in zip(layout["payload_offsets"], payloads)
    ]
    payload_export = exports[0]
    require(
        struct.unpack_from("<III", root_export, 8)
        == (
            19,
            canonical_data["hasExposureData"] if canonical_data else 1,
            len(payloads),
        ),
        "Native NavMesh scalar layout differs",
    )
    for i, (data, export) in enumerate(zip(payloads, exports)):
        require(
            struct.unpack_from("<i", record_export, i * 112 + 4)[0] == -1
            and struct.unpack_from("<I", record_export, i * 112 + 24)[0] == len(data),
            "Native resource scalar layout differs",
        )
        require(export == data, "Native trace-owned BFX payload differs")
    require(
        not native["trace_summary"]["packed_target_stream_counts"],
        "Unexpected packed stream aliases",
    )
    actual = index["max_destination_offsets"]
    require(
        all(streams[i] == actual.get(i, 0) for i in range(11)),
        f"Native exact reservation mismatch: declared{streams}, actual{actual}",
    )
    policy = paths.derive(snapshot)
    prefixes = sorted(
        set(["techsets", "srv", *policy["regions"], *policy["supported_languages"]])
    )
    installation = []
    for name, companion in [(zone, False)] + [
        (prefix + "_" + zone, True) for prefix in prefixes
    ]:
        directory = paths.directory_for_name(name, zone, policy)
        for suffix, data in [
            (".ff", empty_packed if companion else packed),
            (".fp", empty_patch if companion else patch),
        ]:
            target = output / (name + suffix)
            target.write_bytes(data)
            installation.append(
                dict(
                    name=target.name,
                    source=str(target),
                    sha256=sha(data),
                    size=len(data),
                    companion=companion,
                    directory=directory,
                    relative_path=(directory + "/" if directory else "") + target.name,
                )
            )
    empty_file = output / (prefixes[0] + "_" + zone + ".ff")
    empty_native = native_reader.verify_native(
        empty_file,
        empty_body,
        empty_file,
        ACTS,
        IMAGE,
        output / "native-empty-reread",
        60,
        trace=True,
    )
    require(
        empty_native["manifest"]["top_level_index"] == 0,
        "Companion unexpectedly owns assets",
    )
    proof = dict(
        schema="replay120-additive-gulag-nav-package-v1",
        zone_name=zone,
        asset_name=ASSET_NAME,
        asset_type=27,
        original_image_sha256=IMAGE_SHA,
        native_loader_evidence=loaders,
        navmesh_registration_callback_table_rva=0x23FCFF0,
        resource_sha256=sha(payload),
        resource_report=str(resource_report),
        resource_report_sha256=sha(resource_report.read_bytes()),
        resource_validation=validated,
        geometry_provenance=audit.get("geometry_provenance"),
        synthetic_format_fixture=bool(format_fixture),
        production_ready=not format_fixture,
        resources=[
            dict(
                path=str(path),
                report=str(report),
                sha256=sha(data),
                report_sha256=sha(report.read_bytes()),
                validation=validation,
                native_owned_payload_sha256=sha(export),
            )
            for path, report, data, validation, export in zip(
                resources, reports, payloads, validations, exports
            )
        ],
        native_reader=native,
        native_empty_reader=empty_native,
        layout=layout,
        stream_reservations=streams,
        native_destination_high_water=actual,
        native_owned_exports=dict(
            root_sha256=sha(root_export),
            resource_sha256=sha(record_export),
            payload_sha256=sha(payload_export),
        ),
        installation_manifest=installation,
        native_locale_policy=policy,
        native_locale_codes=policy,
        native_folder_rules=policy["installation_folder_rules"],
        resource_bundle_sha256=bundle_hash,
        source_inputs=[
            dict(path=str(path), bytes=path.stat().st_size, sha256=file_sha(path))
            for path in (
                *resources,
                *reports,
                *geometry_inputs,
                *canonical_source_files,
                IMAGE,
                ACTS,
                REFERENCE,
                ROOT / "tools/generate-native-nav-resource.py",
                Path(ff.__file__),
                Path(native_reader.__file__),
                Path(paths.__file__),
                Path(trace_index.__file__),
                *([canonical_path] if canonical_path else []),
            )
        ],
        body_sha256=sha(body),
        fastfile_sha256=sha(packed),
        patch_sha256=sha(patch),
        native_registration_contract=dict(
            must_load_before_exact_zone="mp_donetsk",
            pending_queue_capacity=4,
            total_resource_capacity=128,
            stock_root_must_supply_final_global_bounds_and_exposure=True,
            root_bounds_scope=(
                "pinned canonical stock map globals"
                if canonical_data
                else "synthetic fixture graph bounds"
            ),
            only_exact_map_anchor=True,
            ordinary_native_registration=True,
        ),
        existing_asset_replacements=[],
        stock_navmesh_preserved=True,
        stock_aipaths_preserved=True,
        stock_tacgraph_preserved=True,
        canonical_nav_metadata=(
            None
            if canonical_data is None
            else dict(
                path=str(canonical_path), sha256=canonical_sha, values=canonical_data
            )
        ),
        serializer_reference=dict(
            path=str(REFERENCE),
            sha256=sha(REFERENCE.read_bytes()),
            function="EmitNavMesh/EmitRoot",
        ),
        game_modified=False,
        deployed=False,
        runtime_gulag_tested=False,
    )
    header = render_header(packed, patch, empty_packed, empty_patch, proof)
    header_path = output / "DW_GulagNavPackage.h"
    header_path.write_bytes(header.encode("ascii"))
    if not format_fixture:
        (snapshot / "src/DW_GulagNavPackage.h").write_bytes(header.encode("ascii"))
    proof["header"] = str(header_path)
    proof["header_sha256"] = sha(header.encode("ascii"))
    (output / "package-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    (output / "native-export.bfx").write_bytes(payload_export)
    for i, export in enumerate(exports):
        (output / f"native-export-{i}.bfx").write_bytes(export)
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--resource", type=Path, required=True, action="append")
    parser.add_argument("--resource-report", type=Path, required=True, action="append")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format-fixture", action="store_true")
    parser.add_argument("--canonical-nav", type=Path)
    args = parser.parse_args()
    result = prepare(
        args.snapshot,
        args.resource,
        args.resource_report,
        args.output,
        args.format_fixture,
        args.canonical_nav,
    )
    print(
        json.dumps(
            dict(
                zone=result["zone_name"],
                production_ready=result["production_ready"],
                streams=result["stream_reservations"],
            ),
            indent=2,
        )
    )
