"""Recheck a frozen additive Gulag zone proof; no game operations."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_geometry_audit(audit, source_inputs):
    geometry = Path(audit["input"]).resolve()
    assert (
        file_digest(geometry) == audit["input_sha256"]
    ), "Collision input hash changed"
    tracked = [row for row in source_inputs if Path(row["path"]).resolve() == geometry]
    assert tracked and all(
        row["sha256"] == audit["input_sha256"] for row in tracked
    ), "Geometry input absent from frozen sources"


def stale_geometry_negative(proof, output):
    entry = proof["resources"][0]
    original_audit = json.loads(Path(entry["report"]).read_bytes())
    original_geometry = Path(original_audit["input"]).read_bytes()
    with tempfile.TemporaryDirectory(
        prefix="gulag-stale-", dir=output.parent
    ) as temporary:
        geometry = Path(temporary) / "geometry.json"
        geometry.write_bytes(original_geometry)
        audit = dict(
            original_audit, input=str(geometry), input_sha256=digest(original_geometry)
        )
        sources = [dict(path=str(geometry), sha256=digest(original_geometry))]
        verify_geometry_audit(audit, sources)
        rejected = []
        for name in ("changed_geometry", "missing_source_binding"):
            geometry.write_bytes(
                original_geometry + b" "
                if name == "changed_geometry"
                else original_geometry
            )
            try:
                verify_geometry_audit(
                    audit, sources if name == "changed_geometry" else []
                )
            except AssertionError:
                rejected.append(name)
        assert len(rejected) == 2
    result = dict(
        passed=True,
        existing_package_proof_sha256=digest(
            json.dumps(proof, sort_keys=True).encode()
        ),
        package_rebuilt=False,
        baseline_geometry_guard_passed=True,
        rejected_cases=rejected,
        game_execution=False,
    )
    output.write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-format-fixture", action="store_true")
    parser.add_argument("--stale-geometry-negative", action="store_true")
    args = parser.parse_args()
    proof = json.loads(args.proof.read_bytes())
    if args.stale_geometry_negative:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        stale_geometry_negative(proof, args.output)
        print(
            "PASS existing-package geometry guard rejects stale or untracked geometry"
        )
        return
    assert (
        proof["asset_name"] == "maps/mp/dw_gulag.d3dbsp" and proof["asset_type"] == 27
    )
    assert proof["existing_asset_replacements"] == []
    assert (
        proof["stock_navmesh_preserved"]
        and proof["stock_aipaths_preserved"]
        and proof["stock_tacgraph_preserved"]
    )
    assert (
        not proof["game_modified"]
        and not proof["deployed"]
        and not proof["runtime_gulag_tested"]
    )
    assert (
        args.allow_format_fixture
        or proof["production_ready"]
        and not proof["synthetic_format_fixture"]
    )
    for source in proof["source_inputs"]:
        assert (
            Path(source["path"]).stat().st_size == source["bytes"]
            and file_digest(source["path"]) == source["sha256"]
        ), source["path"]
    assert digest(Path(proof["header"]).read_bytes()) == proof["header_sha256"]
    helpers = next(
        Path(row["path"]).parent
        for row in proof["source_inputs"]
        if Path(row["path"]).name == "workstation_fastfiles.py"
    )
    sys.path.insert(0, str(helpers))
    from workstation_fastfiles import unpack_replay_uncompressed
    from workstation_trace_index import build_read_span_index

    installation = proof["installation_manifest"]
    assert len(installation) == 20
    main_ff = next(
        row
        for row in installation
        if not row["companion"] and row["name"].endswith(".ff")
    )
    main_fp = next(
        row
        for row in installation
        if not row["companion"] and row["name"].endswith(".fp")
    )
    empty_ff = next(
        row for row in installation if row["companion"] and row["name"].endswith(".ff")
    )
    empty_fp = next(
        row for row in installation if row["companion"] and row["name"].endswith(".fp")
    )
    for row in installation:
        data = Path(row["source"]).read_bytes()
        assert len(data) == row["size"] and digest(data) == row["sha256"]
        assert (
            row["relative_path"]
            == (row["directory"] + "/" if row["directory"] else "") + row["name"]
        )
    bundle = b"".join(
        Path(row["source"]).read_bytes()
        for row in (main_ff, main_fp, empty_ff, empty_fp)
    )
    assert digest(bundle) == proof["resource_bundle_sha256"]
    body = unpack_replay_uncompressed(Path(main_ff["source"]).read_bytes())
    assert digest(body) == proof["body_sha256"]
    assert struct.unpack_from("<IIQ", body, 32) == (27, 0, 0xFFFFFFFFFFFFFFFE)
    resource_report = json.loads(Path(proof["resource_report"]).read_bytes())
    resource = Path(resource_report["output"]).read_bytes()
    loader = proof["native_reader"]
    manifest = Path(loader["manifest_path"])
    index = build_read_span_index(
        manifest.parent / "stream-trace.jsonl", manifest, len(body)
    )
    assert all(
        proof["stream_reservations"][i] == index["max_destination_offsets"].get(i, 0)
        for i in range(11)
    )
    assert (
        len(index["assets"]) == 1
        and not loader["trace_summary"]["packed_target_stream_counts"]
    )
    tool = Path(__file__).with_name("prepare-gulag-navigation-package.py")
    spec = importlib.util.spec_from_file_location("gulag_package_codec", tool)
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    layout = proof["layout"]
    owner = index["assets"][0]
    exported = codec.native_owned_export(
        body, owner, layout["payload_offset"], len(resource)
    )
    assert (
        exported == resource
        and digest(exported)
        == proof["native_owned_exports"]["payload_sha256"]
        == proof["resource_sha256"]
    )
    entries = proof.get("resources", [])
    if entries:
        root = codec.native_owned_export(body, owner, layout["root_offset"], 168)
        assert (
            struct.unpack_from("<I", root, 16)[0]
            == len(entries)
            == layout["resource_count"]
        )
        records = codec.native_owned_export(
            body, owner, layout["resource_offset"], 112 * len(entries)
        )
        for i, entry in enumerate(entries):
            data = Path(entry["path"]).read_bytes()
            report_raw = Path(entry["report"]).read_bytes()
            assert (
                digest(data) == entry["sha256"]
                and digest(report_raw) == entry["report_sha256"]
            )
            assert (
                codec.native_owned_export(
                    body, owner, layout["payload_offsets"][i], len(data)
                )
                == data
            )
            assert struct.unpack_from("<i", records, 112 * i + 4)[0] == -1
            assert struct.unpack_from("<I", records, 112 * i + 24)[0] == len(data)
            if not proof["synthetic_format_fixture"]:
                audit = json.loads(report_raw)
                verify_geometry_audit(audit, proof["source_inputs"])
                assert audit["geometry_provenance"]["collision_complete"] is True
                assert audit["collision_fidelity"]["sampled_checks_passed"] is True
                assert audit.get("research_candidate") is False
                geometry = json.loads(Path(audit["input"]).read_bytes())
                assert geometry.get("collision_complete") is True
                assert geometry["provenance"] == audit["geometry_provenance"]
    canonical = proof.get("canonical_nav_metadata")
    if canonical is not None:
        raw = Path(canonical["path"]).read_bytes()
        assert (
            digest(raw) == canonical["sha256"]
            and json.loads(raw) == canonical["values"]
        )
        values = canonical["values"]
        for source in values["source_hashes"]:
            path = Path(source["path"])
            if path.exists():
                assert (
                    file_digest(path) == source["sha256"]
                ), "Canonical source FF/FP hash changed"
        root = codec.native_owned_export(body, owner, layout["root_offset"], 168)
        assert struct.unpack_from("<II", root, 8) == (19, values["hasExposureData"])
        assert root[144:168] == struct.pack(
            "<6f", *values["staticHalf"], *values["staticMid"]
        )
        assert any(
            row["sha256"] == canonical["sha256"] for row in proof["source_inputs"]
        )
    else:
        assert proof[
            "synthetic_format_fixture"
        ], "Production requires canonical map-global fields"
    # Production readiness cannot be gained from structural/format evidence.
    if not proof["synthetic_format_fixture"]:
        assert resource_report["geometry_provenance"]["collision_complete"] is True
        assert resource_report["collision_fidelity"]["sampled_checks_passed"] is True
    result = dict(
        schema=1,
        passed=True,
        proof_sha256=digest(args.proof.read_bytes()),
        asset_name=proof["asset_name"],
        installation_files=len(installation),
        native_owned_payload_sha256=digest(exported),
        production_ready=proof["production_ready"],
        synthetic_format_fixture=proof["synthetic_format_fixture"],
        native_trace_rechecked=True,
        game_execution=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
