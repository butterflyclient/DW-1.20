"""Install one locally verified DW job without publishing an updater release.

The EXE, matching debug symbols and owned native overlays form one transaction.
Existing changed files are retained for rollback; the owner's INI and maps are
never part of this transaction.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct

import dw_client

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def reviewed_image_association(target, previous_image, previous):
    """Accept only a retained final image or its explicitly recorded pre-debug body."""
    before = sha(target)
    final_hash = previous["sha256"]
    assert sha(previous_image) == final_hash, "Reviewed final artifact changed"
    assert not previous["unresolved_symbols"]
    if before == final_hash:
        return "reviewed-final-image"
    debug = previous.get("debug_symbols", {})
    assert (
        debug.get("pre_debug_image_sha256") == before
    ), "Installed image is not the recorded pre-debug image"

    def layout(data):
        assert data[:2] == b"MZ"
        pe = struct.unpack_from("<I", data, 60)[0]
        assert data[pe : pe + 4] == b"PE\0\0"
        count, optional_size = (
            struct.unpack_from("<H", data, pe + 6)[0],
            struct.unpack_from("<H", data, pe + 20)[0],
        )
        optional = pe + 24
        assert struct.unpack_from("<H", data, optional)[0] == 0x20B
        entry, size = (
            struct.unpack_from("<I", data, optional + 16)[0],
            struct.unpack_from("<I", data, optional + 56)[0],
        )
        sections = []
        for i in range(count):
            offset = optional + optional_size + 40 * i
            name = data[offset : offset + 8].rstrip(b"\0").decode("ascii")
            _, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
            assert raw_offset + raw_size <= len(data)
            sections.append(
                dict(
                    name=name,
                    rva=rva,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    sha256=hashlib.sha256(
                        data[raw_offset : raw_offset + raw_size]
                    ).hexdigest(),
                )
            )
        return entry, size, sections

    entry, size, sections = layout(target.read_bytes())
    final_entry, _, final_sections = layout(previous_image.read_bytes())
    preserved = debug["preserved_sections"]
    assert (
        preserved and sections == preserved
    ), "Installed pre-debug section body/layout changed"
    assert (
        final_sections[: len(preserved)] == preserved
    ), "Final artifact does not preserve the recorded body"
    assert (
        len(final_sections) == len(preserved) + 1
        and final_sections[-1]["name"] == ".debug"
    )
    assert size == debug["pre_debug_image_size"]
    assert entry == final_entry == previous["entry_rva"]
    return "reviewed-recorded-pre-debug-image"


def deploy(job, replace_reviewed_build=None):
    job = job.resolve(strict=True)
    assert job.is_relative_to(ROOT / "data/dw-client/jobs")
    ready_path = job / "local-readiness.json"
    ready = read(ready_path)
    assert ready["passed"] and not ready["unresolved_symbols"]
    report_path = Path(ready["build_report"]).resolve(strict=True)
    receipt_path = Path(ready["source_receipt"]).resolve(strict=True)
    assert report_path.is_relative_to(job) and receipt_path.is_relative_to(job)
    assert sha(report_path) == ready["build_report_sha256"]
    assert sha(receipt_path) == ready["source_receipt_sha256"]
    receipt, report = read(receipt_path), read(report_path)
    dw_client.require_current_sources(receipt)
    snapshot = Path(report["source_root"]).resolve(strict=True)
    image = Path(ready["executable"]).resolve(strict=True)
    assert snapshot.is_relative_to(job) and image.is_relative_to(job)
    assert sha(image) == ready["sha256"] == report["sha256"]
    actual = {row["source"]: row["source_sha256"] for row in report["cpp"]}
    assert actual == receipt["cpp_sources"] and not report["unresolved_symbols"]
    for proof in ready["proofs"]:
        path = Path(proof["path"]).resolve(strict=True)
        assert path.is_relative_to(job) and sha(path) == proof["sha256"]
        assert read(path)["passed"]
        assert sha(ROOT / "tools" / proof["checker"]) == proof["checker_sha256"]

    game = Path(read(snapshot / "replay-project.local.json")["game"]).resolve(
        strict=True
    )
    target = game / "game_dx12_ship_replay_dw.exe"
    ini = target.with_suffix(".ini")
    ini_hash = sha(ini)
    before = sha(target)
    retained_previous = None
    if before not in (receipt["baseline_executable_sha256"], ready["sha256"]):
        assert (
            replace_reviewed_build is not None
        ), "Owner EXE changed since preparation; pass its reviewed retained build report"
        previous_report = dw_client.inside(
            Path(replace_reviewed_build).resolve(strict=True)
        )
        previous = read(previous_report)
        previous_image = Path(previous["executable"])
        if not previous_image.is_absolute():
            previous_image = previous_report.parent / previous_image
        previous_image = dw_client.inside(previous_image.resolve(strict=True))
        association = reviewed_image_association(target, previous_image, previous)
        retained_previous = dict(
            sha256=before,
            installed_executable=str(target),
            association_kind=association,
            final_artifact_sha256=previous["sha256"],
            executable=str(previous_image),
            executable_sha256=previous["sha256"],
            build_report=str(previous_report),
            build_report_sha256=sha(previous_report),
            reason="Owner-authorized replacement of the retained validated local candidate",
        )
    if dw_client.running_games():
        raise RuntimeError("DW game is running; close it before local deployment")

    # Validate the frozen helper's manifest against both native package proofs.
    spec = importlib.util.spec_from_file_location(
        "local_deploy_owned_assets", snapshot / "tools/dw_update_assets.py"
    )
    assets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(assets)
    manifest = assets.extract(image.read_bytes())
    metadata = read(snapshot / "generated/update-assets.json")
    assert hashlib.sha256(manifest).hexdigest() == metadata["manifest_sha256"]
    groups = assets.decode_groups(manifest)
    payloads, native_paths = {}, {}
    for group in groups:
        native = assets.package_group(snapshot, group["owner"])
        assert group == {
            key: native[key] for key in ("owner", "bundle_sha256", "entries")
        }
        payloads.update(native["payloads"])
        native_paths.update(native["relative_paths"])
    assert (
        metadata["relative_paths"] == native_paths
    ), "Owned destinations differ from their native package proofs"

    entries = assets.decode(manifest)
    # Like the embedded map-image package, Gulag navigation travels inside the
    # complete executable and can stage itself on first map load. Install its
    # verified native files in the same local transaction for immediate testing.
    gulag_proof_path = snapshot / "generated/gulag-navigation/package-proof.json"
    if gulag_proof_path.exists():
        gulag = read(gulag_proof_path)
        assert gulag["production_ready"] and not gulag["synthetic_format_fixture"]
        assert len(gulag["resources"]) == 6
        assert sha(snapshot / "src/DW_GulagNavPackage.h") == gulag["header_sha256"]
        gates = [
            proof
            for proof in ready["proofs"]
            if proof["checker"] == "test-gulag-integration.py"
        ]
        assert len(gates) == 1
        gate_path = Path(gates[0]["path"]).resolve(strict=True)
        assert gate_path.is_relative_to(job) and sha(gate_path) == gates[0]["sha256"]
        gate = read(gate_path)
        assert gate["passed"] and gate["executable_sha256"] == ready["sha256"]
        assert gate["package_proof_sha256"] == sha(gulag_proof_path)
        assert gate["compiled_package_header_sha256"] == gulag["header_sha256"]
        assert len(gulag["installation_manifest"]) == 20
        for entry in gulag["installation_manifest"]:
            assert re.fullmatch(
                r"(?:[a-z0-9_]{0,16}_)?dw_gulag_nav_[0-9a-f]{16}\.(?:ff|fp)",
                entry["name"],
            )
            assert entry["name"] not in native_paths
            native_paths[entry["name"]] = entry["relative_path"]
            payloads[entry["sha256"]] = dict(source=entry["source"])
            entries.append(entry)

    records = []
    zone = (game / "zone").resolve(strict=True)
    for entry in entries:
        relative = native_paths[entry["name"]]
        path = (zone / relative).resolve()
        assert path.is_relative_to(zone) and path.name == entry["name"]
        source = Path(payloads[entry["sha256"]]["source"]).resolve(strict=True)
        assert source.is_relative_to(snapshot)
        assert source.stat().st_size == entry["size"] and sha(source) == entry["sha256"]
        records.append((source, path, entry["sha256"]))
    owned_files = len(records)
    debug_artifacts = []
    debug = report.get("debug_symbols")
    if debug is not None:
        for kind in ("pdb", "map"):
            artifact = Path(debug[kind]).resolve(strict=True)
            expected = debug[kind + "_sha256"]
            assert artifact.is_relative_to(report_path.parent)
            assert artifact.suffix.casefold() == "." + kind
            assert sha(artifact) == expected
            destination = target.with_suffix("." + kind)
            records.append((artifact, destination, expected))
            debug_artifacts.append(
                dict(kind=kind, path=str(destination), sha256=expected)
            )
    records.append((image, target, ready["sha256"]))
    assert len({str(path).casefold() for _, path, _ in records}) == len(records)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup_root = game / "replay-dw-backups" / ("local-test-" + stamp)
    changes, applied, pending_paths = [], [], []
    try:
        for source, path, expected in records:
            if path.exists() and sha(path) == expected:
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            pending = path.with_name(path.name + f".local-{os.getpid()}.pending")
            with pending.open("xb") as output:
                pending_paths.append(pending)
                with source.open("rb") as incoming:
                    shutil.copyfileobj(incoming, output)
                    output.flush()
                    os.fsync(output.fileno())
            assert sha(pending) == expected
            previous = sha(path) if path.exists() else None
            backup = backup_root / path.relative_to(game) if previous else None
            changes.append(
                dict(
                    path=str(path),
                    pending=str(pending),
                    sha256=expected,
                    previous_sha256=previous,
                    backup=str(backup) if backup else None,
                )
            )
        assert sha(ini) == ini_hash and sha(target) == before
        if dw_client.running_games():
            raise RuntimeError(
                "DW game started during staging; local deployment deferred"
            )
        # Recheck every destination before changing the first one.
        for change in changes:
            path = Path(change["path"])
            assert (sha(path) if path.exists() else None) == change["previous_sha256"]
            if change["backup"]:
                backup = Path(change["backup"])
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, backup)
                assert sha(backup) == change["previous_sha256"]
        dw_client.require_current_sources(receipt)
        for change in changes:
            os.replace(change["pending"], change["path"])
            applied.append(change)
            assert sha(Path(change["path"])) == change["sha256"]
        assert sha(ini) == ini_hash and sha(target) == ready["sha256"]
    except BaseException:
        for change in reversed(applied):
            path = Path(change["path"])
            assert (
                sha(path) == change["sha256"]
            ), "Changed destination retained; manual recovery required"
            if change["backup"]:
                restore = path.with_name(path.name + f".restore-{os.getpid()}")
                backup = Path(change["backup"])
                assert (
                    sha(backup) == change["previous_sha256"]
                ), "Rollback backup changed; original retained for manual recovery"
                shutil.copy2(backup, restore)
                os.replace(restore, path)
                assert (
                    sha(path) == change["previous_sha256"]
                ), "Restored original failed rollback verification"
            else:
                path.unlink()
        raise
    finally:
        for path in pending_paths:
            if path.exists():
                path.unlink()

    evidence = dict(
        passed=True,
        deployed=True,
        published=False,
        executable=str(target),
        sha256=ready["sha256"],
        previous_executable_sha256=before,
        retained_reviewed_previous=retained_previous,
        readiness=str(ready_path),
        readiness_sha256=sha(ready_path),
        owner_ini_preserved=True,
        ini_sha256=ini_hash,
        owned_files_verified=owned_files,
        debug_artifacts=debug_artifacts,
        changed_files=changes,
        backup_root=str(backup_root) if changes else None,
        game_runs_performed=False,
        game_processes_stopped=False,
    )
    dw_client.save(job / "local-deployment.json", evidence)
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True, type=Path)
    parser.add_argument(
        "--replace-reviewed-build",
        type=Path,
        help="Retained zero-unresolved build report matching the installed candidate",
    )
    args = parser.parse_args()
    with dw_client.pipeline_lock():
        deploy(args.job, args.replace_reviewed_build)
