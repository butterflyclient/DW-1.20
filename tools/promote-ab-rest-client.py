"""Promote the verified AB request fix while retaining native production profiles.

This narrow promotion inherits the previous deployment's unchanged protocol
sources. It does not relabel historical game tests as tests of the new image.
The normal full deployment tool remains required for other engine changes.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil

import remote_backend

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    path = path.resolve()
    assert path.is_relative_to(ROOT)
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


def atomic_json(path, document):
    temporary = path.with_suffix(path.suffix + ".pending")
    temporary.write_text(json.dumps(document, indent=2) + "\n")
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    folder = args.receipts.resolve()
    assert folder.is_relative_to(ROOT / "data")
    assert args.output.resolve().is_relative_to(ROOT / "validation")
    prior_path = ROOT / "data/deployment.json"
    prior = load(prior_path)
    destination = Path(prior["executable"])
    assert destination.resolve() == Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe")
    assert digest(destination) == prior["sha256"]
    job = load(folder / "workstation-job.json")
    assert job["status"] == "succeeded" and job["profile"] == "engine"
    build = Path(job["build_directory"]).resolve()
    assert build.parent == ROOT / "data/workstation-builds"
    report = load(build / "build-report.json")
    artifact = Path(job["artifacts"][0]["path"])
    image_hash = digest(artifact)
    assert image_hash == report["sha256"] == job["artifacts"][0]["sha256"]
    snapshot = Path(report["source_root"])
    assert snapshot.resolve().is_relative_to(ROOT / "data")
    snapshot_receipt = load(folder / "compiler-snapshot-receipt.json")
    assert snapshot_receipt["snapshot"] == str(snapshot)
    assert not (snapshot / "src/DW_PlayerDataPath.cpp").exists()
    assert not any("DW_TestHomePath" in row["source"] for row in report["cpp"])
    verify = load(build / "verification-report.json")
    relocation = load(build / "relocation-audit.json")
    assert verify["sha256"] == image_hash and verify["unresolved_symbols"] == 0
    assert verify["windows_sec_image_mapping"]
    assert relocation["sha256"] == image_hash and relocation["passed"]

    previous_build = Path(prior["build_directory"])
    previous_report = load(previous_build / "build-report.json")
    assert previous_report["sha256"] == prior["sha256"]
    old_sources = {row["source"]: row for row in previous_report["cpp"]}
    new_sources = {row["source"]: row for row in report["cpp"]}
    assert new_sources.keys() - old_sources.keys() == {"src/DW_ABTestingEnroll.cpp"}
    assert not old_sources.keys() - new_sources.keys()
    previous_snapshot = Path(previous_report["source_root"])
    changed = []
    for name in old_sources:
        if old_sources[name]["source_sha256"] == new_sources[name]["source_sha256"]:
            continue
        old = (previous_snapshot / name).read_bytes()
        new = (snapshot / name).read_bytes()
        if name == "src/ScrPlace_EndFrame.cpp":
            assert old.rstrip() == new.rstrip()
        elif name == "src/DW_ExecutableUpdate.cpp":
            assert old.replace(b"client revision 1", b"client revision 2") == new
        else:
            raise RuntimeError("Unreviewed production engine change: " + name)
        changed.append(name)

    bindings_path = snapshot / "generated/ab-rest-integration.json"
    bindings = load(bindings_path)
    assert bindings["passed"] and bindings["no_manual_source_rvas_or_layouts"]
    assert bindings["source_sha256"] == new_sources["src/DW_ABTestingEnroll.cpp"]["source_sha256"]
    old_ids = {row["function_id"] for row in previous_report["source_units"]
               if row.get("source", "").endswith(".cpp")}
    new_ids = {row["function_id"] for row in report["source_units"]
               if row.get("source", "").endswith(".cpp")}
    assert new_ids - old_ids == {bindings["original_writer"]["function_id"]}
    assert not old_ids - new_ids
    proofs = {}
    for name, hash_field in (("linked-writer-proof.json", "compiled_input_sha256"),
                              ("linked-client.json", "executable_sha256"),
                              ("linked-ownership.json", "game_sha256"),
                              ("linked-updater.json", "game_sha256")):
        path = folder / name
        proof = load(path)
        assert proof["passed"] and proof[hash_field] == image_hash
        proofs[name] = reference(path)
    writer = load(folder / "linked-writer-proof.json")
    assert writer["binding_receipt_sha256"] == digest(bindings_path)
    assert writer["original_request_validator_executed"]
    assert len(writer["cases"]) == 10
    remote = remote_backend.verify()
    # Validate inherited records before touching the executable. Keep their
    # historical protocol receipts; only object identities change on relink.
    updated = json.loads(json.dumps(prior))
    for row in updated["platform_sources"]:
        current = new_sources[row["compiled_source"]]
        assert current["source_sha256"] == row["source_sha256"]
        row["object_sha256"] = current["object_sha256"]
    for row in updated["sources"]:
        current = new_sources[row["compiled_source"]]
        assert old_sources[row["compiled_source"]]["source_sha256"] == row["content_sha256"]
        if row["compiled_source"] in changed:
            row["content_sha256"] = current["source_sha256"]
            row["revision"] = current["source_sha256"]
        else:
            assert current["source_sha256"] == row["content_sha256"]
        row["object_sha256"] = current["object_sha256"]
    result = dict(passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
                  job_id=job["id"], game_sha256=image_hash,
                  candidate=str(artifact), previous_game_sha256=prior["sha256"],
                  previous_deployment=reference(prior_path),
                  build_report=reference(build / "build-report.json"),
                  snapshot_receipt=reference(folder / "compiler-snapshot-receipt.json"),
                  linked_proofs=proofs, inherited_cpp_sources=len(old_sources),
                  nonfunctional_source_differences=changed,
                  native_production_player_path_retained=True,
                  new_rest_task_completion_verified=False,
                  game_runtime_tested=False, installed=False,
                  live_server=remote, server_restarted=False)
    if args.install:
        # A running game holds its image open. Refuse promotion instead of
        # stopping an owner-launched process or forcing a file replacement.
        import subprocess
        state = subprocess.check_output([
            "powershell", "-NoProfile", "-Command",
            "@(Get-CimInstance Win32_Process -Filter \"Name LIKE 'game_dx12_ship_replay%.exe'\").Count"
        ], text=True).strip()
        assert state == "0", "A Replay instance is running"
        backup = folder / (prior["sha256"] + ".previous.exe")
        if not backup.exists():
            shutil.copyfile(destination, backup)
        assert digest(backup) == prior["sha256"]
        (folder / "previous-deployment.json").write_bytes(prior_path.read_bytes())
        pending = destination.with_suffix(".exe.dw-installing")
        shutil.copyfile(artifact, pending)
        assert digest(pending) == image_hash
        os.replace(pending, destination)
        assert digest(destination) == image_hash
        updated.update(job_id=job["id"], workstation_artifact=str(artifact),
                       build_directory=str(build), compiler_source_root=str(snapshot),
                       source_snapshot_receipt=str(folder / "compiler-snapshot-receipt.json"),
                       sha256=image_hash, native_game_verified=False,
                       linked_client_integration=dict(path=str(folder / "linked-client.json"),
                                                      sha256=digest(folder / "linked-client.json")),
                       linked_unlock_policy=dict(path=str(folder / "linked-ownership.json"),
                                                 sha256=digest(folder / "linked-ownership.json"),
                                                 native_runtime_verified=False),
                       incremental_recompile=dict(previous=reference(folder / "previous-deployment.json"),
                                                  proof=str(args.output.resolve()),
                                                  native_profile_path_retained=True,
                                                  historical_protocol_evidence_inherited=True))
        atomic_json(prior_path, updated)
        result["installed"] = True
        result["rollback_executable"] = reference(backup)
    atomic_json(args.output, result)
    print(json.dumps(dict(passed=True, installed=result["installed"], sha256=image_hash,
                          native_production_player_path_retained=True)))


if __name__ == "__main__":
    main()
