"""Publish one verified complete Replay EXE, with the catalog committed last."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import time

import remote_backend

ROOT = Path(__file__).resolve().parents[1]


def verify_updater(path, target_hash):
    if path is None:
        raise ValueError("Uploading an EXE requires its compiled updater verification receipt")
    proof_bytes = path.read_bytes()
    proof = json.loads(proof_bytes)
    if not proof.get("passed") or proof.get("game_sha256") != target_hash:
        raise ValueError("Updater verification does not bind the published EXE")
    cases = proof.get("initial_update_checks", [])
    expected = {(False, True): (0, 0), (True, True): (1, 1), (True, False): (1, 40)}
    observed = {}
    for case in cases:
        if case.get("compiled_initial_state") != 0 or case.get("frames") != 2:
            raise ValueError("The compiled updater is disabled or its first-frame check is missing")
        key = (case["enabled"], case["thread_creation_succeeds"])
        if key in observed:
            raise ValueError("Duplicate compiled updater startup case")
        observed[key] = (case["worker_starts"], case["final_state"])
    if observed != expected:
        raise ValueError("Compiled updater scheduling or failure handling does not verify")
    checks = proof.get("checks", [])
    if len(checks) != 10 or any(
        not case.get("native_prerequisite_passes") or not case.get("restart_route_correct")
        or case.get("getter_cases") != 10 for case in checks
    ):
        raise ValueError("Compiled update fence and restart routing do not verify")
    return proof_bytes


def publish(image, report, release, output, upload=False, updater_verification=None):
    spec = importlib.util.spec_from_file_location(
        "compiler_publication", ROOT / "tools/publish-executable-update.py"
    )
    verification = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verification)
    data, digest, report_bytes = verification.verify_image(image, report)
    if release <= 0:
        raise ValueError("Release number must be positive")
    updater_bytes = verify_updater(updater_verification, digest) if upload else None
    output.mkdir(parents=True, exist_ok=True)
    binary = output / (digest + ".exe")
    binary.write_bytes(data)
    (output / "build-report.json").write_bytes(report_bytes)
    if updater_bytes is not None:
        (output / "updater-verification.json").write_bytes(updater_bytes)
    catalog = dict(
        schema=1,
        format="full-executable-v1",
        release=release,
        latest=digest,
        target_size=len(data),
    )
    verification.atomic_json(output / "full-image-catalog.json", catalog)
    if not upload:
        return catalog

    catalog_bytes = (output / "full-image-catalog.json").read_bytes()
    incoming = "/var/lib/replay-dw/updates/full-incoming-" + str(time.time_ns())
    with remote_backend.connect() as client:
        _, out, error = client.exec_command(
            "install -d -m 0755 " + incoming, timeout=20
        )
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
        with client.open_sftp() as sftp:
            sftp.put(str(binary), incoming + "/" + binary.name)
            with sftp.file(incoming + "/catalog.json", "wb") as file:
                file.write(catalog_bytes)
        script = r"""
import hashlib,json,os,pathlib
incoming=pathlib.Path(INCOMING)
root=incoming.parent
new=json.loads((incoming/'catalog.json').read_bytes())
assert hashlib.sha256((incoming/'catalog.json').read_bytes()).hexdigest()==CATALOG_SHA
assert new['schema']==1 and new['format']=='full-executable-v1'
image=incoming/(new['latest']+'.exe')
with image.open('rb') as f:
    assert hashlib.file_digest(f,'sha256').hexdigest()==new['latest']
    os.fsync(f.fileno())
assert image.stat().st_size==new['target_size'] and 0<new['target_size']<=512*1024*1024
with image.open('rb') as f: assert f.read(2)==b'MZ'
index=root/'full-image-catalog.json'
if index.exists():
    old=json.loads(index.read_bytes())
    assert old==new or new['release']>old['release'],'Release rollback rejected'
legacy=root/'catalog.json'
if legacy.exists():
    assert new['release']>json.loads(legacy.read_bytes())['release'],'Release must follow legacy publication'
images=root/'images';images.mkdir(exist_ok=True)
destination=images/image.name
if destination.exists():
    with destination.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest()==new['latest']
    assert destination.stat().st_size==new['target_size']
    image.unlink()
else:
    os.chmod(image,0o644);os.replace(image,destination)
directory=os.open(images,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
os.chmod(incoming/'catalog.json',0o644)
with (incoming/'catalog.json').open('rb') as f: os.fsync(f.fileno())
os.replace(incoming/'catalog.json',index)
directory=os.open(root,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
incoming.rmdir()
print(json.dumps(dict(published=True,format=new['format'],release=new['release'],latest=new['latest'],bytes=new['target_size'])))
""".replace(
            "INCOMING", repr(incoming)
        ).replace(
            "CATALOG_SHA", repr(hashlib.sha256(catalog_bytes).hexdigest())
        )
        _, out, error = client.exec_command(
            "python3 - <<'PY'\n" + script + "\nPY", timeout=60
        )
        response = out.read()
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
    result = json.loads(response)
    result["compiled_updater_verified"] = True
    result["updater_verification_sha256"] = hashlib.sha256(updater_bytes).hexdigest()
    verification.atomic_json(output / "droplet-publication.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--build-report", required=True, type=Path)
    parser.add_argument("--release", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--updater-verification", type=Path,
                        help="Hash-bound compiled initial scheduling, fence and restart proof; required for upload")
    args = parser.parse_args()
    print(
        json.dumps(
            publish(
                args.image, args.build_report, args.release, args.output, args.upload,
                args.updater_verification
            ),
            indent=2,
        )
    )
