"""Keep the sole verified DW client and the signed public updater in sync."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import remote_backend

ROOT = Path(__file__).resolve().parents[1]
REMOTE = "/var/lib/replay-dw/updates"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory():
    with remote_backend.connect() as client:
        script = (
            "import json,pathlib\n"
            f"root=pathlib.Path({REMOTE!r})\n"
            "print(json.dumps(dict(catalog=json.loads((root/'full-image-catalog.json').read_bytes()),"
            "legacy=json.loads((root/'catalog.json').read_bytes()) if (root/'catalog.json').exists() else {},"
            "images=sorted(p.stem for p in (root/'images').glob('*.exe')))))\n"
        )
        _, output, error = client.exec_command(
            "python3 - <<'PY'\n" + script + "PY", timeout=30
        )
        result = output.read()
        if output.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
    return json.loads(result)


def require_current(ready):
    """Deployment cannot re-advertise an older ready job over a newer release."""
    catalog = inventory()["catalog"]
    if catalog["latest"] != ready["sha256"]:
        raise ValueError(
            "Public updater differs from this build; publish the current verified job before deployment"
        )
    if catalog["target_size"] != Path(ready["executable"]).stat().st_size:
        raise ValueError("Public updater image size differs from the verified build")
    return catalog


def publish(image, report, source, updater, output):
    image, report, source, updater, output = map(
        Path, (image, report, source, updater, output)
    )
    receipt = json.loads((source.parent / "source-receipt.json").read_bytes())
    for item in receipt["source_inputs"]:
        if sha(ROOT / item["source"]) != item["source_sha256"]:
            raise ValueError(
                "Authored source changed during this build; refusing stale publication: "
                + item["source"]
            )
    target = sha(image)
    remote = inventory()
    catalog = remote["catalog"]
    release = (
        catalog["release"]
        if catalog["latest"] == target
        else max(catalog["release"], remote["legacy"].get("release", 0)) + 1
    )
    spec = importlib.util.spec_from_file_location(
        "full_image_publisher", ROOT / "tools/publish-full-executable.py"
    )
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)
    print(f"Publishing verified DW client as release {release}: {target}", flush=True)
    publisher.publish(image, report, release, output, True, updater)
    hashes = set(remote["images"])
    hashes.update(remote["legacy"].get("patches", {}))
    hashes.add(catalog["latest"])
    history = output / "retained-release-history.json"
    history.write_text(
        json.dumps([dict(sha256=value) for value in sorted(hashes)], indent=2) + "\n"
    )
    older = next((value for value in remote["images"] if value != target), None)
    if older is None:
        raise ValueError(
            "No retained older full image available for actual updater staging verification"
        )
    with tempfile.TemporaryDirectory(
        prefix="publication-base-", dir=ROOT / "data"
    ) as temporary:
        base = Path(temporary) / "previous.exe"
        with remote_backend.connect() as client, client.open_sftp() as sftp:
            sftp.get(REMOTE + "/images/" + older + ".exe", str(base))
        if sha(base) != older:
            raise ValueError("Retained older executable hash failed")
        verification = output / "public-verification.json"
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "tools/verify-full-executable-publication.py"),
                "--publication",
                str(output),
                "--source-root",
                str(source / "src"),
                "--base-exe",
                str(base),
                "--release-history",
                str(history),
                "--output",
                str(verification),
            ],
            cwd=ROOT,
            check=True,
        )
    proof = json.loads(verification.read_bytes())
    if not proof["passed"] or proof["executable_sha256"] != target:
        raise ValueError("Signed updater publication verification failed")
    require_current(dict(sha256=target, executable=str(image)))
    return dict(
        release=release,
        sha256=target,
        verification=str(verification),
        verification_sha256=sha(verification),
        publication=str(output),
    )
