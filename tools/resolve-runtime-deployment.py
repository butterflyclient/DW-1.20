"""Select a validated backend without rewriting the original game build receipt."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


def referenced(row):
    path = (ROOT / row["path"]).resolve()
    if not path.is_relative_to(ROOT) or digest(path) != row["sha256"]:
        raise RuntimeError(
            "Backend validation reference changed or escaped the project"
        )
    return load(path)


def resolve(deployment, server, readiness_reference=None):
    """Retain the game contract; bind a newer backend to its separate evidence."""
    if digest(Path(deployment["executable"])) != deployment["sha256"]:
        raise RuntimeError("Shipping game differs from its original compilation record")
    expected_server = ROOT / "build/Release/iw8-dw-server.exe"
    if Path(server["executable"]).resolve() != expected_server.resolve():
        raise RuntimeError("Server receipt names an unexpected backend executable")
    if digest(expected_server) != server["sha256"]:
        raise RuntimeError("Deployed backend differs from its process receipt")

    result = dict(deployment)
    selection = dict(
        schema=1,
        selected_utc=datetime.now(timezone.utc).isoformat(),
        original_game_deployment=reference(ROOT / "data/deployment.json"),
        original_backend_sha256=deployment["server_sha256"],
        selected_backend_sha256=server["sha256"],
        game_recompiled=False,
    )
    if server["sha256"] != deployment["server_sha256"]:
        if readiness_reference is None:
            raise RuntimeError("New backend needs a hash-bound readiness receipt")
        readiness = referenced(readiness_reference)
        if (
            not readiness.get("passed")
            or readiness.get("backend_sha256") != server["sha256"]
            or readiness.get("unchanged_shipping_game_sha256") != deployment["sha256"]
        ):
            raise RuntimeError(
                "Readiness evidence does not bind this backend/game pair"
            )
        build = referenced(readiness["build_receipt"])
        protocol = referenced(readiness["protocol_evidence"])
        if (
            not build.get("compile_passed")
            or build.get("sha256") != server["sha256"]
            or not protocol.get("passed")
            or protocol.get("server_sha256") != server["sha256"]
        ):
            raise RuntimeError(
                "Backend build/protocol evidence does not match deployment"
            )
        for row in readiness["native_startup"]["evidence"]:
            observed = referenced(row)
            if observed["server_process_verified"]["sha256"] != server["sha256"]:
                raise RuntimeError("Native observation names a different backend")
        selection["backend_readiness"] = readiness_reference
        result["server_sha256"] = server["sha256"]
    result["runtime_backend_selection"] = selection
    return result


def main():
    original = load(ROOT / "data/deployment.json")
    server = load(ROOT / "data/server-process.json")
    latest = ROOT / "data/backend-readiness-latest.json"
    selected = resolve(original, server, load(latest) if latest.exists() else None)
    output = ROOT / "data/current-runtime-deployment.json"
    if output.exists():
        existing = load(output)
        prior_time = existing.get("runtime_backend_selection", {}).get("selected_utc")
        if prior_time:
            selected["runtime_backend_selection"]["selected_utc"] = prior_time
        if existing == selected:
            print(output)
            return
    pending = output.with_suffix(".pending")
    pending.write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")
    os.replace(pending, output)
    print(output)


if __name__ == "__main__":
    main()
