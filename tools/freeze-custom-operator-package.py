"""Freeze a native-reader-verified operator package into one client build."""

import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(snapshot):
    snapshot = Path(snapshot).resolve(strict=True)
    source = ROOT / "data/custom-operators/package"
    manifest_path = source / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    assert manifest["schema"] == 1
    zone = manifest["zone"]
    assert re.fullmatch(r"dw_custom_operators_[0-9a-f]{16}", zone)
    assert len(manifest["operators"]) == 2
    for key in ("native_reader", "native_empty_reader"):
        result = manifest[key]
        native = result["manifest"]
        assert result["return_code"] == 0 and native["complete"] and native["success"]
        assert native["failed"] == native["unavailable"] == 0
        assert digest(Path(result["raw_manifest_path"])) == result["raw_manifest_sha256"]
        assert digest(Path(result["log_path"])) == result["log_sha256"]
    assert manifest["native_reader"]["manifest"]["loaded_by_type"]["xmodel"] == 4
    assert manifest["native_reader"]["manifest"]["loaded_by_type"]["xmodelsurfs"] == 4
    assert digest(Path(manifest["writer_executable"])) == manifest["writer_sha256"]
    assert digest(ROOT / "tools/custom-operator-model.cpp") == manifest["writer_source_sha256"]
    assert digest(ROOT / "tools/import-custom-operator-model.py") == manifest["importer_sha256"]
    for model in manifest["model_inputs"]:
        assert digest(Path(model["path"])) == model["sha256"]

    destination = snapshot / "generated/custom-operators-package"
    destination.mkdir(parents=True, exist_ok=True)
    inputs = []

    def freeze(path, target, expected):
        path = path.resolve(strict=True)
        assert path.is_relative_to(ROOT)
        assert digest(path) == expected
        shutil.copyfile(path, target)
        assert digest(path) == digest(target) == expected
        inputs.append(dict(source=path.relative_to(ROOT).as_posix(), source_sha256=expected,
                           compiled_source=target.relative_to(snapshot).as_posix(),
                           compiled_sha256=expected))

    frozen_manifest = destination / "manifest.json"
    freeze(manifest_path, frozen_manifest, digest(manifest_path))
    freeze(Path(manifest["header"]), snapshot / "src/DW_CustomOperatorsPackage.h",
           manifest["header_sha256"])
    payloads = {}
    for stem, reader in (("custom_operators", "native_reader"), ("empty", "native_empty_reader")):
        for extension in (".ff", ".fp"):
            artifact = manifest[reader]["candidate_artifacts"][extension]
            path = source / (stem + extension)
            assert path.stat().st_size == artifact["bytes"]
            target = destination / path.name
            freeze(path, target, artifact["sha256"])
            payloads[(stem, extension)] = dict(source=str(target), size=artifact["bytes"],
                                              sha256=artifact["sha256"])
    records = []
    for installation in manifest["installations"]:
        name, directory = installation["name"], installation["directory"]
        assert re.fullmatch(r"(?:[a-z0-9_]{0,16}_)?" + re.escape(zone), name)
        assert not directory or re.fullmatch(r"[a-z0-9_]+", directory)
        for extension in (".ff", ".fp"):
            filename = name + extension
            relative = (Path(directory) / filename).as_posix()
            records.append(dict(name=filename, relative_path=relative,
                                **payloads[("custom_operators" if name == zone else "empty", extension)]))
    assert len({r["relative_path"].casefold() for r in records}) == len(records)
    proof = dict(schema=1, production_ready=True, zone=zone,
                 manifest_sha256=digest(frozen_manifest), header_sha256=manifest["header_sha256"],
                 installation_manifest=records, runtime_animation_verified=False)
    (destination / "package-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    return frozen_manifest, inputs
