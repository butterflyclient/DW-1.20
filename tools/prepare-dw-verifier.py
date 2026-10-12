"""Prepare the DW validator without changing the approved compiler base."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_SHA256 = "d8fbf955f6908709aac0b3e9ddddff29283e6385c85fd9eb77c0978695e30e42"
ENUMERATION = '        names_to_unwind = [p["symbol"] for p in report["replacements"]]+["Replay_RegisterUiServerFrameDuration","Dvar_GenerateChecksum","Dvar_RegisterVariant"]'
ACTIVE_ENUMERATION = "        names_to_unwind = dw_active_unwind_names(report)"
LEDGER_CHECK = '''def dw_active_unwind_names(report):
    """Original replacement spans are logical ownership, not emitted functions."""
    from layout import Layout

    replacements = report["replacements"]
    active = {row["symbol"]: row for row in replacements if not row.get("retired")}
    if len({row["symbol"] for row in replacements}) != len(replacements):
        raise ValueError("Duplicate replacement ownership")
    placements = {}
    for row in report["placements"]:
        placements.setdefault(row["symbol"], []).append(row)
    for name in active:
        rows = placements.get(name, [])
        if len(rows) != 1 or rows[0]["size"] <= 0 or report["symbols"].get(name) != rows[0]["rva"]:
            raise ValueError("Active replacement has no unique emitted function: " + name)
    layout = Layout.__new__(Layout)
    layout.replacements = replacements
    previous_end = -1
    for row in sorted(replacements, key=lambda row: row["begin"]):
        if not 0 <= row["begin"] < row["end"] or row["begin"] < previous_end:
            raise ValueError("Invalid original replacement ownership spans")
        previous_end = row["end"]
        if not row.get("retired"):
            continue
        owner = active.get(row.get("owner"))
        if owner is None or row.get("entry") != owner["begin"]:
            raise ValueError("Retired original range has no active entry owner")
        if row["symbol"] in report["symbols"] or row["symbol"] in placements:
            raise ValueError("Retired original range has a standalone emitted function")
        # Exercise the linker's exact rejection, rather than interpreting the
        # original begin/end values as rebuilt addresses or physical tombstones.
        for target in (row["begin"], row["end"] - 1):
            try:
                layout.resolve(target)
            except ValueError as error:
                if not str(error).startswith("Reference targets retired function code:"):
                    raise
            else:
                raise ValueError("Linker accepts an inbound retired-code reference")
        for resolution in report.get("rva_map", {}).get("interior_reference_resolutions", []):
            if row["begin"] <= resolution["original_rva"] < row["end"]:
                raise ValueError("Instruction label targets retired original code")
        for branch in report.get("rva_map", {}).get("widened_branches", []):
            if row["begin"] <= branch["target"] < row["end"]:
                raise ValueError("Relocated branch targets retired original code")
    return list(active) + ["Replay_RegisterUiServerFrameDuration", "Dvar_GenerateChecksum", "Dvar_RegisterVariant"]


'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
    try:
        os.replace(temporary, path)  # Detach inherited hardlinks atomically.
    finally:
        temporary.unlink(missing_ok=True)


def prepare(snapshot):
    snapshot = Path(snapshot).resolve()
    config = json.loads((ROOT / "dw-client.json").read_bytes())
    compiler_base = (ROOT / config["compiler_base"]).resolve()
    sealed = any((folder / name).exists() for folder in (snapshot, snapshot.parent) for name in (
        "client-readiness.json", "readiness.json", "local-readiness.json",
        "source-receipt.json", "workstation-job.json"
    ))
    if not snapshot.is_relative_to(ROOT / "data") or snapshot.is_relative_to(compiler_base) or sealed:
        raise ValueError("Use a fresh private DW source snapshot")
    path = snapshot / "tools/verify.py"
    upstream = path.read_bytes()
    if sha(upstream) != UPSTREAM_SHA256:
        raise ValueError("Approved upstream validator changed")
    source = upstream.decode("utf-8")
    if source.count(ENUMERATION) != 1 or source.count("def windows_image_mapping(path, pe, report):") != 1:
        raise ValueError("Approved unwind enumeration changed")
    prepared = source.replace(ENUMERATION, ACTIVE_ENUMERATION).replace(
        "def windows_image_mapping(path, pe, report):", LEDGER_CHECK + "def windows_image_mapping(path, pe, report):"
    ).encode("utf-8")
    evidence = snapshot / "generated/dw-verifier/upstream-verify.py"
    if evidence.exists():
        raise ValueError("Validator preparation already exists")
    write_private(evidence, upstream)
    write_private(path, prepared)
    receipt = dict(passed=True, upstream_sha256=sha(upstream), prepared_sha256=sha(prepared),
                   generator_sha256=sha(Path(__file__).read_bytes()),
                   original_evidence="generated/dw-verifier/upstream-verify.py",
                   prepared_path="tools/verify.py", patch="active emitted unwind functions with retired logical ownership validation",
                   preserves_other_verification=True, changes_compiler_base=False)
    write_private(snapshot / "generated/dw-verifier-preparation.json", (json.dumps(receipt, indent=2) + "\n").encode())
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    print(json.dumps(prepare(parser.parse_args().snapshot), indent=2))
