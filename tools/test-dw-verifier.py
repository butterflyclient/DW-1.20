"""Check the DW-only unwind enumeration and the actual Windows image unwind."""

import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

import pefile

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(snapshot, build):
    prep = load("dw_verifier_prepare_gate", ROOT / "tools/prepare-dw-verifier.py")
    sealed_guards = []
    with tempfile.TemporaryDirectory(prefix="dw-verifier-guards-", dir=ROOT / "data") as directory:
        for marker in ("client-readiness.json", "readiness.json", "local-readiness.json", "source-receipt.json", "workstation-job.json"):
            for location in ("source", "parent"):
                parent = Path(directory) / (marker + "-" + location)
                fresh = parent / "source"
                fresh.mkdir(parents=True)
                ((fresh if location == "source" else parent) / marker).write_text("{}")
                try:
                    prep.prepare(fresh)
                except ValueError as error:
                    assert str(error) == "Use a fresh private DW source snapshot"
                    sealed_guards.append(marker + ":" + location)
                else:
                    raise AssertionError("Sealed validator source accepted")
    prepared = (snapshot / "tools/verify.py").read_bytes()
    upstream = (snapshot / "generated/dw-verifier/upstream-verify.py").read_bytes()
    receipt = json.loads((snapshot / "generated/dw-verifier-preparation.json").read_bytes())
    assert prep.sha(upstream) == prep.UPSTREAM_SHA256 == receipt["upstream_sha256"]
    assert prep.sha(prepared) == receipt["prepared_sha256"]
    assert prepared.decode().replace(prep.LEDGER_CHECK, "").replace(prep.ACTIVE_ENUMERATION, prep.ENUMERATION).encode() == upstream
    tree = ast.parse(prepared)
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "dw_active_unwind_names")
    namespace = {}
    sys.path.insert(0, str(snapshot / "tools"))
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(snapshot / "tools/verify.py"), "exec"), namespace)
    select = namespace["dw_active_unwind_names"]
    report = json.loads((build / "build-report.json").read_bytes())
    assert prep.sha(Path(report["executable"]).read_bytes()) == report["sha256"]
    selected = select(report)
    retired = [row for row in report["replacements"] if row.get("retired")]
    assert retired, "Fixture must exercise an actual retired original range"
    assert len(selected) == len(report["replacements"]) - len(retired) + 3
    assert not {row["symbol"] for row in retired} & set(selected)
    malformed = []

    def rejects(label, mutate):
        changed = copy.deepcopy(report)
        dead = next(row for row in changed["replacements"] if row.get("retired"))
        mutate(changed, dead)
        try:
            select(changed)
        except ValueError:
            malformed.append(label)
        else:
            raise AssertionError("Malformed ownership accepted: " + label)

    rejects("missing active owner", lambda r, d: d.update(owner="missing"))
    rejects("wrong original entry", lambda r, d: d.update(entry=d["entry"] + 1))
    rejects("standalone retired symbol", lambda r, d: r["symbols"].update({d["symbol"]: 0x123000}))
    rejects("standalone retired placement", lambda r, d: r["placements"].append(dict(symbol=d["symbol"], rva=0x123000, size=8)))
    rejects("missing active emitted symbol", lambda r, d: r["symbols"].pop(d["owner"]))
    rejects("missing active emitted placement", lambda r, d: r.update(placements=[p for p in r["placements"] if p["symbol"] != d["owner"]]))
    rejects("empty retired range", lambda r, d: d.update(end=d["begin"]))
    rejects("overlapping original ranges", lambda r, d: d.update(begin=d["entry"] + 1))
    rejects("duplicate original ownership", lambda r, d: r["replacements"].append(copy.deepcopy(d)))
    rejects("retired instruction label", lambda r, d: r["rva_map"]["interior_reference_resolutions"].append(dict(original_rva=d["begin"], mapped_rva=0x123000, symbol=d["owner"])))
    rejects("retired inbound branch", lambda r, d: r["rva_map"]["widened_branches"].append(dict(target=d["begin"])))
    print("PASS exact upstream preservation and", len(malformed), "malformed retired ledgers", flush=True)
    verifier = load("dw_private_verifier", snapshot / "tools/verify.py")
    image = pefile.PE(report["executable"])
    unwind_cases, leaves = verifier.windows_image_mapping(Path(report["executable"]), image, report)
    result = dict(passed=True, executable_sha256=report["sha256"], prepared_sha256=prep.sha(prepared),
                  upstream_sha256=prep.sha(upstream), actual_functions=len(selected),
                  windows_virtual_unwind_cases=unwind_cases, verified_frameless_leaves=leaves,
                  malformed_ledgers_rejected=malformed, upstream_other_bytes_exact=True,
                  sealed_snapshot_guards=sealed_guards,
                  retired_logical_ranges=retired, live_game_tested=False)
    print("PASS actual Windows SEC_IMAGE / RtlVirtualUnwind", unwind_cases, "cases", flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "data"):
        raise ValueError("Keep validator evidence in the private workspace")
    result = check(args.snapshot.resolve(), args.build.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
