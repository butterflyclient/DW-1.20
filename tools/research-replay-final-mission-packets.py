"""Join original mission packets and execute additional terminal packets."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT)
    parent_path = ROOT / "data/remaining-kill-modifiers-20261010/challenge-parser-verified.json"
    mp_path = ROOT / "validation/20261011-replay-mp-mission-events.json"
    proof = json.loads(parent_path.read_bytes())
    mp = json.loads(mp_path.read_bytes())
    base_tool = ROOT / "tools/research-challenge-event-parser.py"
    assert proof["target_image_sha256"] == mp["target_image_sha256"]
    assert mp["passed"] and mp["base_parser_tool_sha256"] == digest(base_tool)
    assert len(proof["cases"]) == 379 and len(mp["cases"]) == 123
    for index, row in enumerate(mp["cases"]):
        addition = copy.deepcopy(row)
        if addition["accepted"]:
            addition["fixture_label"] = f"mp_action_{index}"
        proof["cases"].append(addition)
    previous = sys.argv
    try:
        sys.argv = [str(base_tool), "--output", str(args.output.parent / "base-reexecution.json")]
        native = runpy.run_path(str(base_tool))["case"]
    finally:
        sys.argv = previous
    terminal = []
    for mode in (6, 7, 25, 26):
        row = native("start_match", str(mode))
        assert row["accepted"] and row["values"] == [987654321, mode]
        row["fixture_label"] = f"complete_start_{mode}"
        terminal.append(row)
        for outcome in (0, 1, 2, 3):
            row = native("end_match", f"{mode},{outcome},0,2,3,wyatt_western|spetsnaz_eastern")
            assert row["accepted"] and len(row["values"]) == 5
            assert row["values"][0] & 0xFFFFFFFF == mode and row["values"][1] == outcome
            row["fixture_label"] = f"complete_end_{mode}_{outcome}"
            terminal.append(row)
    proof["cases"].extend(terminal)
    ground_path = ROOT / "validation/20261011-ground-war-mission-contracts.json"
    ground = json.loads(ground_path.read_bytes())
    assert ground["original_contract_verified"] and ground["target_image_sha256"] == proof["target_image_sha256"]
    assert len(ground["cases"]) == 12
    proof["cases"].extend(ground["cases"])
    assert len(proof["cases"]) == 534
    labels = [row["fixture_label"] for row in proof["cases"] if "fixture_label" in row]
    assert len(labels) == len(set(labels))
    proof.update(finalization_tool_sha256=digest(Path(__file__)),
                 finalization_parent_sha256=digest(parent_path),
                 mp_contract_sha256=digest(mp_path), finalization_cases=143,
                 groundwar_contract_sha256=digest(ground_path), groundwar_cases=12,
                 terminal_original_cases=20)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("Verified 534 original mission parser cases")


if __name__ == "__main__":
    main()
