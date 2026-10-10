"""Execute original Replay parser instructions for overlapping target flags."""

import argparse
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    original = ROOT / "tools/research-challenge-event-parser.py"
    # This harness retains the original emulator/CRT/table boundaries and all
    # 221 existing cases. Its baseline tool and historical receipts stay intact.
    environment = runpy.run_path(str(original))
    proof = json.loads(output.read_bytes())
    assert len(proof["cases"]) == 221
    case, kill_input = environment["case"], environment["kill_input"]
    targets = {
        "air_streak_target": 2 | 4,
        "ground_streak_target": 2 | 8,
        "support_streak_target": 2 | 4 | 16,
        "ground_vehicle_target": 32 | 8,
        "streak_vehicle_target": 2 | 32 | 8,
        "agent_soldier_target": 512,
        "agent_juggernaut_target": 128,
        "agent_shield_target": 256,
        "agent_suicide_target": 1024,
        "unknown_target_bit": 0x8000,
    }
    for label, mask in targets.items():
        row = case("kill", kill_input("iw8_pi_golf21_mp", target_type=mask))
        assert row["accepted"] and row["parameter_count"] == 7
        assert row["values"][5] >> 16 & 0xFFFF == mask
        row["fixture_label"] = label
        proof["cases"].append(row)
    proof.update(base_tool_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 target_mask_cases=targets)
    output.write_text(json.dumps(proof, indent=2) + "\n")
    print("Verified 231 original parser cases, including ten overlapping/subtype masks")


if __name__ == "__main__":
    main()
