"""Audit retained original Replay BR/CP mission contracts without launching a game."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    folder = ROOT / "data/remaining-br-cp-20261011"
    folder.mkdir(exist_ok=True)
    recovery_path = ROOT / "data/remaining-contracts-20261009/native-challenge-scripts/recovery-receipt.json"
    recovery = json.loads(recovery_path.read_bytes())
    for source in (recovery["source"], *recovery["source"]["patches"]):
        assert digest(Path(source["path"])) == source["sha256"]
    row = next(row for row in recovery["records"] if row["name"] == "scripts/cp_mp/challenges.gsc")
    script = ROOT / row["decompiled_path"]
    assert digest(script) == row["decompiled_sha256"]
    assert digest(script.with_suffix(".gscbin")) == row["payload_sha256"]
    text = script.read_text()
    assert '"match_placement", var_2, var_0, getoperators()' in text
    assert 'var_5 = [ 0, 0 ];' in text and '"assist", var_5, var_4, var_6' in text
    assert "usedkillstreak( var_0 )\n{\n\n}" in text
    parser_path = ROOT / "data/remaining-kill-modifiers-20261010/challenge-parser-verified.json"
    parser = json.loads(parser_path.read_bytes())
    assert parser["target_image_sha256"] == SHA
    fixtures = {row.get("fixture_label"): row for row in parser["cases"]}
    selected = [fixtures[key] for key in ("placement_br_15", "placement_br_16", "br_victim_downed", "br_attacker_downed", "br_equipment_downed")]
    assert selected[0]["values"] == [24, 15, 0]
    assert selected[1]["values"] == [24, 16, 0]
    assert all(row["accepted"] for row in selected)
    (folder / "native-cases.json").write_text(json.dumps(selected, indent=2) + "\n")
    result = dict(passed=True, target_image_sha256=SHA,
                  evidence=[dict(path=str(path.relative_to(ROOT)), sha256=digest(path)) for path in (recovery_path, script, script.with_suffix(".gscbin"), parser_path)],
                  implemented_stages=[50017, 50018, 50025, 50032, 50039, 50046, 50053, 50060, 50067, 50074, 50081, 50088],
                  remaining=dict(vehicle_assists=[50013, 50045, 50080], occupied_vehicle_destruction=[50020, 50056, 50087], coop=list(range(10057, 10070))),
                  limits=["Assist packets contain no vehicle-state field.", "Vehicle explosion player-kill flags do not identify one distinct occupied vehicle destruction.", "CP operations require verified public family eligibility, operation identity, owner and CP producers; cp_complete parser acceptance alone is insufficient.", "Shipped usedkillstreak function is empty; killstreak_end must not count failed, cancelled or duplicate uses.", "Decompiled producer flow is supporting context; packet field positions are verified original native parser execution."])
    output = ROOT / "validation/20261011-replay-br-cp-contracts.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=True, stages=len(result["implemented_stages"]), output=str(output))))


if __name__ == "__main__":
    main()
