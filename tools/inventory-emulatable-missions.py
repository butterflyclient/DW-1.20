"""Write a source-bound stage partition without claiming a combined build."""

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def evidence(relative):
    path = ROOT / relative
    return {"path": relative, "sha256": sha(path.read_bytes())}


canonical_path = (
    "data/remaining-contracts-20261009/mission-descriptions-eng_ui-verified.json"
)
canonical = json.loads((ROOT / canonical_path).read_bytes())["quests"]
quests = {row["id"]: row for row in canonical}
assert len(quests) == 232
header = (ROOT / "src/replay_quest_data.h").read_text()
header_rows = re.findall(
    r'\{(\d+), (\d+), (\d+), (\d+), (\d+), (\d+), "([^"]+)", "([^"]+)"\}', header
)
assert len(header_rows) == 232
for row in header_rows:
    identity, target, category, next_id, xp, item = map(int, row[:6])
    expected = quests[identity]
    assert (target, category, next_id, xp, item, row[6], row[7]) == (
        expected["target"],
        expected["category"],
        expected["next_id"],
        expected["xp_reward"],
        expected["item_reward"],
        expected["name"],
        expected["description"],
    )

base_commit = "c835073"
base_source = subprocess.check_output(
    ["git", "-C", str(ROOT), "show", base_commit + ":src/quest_services.cpp"]
)
base_fixture = subprocess.check_output(
    [
        "git",
        "-C",
        str(ROOT),
        "show",
        base_commit + ":tools/test-replay-quest-earning.py",
    ]
)
retained_fixture_path = "data/remaining-kill-modifiers-20261010/validation-cohort/tools/test-replay-quest-earning.py"
retained_fixture = (ROOT / retained_fixture_path).read_bytes()
assert base_fixture.replace(b"\n", b"\r\n") == retained_fixture
baseline_receipts = []
receipt_ids = None
for relative in (
    "data/remaining-kill-modifiers-20261010/windows-earning.json",
    "data/remaining-kill-modifiers-20261010/linux-earning.json",
):
    receipt = json.loads((ROOT / relative).read_bytes())
    assert receipt["passed"] and receipt["supported_stage_count"] == 127
    assert receipt["tool_sha256"] == sha(retained_fixture)
    direct = {
        int(v) for check in receipt["checks"] for v in re.findall(r"Stage (\d+)", check)
    }
    assert len(direct) == 108
    if receipt_ids is None:
        receipt_ids = direct
    else:
        assert receipt_ids == direct
    baseline_receipts.append(
        {
            **evidence(relative),
            "server_sha256": receipt["server_sha256"],
            "supported_stage_count": 127,
        }
    )

fixture_ast = ast.parse(base_fixture)
assignments = {}
for node in ast.walk(fixture_ast):
    if isinstance(node, ast.Assign):
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                assignments[target.id] = value
assert len(assignments["fixtures"]) == 57
assert set(assignments["fixtures"]) <= receipt_ids

grouped = [
    {
        "ids": [1558],
        "fixture_contract": "stim tests explicitly seed/complete1558",
        "receipt_check": "Stim counts native integer health rather than uses; fractional/zero/wrong-mode reports, exact target, XP/item/successor and retry are correct",
    },
    {
        "ids": sorted(assignments["br_pickups"]),
        "fixture_contract": "br_pickups dictionary and complete/retry loop",
        "receipt_check": "All eight BR weapon/cash/cache pickup stages consume original aggregated fields, clamp targets and preserve retries without MP-mode cross-credit",
    },
    {
        "ids": [50008, 50009, 50021, 50059, 50063],
        "fixture_contract": "literal five-stage native timer iteration",
        "receipt_check": "Five BR gas/driving/non-downed timers preserve fractional units and retries; seconds/minutes do not round up from milliseconds",
    },
    {
        "ids": sorted(assignments["actions"]),
        "fixture_contract": "actions dictionary and complete/retry loop",
        "receipt_check": "Five BR revive/Gulag stages distinguish the actor, self-revival and win/loss; malformed flags, MP mode and retries cannot duplicate credit",
    },
]
for group in grouped:
    for relative in (
        "data/remaining-kill-modifiers-20261010/windows-earning.json",
        "data/remaining-kill-modifiers-20261010/linux-earning.json",
    ):
        assert (
            group["receipt_check"]
            in json.loads((ROOT / relative).read_bytes())["checks"]
        )
    assert all(str(identity).encode() in base_fixture for identity in group["ids"])
base_ids = receipt_ids | {identity for group in grouped for identity in group["ids"]}
assert len(base_ids) == 127
# Stage selectors, not every numeric literal: MP weapon ID 50017 collides with an
# as-yet unsupported BR quest ID in the old source.
text = base_source.decode()
section = text[
    text.index("bool killMatches(") : text.index("std::string snapshotHash(")
]
selectors = set(map(int, re.findall(r"(?:case\s+|\bid\s*==\s*)(\d+)", section))) & set(
    quests
)
assert selectors == base_ids

mp_proof = json.loads(
    (ROOT / "validation/20261011-replay-mp-mission-helper.json").read_bytes()
)
assert mp_proof["passed"] and mp_proof["header_sha256"] == sha(
    (ROOT / "src/replay_mp_mission_earning.h").read_bytes()
)
mp_ids = set(mp_proof["stage_ids"])
assert len(mp_ids) == 29
br_proof = json.loads(
    (ROOT / "validation/20261011-replay-br-cp-contracts.json").read_bytes()
)
br_ids = set(br_proof["implemented_stages"])
assert len(br_ids) == 12
br_compile = json.loads(
    (ROOT / "validation/20261011-replay-br-cp-predicates.json").read_bytes()
)
assert br_compile["passed"] and br_compile["header_sha256"] == sha(
    (ROOT / "src/replay_br_cp_mission_earning.h").read_bytes()
)
match_source = (ROOT / "src/replay_match_completion.h").read_text()
match_ids = set(map(int, re.findall(r"case\s+(\d+)", match_source)))
assert len(match_ids) == 9
match_proof = json.loads(
    (ROOT / "validation/20261011-match-completion-contracts.json").read_bytes()
)
assert match_proof["passed"]
assert any(
    row["path"].replace("\\", "/") == "src/replay_match_completion.h"
    and row["sha256"] == sha(match_source.encode())
    for row in match_proof["evidence"]
)
assert not (
    base_ids & mp_ids
    or base_ids & br_ids
    or base_ids & match_ids
    or mp_ids & br_ids
    or mp_ids & match_ids
    or br_ids & match_ids
)
ground_proof = json.loads(
    (ROOT / "validation/20261011-ground-war-mission-helper.json").read_bytes()
)
assert ground_proof["passed"] and ground_proof["header_sha256"] == sha(
    (ROOT / "src/replay_groundwar_mission_earning.h").read_bytes()
)
ground_ids = set(ground_proof["stage_ids"])
assert ground_ids == {1515, 1572, 1591, 10048}
current_source = (ROOT / "src/quest_services.cpp").read_text()
assert '#include "replay_groundwar_mission_earning.h"' in current_source
assert (
    "replay_groundwar_mission_earning::captureProgress(id, objective)" in current_source
)
assert "replay_groundwar_mission_earning::killProgress(id, event)" in current_source
implemented = base_ids | mp_ids | br_ids | match_ids | ground_ids
assert len(implemented) == 181

blockers = []


def block(key, ids, required, missing, proofs):
    blockers.append(
        {
            "key": key,
            "stage_ids": ids,
            "required_original_contract": required,
            "missing_contract": missing,
            "evidence_paths": proofs,
            "classification": "excluded_until_contract_is_verified",
            "impossibility_claim": False,
        }
    )


mp_doc = [
    "docs/DW_MP_MISSION_EARNING_20261011.txt",
    "validation/20261011-replay-mp-mission-events.json",
]
br_doc = [
    "docs/DW_BR_CP_MISSIONS_20261011.txt",
    "validation/20261011-replay-br-cp-contracts.json",
]
rapid = ["validation/20261011-multikill-mission-contracts.json"]

block(
    "stun",
    [1554],
    "Count successful stuns of enemy players from the native stun producer and packed result.",
    "Parser acceptance does not establish which count/result distinguishes enemy stuns from other affected actors or duration.",
    mp_doc,
)
block(
    "scavenger",
    [1561],
    "Original Scavenger enemy-ammo pickup achievement report.",
    "Retained scripts update scavengerPickedUp locally; candidate scavenger/resupply event names are rejected by original ProcessParams.",
    mp_doc,
)
block(
    "spotter",
    [1564],
    "Successful enemy-equipment hack producer plus first-argument semantics and Spotter perk snapshot.",
    "Hack packing and native Spotter27 are verified; a successful equipment-hack caller and the meaning of Param0 remain unverified.",
    mp_doc,
)
block(
    "kill_chain",
    [1567],
    "Per-kill native Kill Chain eligibility attached to killstreak earnings.",
    "Terminal killstreak_end aggregates kills without a loadout perk snapshot; it cannot prove Kill Chain eligibility for those kills.",
    mp_doc,
)
block(
    "unsuppressed_barrel",
    [1599],
    "Exact original barrel remapping/classification and distinction from integral suppression.",
    "Generic attachment packing does not prove the requested unsuppressed barrel family.",
    mp_doc,
)
block(
    "golem_operator",
    [10002],
    "Original operator/faction selection mapping for the specified faction slot.",
    "A numeric operator ID alone does not prove Golem is selected in the requested faction/slot.",
    mp_doc,
)
block(
    "enemy_near_smoke",
    [10008],
    "Victim proximity to smoke at the kill.",
    "The retained Insmoke modifier describes the attacker; using it would credit a different condition.",
    mp_doc,
)
block(
    "specific_optics",
    [10042, 10043],
    "Exact native attachment remapping for Cronen LP945 Mini Reflex and Scout optic.",
    "Native family collapse/reticle class does not establish these requested named optic identities.",
    mp_doc,
)
block(
    "mp_vehicle_identity",
    [10032, 10033, 10034, 10035, 10036, 10037],
    "Original IAV/APC/Little Bird actor/weapon and vehicle destruction identity contracts.",
    "A generic actor/victim vehicle bit does not prove the exact vehicle, turret, runover, or one distinct destruction.",
    mp_doc,
)
block(
    "br_vehicle_assists",
    [50013, 50045, 50080],
    "Kill-or-assist reports with native attacker vehicle state.",
    "Original assist packet contains zero modifier words and no vehicle-state field. Counting only kills would omit qualifying assists.",
    br_doc,
)
block(
    "br_occupied_vehicle_destruction",
    [50020, 50056, 50087],
    "One unique enemy-occupied vehicle destruction report.",
    "Player-kill vehicle explosion/victim flags do not identify one destruction; counting occupants would overcount.",
    br_doc,
)
block(
    "co_op_operations",
    list(range(10057, 10070)),
    "Eligible public co-op operation family, operation identity/completion, and stage-specific actors/actions.",
    "Retained agent/weapon/operator bits and accepted cp_complete do not establish public operation ownership or successful operation completion; survival/trial cannot substitute.",
    br_doc,
)
block(
    "rapid_kills",
    [1580, 1582, 1584, 10041, 10132],
    "Original rapid grouping/consumption, exact event occurrence ordering and stage-specific weapon/optic qualifiers.",
    "Native script rearms a 4-second wait after kills, but emitted challenge packets carry no rapid counter; authoritative timestamps/order and consumption are unproven.",
    rapid,
)
block(
    "repeated_per_life",
    [1581, 1583, 1585, 10045, 10133],
    "Ordered owner kills/deaths and reset/consumption rules for each requested repeated streak.",
    "Native kill/death arrival ordering and repeat/reset semantics are not proven by packet acceptance.",
    rapid,
)
block(
    "headshots_single_life",
    [10049],
    "Two ordered qualifying pistol headshots in one continuous native life.",
    "Authoritative kill/death ordering and reset at activation/start/death/end still need integration evidence. This target1 criterion does not require a time window.",
    rapid,
)
block(
    "minute_windows",
    [10136, 10137, 10138, 10139, 10140, 10141],
    "Exact native 60-second window origin/boundaries, timestamp precision and overlapping/repeated-window policy.",
    "The 60-second producer/window/counter and repeated consumption semantics remain unverified.",
    rapid,
)
excluded = {identity for group in blockers for identity in group["stage_ids"]}
assert (
    len(excluded) == 51
    and implemented.isdisjoint(excluded)
    and implemented | excluded == set(quests)
)
assert sum(len(group["stage_ids"]) for group in blockers) == 51
sources = [
    canonical_path,
    "src/replay_quest_data.h",
    "src/quest_services.cpp",
    "src/quest_services.h",
    "src/replay_mp_mission_earning.h",
    "src/replay_br_cp_mission_earning.h",
    "src/replay_match_completion.h",
    "src/replay_groundwar_mission_earning.h",
    "tools/test-replay-quest-earning.py",
    retained_fixture_path,
    "validation/20261011-replay-mp-mission-events.json",
    "validation/20261011-replay-mp-mission-helper.json",
    "validation/20261011-replay-br-cp-contracts.json",
    "validation/20261011-replay-br-cp-predicates.json",
    "validation/20261011-match-completion-contracts.json",
    "validation/20261011-multikill-mission-contracts.json",
    "validation/20261011-ground-war-mission-contracts.json",
    "validation/20261011-ground-war-mission-helper.json",
]
by_block = {
    identity: group["key"] for group in blockers for identity in group["stage_ids"]
}
rows = []
for identity, row in sorted(quests.items()):
    status = (
        "implemented_source"
        if identity in implemented
        else "excluded_contract_unverified"
    )
    owner = (
        "baseline127"
        if identity in base_ids
        else (
            "mp_actions29"
            if identity in mp_ids
            else (
                "br12"
                if identity in br_ids
                else (
                    "mp_completion9"
                    if identity in match_ids
                    else "groundwar4" if identity in ground_ids else by_block[identity]
                )
            )
        )
    )
    rows.append(
        {
            "id": identity,
            "category": row["category"],
            "target": row["target"],
            "name": row["name"],
            "description_key": row["description"],
            "description": row["plain_description"],
            "status": status,
            "implementation_or_blocker": owner,
        }
    )
proof = {
    "partition_verified": True,
    "canonical_stage_count": 232,
    "implemented_stage_count": 181,
    "excluded_stage_count": 51,
    "implemented_stage_ids": sorted(implemented),
    "excluded_stage_ids": sorted(excluded),
    "implementation_groups": {
        "baseline127": sorted(base_ids),
        "mp_actions29": sorted(mp_ids),
        "br12": sorted(br_ids),
        "mp_completion9": sorted(match_ids),
        "groundwar4": sorted(ground_ids),
    },
    "baseline_evidence": {
        "commit": base_commit,
        "git_source_blob_sha256": sha(base_source),
        "git_fixture_blob_sha256": sha(base_fixture),
        "retained_crlf_fixture_sha256": sha(retained_fixture),
        "explicit_receipt_stage_count": 108,
        "grouped_fixture_stage_count": 19,
        "grouped_fixture_evidence": grouped,
        "compiled_receipts": baseline_receipts,
    },
    "blocker_groups": blockers,
    "stages": rows,
    "source_and_proof_hashes": [evidence(path) for path in sources],
    "validation_scope": {
        "baseline": "Prior exact-binary encrypted Windows/Linux receipts for 127 stages, matched to retained fixture bytes.",
        "new_mp_helper": "123 original parser cases and 1421 isolated compiled helper assertions.",
        "new_br_helper": "12 source predicates and isolated compiled helper assertions.",
        "new_mp_completion": "9 source predicates with original producer/outcome proof; combined lifecycle test owned by root.",
        "new_groundwar_helper": "4 source-integrated predicates; 12 original parser packets and 162 isolated MSVC helper checks. Combined validation owned by root.",
        "combined_build_ready": False,
        "combined_validation": "Pending root combined build and encrypted suites; this inventory is source/proof-bound, not a final binary readiness receipt.",
        "game_interactions": 0,
        "runtime_callbacks_proven_by_inventory": False,
    },
}
(ROOT / "validation/20261011-emulatable-stage-inventory.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
lines = [
    "REPLAY EMULATABLE MISSION SCOPE - 2026-10-11",
    "",
    "Exact source partition: 181 implemented stages; 51 excluded stages; 232 canonical rows.",
    "Implemented means a retained-contract earning predicate exists.",
    "Ground War source integration is present. Combined Windows/Linux",
    "builds and encrypted lifecycle tests belong to the root task and are pending here.",
    "This document makes no claim that excluded contracts are inherently impossible.",
    "",
    "BASELINE EVIDENCE",
    "",
    "The prior 127 stage baseline is bound to passed exact-binary Windows/Linux receipts.",
    "Their fixture SHA matches the retained CRLF bytes and commit c835073 fixture content.",
    "108 IDs appear explicitly in receipt checks; 19 more are covered by named Stim, pickup,",
    "timer and revive/Gulag fixture loops. Source stage selectors match this exact 127.",
    "A broad numeric scan is invalid: weapon ID 50017 collides with BR stage 50017.",
    "",
    "IMPLEMENTED IDS",
]
for group, ids in proof["implementation_groups"].items():
    lines += ["", group + " (" + str(len(ids)) + "):", ", ".join(map(str, ids))]
lines += ["", "EXCLUDED IDS AND ORIGINAL CONTRACT BLOCKERS"]
for group in blockers:
    lines += [
        "",
        group["key"] + " (" + ", ".join(map(str, group["stage_ids"])) + ")",
        "Required: " + group["required_original_contract"],
        "Missing: " + group["missing_contract"],
    ]
    for identity in group["stage_ids"]:
        lines.append(str(identity) + ": " + quests[identity]["plain_description"])
lines += [
    "",
    "BOUNDARIES",
    "",
    "Public ownership/version/gamemode, complete packet validation, exact target/reward,",
    "retry idempotency and stage activation/lifecycle remain the shared service gates.",
    "Generic public event names do not grant ownership. Generic vehicle or attacker-smoke",
    "flags do not replace distinct actor/victim/destruction criteria.",
    "Implemented stage 1566 accepts only nine proven native field-end types. Implemented stage 1516",
    "recognizes four proven muzzle suppressor families; integral suppressed barrel",
    "alternatives still need their own retained mapping. Terminal streak actions earn",
    "when the native terminal report arrives. This is not an instantaneous client hook.",
    "Unknown original semantics receive no approximate credit. Missing generic live UI",
    "callback evidence is a separate verification gate, not an impossibility finding.",
    "",
    "Exact232row details, source/proof SHA256 values, per-group evidence and all IDs:",
    "validation/20261011-emulatable-stage-inventory.json",
]
(ROOT / "docs/DW_EMULATABLE_SCOPE_20261011.txt").write_text("\n".join(lines) + "\n")
print(
    json.dumps(
        {
            "partition_verified": True,
            "implemented": len(implemented),
            "excluded": len(excluded),
            "new_groundwar_helper": "4 source-integrated predicates; 12 original parser packets and 162 isolated MSVC helper checks. Combined validation owned by root.",
            "combined_build_ready": False,
        }
    )
)
