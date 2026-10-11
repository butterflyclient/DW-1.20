"""Execute original Replay parser packets and retain native producer evidence."""

import sys
import json
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / "data/remaining-mp-missions-20261011/parser-probes.json"
out.parent.mkdir(parents=True, exist_ok=True)
sys.argv = [
    str(ROOT / "tools/research-challenge-event-parser.py"),
    "--output",
    str(out),
]
source = (
    (ROOT / "tools/research-challenge-event-parser.py")
    .read_text()
    .split("\nrows = []\n")[0]
)
ns = {"__file__": str(ROOT / "tools/research-challenge-event-parser.py")}
exec(compile(source, ns["__file__"], "exec"), ns)
rows = []
for name, params in [
    ("killstreak_end", "uav,11,22,33,44,55,66, "),
    ("field_end", "super_ammo_drop,17, "),
    ("field_end", "super_tac_cover,17, "),
    ("hack", "claymore,specialty_spotter"),
    ("hack", "claymore,no_perks"),
    ("killstreak", "uav, "),
    ("fieldupgrade", "super_ammo_drop, "),
    ("scavenger", "1, "),
    ("resupply", "1, "),
]:
    try:
        rows.append(ns["case"](name, params))
    except Exception as e:
        rows.append({"name": name, "input": params, "error": str(e)})


# Additional packed attachment cases use the same original-instruction runner.
def kill_input(attachments):
    return f"1|2,iw8_sm_mpapa5_mp,16,0,unknown_operator,6,{attachments},no_perks,1,no_super,0,MOD_RIFLE_BULLET,0,0"


for ref in (
    "no_attachments",
    "laser",
    "laserir",
    "laserrange",
    "laserbalanced",
    "laserads",
    "laser|silencer",
    "silencer|laser",
    "reflex|laser|silencer",
    "silencer",
    "silencer2",
    "silencer3",
    "gunperk_fastmelee",
    "barrel",
    "barrel_long",
):
    try:
        rows.append(ns["case"]("kill", kill_input(ref)))
    except Exception as e:
        rows.append({"name": "kill", "input": ref, "error": str(e)})
for params in (
    "1,specialty_spotter",
    "1,specialty_ghost|specialty_spotter",
    "1,specialty_ghost|specialty_doubletime|specialty_spotter",
    "2,specialty_spotter",
    "-1,specialty_spotter",
):
    rows.append(ns["case"]("hack", params))

for ref in (
    "silencer4",
    "reflex|gripvert|xmags|stockl|laser",
    "reflex|gripvert|xmags|stockl|gunperk_fastmelee",
    "reflex|gripvert|xmags|stockl|silencer",
    "reflex|laser|silencer|gripvert|xmags",
    "frontlight",
    "frontlong",
    "frontsilenced",
):
    rows.append(ns["case"]("kill", kill_input(ref)))
for cause in ("MOD_MELEE", "MOD_MELEE_ALT", "MOD_HEAD_SHOT"):
    rows.append(
        ns["case"](
            "kill", kill_input("gunperk_fastmelee").replace("MOD_RIFLE_BULLET", cause)
        )
    )

for name, params in (
    ("field_end", "super_ammo_drop,0, "),
    ("field_end", "super_ammo_drop,-1, "),
    ("field_end", "unknown_super,17, "),
    ("field_end", "super_tac_cover,0, "),
):
    rows.append(ns["case"](name, params))

# Retained native callbacks pass the per-upgrade result and native streak kills.
for ref in (
    "super_recon_drone",
    "super_emp_drone",
    "super_support_box",
    "super_trophy",
    "super_deadsilence",
    "super_tac_insert",
    "super_weapon_drop",
):
    for value in (0, 1, 17):
        rows.append(ns["case"]("field_end", f"{ref},{value}, "))
for ref in (
    "uav",
    "airdrop",
    "counter_uav",
    "radar_drone_overwatch",
    "manual_turret",
    "toma_strike",
    "precision_airstrike",
    "pac_sentry",
    "chopper_gunner",
):
    for kills in (0, 17):
        rows.append(ns["case"]("killstreak_end", f"{ref},1234,5678,{kills},0,0,0, "))
for params in (
    "unknown_streak,1234,5678,17,0,0,0, ",
    "specialist_perk_1,1234,5678,17,0,0,0, ",
    "uav,1234,5678,-1,0,0,0, ",
):
    rows.append(ns["case"]("killstreak_end", params))


# Verify every retained native streak ID, including specialist exclusions.
import csv

asset_root = Path(
    r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable"
)
table = next((asset_root / "loot").glob("killstreak_ids.csv.*.csv"))
assert (
    hashlib.sha256(table.read_bytes()).hexdigest()
    == "1dfbb3ea0777925d6712a8c497079a4b3bbb65186a738b36290ee5a9d44b19ed"
)
for fields in csv.reader(table.read_text(encoding="utf-8-sig").splitlines()):
    row = ns["case"]("killstreak_end", f"{fields[1]},1234,5678,17,0,0,0, ")
    assert row["values"] == [int(fields[0]), 17, 0, 0, 0, 1234, 5678], row
    rows.append(row)

# Resolve shipped English labels through the existing complete Localize tail
# decoder. It rejects ambiguous prior-string aliases before exposing names.
localize_tool = ROOT / "data/remaining-contracts-20261009/read-mission-descriptions.py"
sys.argv = [str(localize_tool), "--zone", "eng_global_mp"]
localize = {"__file__": str(localize_tool)}
exec(
    compile(
        localize_tool.read_text().split("\nquests = json.loads")[0],
        str(localize_tool),
        "exec",
    ),
    localize,
)
labels = {
    "killstreaks/radar_drone_overwatch": "Personal Radar",
    "killstreaks/manual_turret": "Shield Turret",
    "killstreaks/toma_strike": "Cluster Strike",
    "killstreaks/pac_sentry": "Wheelson",
    "killstreaks/precision_airstrike": "Precision Airstrike",
    "killstreaks/chopper_gunner": "Chopper Gunner",
}
label_rows = []
for key, value in labels.items():
    row = localize["names"][key]
    assert row["value"] == value
    label_rows.append(row)
label_proof = {
    "source": localize["receipt"]["source"],
    "body_sha256": localize["receipt"]["final_body_sha256"],
    "rows": label_rows,
    "decoder_sha256": hashlib.sha256(localize_tool.read_bytes()).hexdigest(),
}
(ROOT / "data/remaining-mp-missions-20261011/native-killstreak-labels.json").write_text(
    json.dumps(label_proof, indent=2) + "\n"
)

assert all("error" not in row for row in rows), rows
assert rows[0]["values"] == [70000, 33, 44, 55, 66, 11, 22]
assert rows[1]["values"] == [280019, 17, 0]
assert rows[2]["values"] == [280009, 17, 0]
for row in rows:
    if row["name"] == "kill":
        refs = row["input"].split(",")[6].split("|")
        if refs == ["no_attachments"]:
            assert row["values"][5] & 255 == 255
        elif len(refs) <= 5:
            expected = {
                "laser": 54,
                "laserir": 55,
                "laserrange": 56,
                "laserbalanced": 57,
                "laserads": 58,
                "silencer": 35,
                "silencer2": 36,
                "silencer3": 37,
                "silencer4": 184,
                "gunperk_fastmelee": 120,
                "reflex": 5,
                "gripvert": 38,
                "xmags": 51,
                "stockl": 59,
            }
            known = [expected[ref] for ref in refs if ref in expected]
            assert row["values"][3] == sum(
                value << (12 * slot) for slot, value in enumerate(known)
            ), row
            assert row["values"][5] & 255 == len(known), row
sources = []
for path in sorted(
    (ROOT / "data/remaining-mp-missions-20261011/native-producers").glob("*.gsc")
):
    sources.append(
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    )
import hashlib

for rel in (
    "data/remaining-contracts-20261009/native-challenge-scripts/scripts/cp_mp/challenges.gsc",
    "data/remaining-match-outcomes-20261010/common_base_mp/10845.gsc",
    "data/remaining-match-outcomes-20261010/common_base_mp/10847.gsc",
):
    path = ROOT / rel
    sources.append(
        {"path": rel, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
producer_receipt = (
    ROOT / "data/remaining-mp-missions-20261011/native-producers/receipt.json"
)
producer_records = json.loads(producer_receipt.read_bytes())
base_producers = json.loads(
    (
        ROOT / "data/remaining-match-outcomes-20261010/producer-recovery.json"
    ).read_bytes()
)
producer_zones = []
for zone in base_producers:
    if zone["zone"] not in ("global_mp", "common_base_mp"):
        continue
    index_path = ROOT / zone["export_index_path"]
    assert (
        hashlib.sha256(index_path.read_bytes()).hexdigest()
        == zone["export_index_sha256"]
    )
    producer_zones.append(
        {
            key: zone[key]
            for key in (
                "zone",
                "source",
                "body_sha256",
                "export_index_path",
                "export_index_sha256",
            )
        }
    )
producer_chain = {
    "receipt_sha256": hashlib.sha256(producer_receipt.read_bytes()).hexdigest(),
    "zones": producer_zones,
    "scripts": producer_records,
}

proof = {
    "passed": True,
    "target_image_sha256": hashlib.sha256(ns["raw"]).hexdigest(),
    "original_parser_range": ["0x140F35980", "0x140F385DC"],
    "base_parser_tool_sha256": hashlib.sha256(
        (ROOT / "tools/research-challenge-event-parser.py").read_bytes()
    ).hexdigest(),
    "sources": sources,
    "producer_chain": producer_chain,
    "killstreak_labels": label_proof,
    "case_count": len(rows),
    "cases": rows,
}
out.write_text(json.dumps(proof, indent=2) + "\n")
public = ROOT / "validation/20261011-replay-mp-mission-events.json"
public.write_text(json.dumps(proof, indent=2) + "\n")
print(json.dumps({"passed": True, "case_count": len(rows), "proof": str(public)}))
