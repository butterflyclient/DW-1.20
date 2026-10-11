"""Audit original rapid/life/minute producers without inventing achievement credit."""
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    folder = ROOT / "data/remaining-multikill-20261011"
    folder.mkdir(exist_ok=True)
    recovery_path = ROOT / "data/remaining-match-outcomes-20261010/producer-recovery.json"
    recovery = json.loads(recovery_path.read_bytes())
    sys.path.insert(0, r"E:\replay-compiler\tools")
    from workstation_asset_codecs import inspect_gscbin, decompile_scriptfile, normalize_replay_scriptfile_for_gsc_tool, _convert_gsc_local_reference_scale
    config = json.loads(Path(r"E:\replay-compiler\replay-project.local.json").read_bytes())
    tool = Path(r"E:\replay-compiler") / config["tools"]["gsc"]["path"]
    assert digest(tool) == config["tools"]["gsc"]["sha256"]
    scan = []
    listeners = []
    for zone in recovery:
        if "export_index_path" not in zone:
            continue
        index_path = ROOT / zone["export_index_path"]
        assert digest(index_path) == zone["export_index_sha256"]
        index = json.loads(index_path.read_bytes())
        assert index["replay_executable_sha256"] == SHA
        count, empty, hits = 0, 0, []
        for row in index["items"]:
            payload_path = index_path.parent / row["payload_relative_path"]
            assert digest(payload_path) == row["payload_sha256"]
            blob = payload_path.read_bytes()
            count += 1
            if row["name"] == "$default":
                empty += 1
                continue
            if len(blob) == 24 and struct.unpack_from("<4I", blob) == (0x435347, 8, 0, 0):
                assert zlib.decompress(blob[16:]) == b""
                empty += 1
                continue
            source = zlib.decompress(inspect_gscbin(blob).compressed_source)
            if b"update_rapid_kill_buffered" not in source:
                continue
            target = folder / (zone["zone"] + "-" + str(row["asset_index"]) + ".gscbin")
            target.write_bytes(blob)
            decoded = decompile_scriptfile(blob, tool=tool, asset_name=target.stem)
            target.with_suffix(".gsc").write_text(decoded)
            hit = dict(zone=zone["zone"], asset_index=row["asset_index"], name=row["name"], sha256=row["payload_sha256"], retained_path=str(target.relative_to(ROOT)))
            hits.append(hit)
            if row["asset_index"] != 10695:
                assert 'waittill( "update_rapid_kill_buffered"' in decoded
                assert "reportchallengeuserevent" not in decoded
                listeners.append(hit)
            else:
                normalized = normalize_replay_scriptfile_for_gsc_tool(blob)
                assert _convert_gsc_local_reference_scale(normalized, to_replay=True) == blob
                normalized_path = folder / "rapid-normalized.gscbin"
                normalized_path.write_bytes(normalized)
                run = subprocess.run([str(tool), "-g", "iw8", "-s", "pc", "-m", "disasm", normalized_path.name], cwd=folder, text=True, capture_output=True)
                assert run.returncode == 0, run.stdout + run.stderr
                assembly = (folder / "disassembled/iw8/rapid-normalized.gscasm").read_text()
                routine = assembly.split("sub:updaterecentkills\n", 1)[1].split("end:updaterecentkills", 1)[0]
                assert 'OP_GetString "update_rapid_kill_buffered"' in routine
                assert "OP_GetFloat 4" in routine
                assert "reportchallengeuserevent" not in routine
        scan.append(dict(zone=zone["zone"], scanned_payloads=count, defaults=empty, hits=hits, index_sha256=digest(index_path)))
    assert {row["asset_index"] for row in listeners} == {10776, 10777, 10782}
    parser_path = ROOT / "data/remaining-kill-modifiers-20261010/challenge-parser-verified.json"
    parser = json.loads(parser_path.read_bytes())
    assert parser["target_image_sha256"] == SHA
    death = next(row for row in parser["cases"] if row["name"] == "death")
    assert death["accepted"] and death["parameter_count"] == 0 and death["values"] == []
    descriptions_path = ROOT / "data/remaining-contracts-20261009/mission-descriptions-eng_ui-verified.json"
    ids = [1580,1581,1582,1583,1584,1585,10041,10045,10049,10132,10133,*range(10136,10142)]
    descriptions = [row for row in json.loads(descriptions_path.read_bytes())["quests"] if row["id"] in ids]
    assert len(descriptions) == len(ids)
    result = dict(audit_passed=True, target_image_sha256=SHA, tool_sha256=digest(Path(__file__)), scanned_zones=scan,
                  rapid_native_rule="rearm a 4.0-second wait after every kill; emit buffered script notification; no rapid counter field in native seven-parameter kill packet",
                  rapid_listeners="airstrike kill count, chopper gunner dialog, gunship dialog; none reports achievement events",
                  death_packet=death, descriptions=descriptions,
                  groups=[dict(ids=[1580,1582,1584,10041,10132], required="native rapid ordinal/chain identity, or ordered subsecond occurrence times and original count/overlap policy", missing="uploaded rapid chain/ordinal; native 4-second timer state; exact threshold boundary from serialized kill timestamps"),
                          dict(ids=[1581,1583,1585,10045,10133], required="ordered per-owner kills/deaths, life start/reset and repeated threshold consumption policy", missing="life sequence/generation and original repeated threshold consumption policy; death is present as a zero-param marker; native SDK submission/processing order, life generation and original repeated threshold policy remain unbound; parameter count alone does not select the four named aggregate caches"),
                          dict(ids=[10049], required="ordered per-owner kills/deaths, reset at stage activation/start/death/end", missing="authoritative ordering/replay identity still requires root integration proof; native SDK submission/processing and event occurrence order remain unproven; death is not inferred to use an aggregate cache; this non-repeating target1 criterion needs no time window"),
                          dict(ids=list(range(10136,10142)), required="exact occurrence timestamp precision, native 60-second window origin/boundaries and repeated/overlap policy", missing="60-second producer/window/counter; precise window and consumption semantics")],
                  scope="Hash-verified original ScriptFile payload scan plus disassembled rapid producer and native parser death packet. No backend earning, game execution or absence claim beyond scanned zones.")
    (ROOT / "validation/20261011-multikill-mission-contracts.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(audit_passed=True, stages=len(ids), scanned_payloads=sum(row["scanned_payloads"] for row in scan))))


if __name__ == "__main__":
    main()
