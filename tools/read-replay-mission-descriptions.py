"""Recover the complete Localize tail and its prior-string aliases.

Only the observed inline-name type-41 tail is supported. The stream prefix
is inferred by intersecting all prior-string reference constraints; ambiguity
is rejected rather than selecting a convenient text by proximity.
"""
import hashlib
import json
from pathlib import Path
import struct
import re
import argparse

ROOT = Path(__file__).resolve().parents[1]

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--decode-receipt", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
receipt_path = args.decode_receipt.resolve()
assert args.output.resolve().is_relative_to(ROOT)
receipt = json.loads(receipt_path.read_bytes())
body_path = receipt_path.parent / receipt["final_body_relative_path"]
raw = body_path.read_bytes()
assert hashlib.sha256(raw).hexdigest() == receipt["final_body_sha256"]
table = receipt["xasset_table"]
types = [struct.unpack_from("<I", raw, table["asset_table_offset"] + 16 * i)[0]
         for i in range(table["asset_count"])]
first = next(i for i, kind in enumerate(types) if kind == 41)
assert all(kind == 41 for kind in types[first:])
count = len(types) - first
inline = {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF}


def string(position):
    end = raw.index(0, position)
    return raw[position:end].decode("utf-8"), end + 1


roots = {}
for marker in inline:
    needle = struct.pack("<Q", marker)
    start = table["first_payload_offset"] - 1
    while (start := raw.find(needle, start + 1)) >= 0:
        if start + 16 >= len(raw):
            continue
        value_word = struct.unpack_from("<Q", raw, start + 8)[0]
        if value_word not in inline and value_word >> 32 != 5 and value_word != 0:
            continue
        try:
            name, after_name = string(start + 16)
            if not name or not all(32 <= ord(c) <= 126 for c in name):
                continue
            if value_word in inline:
                value, following = string(after_name)
            else:
                value, following = None, after_name
            roots[start] = dict(name=name, value=value, word=value_word,
                                after_name=after_name, following=following)
        except (UnicodeDecodeError, ValueError):
            continue

lengths = {}
for start in sorted(roots, reverse=True):
    following = roots[start]["following"]
    if following == len(raw):
        lengths[start] = 1
    elif following in lengths:
        lengths[start] = 1 + lengths[following]
starts = [start for start, length in lengths.items() if length == count]
assert len(starts) == 1, (count, starts, max(lengths.values(), default=0))
rows, strings, references = [], {}, []
position, relative = starts[0], 0
for _ in range(count):
    row = dict(roots[position], archive_offset=position)
    strings[relative] = row["name"]
    relative += row["after_name"] - position - 16
    if row["word"] in inline:
        strings[relative] = row["value"]
        relative += row["following"] - row["after_name"]
    elif row["word"]:
        references.append((row["word"] & 0xFFFFFFFF, relative, row))
    else:
        row["value"] = ""
    rows.append(row)
    position = row["following"]

prefixes = None
for token, current, row in references:
    options = {token - 1 - index for index in strings if index < current}
    prefixes = options if prefixes is None else prefixes & options
assert prefixes is not None and len(prefixes) == 1, (len(prefixes or ()), len(references))
prefix = next(iter(prefixes))
for token, current, row in references:
    offset = token - 1 - prefix
    assert offset < current
    row["value"] = strings[offset]
names = {row["name"]: row for row in rows}
assert len(names) == count
quest_path = ROOT / "validation/20261008-replay-quest-rewards-assets.json"
quests = json.loads(quest_path.read_bytes())
assert quests["all_native_rows_match"] and quests["supported_mission_stages"] == 232
resolved = []
for quest in quests["quests"]:
    row = names[quest["description"].lower()]
    assert isinstance(row["value"], str)
    resolved.append(dict(**quest, localized_description=row["value"],
                         plain_description=re.sub(r"\^[0-9]", "", row["value"]),
                         localize_root_offset=row["archive_offset"]))
proof = dict(source=receipt["source"], body_sha256=receipt["final_body_sha256"],
             tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             metadata_sha256=hashlib.sha256(quest_path.read_bytes()).hexdigest(),
             declared_localize_tail=count, recovered_localize_tail=len(rows),
             prior_string_references=len(references), unique_stream_prefix=prefix,
             quests=resolved, earning_rules_reconstructed=False)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(proof, indent=2) + "\n")
print("PASS:", count, "Localize rows;", len(resolved), "mission descriptions;", len(references), "prior-string references")
for row in resolved[:17]:
    print(row["id"], row["plain_description"])
