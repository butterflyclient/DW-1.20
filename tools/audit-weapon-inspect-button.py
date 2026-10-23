"""Read-only Replay usercmd high-button audit. Never assembles or builds code.

The literal scan covers the original .text. The narrower sign/subword scan is
deliberately reported separately: it is a review aid, not a whole-program
pointer/dataflow proof. Supply --details to review all matching instructions.
"""

import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path
import re
import sqlite3

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
DATABASE = IMAGE.with_suffix(IMAGE.suffix + ".sqlite")
MASK = (1 << 64) - 1
# Native movement/weapon, server player/use, client input, and input finishing.
# Broad intervals include unnamed helpers, rather than trusting names alone.
REGIONS = ((0x1100000, 0x1188000), (0x11ECD40, 0x11EF150),
           (0x1260000, 0x1289000), (0x15ABBD0, 0x15C2000),
           (0x16C5000, 0x16C7000), (0x1719640, 0x1719900),
           (0x178A670, 0x178AA00))
NUMBER = re.compile(r"(?<![\w])(?:0x[0-9a-f]+|[0-9]+)(?![\w])")


def audit(details=False):
    raw = IMAGE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == IMAGE_SHA
    pe = pefile.PE(data=raw, fast_load=True)
    text = next(section for section in pe.sections if section.Name.rstrip(b"\0") == b".text")
    catalog = json.loads((ROOT / "data/dw-client/compiler-base/generated/function-catalog.json").read_bytes())
    assert catalog["image_sha256"] == IMAGE_SHA
    functions = sorted((row["rva"], row) for row in catalog["functions"])
    starts = [item[0] for item in functions]

    def owner(address):
        index = bisect.bisect_right(starts, address) - 1
        return functions[index][1] if index >= 0 else {}

    def record(address, mnemonic, operands, **extra):
        row = owner(address)
        return dict(rva=hex(address), instruction=f"{mnemonic} {operands}",
                    owner_rva=hex(row.get("rva", 0)), identity=row.get("id"), **extra)

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.skipdata = True
    high_masks = []
    bit_indexes = []
    sign_branches = []
    narrow_masks = []
    history = collections.deque(maxlen=8)
    instructions = 0
    for address, size, mnemonic, operands in decoder.disasm_lite(text.get_data(), text.VirtualAddress):
        instructions += 1
        numbers = [int(value, 0) for value in NUMBER.findall(operands)]
        for value in numbers:
            if value > 0xFFFFFFFF and value <= MASK and value != MASK:
                # Sparse high bits and sparse cleared high bits are the useful
                # button masks; dense unrelated pointers/constants stay visible.
                high_masks.append(record(address, mnemonic, operands,
                    value=hex(value), set_bits=value.bit_count(),
                    cleared_bits=(value ^ MASK).bit_count()))
        if mnemonic in ("bt", "bts", "btr", "btc") and numbers and numbers[-1] in (60, 61, 62, 63):
            bit_indexes.append(record(address, mnemonic, operands, bit=numbers[-1]))
        scoped = any(low <= address < high for low, high in REGIONS)
        if scoped and mnemonic in ("js", "jns", "sets", "setns", "cmovs", "cmovns"):
            sign_branches.append(record(address, mnemonic, operands,
                preceding=[f"{hex(a)}: {m} {o}" for a, m, o in history]))
        if scoped and mnemonic in ("and", "or", "xor", "test", "cmp"):
            immediate_text = operands.rsplit(",", 1)[-1].strip()
            if immediate_text in ("0x80", "0x7f", "0x80000000", "0x7fffffff"):
                narrow_masks.append(record(address, mnemonic, operands))
        history.append((address, mnemonic, operands))

    # Names/pseudocode are explanatory only; instructions above come from the
    # digest-verified native executable, not the SQLite assembly export.
    database = sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True)
    names = {int(row[0]): row[1] for row in database.execute("SELECT rva,name FROM functions")}
    for collection in (high_masks, bit_indexes, sign_branches, narrow_masks):
        for row in collection:
            row["name"] = names.get(int(row["owner_rva"], 16))
    high_bit_masks = [row for row in high_masks if
                     (int(row["value"], 16) & (1 << 63) and row["set_bits"] <= 8) or
                     (not int(row["value"], 16) & (1 << 63) and row["cleared_bits"] <= 8)]
    scoped_high = [row for row in high_bit_masks if any(
        low <= int(row["rva"], 16) < high for low, high in REGIONS)]
    def native_proof(address, length):
        body = pe.get_data(address, length)
        return dict(rva=hex(address), bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            instructions=[f"{hex(a)}: {m} {o}" for a, _, m, o in
                          decoder.disasm_lite(body, address)])

    # These are conflicts, not heuristic absences. The server also consumes bit
    # 63 through a signed 64-bit test, demonstrating why literal-only audits fail.
    proofs = {
        "bit44_mount_modifier_writer": native_proof(0x15B5AAB, 0x37),
        "bit63_location_alt_writer": native_proof(0x15B9A5F, 0x21),
        "bit63_or14_location_server_mask": native_proof(0x11EEDCF, 10),
        "bit63_location_server_implicit_sign": native_proof(0x11EEFA1, 0x42),
        "bit63_or14_location_client_mask": native_proof(0x17197B9, 10),
    }
    assert "0x8000000000000000" in " ".join(proofs["bit63_location_alt_writer"]["instructions"])
    assert "test rcx, rcx" in " ".join(proofs["bit63_location_server_implicit_sign"]["instructions"])
    assert "cmovns" in " ".join(proofs["bit63_location_server_implicit_sign"]["instructions"])
    report = dict(image_sha256=IMAGE_SHA, text_rva=hex(text.VirtualAddress),
        text_bytes=len(text.get_data()), decoded_instructions=instructions,
        scope=[(hex(low), hex(high)) for low, high in REGIONS],
        global_sparse_bit63_masks=len(high_bit_masks), global_bit_indexes=bit_indexes,
        scoped_bit63_masks=scoped_high,
        scoped_sign_consumer_count=len(sign_branches),
        scoped_subword_mask_count=len(narrow_masks),
        verified_conflict_proofs=proofs, verified_unused_bit=None,
        conclusion="Bit 44 conflicts with Replay mount input. Bit 63 conflicts with alternate location confirmation. No unused usercmd button has been established.",
        limitations="The whole-section linear sweep includes padding/data and attributes owners by nearest catalog start. No whole-program pointer or interprocedural dataflow proof; signed branches and subword masks require semantic review. Exact conflict slices are independently decoded at known native instruction boundaries.")
    if details:
        report["global_sparse_bit63_mask_details"] = high_bit_masks
        report["scoped_sign_consumers"] = sign_branches
        report["scoped_subword_masks"] = narrow_masks
    database.close()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--details", action="store_true")
    parser.add_argument("--output", type=Path,
                        help="Optionally save the JSON receipt at this explicit path")
    arguments = parser.parse_args()
    result = json.dumps(audit(arguments.details), indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(result, encoding="utf-8")
        print(f"Wrote read-only native audit receipt: {arguments.output}")
    else:
        print(result)
