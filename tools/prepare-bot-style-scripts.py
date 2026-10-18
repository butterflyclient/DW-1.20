"""Replay 1.20 preserving bot-style ScriptFile compiler and native package proof.

Input functions remain original; splice sites and relocation widths are typed.
A known stock method is usable ONLY for offline structural probes. Publication
requires the custom native method's verified binding receipt.
"""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib
import os
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load_tools(snapshot):
    global inspect_gscbin, _script_instructions, _GSC_LOCAL_REFERENCES, trace
    sys.path.insert(0, str(Path(snapshot) / "tools"))
    from workstation_asset_codecs import (
        inspect_gscbin as inspect,
        _script_instructions as instructions,
        _GSC_LOCAL_REFERENCES as references,
    )
    from trace_gscbin_source_cursor import trace as source_trace

    inspect_gscbin, _script_instructions, _GSC_LOCAL_REFERENCES, trace = (
        inspect,
        instructions,
        references,
        source_trace,
    )


EXPORT = Path("E:/replay-compiler/evidence/replay120-base-mp-scriptfiles")
OUT = None
IMAGE_HASH = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
METHOD_ID = 0x8787
SURVIVAL_METHOD_ID = 0x8788
MP_CLASS_METHOD_ID = 0x8789
GAS_STATE_METHOD_ID = 0x878A
ORIGINAL_HASHES = {
    "1827.gscbin": "b6ede9e3437161cd6eafa3de808d69a1d9e724e4f04b93d8a71fecf53ea28be2",
    "scripts/mp/bots/bots_gametype_br.gsc.gscbin": "e3abf284c279a21d6567dc93cc47f1e9d927ec92924af0cc1f6043e4dc62a58a",
    "scripts/mp/gametypes/br_weapons.gsc.gscbin": "06cead66afa73d00b678733f22d1d262ad95538c03eed3717f744072d97c7971",
}
POLICY_SOURCE_HASHES = {
    "2398.gscbin": "d34e9aa31ab93df67fed860fe508dea76103868bac82bbbb28225d7c016d25ae",
    "scripts/mp/gametypes/war.gsc.gscbin": "ca9a7e0f355dbc0c0d5be834a56f3e206a4f3fd3f88410c87b147f706c947234",
    "scripts/mp/gametypes/br.gsc.gscbin": "a45cb419d3a47fca11244ed273f515bd3d3a45fc62b1b1f45ff4cfaf0592d596",
    "2300.gscbin": "a3a929faf49ba9958ee15d467fe39746eabe5803fc875e51553b4daa36800e10",
}


@dataclass(frozen=True)
class Reference:
    operand: int
    width: int
    target: int
    scale: int
    kind: str


@dataclass(frozen=True)
class Edit:
    offset: int
    old: bytes
    new: bytes
    purpose: str
    function_token: int | str | None = None
    source: bytes = b""
    references: tuple[Reference, ...] = ()


@dataclass(frozen=True)
class Plan:
    file: str
    function_token: int | str
    edits: tuple[Edit, ...]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_private(path, data):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT / "data"):
        raise ValueError("Generated script output escaped the private DW workspace")
    payload = data.encode("utf-8") if isinstance(data, str) else data
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=path.name + ".", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_original_owners():
    import mmap

    manifest = json.loads((EXPORT / "manifest.json").read_bytes())
    names = {
        path.removesuffix(".gscbin"): digest for path, digest in ORIGINAL_HASHES.items()
    }
    owners = []
    for filename in ("common_base_mp.ff.dec", "common_base_mp.fp.patched.dec"):
        path = Path("E:/replay-compiler/assets/replay120-base-mp-decoded") / filename
        with path.open("rb") as stream, mmap.mmap(
            stream.fileno(), 0, access=mmap.ACCESS_READ
        ) as body:
            for name, digest in names.items():
                rows = [row for row in manifest["assets"] if row["name"] == name]
                if len(rows) != 1:
                    raise ValueError(
                        "Original common zone ScriptFile identity is ambiguous: " + name
                    )
                row = rows[0]
                at = int(row["source_offset"], 16)
                fields = struct.unpack_from("<QiiiIQQ", body, at)
                expected = (
                    0xFFFFFFFFFFFFFFFE,
                    row["compressed_len"],
                    row["decompressed_len"],
                    row["bytecode_len"],
                    0,
                    0xFFFFFFFFFFFFFFFE,
                    0xFFFFFFFFFFFFFFFE,
                )
                if fields != expected:
                    raise ValueError(
                        "Original complete ScriptFile root layout changed: " + name
                    )
                encoded = name.encode() + b"\0"
                if body[at + 40 : at + 40 + len(encoded)] != encoded:
                    raise ValueError("Original ScriptFile name changed")
                start = at + 40 + len(encoded)
                payload = (
                    struct.pack("<4I", 0x435347, *fields[1:4])
                    + body[start : start + fields[1] + fields[3]]
                )
                if sha(payload) != digest:
                    raise ValueError(
                        "Original common zone or final patch changed ScriptFile bytes: "
                        + name
                    )
                owners.append(
                    dict(
                        source=str(path),
                        name=name,
                        offset=at,
                        payload_sha256=digest,
                        root_bytes=40,
                    )
                )
    global_path = Path(
        "E:/replay-compiler/evidence/replay120-global-mp-scriptfiles/manifest.json"
    )
    global_manifest = json.loads(global_path.read_bytes())
    if any(row["name"] in names for row in global_manifest["assets"]):
        raise ValueError(
            "A later global_mp ScriptFile would override a patched identity"
        )
    return dict(
        original_and_final_patch_owners=owners,
        global_mp_duplicate_names=[],
        global_mp_manifest=str(global_path),
        global_mp_manifest_sha256=sha(global_path.read_bytes()),
        later_level_zone_assets_not_live_verified=True,
    )


def native_locale_codes(snapshot):
    import importlib.util
    spec = importlib.util.spec_from_file_location("dw_bot_style_paths", ROOT / "tools/bot_style_paths.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.derive(snapshot)


def parts(blob):
    info = inspect_gscbin(blob)
    return zlib.decompress(info.compressed_source), info.bytecode


def pack(source, code):
    compressed = zlib.compress(source, 9)
    return (
        struct.pack("<4I", 0x435347, len(compressed), len(source), len(code))
        + compressed
        + code
    )


def exported(file, token):
    path = EXPORT / file
    expected = (ORIGINAL_HASHES | POLICY_SOURCE_HASHES)[file]
    if sha(path.read_bytes()) != expected:
        raise ValueError("Stock survival policy source changed: " + file)
    source, code = parts(path.read_bytes())
    events = trace(path, len(code), strict=True)
    matches = [e for e in events if "function_at" in e and
               (e["name"].get("string") == token if isinstance(token, str)
                else int(e["name"]["id"], 16) == token)]
    if len(matches) != 1:
        raise ValueError("Stock survival function identity is ambiguous")
    return source, code, events, matches[0]


def stock_instruction(export, offset):
    source, code, events, function = export
    pc = int(function["function_at"], 16) + offset
    event = next(e for e in events if e.get("pc") == hex(pc))
    return (code[pc:int(event["next_pc"], 16)],
            source[int(event["source_before"], 16):int(event["source_after"], 16)], event)


def survival_edits():
    bot = exported("scripts/mp/bots/bots_gametype_br.gsc.gscbin", 0x2039)
    start = int(bot[3]["function_at"], 16)
    if bot[1][start + 0x394:start + 0x39A] != bytes.fromhex("70cdcc4c3d5d"):
        raise ValueError("Stock BR main loop wait changed")
    heal, heal_source, heal_event = stock_instruction(
        exported("scripts/mp/gametypes/br.gsc.gscbin", 0x2395), 0x69)
    inserting, inserting_source, inserting_event = stock_instruction(
        exported("2300.gscbin", "br_use_armor_plate"), 0x17)
    if (heal[0] != 0x60 or len(heal) != 4 or
        heal_event["first"].get("string") != "scripts/mp/gametypes/br_pickups.gsc" or
        heal_event["second"].get("string") != "playerusehealslot" or
        inserting[0] != 0x3C or inserting_event["token"].get("string") != "insertingarmorplate"):
        raise ValueError("Stock armor/import contract changed")
    functions = {e["name"].get("string"): int(e["function_at"], 16)
                 for e in bot[2] if "function_at" in e}
    field = bytes.fromhex("ffffffff")
    literal = struct.pack("<I", 0) + b"dw_survival_next_ms\0"

    def armor_fragment():
        code, source, references = bytearray(), bytearray(), []
        labels, branches = {}, []
        def emit(value, consumed=b""):
            code.extend(value); source.extend(consumed)
        def branch(opcode, label):
            emit(bytes([opcode]) + bytes(2)); branches.append((len(code) - 2, label))
        def local(name):
            emit(b"\x4f" + bytes(3))
            references.append(Reference(len(code) - 3, 3, functions[name], 2, "local"))
        emit(b"\x3c" + field, literal); emit(b"\xa7\xa5"); branch(0x1C, "due_condition")
        emit(bytes.fromhex("1dd700")); emit(b"\x3c" + field, literal)
        emit(b"\x53\x59")
        labels["due_condition"] = len(code)
        branch(0x72, "normal")
        # Advance the cadence even when armor is denied or gas owns the route.
        # The stock heal-slot chain retains charge/armor checks.
        emit(bytes.fromhex("1dd70066f4010218") + field, literal)
        local("bot_is_in_gas"); branch(0x0E, "normal")
        emit(b"\x3a\x7e" + struct.pack("<H", SURVIVAL_METHOD_ID)); branch(0x72, "normal")
        emit(inserting, inserting_source); emit(b"\xa8"); branch(0x0E, "normal")
        emit(b"\x15\x1a"); emit(heal, heal_source); emit(b"\x58")
        labels["normal"] = len(code)
        for operand, label in branches:
            struct.pack_into("<h", code, operand, labels[label] - operand - 2)
        return Edit(0x394, b"", bytes(code),
                    "500ms stock heal-slot armor policy yielding to gas",
                    function_token=0x2039, source=bytes(source), references=tuple(references))
    # Publish authoritative current/next circles before the ordinary tactical
    # destination gate. Native evacuation now selects a stable destination;
    # distant random safe-point projection no longer gates gas movement.
    gas_function = exported("scripts/mp/bots/bots_gametype_br.gsc.gscbin", "bot_is_in_gas")
    code, consumed = bytearray(), bytearray()
    labels, branches = {}, []
    gas_stamp_literal = struct.pack("<I", 0) + b"dw_gas_sample_ms\0"
    def gas_branch(opcode, target):
        code.extend(bytes([opcode]) + bytes(2))
        branches.append((len(code) - 2, target))
    def gas_stamp(opcode):
        code.extend(bytes([opcode]) + field)
        consumed.extend(gas_stamp_literal)
    def copy_instruction(owner, offset):
        instruction, source_bytes, _ = stock_instruction(owner, offset)
        code.extend(instruction); consumed.extend(source_bytes)
    copy_instruction(bot, 0x23B)  # level.br_circle
    code.extend(b"\xa7"); gas_branch(0x72, "done")
    # The circles are global: sample once per level time, before any getter.
    # This is the pinned compiler's exact level-field/short-circuit pattern.
    # Inequality permits clock rewind; a new map owns a fresh level object.
    gas_stamp(0x7B); code.extend(b"\xa7\x77")
    gas_branch(0x1C, "due_condition")
    gas_stamp(0x7B); code.extend(bytes.fromhex("1dd7009759"))
    labels["due_condition"] = len(code)
    gas_branch(0x72, "done")
    copy_instruction(gas_function, 0xD)  # level.circleclosing
    code.extend(b"\xa8")  # stock istrue: undefined becomes false
    for offset in (0x1C, 0x16, 0x7, 0x1):
        copy_instruction(gas_function, offset)  # reverse argument order
    code.extend(b"\x3a\x83" + struct.pack("<H", GAS_STATE_METHOD_ID))
    gas_branch(0x72, "done")
    # Failed/rejected publishers must leave the same tick available to a later
    # valid bot. Never suppress retries by stamping an unaccepted sample.
    code.extend(bytes.fromhex("1dd700")); gas_stamp(0x38)
    labels["done"] = len(code)
    for operand, label in branches:
        struct.pack_into("<h", code, operand, labels[label] - operand - 2)
    publish = Edit(0x23B, b"", bytes(code),
                   "publish accepted global BR circles once per level time before tactical-goal gate",
                   function_token=0x2039, source=bytes(consumed))
    return publish, armor_fragment()


def custom_loadout_gate():
    # Stock game::allowclasschoice owns mode callbacks, skiploadout, infiltration
    # and the gametype table. The match-rules switch independently forbids CAC.
    policy = exported("2398.gscbin", 0xB174)
    assignment, _, event = stock_instruction(policy, 0x579)
    if assignment != bytes.fromhex("3867820000") or event["canonical_token"]["id"] != "0x8267":
        raise ValueError("Stock allowCustomClasses match-rules field changed")
    call, source, event = stock_instruction(exported("1827.gscbin", 0xC4B9), 0x87)
    if call[0] != 0x75 or event["first"].get("id") != "0x95e" or event["second"].get("id") != "0x1193":
        raise ValueError("Stock game::allowclasschoice import changed")
    war_using, war_source, _ = stock_instruction(
        exported("scripts/mp/gametypes/war.gsc.gscbin", 0x254), 0x2C)
    br_using, br_source, _ = stock_instruction(
        exported("scripts/mp/gametypes/br.gsc.gscbin", 0x254), 0x4F)
    if war_using != bytes.fromhex("1d2101") or br_using != war_using or war_source or br_source:
        raise ValueError("Stock isusingmatchrulesdata zero-argument builtin changed")
    # The field exists only with explicit match rules. Ordinary mode defaults
    # still use classchoice; explicit rules fail closed when their field is unset.
    return war_using + bytes.fromhex("a51c07007b67820000a859190500") + call + b"\x59", source


def custom_loadout_slot(slot):
    gate, source = custom_loadout_gate()
    # Keep the existing two-argument native ABI. A denied slot is an exact
    # managed clone; preserve BR ground/starter/mode weapons without styling.
    value = {b"\x5c": 0, b"\x16\x01": 1, b"\x51\x01": -1}[slot]
    # A single expression leaves exactly one argument below the stock builder
    # call marker: allowed * (slot + 2) - 2. No branch crosses that marker.
    return gate + bytes((0x16, value + 2, 0x8B, 0x16, 2, 0x4E)), source


def mp_class_refresh_edit():
    stock = exported("1827.gscbin", 0x5CF8)
    start = int(stock[3]["function_at"], 16)
    # Both the preloaded and freshly built branches converge here before
    # assigning self.classstruct and invoking the original grant pipeline.
    if stock[1][start + 0x79:start + 0x7F] != bytes.fromhex("3e18022e0000"):
        raise ValueError("Stock MP cached/preloaded class convergence changed")
    functions = {e["name"].get("string", e["name"].get("id")): int(e["function_at"], 16)
                 for e in stock[2] if "function_at" in e}
    gate, source = custom_loadout_gate()
    code, refs = bytearray(gate), []
    denied = len(code) + 1
    code.extend(b"\x72\0\0")
    code.extend(bytes.fromhex("3a7e") + struct.pack("<H", MP_CLASS_METHOD_ID))
    unready = len(code) + 1
    code.extend(b"\x72\0\0")
    def local(token):
        code.extend(b"\x98\0\0\0")
        refs.append(Reference(len(code) - 3, 3, functions[token], 2, "local"))
    # Stock copy creates a fresh struct and runs its complete class validation
    # and final-weapon reconstruction. Never mutate a shared cached root.
    code.extend(bytes.fromhex("153e"))
    local("loadout_copyclassstruct")
    code.extend(bytes.fromhex("24"))
    # Existing helper consumes the refreshed fullnames, requests native weapon
    # assets, and skips redundant customization via its stock third argument.
    code.extend(bytes.fromhex("1516011a3e"))
    local("0x9c55")
    code.extend(bytes.fromhex("583625569c0000"))
    for operand in (denied, unready):
        struct.pack_into("<h", code, operand, len(code) - operand - 2)
    return Edit(0x79, b"", bytes(code),
                "Post-bind managed MP class clone, reconstruction and native weapon preload before grant",
                function_token=0x5CF8, source=source, references=tuple(refs))


def plans(method_id):
    direct = b"\x3a\x80" + struct.pack("<H", method_id)
    primary, secondary, acquired = b"\x5c", b"\x16\x01", b"\x51\x01"
    fullname = bytes.fromhex("1e4203")
    result = (
        Plan(
            "scripts/mp/bots/bots_gametype_br.gsc.gscbin",
            "bot_give_weapon",
            (
                Edit(
                    0xEF,
                    b"",
                    acquired,
                    "Push BR preserve-base slot before builder call marker",
                ),
                Edit(
                    0x10B,
                    b"",
                    direct,
                    "Style bot random weapon before its existing cached store",
                ),
                *survival_edits(),
            ),
        ),
        Plan(
            "1827.gscbin",
            0x7DD5,
            (
                mp_class_refresh_edit(),
                Edit(
                    0x0E,
                    b"",
                    primary,
                    "Push primary slot below blueprint builder call marker",
                ),
                Edit(
                    0x53,
                    b"",
                    direct,
                    "Style primary blueprint object before struct store",
                ),
                Edit(
                    0x60,
                    b"",
                    primary,
                    "Push primary slot below ordinary builder call marker",
                ),
                Edit(
                    0xA5,
                    b"",
                    direct,
                    "Style primary ordinary object before struct store",
                ),
                Edit(
                    0xF3,
                    b"",
                    secondary,
                    "Push secondary slot below blueprint builder call marker",
                ),
                Edit(
                    0x138,
                    b"",
                    direct,
                    "Style secondary blueprint object before struct store",
                ),
                Edit(
                    0x145,
                    b"",
                    secondary,
                    "Push secondary slot below ordinary builder call marker",
                ),
                Edit(
                    0x18A,
                    b"",
                    direct,
                    "Style secondary ordinary object before struct store",
                ),
            ),
        ),
        Plan(
            "scripts/mp/gametypes/br_weapons.gsc.gscbin",
            0xC641,
            (
                Edit(
                    0x36,
                    b"",
                    acquired,
                    "Push preserve-base slot below native makeweaponfromstring argument",
                ),
                Edit(
                    0x3A,
                    b"",
                    direct,
                    "Style custom-name script weapon before cached store",
                ),
                Edit(
                    0x3C,
                    b"",
                    b"\x42" + fullname + b"\x24",
                    "Refresh custom fullname from styled object in cached4",
                ),
                Edit(
                    0x4C,
                    b"",
                    acquired,
                    "Push preserve-base slot below scriptable builder marker",
                ),
                Edit(
                    0x52,
                    b"",
                    direct,
                    "Style normal scriptable loot before cached store and fullname",
                ),
                Edit(
                    0x5F,
                    b"",
                    acquired,
                    "Push preserve-base slot below complete-weapon builder marker",
                ),
                Edit(
                    0x78, b"", direct, "Style complete loadout loot before cached store"
                ),
                Edit(
                    0x7A,
                    bytes.fromhex("47052c0d7e0000"),
                    b"\x41" + fullname,
                    "Derive complete fullname from styled cached3 instead of original pickup field",
                ),
            ),
        ),
    )
    # All managed weapon handoffs share the same stock gameplay permission.
    # Slots sit below the original builder marker, so denial must retain one
    # slot argument rather than bypassing the callback and unbalancing the VM.
    slots = {slot: custom_loadout_slot(slot) for slot in (primary, secondary, acquired)}
    return tuple(replace(plan, edits=tuple(
        replace(edit, new=slots[edit.new][0], source=slots[edit.new][1])
        if "Push " in edit.purpose and "slot " in edit.purpose else edit
        for edit in plan.edits)) for plan in result)


def reference_fields(code, function_ranges):
    for pc, op, end in _script_instructions(code):
        if op in _GSC_LOCAL_REFERENCES:
            operand = pc + 1
            delta = int.from_bytes(code[operand : operand + 3], "little", signed=True)
            if delta & 1:
                raise ValueError("Invalid Replay signed24 reserved bit")
            yield operand, 3, operand + (delta >> 1), 2, "local"
        elif op == 0x56:
            for i in range(struct.unpack_from("<H", code, pc + 1)[0]):
                operand = pc + 7 + 7 * i
                delta = int.from_bytes(
                    code[operand : operand + 3], "little", signed=True
                )
                if delta & 1:
                    raise ValueError("Invalid Replay switch-case reserved bit")
                yield operand, 3, operand + (delta >> 1), 2, "switch_case"
        elif any(start <= pc < stop for start, stop in function_ranges):
            if op in (0x0B, 0x0E, 0x19, 0x1C, 0x72):
                delta = struct.unpack_from("<h", code, pc + 1)[0]
                yield pc + 1, 2, end + delta, 1, "short_forward"
            elif op == 0x1B:
                distance = struct.unpack_from("<H", code, pc + 1)[0]
                yield pc + 1, 2, end - distance, -1, "short_back"
            elif op in (0x94, 0x86):
                delta = struct.unpack_from("<i", code, pc + 1)[0]
                yield pc + 1, 4, end + delta, 1, (
                    "long" if op == 0x94 else "switch_table"
                )


def transform(plan, method_id, bound=False):
    path = EXPORT / plan.file
    original = path.read_bytes()
    manifest = json.loads((EXPORT / "manifest.json").read_bytes())
    row = next(
        r for r in manifest["assets"] if Path(r["path"]).resolve() == path.resolve()
    )
    if (
        sha(original) != ORIGINAL_HASHES[plan.file]
        or row["sha256"] != ORIGINAL_HASHES[plan.file]
    ):
        raise ValueError("Original export is not the pinned source manifest payload")
    source, code = parts(original)
    events = trace(path, len(code), strict=True)
    functions = [e for e in events if "function_at" in e]
    selected = {}
    for token in [plan.function_token, *(e.function_token for e in plan.edits if e.function_token is not None)]:
        matches = [e for e in functions if (e["name"].get("string") == token
                   if isinstance(token, str) else int(e["name"]["id"], 16) == token)]
        if len(matches) != 1:
            raise ValueError("Function identity does not resolve uniquely")
        selected[token] = matches[0]
    fn = selected[plan.function_token]
    start, size = int(fn["function_at"], 16), int(fn["size"], 16)
    stop = start + size
    decoded = list(_script_instructions(code))
    boundaries = {pc for pc, _, _ in decoded} | {len(code)}
    edits = sorted((replace(e, function_token=e.function_token if e.function_token is not None else plan.function_token,
                    offset=int(selected[e.function_token if e.function_token is not None else plan.function_token]["function_at"], 16) + e.offset)
                    for e in plan.edits), key=lambda e: e.offset)
    for previous, edit in zip(edits, edits[1:]):
        if previous.offset + len(previous.old) > edit.offset:
            raise ValueError("Edited ranges overlap")
    for e in edits:
        at = e.offset
        owner = selected[e.function_token]
        owner_start = int(owner["function_at"], 16)
        if not owner_start <= at <= owner_start + int(owner["size"], 16) - len(e.old):
            raise ValueError("Edit escaped its declared function")
        if "below" in e.purpose and "marker" in e.purpose and code[at] != 0x15:
            raise ValueError("Slot push must precede the original call marker")
        if at not in boundaries or at + len(e.old) not in boundaries:
            raise ValueError("Edit is not at whole-instruction boundaries")
        if code[at : at + len(e.old)] != e.old:
            raise ValueError("Original instruction expectation failed")
        # All removed instructions must be canonical-token instructions that
        # consume no source. New literals/imports have explicitly paired source.
        for event in events:
            if "pc" in event and at <= int(event["pc"], 16) < at + len(e.old):
                if event["source_before"] != event["source_after"]:
                    raise ValueError("Replacement removes native source consumption")

    # A target landing at an insertion must execute the insertion. In contrast,
    # moved original instructions and their operands begin after the insertion.
    def target_map(pc):
        for e in edits:
            at = e.offset
            if at < pc < at + len(e.old):
                raise ValueError("Reference targets removed instruction interior")
        return pc + sum(len(e.new) - len(e.old) for e in edits if e.offset < pc)

    def instruction_map(pc):
        for e in edits:
            at = e.offset
            if at <= pc < at + len(e.old):
                raise ValueError("Reference operand belongs to removed instruction")
        return pc + sum(
            len(e.new) - len(e.old) for e in edits if e.offset <= pc
        )

    output_code = bytearray()
    cursor = 0
    for e in edits:
        at = e.offset
        output_code.extend(code[cursor:at])
        output_code.extend(e.new)
        cursor = at + len(e.old)
    output_code.extend(code[cursor:])
    relocations = []
    ranges = [(int(f["function_at"], 16), int(f["function_at"], 16) + int(f["size"], 16))
              for f in selected.values()]
    for operand, width, target, scale, kind in reference_fields(code, ranges):
        allowed_targets = boundaries | (
            {pc + 1 for pc, op, _ in decoded if op == 0x56}
            if kind == "switch_table"
            else set()
        )
        if target not in allowed_targets:
            raise ValueError(f"Original {kind} misses instruction boundary")
        new_operand, new_target = instruction_map(operand), target_map(target)
        base = new_operand if scale == 2 else new_operand + width
        value = (new_target - base) * scale
        signed = kind != "short_back"
        if not (-(1 << (8 * width - 1)) <= value < (1 << (8 * width - 1))) and signed:
            raise ValueError("Relocation exceeds native signed operand range")
        if not signed and not 0 <= value < (1 << (8 * width)):
            raise ValueError("Backwards branch exceeds native unsigned operand range")
        output_code[new_operand : new_operand + width] = value.to_bytes(
            width, "little", signed=signed
        )
        relocations.append(
            dict(
                kind=kind,
                old_operand=operand,
                new_operand=new_operand,
                width=width,
                old_target=target,
                new_target=new_target,
                changed=code[operand : operand + width]
                != output_code[new_operand : new_operand + width],
            )
        )
    inserted_references = []
    for edit in edits:
        for reference in edit.references:
            operand = target_map(edit.offset) + reference.operand
            target = target_map(reference.target)
            if reference.target not in boundaries:
                raise ValueError("Inserted reference misses an original instruction boundary")
            value = (target - (operand if reference.scale == 2 else operand + reference.width)) * reference.scale
            output_code[operand:operand + reference.width] = value.to_bytes(reference.width, "little", signed=True)
            inserted_references.append(dict(kind=reference.kind, new_operand=operand,
                                           new_target=target, original_target=reference.target, width=reference.width))
    delta = sum(len(e.new) - len(e.old) for e in edits)
    output_source = bytearray(source)
    function_sizes = []
    for token, function in selected.items():
        entry, extent = int(function["function_at"], 16), int(function["size"], 16)
        header = 0 if entry == 1 else next(int(e["source_after"], 16) for e in events if e.get("next_pc") == hex(entry))
        if struct.unpack_from("<I", source, header)[0] != extent:
            raise ValueError("Source function extent mismatch")
        growth = sum(len(e.new) - len(e.old) for e in edits if e.function_token == token)
        struct.pack_into("<I", output_source, header, extent + growth)
        function_sizes.append(dict(token=token, header=header, original_start=entry, original_size=extent,
                                   output_size=extent + growth))
    additions = []
    for edit in edits:
        if edit.source:
            event = next(e for e in events if e.get("pc") == hex(edit.offset))
            additions.append((int(event["source_before"], 16), edit.source))
    additions.sort(key=lambda item: item[0])
    source_insertions = []
    added = 0
    for at, content in additions:
        source_insertions.append(dict(original_offset=at, output_offset=at + added, hex=content.hex()))
        added += len(content)
    for at, content in reversed(additions):
        output_source[at:at] = content
    output = pack(output_source, output_code)
    target_path = OUT / ("bound" if bound else "probe-only") / plan.file
    target_path.parent.mkdir(parents=True, exist_ok=True)
    write_private(target_path, output)
    result_events = trace(target_path, len(output_code), strict=True)
    result_functions = [e for e in result_events if "function_at" in e]
    if len(result_functions) != len(functions):
        raise ValueError("Export count changed")
    for old, new in zip(functions, result_functions):
        if old["name"]["id"] != new["name"]["id"] or old["name"].get("string") != new[
            "name"
        ].get("string"):
            raise ValueError("Export identity changed")
        expected_entry = target_map(int(old["function_at"], 16))
        if int(new["function_at"], 16) != expected_entry:
            raise ValueError("Export entry relocation mismatch")
    # Reconstruct the entire original bytecode from reviewed edits/operands.
    undo = bytearray(output_code)
    for r in relocations:
        old, new, width = r["old_operand"], r["new_operand"], r["width"]
        undo[new : new + width] = code[old : old + width]
    for e in reversed(edits):
        at = target_map(e.offset)
        undo[at : at + len(e.new)] = e.old
    if bytes(undo) != code:
        raise ValueError("Unreviewed original bytecode modification")
    undo_source = bytearray(output_source)
    for insertion in reversed(source_insertions):
        at = insertion["output_offset"]
        del undo_source[at:at + len(bytes.fromhex(insertion["hex"]))]
    for function in function_sizes:
        struct.pack_into("<I", undo_source, function["header"], function["original_size"])
    if bytes(undo_source) != source:
        raise ValueError("Unreviewed original source modification")

    # Export/import/canonical/source-consumption identities remain original.
    # Only PC coordinates and the selected function-size dword may differ.
    def semantic(events, original_events=False):
        result = []
        for e in events:
            if "pc" not in e:
                continue
            if original_events and any(
                edit.offset
                <= int(e["pc"], 16)
                < edit.offset + len(edit.old)
                for edit in edits
            ):
                continue
            payload = {
                k: v
                for k, v in e.items()
                if k not in ("pc", "next_pc", "source_before", "source_after", "opcode")
            }
            if "canonical_token" in payload:
                payload["canonical_token"] = {"id": payload["canonical_token"]["id"]}
            if payload:
                result.append(payload)
        return result

    inserted_ranges = [(target_map(e.offset), target_map(e.offset) + len(e.new)) for e in edits]
    original_result = [e for e in result_events if "pc" not in e or
                       not any(a <= int(e["pc"], 16) < b for a, b in inserted_ranges)]
    def stable(value):
        if isinstance(value, dict):
            return {k: stable(v) for k, v in value.items() if k not in ("source_offset", "bytecode_offset")}
        if isinstance(value, list):
            return [stable(v) for v in value]
        return value
    if stable(semantic(events, True)) != stable(semantic(original_result)):
        raise ValueError(
            "Original imports, canonical tokens, strings or source token identities changed"
        )
    return dict(
        asset_name=row["name"],
        original_sha256=sha(original),
        output_sha256=sha(output),
        function_token=plan.function_token,
        original_function_start=start,
        original_function_size=size,
        output_function_size=next(f["output_size"] for f in function_sizes if f["token"] == plan.function_token),
        function_edits=function_sizes,
        source_insertions=source_insertions,
        inserted_references=inserted_references,
        inserted_survival_method_id=SURVIVAL_METHOD_ID if any(e.function_token == 0x2039 for e in edits) else None,
        mp_class_refresh=dict(method_id=MP_CLASS_METHOD_ID, grant_token=0x5CF8,
                              fresh_stock_clone=True, native_preload_before_grant=True)
                         if any(e.function_token == 0x5CF8 for e in edits) else None,
        custom_loadout_policy=dict(
            match_rules_field=0x8267, stock_class_choice_import=[0x95E, 0x1193],
            stock_using_match_rules_builtin=0x121,
            ordinary_defaults_use_stock_class_choice=True,
            denied_preserve_original_slot=-2, source_provenance=POLICY_SOURCE_HASHES,
            weapon_handoffs=sum("Push " in e.purpose and "slot " in e.purpose for e in edits),
            native_abi_changed=False,
        ),
        function_count=len(functions),
        inserted_method_id=method_id,
        method_bound=bound,
        packaging_allowed=bound,
        strict_native_source_cursor_passed=True,
        exact_original_reconstruction_passed=True,
        export_import_source_identity_preserved=True,
        edits=[
            dict(
                offset=e.offset - int(selected[e.function_token]["function_at"], 16),
                function_token=e.function_token,
                old_hex=e.old.hex(),
                new_hex=e.new.hex(),
                purpose=e.purpose,
            )
            for e in edits
        ],
        references=relocations,
        output_path=str(target_path),
    )


NATIVE = (
    (
        "fn_ffbb1f24befc9227",
        "DW_BotStyle_ProcessScriptFile",
        "af4353363f2ae4e641165834688ec649f13b871fc84493e14a6f89a10d60e3d8",
    ),
    (
        "fn_2c80329c0d908f5c",
        "DWBS_FindAsset",
        "e7491e8262bbf0a3bffec6dca92ef981b1377e20638949a881d72f4df576bab1",
    ),
    (
        "fn_3de51deb3450db19",
        "DWBS_IsDefaultAsset",
        "ba32bccc309dcae3882c447b1318e4cf39d5ba111ef908556f8d46d17e04b50a",
    ),
    (
        "fn_a5bdf4e08f90ab6f",
        "DWBS_ProcessScriptFile",
        "893c17617aaccfc8124e129ec93e154d835f309919c25ed0278c71a7d0c98a79",
    ),
)


def inspect_native(snapshot):
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    image = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
    raw = image.read_bytes()
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    if sha(raw) != IMAGE_HASH or catalog["image_sha256"] != IMAGE_HASH:
        raise ValueError("Original Replay executable identity mismatch")
    pe = shared_original_pe(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    groups = {}
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        groups.setdefault(owner.struct.BeginAddress, []).append(
            (entry.struct.BeginAddress, entry.struct.EndAddress)
        )
    by_id = {
        row["id"]: row for row in catalog["functions"] if not row.get("quarantined")
    }
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    result = []
    for identity, symbol, expected in NATIVE:
        row = by_id[identity]
        chunks = sorted(groups[row["rva"]])
        if chunks[0][0] != row["rva"] or any(
            a[1] != b[0] for a, b in zip(chunks, chunks[1:])
        ):
            raise ValueError("Native unwind ownership is not contiguous")
        body = pe.get_data(row["rva"], chunks[-1][1] - row["rva"])
        if sha(body) != expected:
            raise ValueError("Native import/replacement body changed: " + identity)
        instructions = list(
            decoder.disasm(body, pe.OPTIONAL_HEADER.ImageBase + row["rva"])
        )
        if identity == NATIVE[0][0] and sum(i.size for i in instructions) != len(body):
            raise ValueError("Native full wrapper did not decode completely")
        if identity == NATIVE[0][0]:
            calls = [int(i.op_str, 16) for i in instructions if i.mnemonic == "call"]
            wanted = [
                pe.OPTIONAL_HEADER.ImageBase + by_id[x[0]]["rva"] for x in NATIVE[1:]
            ]
            if calls != wanted or not any(
                i.mnemonic == "mov" and i.op_str == "ecx, 0x34" for i in instructions
            ):
                raise ValueError(
                    "Native full ScriptFile wrapper lookup/processor contract changed"
                )
        result.append(
            dict(
                identity=identity,
                symbol=symbol,
                rva=row["rva"],
                bytes=len(body),
                sha256=expected,
            )
        )
    return result


def method_binding(snapshot):
    path = snapshot / "generated/bot-style-method-integration.json"
    receipt = json.loads(path.read_bytes())
    if (
        receipt.get("passed") is not True
        or receipt.get("method_id") != METHOD_ID
        or receipt.get("argument_count") != 2
        or receipt.get("image_sha256") != IMAGE_HASH
    ):
        raise ValueError(
            "Custom bot style method does not have a verified two-argument target binding"
        )
    bounds = receipt.get("bounds", {})
    registry = receipt.get("registry", [])
    registered_ids = sorted(row.get("id", -1) for row in registry)
    if (
        bounds.get("native_begin") != 0x8000
        or bounds.get("native_count") != 1927
        or bounds.get("extended_count") != 1927 + len(registry)
        or bounds.get("extended_end") != 0x8000 + 1927 + len(registry)
        or registered_ids != list(range(0x8787, 0x8787 + len(registry)))
        or len(registry) != 4
    ):
        raise ValueError(
            "Custom method array bounds do not include the expected registered ID"
        )
    entries = [r for r in registry if r.get("id") == METHOD_ID]
    if (
        len(entries) != 1
        or entries[0].get("argument_count") != 2
        or entries[0].get("receiver") != "entity"
        or entries[0].get("result") != "managedWeaponObject"
    ):
        raise ValueError("Custom method receiver/result contract mismatch")
    survival = [r for r in registry if r.get("id") == SURVIVAL_METHOD_ID]
    if (len(survival) != 1 or survival[0].get("name") != "dw_bot_survival" or
        survival[0].get("argument_count") != 0 or survival[0].get("receiver") != "entity" or
        survival[0].get("result") != "bool" or survival[0].get("opcode") != 0x7E or
        survival[0].get("callback_symbol") != "DW_BotSurvivalAllowedMethod"):
        raise ValueError("Survival method requires the coherent zero-argument scalar bool registry")
    mp_class = [r for r in registry if r.get("id") == MP_CLASS_METHOD_ID]
    if (len(mp_class) != 1 or mp_class[0].get("name") != "dw_bot_mp_class_ready" or
        mp_class[0].get("argument_count") != 0 or mp_class[0].get("receiver") != "entity" or
        mp_class[0].get("result") != "bool" or mp_class[0].get("opcode") != 0x7E or
        mp_class[0].get("callback_symbol") != "DW_BotMPClassReadyMethod"):
        raise ValueError("MP class readiness requires the exact zero-argument scalar bool registry")
    gas = [r for r in registry if r.get("id") == GAS_STATE_METHOD_ID]
    if (len(gas) != 1 or gas[0].get("name") != "dw_bot_gas_state" or
        gas[0].get("argument_count") != 5 or gas[0].get("receiver") != "entity" or
        gas[0].get("result") != "bool" or gas[0].get("opcode") != 0x83 or
        gas[0].get("callback_symbol") != "DW_BotGasStateMethod"):
        raise ValueError("Gas state requires the exact five-argument scalar bool registry")
    owner = snapshot / receipt["source"]
    if sha(owner.read_bytes()) != receipt["source_sha256"]:
        raise ValueError(
            "Custom method registration source changed after its binding proof"
        )
    return dict(
        path=str(path),
        sha256=sha(path.read_bytes()),
        method_id=METHOD_ID,
        argument_count=2,
        registry_name=entries[0]["name"],
        source_sha256=receipt["source_sha256"],
        survival_method_id=SURVIVAL_METHOD_ID,
        survival_argument_count=0,
        survival_result="bool",
    )


def compile_package(snapshot, binding):
    from workstation_fastfiles import (
        pack_replay_uncompressed,
        make_replay_header_only_patch,
        unpack_replay_uncompressed,
        sha256_file,
    )
    from workstation_trace_index import build_read_span_index
    from workstation_scriptfile_crud import _scriptfile_payload
    from roundtrip_replay_fastfile import verify_native

    results = [transform(p, METHOD_ID, bound=True) for p in plans(METHOD_ID)]
    from workstation_asset_codecs import decompile_scriptfile
    tool_record = json.loads((snapshot / "replay-project.local.json").read_bytes())["tools"]["gsc"]
    tool = Path(tool_record["path"])
    if not tool.is_absolute():
        tool = snapshot / tool
    if sha(tool.read_bytes()) != tool_record["sha256"]:
        raise ValueError("Fresh GSC decompiler tool identity changed")
    for result in results:
        fresh = decompile_scriptfile(Path(result["output_path"]).read_bytes(), tool=tool,
                                     asset_name=Path(result["asset_name"]).name)
        decompiled = OUT / "fresh-decompile" / (result["asset_name"] + ".gsc")
        decompiled.parent.mkdir(parents=True, exist_ok=True)
        write_private(decompiled, fresh)
        result["fresh_decompile"] = dict(path=str(decompiled), sha256=sha(fresh.encode()),
                                         tool_sha256=tool_record["sha256"],
                                         builtin_names_from_tool_table=True,
                                         actual_custom_method_binding=binding)
        if result["inserted_survival_method_id"]:
            if not all(value in fresh for value in ("dw_survival_next_ms", "playerusehealslot",
                       "dw_gas_sample_ms", "gettime() + 500", "!bot_is_in_gas()")):
                raise ValueError("Fresh decompile does not retain the survival policy")
            result["survival_policy"] = dict(main_function=0x2039, gas_offset=0x23B, armor_offset=0x394,
                cooldown_ms=500, gas_state_method=GAS_STATE_METHOD_ID,
                gas_before_tactical_gate=True, gas_random_destination_removed=True,
                gas_global_sample_field="level.dw_gas_sample_ms",
                gas_publication_once_per_level_time=True, gas_stamp_only_after_acceptance=True,
                armor_stock_import="scripts/mp/gametypes/br_pickups.gsc::playerusehealslot",
                source_provenance=POLICY_SOURCE_HASHES, original_wait_preserved=True,
                armor_yields_to_gas=True, no_extra_infinite_thread=True)
    owner_proof = verify_original_owners()
    # Deterministic three-row native overlay; class keeps its original numeric
    # canonical XAsset identity. The source dictionary remains inside GSCBIN.
    body = bytearray(
        struct.pack("<IIQIIQ", 0, 0, 0, len(results), 0, 0xFFFFFFFFFFFFFFFF)
    )
    body.extend(struct.pack("<IIQ", 52, 0, 0xFFFFFFFFFFFFFFFF) * len(results))
    stream5 = 16 * len(results)
    stream6 = 0
    for row in results:
        payload = Path(row["output_path"]).read_bytes()
        info = inspect_gscbin(payload)
        name = row["asset_name"].encode("utf-8") + b"\0"
        body.extend(
            struct.pack(
                "<QiiiIQQ",
                0xFFFFFFFFFFFFFFFF,
                len(info.compressed_source),
                info.source_size,
                len(info.bytecode),
                0,
                0xFFFFFFFFFFFFFFFE,
                0xFFFFFFFFFFFFFFFE,
            )
        )
        body.extend(name)
        body.extend(payload[16:])
        stream5 += len(name)
        stream6 += len(payload) - 16
    reservations = [0, 40, 0, 0, 0, stream5, stream6, 0, 0, 0, 0]
    packed = pack_replay_uncompressed(bytes(body), reservations)
    ff = OUT / "dw_bot_styles_mp.ff"
    write_private(ff, packed)
    template = bytearray(0x148)
    template[:8] = b"IWffd100"
    struct.pack_into("<II", template, 8, 6, 4)
    patch = make_replay_header_only_patch(bytes(template), packed)
    write_private(ff.with_suffix(".fp"), patch)
    if unpack_replay_uncompressed(packed) != bytes(body):
        raise ValueError("Fastfile container roundtrip changed its serialized body")
    output = OUT / ("native-reread-" + sha(packed)[:16])
    if output.exists():
        import uuid

        output = OUT / (
            "native-reread-" + sha(packed)[:16] + "-" + uuid.uuid4().hex[:8]
        )
    replay = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
    acts = Path("D:/mw124/atian-cod-tools/build-workstation/bin/Release/acts.exe")
    # Both tools and the original image are hash-bound by the existing native
    # verifier. No game process or game file is touched by this offline read.
    native = verify_native(ff, bytes(body), ff, acts, replay, output, 60, trace=True)
    manifest = Path(native["manifest_path"])
    index = build_read_span_index(
        manifest.parent / "stream-trace.jsonl", manifest, len(body)
    )
    journal = [
        json.loads(line)
        for line in (manifest.parent / "assets.jsonl").read_text().splitlines()
        if line.strip()
    ]
    exports = []
    for owner, journal_row, row in zip(index["assets"], journal, results, strict=True):
        typed = dict(owner, xasset_index=owner["index"], name=journal_row["name"])
        root_at, payload = _scriptfile_payload(
            bytes(body), typed, owner["index"], row["asset_name"]
        )
        if sha(payload) != row["output_sha256"]:
            raise ValueError(
                "Native trace-owned ScriptFile export differs from compiled payload"
            )
        exports.append(
            dict(
                name=row["asset_name"],
                xasset_index=owner["index"],
                root_offset=root_at,
                payload_sha256=sha(payload),
            )
        )
    if native["trace_summary"]["packed_target_stream_counts"]:
        raise ValueError("Overlay introduced packed stream aliases")
    actual = index["max_destination_offsets"]
    if any(reservations[i] != actual.get(i, 0) for i in range(11)):
        raise ValueError(
            "Native overlay stream high-water differs from exact reservation"
        )
    proof = dict(
        schema="replay120-bot-style-native-overlay-v1",
        image_sha256=IMAGE_HASH,
        original_owner_proof=owner_proof,
        method_binding=binding,
        asset_results=results,
        stream_reservations=reservations,
        output_fastfile=str(ff),
        output_fastfile_sha256=sha(packed),
        output_patch_sha256=sha(patch),
        native_reader=native,
        native_trace_owned_exports=exports,
        packaged=True,
        bytecode_storage="Native DB script-pool storage after ordinary zone load",
        direct_static_bytecode_delivery=False,
        game_modified=False,
        runtime_tested=False,
    )
    # Original Replay requires dependencies even for a ScriptFile-only zone.
    # Native empty companions preserve that path without introducing assets.
    empty_body = struct.pack("<IIQIIQ", 0, 0, 0, 0, 0, 0)
    empty_packed = pack_replay_uncompressed(empty_body, [0] * 11)
    empty_patch = make_replay_header_only_patch(bytes(template), empty_packed)
    empty_file = OUT / "dw_bot_styles_empty.ff"
    write_private(empty_file, empty_packed)
    write_private(empty_file.with_suffix(".fp"), empty_patch)
    empty_output = OUT / ("native-empty-reread-" + sha(empty_packed)[:16])
    if empty_output.exists():
        import uuid

        empty_output = OUT / (
            "native-empty-reread-" + sha(empty_packed)[:16] + "-" + uuid.uuid4().hex[:8]
        )
    empty_native = verify_native(
        empty_file, empty_body, empty_file, acts, replay, empty_output, 60, trace=True
    )
    if empty_native["manifest"]["top_level_index"] != 0:
        raise ValueError("Native companion zone unexpectedly contains assets")
    proof["empty_companion"] = dict(
        fastfile_sha256=sha(empty_packed),
        patch_sha256=sha(empty_patch),
        native_reader=empty_native,
        asset_count=0,
        output_fastfile=str(empty_file),
    )
    locale = native_locale_codes(snapshot)
    bundle_hash = sha(packed + patch + empty_packed + empty_patch)
    zone = "dw_bot_styles_mp_" + bundle_hash[:16]
    installation = []
    prefixes = sorted(
        set(["techsets", "srv", *locale["regions"], *locale["supported_languages"]])
    )
    for name, source, companion in [(zone, ff, False)] + [
        (prefix + "_" + zone, empty_file, True) for prefix in prefixes
    ]:
        prefix = name[:-len("_" + zone)] if name != zone else None
        directory = locale["language_directories"].get(prefix, locale["region_directories"].get(prefix, ""))
        for extension, resource in (
            (".ff", empty_packed if companion else packed),
            (".fp", empty_patch if companion else patch),
        ):
            installation.append(
                dict(
                    name=name + extension,
                    source=str(source.with_suffix(extension)),
                    sha256=sha(resource),
                    size=len(resource),
                    companion=companion,
                    relative_path=(directory + "/" if directory else "") + name + extension,
                )
            )
    proof["zone_name"] = zone
    proof["resource_bundle_sha256"] = bundle_hash
    proof["native_locale_codes"] = locale
    proof["native_folder_rules"] = locale["installation_folder_rules"]
    proof["installation_manifest"] = installation
    write_private(OUT / "package-proof.json", json.dumps(proof, indent=2) + "\n")
    return packed, patch, empty_packed, empty_patch, proof


def render_package(packed, patch, empty_packed, empty_patch, proof):
    def array(name, body):
        lines = [f"inline const uint8_t {name}[] = {{"]
        lines += [
            "    " + ",".join(f"0x{x:02x}" for x in body[i : i + 24]) + ","
            for i in range(0, len(body), 24)
        ]
        return "\n".join(lines + ["};"])

    header = """#pragma once
#include <stdint.h>
struct DWBotStyleScriptPackage
{
    const char *zoneName;
    const uint8_t *fastfile;
    uint32_t fastfileBytes;
    const uint8_t *patch;
    uint32_t patchBytes;
    const uint8_t *emptyFastfile;
    uint32_t emptyFastfileBytes;
    const uint8_t *emptyPatch;
    uint32_t emptyPatchBytes;
    const char *const *installationNames;
    const char *const *installationDirectories;
    uint32_t installationNameCount;
    uint32_t reserved;
};
namespace DWBotStyleScripts
{
"""
    header += (
        array("Fastfile", packed)
        + "\n"
        + array("Patch", patch)
        + "\n"
        + array("EmptyFastfile", empty_packed)
        + "\n"
        + array("EmptyPatch", empty_patch)
        + "\n"
    )
    names = [row["name"][:-3] for row in proof["installation_manifest"] if row["name"].endswith(".ff")]
    expected_names = 1 + len(set(["techsets", "srv", *proof["native_locale_codes"]["regions"],
                                *proof["native_locale_codes"]["supported_languages"]]))
    if len(names) != expected_names or len(set(names)) != expected_names or any(
        row["name"][:-3] not in names for row in proof["installation_manifest"]):
        raise ValueError("Embedded installation names do not cover the native manifest")
    header += "inline const char *const InstallationNames[] = {\n" + "\n".join(
        '    "' + name + '",' for name in names) + "\n};\n"
    directories = [row["relative_path"].rsplit("/", 1)[0] if "/" in row["relative_path"] else ""
                   for row in proof["installation_manifest"] if row["name"].endswith(".ff")]
    header += "inline const char *const InstallationDirectories[] = {\n" + "\n".join(
        '    "' + directory + '",' for directory in directories) + "\n};\n"

    header += (
        'inline const DWBotStyleScriptPackage Package = {"dw_bot_styles_mp_'
        + sha(packed + patch + empty_packed + empty_patch)[:16]
        + '", Fastfile, sizeof(Fastfile), Patch, sizeof(Patch), EmptyFastfile, sizeof(EmptyFastfile), EmptyPatch, sizeof(EmptyPatch), InstallationNames, InstallationDirectories, sizeof(InstallationNames) / sizeof(*InstallationNames), 0};\n}\n'
    )
    return header


def prepare(snapshot, replace_owned=False):
    global OUT
    import importlib.util

    snapshot = Path(snapshot).resolve()
    if not snapshot.is_relative_to((ROOT / "data").resolve()):
        raise ValueError("Bot style script preparation requires a private DW snapshot")
    if (snapshot.parent / "client-readiness.json").exists():
        raise ValueError("Never regenerate a sealed completed client snapshot")
    load_tools(snapshot)
    native = inspect_native(snapshot)
    binding = method_binding(snapshot)
    OUT = snapshot / "generated/bot-style-scripts"
    OUT.mkdir(parents=True, exist_ok=True)
    packed, patch, empty_packed, empty_patch, proof = compile_package(snapshot, binding)
    source = ROOT / "integration/replay/DW_BotStyleScripts.cpp"
    staged = snapshot / "src/DW_BotStyleScripts.cpp"
    if (
        staged.exists()
        and not replace_owned
        and staged.read_bytes() != source.read_bytes()
    ):
        raise ValueError("Staged script wrapper differs from canonical owner")
    write_private(staged, source.read_bytes())
    header = render_package(packed, patch, empty_packed, empty_patch, proof)
    write_private(snapshot / "src/DW_BotStyleScriptPackage.h", header)
    write_private(
        snapshot / "src/DW_BotStyleScriptBindings.h",
        "#pragma once\n// Native imports are bound by stable target identities and full body hashes.\n",
    )
    spec = importlib.util.spec_from_file_location(
        "bot_style_script_catalog", snapshot / "tools/source_catalog.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shim = importlib.util.spec_from_file_location("dw_catalog", Path(__file__).resolve().with_name("dw_catalog.py"))
    shim_module = importlib.util.module_from_spec(shim)
    shim.loader.exec_module(shim_module)
    shim_module.share_catalog(module)  # one catalog parse, not one per binding
    associations = json.loads((snapshot / "source-units.json").read_bytes())
    if (snapshot / "source-units.json").stat().st_nlink != 1:
        raise ValueError(
            "Detach inherited root/import metadata before script preparation"
        )
    for row in native[1:]:
        previous = [
            r for r in associations.get("imports", []) if r["symbol"] == row["symbol"]
        ]
        if previous:
            if previous[0]["symbol_id"] != row["identity"]:
                raise ValueError("Existing native script import binding conflicts")
        else:
            module.bind_import(row["identity"], row["symbol"])
    identity, symbol = NATIVE[0][:2]
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    prior = [u for u in associations["units"] if u["function_id"] == identity]
    if prior:
        if (
            not replace_owned
            or prior[0]["source"] != "src/DW_BotStyleScripts.cpp"
            or prior[0]["symbol"] != symbol
        ):
            raise ValueError(
                "ScriptFile processor wrapper already has another source owner"
            )
    else:
        module.bind(identity, Path("src/DW_BotStyleScripts.cpp"), symbol)
    prior_units = [u for u in units["units"] if u["function_id"] == identity]
    if prior_units:
        if (
            not replace_owned
            or prior_units[0]["source"] != "src/DW_BotStyleScripts.cpp"
        ):
            raise ValueError("Script wrapper has another editable unit owner")
        units["units"] = [u for u in units["units"] if u["function_id"] != identity]
    digest = sha(staged.read_bytes())
    units["units"].append(
        dict(
            function_id=identity,
            kind="cpp",
            source="src/DW_BotStyleScripts.cpp",
            symbol=symbol,
            sha256=digest,
            revision=digest,
            language="cpp",
        )
    )
    write_private(units_path, json.dumps(units, indent=2) + "\n")
    result = dict(
        schema=1,
        passed=True,
        image_sha256=IMAGE_HASH,
        method_id=METHOD_ID,
        argument_count=2,
        method_binding=binding,
        native=native,
        scriptfile_bytes=40,
        scriptfile_offsets=dict(
            name=0,
            compressedLen=8,
            sourceLen=12,
            bytecodeLen=16,
            reserved=20,
            compressedSource=24,
            bytecode=32,
        ),
        package_proof=str(OUT / "package-proof.json"),
        package_sha256=sha(packed),
        patch_sha256=sha(patch),
        generated_header_sha256=sha(header.encode()),
        source_sha256=digest,
        generator_sha256=sha(Path(__file__).read_bytes()),
        native_overlay_read_verified=True,
        requires_native_zone_load_before_script_compilation=True,
        source_embedded_bytecode_processed_directly=False,
        game_modified=False,
        runtime_tested=False,
    )
    write_private(
        snapshot / "generated/bot-style-scripts-integration.json",
        json.dumps(result, indent=2) + "\n",
    )
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
