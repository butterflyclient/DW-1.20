"""Resolve Replay's real Lua reward bindings and native callees, read-only."""

import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_REG_R8
import pefile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/reward-claim-20261011"
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
assert sha == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True


def string(address):
    assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage
    return pe.get_data(address - base, 512).split(b"\0", 1)[0].decode("ascii")


with sqlite3.connect(
    image.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True
) as db:
    db.execute("pragma query_only=on")

    def function(address):
        row = db.execute(
            "select name,size,pseudocode,assembly from functions where address=?",
            (str(address),),
        ).fetchone()
        if not row:
            return dict(address=address, missing=True)
        name, size, pseudocode, assembly = row
        body = pe.get_data(address - base, size)
        code = list(decoder.disasm(body, address))
        return dict(
            address=address,
            name=name,
            size=size,
            pseudocode=pseudocode,
            assembly=assembly,
            native_sha256=hashlib.sha256(body).hexdigest(),
            calls=sorted(
                {
                    i.operands[0].imm
                    for i in code
                    if i.operands
                    and i.operands[0].type == X86_OP_IMM
                    and (
                        i.mnemonic == "call"
                        or (
                            i.mnemonic == "jmp"
                            and not address <= i.operands[0].imm < address + size
                        )
                    )
                }
            ),
        )

    register = int(
        db.execute(
            "select address from functions where name=?",
            ("OnlineProgression::RegisterLuaFunctions",),
        ).fetchone()[0]
    )
    registration = function(register)
    candidates = []
    for i in decoder.disasm(
        pe.get_data(register - base, registration["size"]), register
    ):
        if (
            i.mnemonic == "lea"
            and i.operands[0].reg == X86_REG_R8
            and i.operands[1].type == X86_OP_MEM
            and i.operands[1].mem.base == X86_REG_RIP
        ):
            candidates.append(i.address + i.size + i.operands[1].mem.disp)
    assert len(candidates) == 1
    table = candidates[0]
    bindings = {}
    for index in range(100):
        label, target = struct.unpack("<QQ", pe.get_data(table - base + index * 16, 16))
        if not label:
            break
        bindings[string(label)] = target
    else:
        raise ValueError("Unterminated Lua registration table")
    functions = {}
    for label in ("CCIEBBDDFH", "DFBEBDGCHJ"):
        target = bindings[label]
        selected = function(target)
        functions[str(target)] = selected
        for called in selected["calls"]:
            functions[str(called)] = function(called)
    callback = int(
        db.execute(
            "select address from functions where name=?",
            ("q_OnlineProgression_OnGetUserStateComplete",),
        ).fetchone()[0]
    )
    callbacks = {callback: function(callback)}
    for called in callbacks[callback]["calls"]:
        callbacks[called] = function(called)
    for selected in list(callbacks.values()):
        if selected.get("size", 0) > 150:
            for called in selected.get("calls", []):
                callbacks.setdefault(called, function(called))
    callback_strings = {}
    for selected in callbacks.values():
        if selected.get("missing"):
            continue
        refs = {}
        for i in decoder.disasm(
            pe.get_data(selected["address"] - base, selected["size"]),
            selected["address"],
        ):
            for operand in i.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    target = i.address + i.size + operand.mem.disp
                    try:
                        value = string(target)
                        if len(value) > 3 and all(c.isprintable() for c in value):
                            refs[hex(target)] = value
                    except (UnicodeDecodeError, AssertionError, pefile.PEFormatError):
                        pass
        if refs:
            callback_strings[hex(selected["address"])] = dict(
                name=selected["name"], strings=refs
            )
    result_callbacks = dict(functions=callbacks, strings=callback_strings)
    (OUT / "native-reward-user-state.json").write_text(
        json.dumps(result_callbacks, indent=2) + "\n"
    )
    result = dict(
        executable_sha256=sha,
        registration=registration,
        lua_bindings=bindings,
        functions=functions,
    )
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "native-reward-target.json").write_text(json.dumps(result, indent=2) + "\n")
    for label in ("CCIEBBDDFH", "DFBEBDGCHJ"):
        target = bindings[label]
        print(label, hex(target), functions[str(target)]["pseudocode"])
    for selected in functions.values():
        if any(
            token in selected.get("name", "").lower()
            for token in ("reward", "progression", "activate")
        ):
            print(hex(selected["address"]), selected["name"], selected["pseudocode"])
    print(json.dumps(callback_strings, indent=2))
