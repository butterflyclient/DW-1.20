"""Bind all four Replay account REST writers and response slots to original bytes."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
snapshot = database.stat()
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
routes = [
    dict(
        operation="updatesecuredfields",
        writer=0x142100B00,
        constructor=0x142100F30,
        table=0x14269E4B8,
        success=0x142101270,
        failure=0x142100FE0,
        method=0x505554,
        error_offset=1064,
        request_strings=[
            "UnoRes",
            "updatesecuredfields",
            "Bearer %s",
            "/v1.0/users/%llu/securedfields/",
            "client",
            "userName",
            "email",
            "accountType",
            "full",
            "password",
            "firstName",
            "lastName",
            "dateOfBirth",
            "country",
            "subscriptionOptIn",
        ],
        response_strings=["success", "IDToken"],
        capacities={"IDToken": 1024},
    ),
    dict(
        operation="authenticateUser",
        writer=0x142166F50,
        constructor=0x1421671F0,
        table=0x1426A7C10,
        success=0x142167560,
        failure=0x1421672D0,
        method=0x504F5354,
        error_offset=9264,
        request_strings=[
            "UserResource",
            "authenticateUser",
            "/v1.0/auth/",
            "client",
            "email",
            "password",
            "grantType",
        ],
        response_strings=["unoID", "tokens", "IDToken", "accessToken", "refreshToken"],
        capacities={"IDToken": 1024, "accessToken": 4096, "refreshToken": 4096},
    ),
    dict(
        operation="linkUser",
        writer=0x1421677C0,
        constructor=0x142167BD0,
        table=0x1426A7CF0,
        success=0x142167E70,
        failure=0x142167C60,
        method=0x505554,
        error_offset=48,
        request_strings=[
            "umbrella",
            "UserResource",
            "linkUser",
            "Bearer  %s",
            "/v1.0/users/crossplatform/{m_umbrellaID}/",
            "client",
            "unoIDToken",
            "accessToken",
            "refreshToken",
        ],
        response_strings=["umbrellaID"],
        capacities={},
    ),
    dict(
        operation="updateUmbrellaAccount",
        writer=0x142167F80,
        constructor=0x142168290,
        table=0x1426A7DB0,
        success=0x142168530,
        failure=0x142168320,
        method=0x504F5354,
        error_offset=40,
        request_strings=[
            "umbrella",
            "Umbrella",
            "updateUmbrellaAccount",
            "/v1.0/tokens/uno/",
            "client",
            "accountID",
            "tokens",
            "accessToken",
            "refreshToken",
        ],
        response_strings=["umbrellaID"],
        capacities={},
    ),
]


def function(db, address):
    alias, size = db.execute(
        "select name,size from functions where address=?", (str(address),)
    ).fetchone()
    code = pe.get_data(address - base, size)
    calls, references, literals, immediates = [], [], set(), set()
    for instruction in decoder.disasm(code, address):
        if (
            instruction.mnemonic == "call"
            and instruction.operands[0].type == X86_OP_IMM
        ):
            calls.append(instruction.operands[0].imm)
        for operand in instruction.operands:
            if operand.type == X86_OP_IMM:
                immediates.add(operand.imm)
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                pointer = instruction.address + instruction.size + operand.mem.disp
                references.append(pointer)
                if pointer >= base:
                    value = pe.get_data(pointer - base, 256).split(b"\0", 1)[0]
                    if (
                        value
                        and len(value) < 128
                        and all(32 <= byte < 127 for byte in value)
                    ):
                        literals.add(value.decode("ascii"))
    return (
        dict(
            va=address,
            candidate_alias=alias,
            size=size,
            bytes_sha256=hashlib.sha256(code).hexdigest(),
            direct_calls=calls,
            rip_references=references,
            literal_strings=sorted(literals),
        ),
        immediates,
    )


with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for route in routes:
        writer, constants = function(db, route["writer"])
        assert route["method"] in constants
        assert set(route["request_strings"]).issubset(writer["literal_strings"])
        constructor, _ = function(db, route["constructor"])
        assert route["table"] in constructor["rip_references"]
        entries = struct.unpack("<4Q", pe.get_data(route["table"] - base, 32))
        assert entries[1:3] == (route["success"], route["failure"])
        success, constants = function(db, route["success"])
        assert set(route["response_strings"]).issubset(success["literal_strings"])
        assert set(route["capacities"].values()).issubset(constants)
        failure, _ = function(db, route["failure"])
        route["response_vtable"] = list(entries)
        route["functions"] = [writer, constructor, success, failure]
assert snapshot.st_mtime_ns == database.stat().st_mtime_ns
output = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=digest,
    routes=routes,
    native_account_menu_callbacks_verified=False,
    account_policy="Optional credentials attach to the current signed machine-owned player. Local account IDs remain stable; cross-player migration and retail account ownership are not inferred.",
)
path = ROOT / "validation/20261006-native-account-auth-layout.json"
path.write_text(json.dumps(output, indent=2) + "\n")
print("Verified four original account REST writers and native response vtable slots.")
