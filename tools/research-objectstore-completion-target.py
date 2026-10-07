"""Trace Replay's original post-HTTP completion tasks without running the game.

Executes unchanged x64 instructions. Only HTTP method boundaries and the task
manager's output handle are modeled; request/response serializers are not.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_GS_BASE,
)

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
image_hash = hashlib.sha256(raw).hexdigest()
assert image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
entry, constructor = 0x14215FFE0, 0x142117C10
code = pe.get_data(entry - base, 1255)
instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, entry))
assert instructions[-1].address + instructions[-1].size == entry + len(code)
calls = [instruction.address for instruction in instructions
         if instruction.mnemonic == "call" and instruction.op_str == hex(constructor)]
assert calls == [0x1421600E3, 0x142160335]


def case(mode):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, objects, api = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x10000)
    vm.mem_map(objects, 0x10000)
    vm.mem_map(api, 0x1000)
    tib = api + 0x1000
    vm.mem_map(tib, 0x1000)
    vm.mem_write(tib + 8, struct.pack("<QQ", stack + 0x10000, stack))
    vm.reg_write(UC_X86_REG_GS_BASE, tib)
    stream, manager, parent, http = (objects + offset for offset in (0, 0x1000, 0x2000, 0x3000))
    vtable, request, response, lobby, result = (
        objects + offset for offset in (0x4000, 0x5020, 0x6008, 0x7000, 0x8000)
    )
    halt, http_stop, http_release = api, api + 0x10, api + 0x20
    pages = set()

    def original_page(address):
        page = address & ~4095
        if page in pages:
            return
        assert base <= page < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(page, 4096)
        content = pe.get_data(page - base, 4096)
        if content:
            vm.mem_write(page, content)
        pages.add(page)

    def missing(machine, access, address, size, value, context):
        if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            raise RuntimeError(
                f"Unexpected VM access {address:#x} at {machine.reg_read(UC_X86_REG_RIP):#x}, mode {mode}"
            )
        original_page(address)
        original_page(address + size - 1)
        return True

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    put32 = lambda address, value: vm.mem_write(address, struct.pack("<I", value))
    put64 = lambda address, value: vm.mem_write(address, struct.pack("<Q", value))
    get32 = lambda address: struct.unpack("<I", vm.mem_read(address, 4))[0]
    get64 = lambda address: struct.unpack("<Q", vm.mem_read(address, 8))[0]
    for offset, pointer in ((8, manager), (16, parent), (32, lobby), (40, http),
                            (160, request), (168, response)):
        put64(stream + offset, pointer)
    put32(stream + 48, mode)
    put32(stream + 52, 1)
    put32(result + 8, 1)
    put32(result + 80, 37)
    put64(http, vtable)
    put64(vtable + 152, http_stop)
    put64(vtable + 136, http_release)
    put64(stack + 0xF008, halt)
    vm.reg_write(UC_X86_REG_RCX, stream)
    vm.reg_write(UC_X86_REG_RSP, stack + 0xF008)
    captured, http_calls, trail = [], [], []

    def returned(machine, value=0):
        position = machine.reg_read(UC_X86_REG_RSP)
        target = get64(position)
        machine.reg_write(UC_X86_REG_RAX, value)
        machine.reg_write(UC_X86_REG_RSP, position + 8)
        machine.reg_write(UC_X86_REG_RIP, target)

    def boundary(machine, address, size, context):
        trail.append(hex(address))
        if len(trail) > 24:
            trail.pop(0)
        if address == halt:
            machine.emu_stop()
        elif address in (http_stop, http_release):
            assert machine.reg_read(UC_X86_REG_RCX) == http
            http_calls.append(address)
            returned(machine)
        elif address == constructor:
            position = machine.reg_read(UC_X86_REG_RSP)
            row = {
                "service": machine.reg_read(UC_X86_REG_R8) & 255,
                "task": machine.reg_read(UC_X86_REG_R9) & 255,
                "manager": machine.reg_read(UC_X86_REG_RCX),
                "request": get64(position + 40),
                "response": get64(position + 48),
                "lobby_service": get64(position + 56),
            }
            assert row == {
                "service": 193, "task": 12 if mode == 2 else 24,
                "manager": manager, "request": request,
                "response": response, "lobby_service": lobby,
            }
            captured.append(row)
            put64(machine.reg_read(UC_X86_REG_RDX), result)
            returned(machine)

    vm.hook_add(UC_HOOK_CODE, boundary)
    try:
        vm.emu_start(entry, halt, count=20000)
    except Exception as error:
        raise RuntimeError(
            f"Completion VM mode {mode}, RIP={vm.reg_read(UC_X86_REG_RIP):#x}, "
            f"RSP={vm.reg_read(UC_X86_REG_RSP):#x}, trail={trail}"
        ) from error
    assert vm.reg_read(UC_X86_REG_RIP) == halt
    assert captured and http_calls == [http_stop, http_release]
    assert get64(stream + 24) == result and get32(stream + 52) == 4
    assert get32(parent + 80) == 37
    return {
        "mode": mode, "call": captured[0], "post_http_state": get32(stream + 52),
        "parent_error": get32(parent + 80), "passed": True,
        "request_response_readers_executed": False,
        "initiation_path_verified": False,
    }


cases = [case(mode) for mode in (2, 4)]
database = image.with_suffix(".exe.sqlite")
rejected_aliases = []
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address, reason in (
        (0x1420F1890, "Original SHA1/HMAC helper, not an object-store JSON response reader"),
        (0x142241BA4, "Original CRT floating-point exception/status helper, not a response reader"),
        (0x140CC35F0, "Original MSG bit-field reader, not an upload-session request destructor"),
        (0x1421F9998, "Original InitializeCriticalSectionEx compatibility wrapper, not upload initialization"),
    ):
        row = db.execute("select name,size from functions where address=?", (str(address),)).fetchone()
        assert row
        contents = pe.get_data(address - base, row[1])
        rejected_aliases.append({
            "address": hex(address), "analysis_label": row[0],
            "bytes_sha256": hashlib.sha256(contents).hexdigest(), "reason": reason,
        })

report = {
    "schema": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
    "target_image_sha256": image_hash,
    "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "original_function": {"address": hex(entry), "size": len(code),
                          "bytes_sha256": hashlib.sha256(code).hexdigest()},
    "completion_calls": cases, "rejected_analysis_aliases": rejected_aliases,
    "interpretation": {
        "193/12": "Post-HTTP single-upload session completion",
        "193/24": "Post-HTTP multiple-upload session completion",
        "initial_upload_task_binding_verified": False,
        "cached_request_response_class_binding_verified": False,
        "full_native_method_completion_verified": False,
    },
    "modeled_boundaries": ["HTTP stop/release callbacks", "Native task manager output handle"],
    "vm_environment": {
        "windows_x64_entry_stack_alignment": 8,
        "native_stack_probe_executed": True,
        "tib_stack_base_limit_supplied": True,
        "conditional_modes_initialized_by_fixture": [2, 4],
    },
    "game_runs_performed": False,
}
destination = ROOT / "validation/20261007-objectstore-completion-target.json"
destination.write_text(json.dumps(report, indent=2) + "\n")
print(f"PASS: original post-HTTP modes 2 and 4 bind 193/12 and 193/24; {destination}")
