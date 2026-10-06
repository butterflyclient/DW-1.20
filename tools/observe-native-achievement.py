"""Read Replay's actual achievement batch response, without invoking game code."""

import argparse
import ctypes
from ctypes import wintypes as w
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--state-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
state = args.state_root.resolve()
output = args.output.resolve()
assert state.is_relative_to(ROOT / "data") and output.is_relative_to(state)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


# The source oracle supplies names only. Every offset below is checked against
# the original Replay instructions, then the live image's linked symbols.
original = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
assert (
    digest(original)
    == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
)
pe = pefile.PE(str(original), fast_load=True)
original_base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
target_functions = {}
with sqlite3.connect(
    original.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True
) as db:
    db.execute("pragma query_only=on")
    for address in (
        0x140F6B120,
        0x140F6E940,
        0x14212C470,
        0x1420F8D40,
        0x14211E430,
        0x14211AB20,
        0x142158D30,
        0x142169760,
        0x1420FE260,
        0x1420FE280,
        0x142117EB0,
        0x142118060,
        0x142168B90,
        0x142157FF0,
        0x1420FF530,
    ):
        size = db.execute(
            "select size from functions where address=?", (str(address),)
        ).fetchone()[0]
        code = pe.get_data(address - original_base, size)
        instructions = [(i.mnemonic, i.op_str) for i in decoder.disasm(code, address)]
        target_functions[address] = dict(
            va=address,
            bytes_sha256=hashlib.sha256(code).hexdigest(),
            instructions=instructions,
        )


def require_instruction(address, mnemonic, operands):
    assert (mnemonic, operands) in target_functions[address]["instructions"], (
        hex(address),
        mnemonic,
        operands,
    )


for address, mnemonic, operands in (
    (0x140F6B120, "imul", "rdx, rax, 0x470"),
    (0x140F6B120, "lea", "rax, [rcx + 0x258]"),
    (0x140F6E940, "mov", "rcx, qword ptr [rcx + 0x10]"),
    (0x140F6E940, "call", "0x14212c470"),
    (0x140F6E940, "call", "0x1420f8d40"),
    (0x140F6E940, "jmp", "0x14211e430"),
    (0x14212C470, "lea", "rax, [rcx + 0x1b90]"),
    (0x1420F8D40, "mov", "rax, qword ptr [rcx + 0x5830]"),
    (0x14211E430, "mov", "rdi, qword ptr [rbx + 0x118]"),
    (0x14211AB20, "lea", "rcx, [rbp + 0x1f328]"),
    (0x142158D30, "mov", "ecx, dword ptr [rcx + 0x19e88]"),
    (0x142158D30, "lea", "rcx, [rbp + 0x19f00]"),
    (0x142158D30, "mov", "dword ptr [rbp + 0x19e88], 3"),
    (0x142169760, "lea", "r8, [rsi + 0x12c]"),
    (0x1420FE260, "mov", "eax, dword ptr [rcx + 0x50]"),
    (0x1420FE280, "mov", "eax, dword ptr [rcx + 0x1c]"),
    (0x142117EB0, "lea", "rcx, [rdi + 0x38]"),
    (0x142168B90, "mov", "edi, 2"),
    (0x142168B90, "call", "qword ptr [rax + 8]"),
    (0x142168B90, "mov", "dword ptr [rax + 8], edi"),
    (0x1420FF530, "mov", "byte ptr [rcx + 0x10], al"),
    (0x1420FF530, "mov", "dword ptr [rcx + 0x14], eax"),
):
    require_instruction(address, mnemonic, operands)

deployment = load(state / "alpha/deployment.json")
launch = load(state / "alpha/launch.json")
assert (
    launch["sha256"] == deployment["sha256"] == digest(Path(deployment["executable"]))
)
report = load(Path(deployment["build_directory"]) / "build-report.json")
symbols = report["symbols"]
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
kernel.OpenProcess.restype = w.HANDLE
kernel.CloseHandle.argtypes = (w.HANDLE,)
kernel.ReadProcessMemory.argtypes = (
    w.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
kernel.QueryFullProcessImageNameW.argtypes = (
    w.HANDLE,
    w.DWORD,
    w.LPWSTR,
    ctypes.POINTER(w.DWORD),
)
kernel.GetProcessTimes.argtypes = (w.HANDLE,) + (ctypes.POINTER(w.FILETIME),) * 4
process = kernel.OpenProcess(0x410, False, launch["pid"])
if not process:
    raise ctypes.WinError(ctypes.get_last_error())
try:
    name = ctypes.create_unicode_buffer(32768)
    length = w.DWORD(len(name))
    if not kernel.QueryFullProcessImageNameW(process, 0, name, ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    assert Path(name.value).resolve() == Path(deployment["executable"]).resolve()
    times = [w.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(process, *(ctypes.byref(t) for t in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    expected_created = datetime.fromisoformat(
        launch["process_created_utc"].replace("Z", "+00:00")
    )
    assert (
        abs(
            created
            - int(expected_created.timestamp() * 10_000_000)
            - 116444736000000000
        )
        <= 10
    )
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumProcessModulesEx.argtypes = (
        w.HANDLE,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
        w.DWORD,
    )
    modules, needed = (w.HMODULE * 1024)(), w.DWORD()
    if not psapi.EnumProcessModulesEx(
        process, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    base = modules[0]

    def read(address, count):
        assert 0x10000 <= address <= 0x7FFFFFFFFFFF and 0 < count <= 4096
        buffer, copied = ctypes.create_string_buffer(count), ctypes.c_size_t()
        if (
            not kernel.ReadProcessMemory(
                process, address, buffer, count, ctypes.byref(copied)
            )
            or copied.value != count
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw

    def pointer(address):
        value = struct.unpack("<Q", read(address, 8))[0]
        assert value >= 0x10000
        return value

    getter = symbols["DWServicesAccess::GetInstance"]
    for _ in range(3):
        code = read(base + getter, 8)
        if code[0] != 0xE9:
            break
        getter += 5 + struct.unpack_from("<i", code, 1)[0]
    assert code[:3] == b"\x48\x8d\x05" and code[7] == 0xC3
    services = base + getter + 7 + struct.unpack_from("<i", code, 3)[0]
    # Verify the controller-0 wrapper's original native getter still has its
    # linked encoding; no raw-pointer scan or function execution is performed.
    client_wrapper = services + 600
    client_getter = base + symbols["func_140F6B120"]
    for _ in range(3):
        linked = read(client_getter, 32)
        if linked[0] != 0xE9:
            break
        client_getter += 5 + struct.unpack_from("<i", linked, 1)[0]
    linked_instructions = []
    for instruction in decoder.disasm(linked, client_getter):
        linked_instructions.append((instruction.mnemonic, instruction.op_str))
        if instruction.mnemonic == "ret":
            break
    assert linked_instructions == target_functions[0x140F6B120]["instructions"]
    owner = pointer(client_wrapper + 8)
    login_wrapper = pointer(owner + 904 + 16)
    login = pointer(login_wrapper + 16)
    lobby = pointer(login + 7056 + 22576)
    client = pointer(lobby + 280)
    engine = pointer(lobby + 272)
    single_response = engine + 56
    batch = client + 127784
    response = batch + 106240

    def snapshot():
        return dict(
            client_status=struct.unpack("<I", read(client + 36, 4))[0],
            batch_status=struct.unpack("<I", read(batch + 106120, 4))[0],
            batch_entry_count=struct.unpack("<I", read(batch + 106112, 4))[0],
            task_pointer=struct.unpack("<Q", read(batch + 106176, 8))[0],
            response_vtable=struct.unpack("<Q", read(response, 8))[0],
            response_status=struct.unpack("<I", read(response + 8, 4))[0],
            response_error=struct.unpack("<I", read(response + 20, 4))[0],
            response_result_count=struct.unpack("<I", read(response + 296, 4))[0],
            response_all_succeeded=read(response + 300, 1)[0],
            single_response_vtable=struct.unpack("<Q", read(single_response, 8))[0],
            single_response_status=struct.unpack("<I", read(single_response + 8, 4))[0],
            single_response_error_set=read(single_response + 16, 1)[0],
            single_response_error=struct.unpack("<I", read(single_response + 20, 4))[0],
            rest_requests_enabled=bool(read(engine + 96, 1)[0]),
        )

    for _ in range(3):
        a, b = snapshot(), snapshot()
        if a == b:
            break
    assert a == b, "Native achievement state changed during bounded read"
    assert (
        a["client_status"] <= 3
        and a["batch_status"] <= 3
        and a["batch_entry_count"] <= 16
    )
    assert a["response_all_succeeded"] <= 1 and a["response_result_count"] <= 64
    table = a.pop("response_vtable")
    reader = struct.unpack("<Q", read(table + 8, 8))[0] - base
    assert reader == symbols["func_142169760"]
    single_table = a.pop("single_response_vtable")
    single_reader = struct.unpack("<Q", read(single_table + 8, 8))[0] - base
    assert single_reader == symbols["func_142158070"]
    task = a.pop("task_pointer")
    if task:
        a["remote_task_status"] = struct.unpack("<I", read(task + 28, 4))[0]
        a["remote_task_error"] = struct.unpack("<I", read(task + 80, 4))[0]
    else:
        a["remote_task_status"] = None
        a["remote_task_error"] = None
    result = dict(
        schema=1,
        observed_utc=datetime.now(timezone.utc).isoformat(),
        pid=launch["pid"],
        game_sha256=deployment["sha256"],
        backend_sha256=deployment["server_sha256"],
        observer_sha256=digest(Path(__file__)),
        original_image_sha256=digest(original),
        deployment=reference(state / "alpha/deployment.json"),
        launch=reference(state / "alpha/launch.json"),
        target_functions=list(target_functions.values()),
        native_state=a,
        response_success_reader_rva=reader,
        single_response_success_reader_rva=single_reader,
        native_single_callback_success=bool(
            a["single_response_status"] == 2
            and not a["single_response_error_set"]
            and a["single_response_error"] == 0
        ),
        native_batch_callback_success=bool(
            a["response_all_succeeded"] == 1
            and a["remote_task_status"] == 2
            and a["remote_task_error"] == 0
            and a["batch_status"] == 3
            and a["client_status"] == 0
        ),
        scope="Read-only original response field, SDK task result and batch/client completion; no game code called or state written",
    )
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            dict(
                native_state=a,
                native_single_callback_success=result["native_single_callback_success"],
                native_batch_callback_success=result["native_batch_callback_success"],
            )
        )
    )
finally:
    kernel.CloseHandle(process)
