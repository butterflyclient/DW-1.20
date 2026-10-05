"""Read only verified DW-process state, resolving globals through linked symbols."""

import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import struct
from datetime import datetime, timezone
import urllib.request
import argparse

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--pid",
    type=int,
    help="Attach read-only to an owner-launched DW process without a launch receipt",
)
parser.add_argument(
    "--commands", action="store_true", help="Include all native command registrations"
)
parser.add_argument(
    "--output",
    type=Path,
    help="Write a separate observation without replacing the shared latest receipt",
)
parser.add_argument(
    "--dvars",
    nargs="*",
    default=[],
    help="Read selected registered dvar names from the native pool",
)
parser.add_argument(
    "--counters",
    action="store_true",
    help="Read native global-counter tables and task slots, without changing them",
)
args = parser.parse_args()
deployment = json.loads((root / "data" / "deployment.json").read_text())
launch = (
    None
    if args.pid
    else json.loads(
        (root / "data" / "current-runtime-launch.json").read_text(encoding="utf-8-sig")
    )
)
if launch and deployment["sha256"] != launch["sha256"]:
    raise RuntimeError("Launch receipt does not match the deployed DW image")
pid = args.pid if args.pid else launch["pid"]
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
kernel.OpenProcess.restype = w.HANDLE
kernel.CloseHandle.argtypes = (w.HANDLE,)
kernel.QueryFullProcessImageNameW.argtypes = (
    w.HANDLE,
    w.DWORD,
    w.LPWSTR,
    ctypes.POINTER(w.DWORD),
)
kernel.ReadProcessMemory.argtypes = (
    w.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
kernel.GetModuleHandleW.argtypes = (w.LPCWSTR,)
kernel.GetModuleHandleW.restype = w.HMODULE
process = kernel.OpenProcess(0x410, False, pid)
if not process:
    raise ctypes.WinError(ctypes.get_last_error())
try:
    name = ctypes.create_unicode_buffer(32768)
    length = w.DWORD(len(name))
    if not kernel.QueryFullProcessImageNameW(process, 0, name, ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    path = Path(name.value)
    if (
        path.resolve() != Path(deployment["executable"]).resolve()
        or hashlib.sha256(path.read_bytes()).hexdigest() != deployment["sha256"]
    ):
        raise RuntimeError("Process image is not the verified DW deployment")
    server_deployment = None
    server_receipt_path = root / "data/server-process.json"
    if server_receipt_path.exists():
        receipt = json.loads(server_receipt_path.read_text(encoding="utf-8-sig"))
        server_process = kernel.OpenProcess(0x1000, False, receipt["pid"])
        if not server_process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            server_name = ctypes.create_unicode_buffer(32768)
            server_length = w.DWORD(len(server_name))
            if not kernel.QueryFullProcessImageNameW(
                server_process, 0, server_name, ctypes.byref(server_length)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            server_path = Path(server_name.value)
            if (
                server_path.resolve() != Path(receipt["executable"]).resolve()
                or server_path.resolve()
                != (root / "build/Release/iw8-dw-server.exe").resolve()
                or hashlib.sha256(server_path.read_bytes()).hexdigest()
                != receipt["sha256"]
                or receipt["sha256"] != deployment["server_sha256"]
            ):
                raise RuntimeError("Live server process differs from the deployment")
            server_deployment = dict(
                receipt,
                verified_live_process=True,
                launch_receipt_matches=bool(
                    launch and launch.get("server_process") == receipt
                ),
            )
        finally:
            kernel.CloseHandle(server_process)
    connection = launch
    connection_path = root / "data/current-runtime-connection.json"
    if launch and server_deployment and connection_path.exists():
        refreshed = json.loads(connection_path.read_text(encoding="utf-8-sig"))
        if (
            refreshed["pid"] == pid
            and refreshed["sha256"] == deployment["sha256"]
            and refreshed["server_process"] == receipt
            and refreshed["command"] == "dw_restart"
            and refreshed.get("dispatched_utc")
            and datetime.fromisoformat(refreshed["requested_utc"])
            > datetime.fromisoformat(launch["launched_utc"])
        ):
            connection = refreshed
    if server_deployment:
        server_deployment["connection_receipt_matches"] = bool(
            connection and connection.get("server_process") == receipt
        )
    # Enumerate modules read-only to obtain the ASLR base; no fixed runtime VA.
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumProcessModulesEx.argtypes = (
        w.HANDLE,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
        w.DWORD,
    )
    modules = (w.HMODULE * 1024)()
    needed = w.DWORD()
    if not psapi.EnumProcessModulesEx(
        process, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    base = modules[0]
    report = json.loads(
        (Path(deployment["build_directory"]) / "build-report.json").read_text()
    )
    symbols = report["symbols"]
    symbol_names = {}
    for symbol_name, symbol_rva in symbols.items():
        symbol_names.setdefault(symbol_rva, []).append(symbol_name)
    # Same-Replay native getters iterate until s_clientMgrMode, which follows
    # the controller map. Do not count that mode word as another controller.
    client_map_count = (
        symbols["s_clientMgrMode"] - symbols["s_clientControllerMap"]
    ) // 4
    if not 1 <= client_map_count <= 8:
        raise RuntimeError("Native client mapping bounds changed")

    def read(rva, size):
        buffer = ctypes.create_string_buffer(size)
        count = ctypes.c_size_t()
        if (
            not kernel.ReadProcessMemory(
                process, base + rva, buffer, size, ctypes.byref(count)
            )
            or count.value != size
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw

    def native_string_buffer(pointer_symbol, capacity_symbol):
        pointer = struct.unpack("<Q", read(symbols[pointer_symbol], 8))[0]
        capacity = struct.unpack("<I", read(symbols[capacity_symbol], 4))[0]
        if not pointer or not 0 < capacity <= 16384:
            return None
        return (
            read(pointer - base, capacity).split(b"\0", 1)[0].decode(errors="replace")
        )

    def global_from_getter(symbol):
        rva = symbols[symbol]
        for _ in range(3):
            code = read(rva, 8)
            if code[0] == 0xE9:
                rva += 5 + struct.unpack_from("<i", code, 1)[0]
                continue
            if code[:3] != b"\x48\x8d\x05" or code[7] != 0xC3:
                raise RuntimeError("Verified native getter encoding changed: " + symbol)
            return rva + 7 + struct.unpack_from("<i", code, 3)[0]
        raise RuntimeError("Native getter has an unexpected gateway chain")

    def native_marketing():
        getter = "q_MarketingCommsManager::GetInstance"
        if getter not in symbols:
            return None
        # Target getter 140F69230 and completion 140F69AB0 establish these
        # fields. All addresses follow the current linked getter/ASLR mapping.
        manager = global_from_getter(getter)
        record = read(manager, 432)
        request, response = struct.unpack_from("<QQ", record, 208)
        result = {
            "fetch_in_flight": bool(record[65]),
            "remote_task_present": bool(struct.unpack_from("<Q", record, 264)[0]),
            "controller": struct.unpack_from("<i", record, 296)[0],
            "request": None,
            "response_count": 0,
            "messages": [],
            "parsed_locations": [],
        }
        if request:
            header = read(request - base, 72)
            capacity, count = struct.unpack_from("<II", header, 64)
            if count > capacity or count > 64:
                raise RuntimeError("Native marketing request bounds changed")
            result["request"] = {
                "context": header[16:32].split(b"\0")[0].decode(errors="replace"),
                "language": header[32:52].split(b"\0")[0].decode(errors="replace"),
                "location_count": count,
            }
        if response:
            header = read(response - base, 32)
            data, capacity, count = struct.unpack_from("<QII", header, 16)
            if count > capacity or count > 512 or (count and data < 65536):
                raise RuntimeError("Native marketing response bounds changed")
            result["response_count"] = count
            for index in range(count):
                # Actual 142114EC0 array stride and 142114CF0 member offsets.
                item = read(data - base + index * 7328, 7312)
                message = {
                    "id": struct.unpack_from("<Q", item, 16)[0],
                    "language": item[24:44].split(b"\0")[0].decode(errors="replace"),
                    "assignment": struct.unpack_from("<Q", item, 7296)[0],
                    "location": struct.unpack_from("<I", item, 7304)[0],
                }
                for name, at, maximum, length_at in (
                    ("content", 44, 4096, 4140),
                    ("metadata", 4144, 2048, 6192),
                    ("payload", 6196, 1024, 7220),
                    ("signature", 7224, 65, 7292),
                ):
                    size = struct.unpack_from("<I", item, length_at)[0]
                    if size > maximum:
                        raise RuntimeError("Native marketing blob bounds changed")
                    message[name + "_size"] = size
                    message[name + "_sha256"] = hashlib.sha256(
                        item[at : at + size]
                    ).hexdigest()
                result["messages"].append(message)
        for location in range(15):
            pointer = struct.unpack_from("<Q", record, 88 + 8 * location)[0]
            maximum = struct.unpack_from("<I", record, 312 + 4 * location)[0]
            parsed_count = struct.unpack_from("<I", record, 372 + 4 * location)[0]
            if not pointer or not maximum:
                continue
            if maximum > 100 or parsed_count > maximum:
                raise RuntimeError("Native marketing parsed-cache bounds changed")
            cached = read(pointer - base, 6152)
            value = cached[:6144].split(b"\0")[0]
            parsed = None
            if cached[6144] and value:
                try:
                    parsed = json.loads(value)
                except (UnicodeDecodeError, ValueError):
                    pass
            result["parsed_locations"].append(
                {
                    "location": location,
                    "maximum": maximum,
                    "parsed_count": parsed_count,
                    "first_parsed": bool(cached[6144]),
                    "first_json": parsed,
                    "first_sha256": hashlib.sha256(value).hexdigest(),
                }
            )
        return result

    def pointer_from_getter(symbol):
        rva = symbols[symbol]
        for _ in range(3):
            code = read(rva, 8)
            if code[0] == 0xE9:
                rva += 5 + struct.unpack_from("<i", code, 1)[0]
                continue
            if code[:3] != b"\x48\x8b\x05" or code[7] != 0xC3:
                raise RuntimeError(
                    "Verified native pointer getter encoding changed: " + symbol
                )
            slot = rva + 7 + struct.unpack_from("<i", code, 3)[0]
            return struct.unpack("<Q", read(slot, 8))[0]
        raise RuntimeError("Native pointer getter has an unexpected gateway chain")

    def dvar_current(symbol, fmt):
        if symbol not in symbols:
            return None
        pointer = struct.unpack("<Q", read(symbols[symbol], 8))[0]
        if not pointer:
            return None
        return struct.unpack(fmt, read(pointer - base + 40, struct.calcsize(fmt)))[0]

    def dvar_details(symbol):
        if symbol not in symbols:
            return None
        pointer = struct.unpack("<Q", read(symbols[symbol], 8))[0]
        if not pointer:
            return None
        record = read(pointer - base, 112)
        name = struct.unpack_from("<Q", record)[0]
        return {
            "name": read(name - base, 128).split(b"\0")[0].decode(errors="replace"),
            "flags": struct.unpack_from("<I", record, 24)[0],
            "type": record[29],
        }

    selected_dvars = {}
    if args.dvars:
        # Same-Replay Dvar_FindMalleableVar (0x1413E62C0) indexes 112-byte
        # records. Read only requested names and never issue native setters.
        pool = read(symbols["gl_14E37EE30"], 7000 * 112)
        requested = set(args.dvars)
        for offset in range(0, len(pool), 112):
            record = pool[offset : offset + 112]
            name_pointer = struct.unpack_from("<Q", record)[0]
            if not name_pointer:
                continue
            try:
                name = (
                    read(name_pointer - base, 128)
                    .split(b"\0")[0]
                    .decode(errors="replace")
                )
            except OSError:
                continue
            if name not in requested:
                continue
            kind = record[29]
            value = None
            if kind == 0:
                value = bool(record[40])
            elif kind == 1:
                value = struct.unpack_from("<f", record, 40)[0]
            elif kind in (5, 8):
                value = struct.unpack_from("<i", record, 40)[0]
            elif kind == 9:
                pointer = struct.unpack_from("<Q", record, 40)[0]
                value = (
                    read(pointer - base, 256).split(b"\0")[0].decode(errors="replace")
                    if pointer
                    else ""
                )
            selected_dvars[name] = {
                "type": kind,
                "flags": struct.unpack_from("<I", record, 24)[0],
                "value": value,
            }
            if len(selected_dvars) == len(requested):
                break
    counter_state = None
    if args.counters:
        # Actual Replay LiveCounter_CheckOngoingTasks / IncrementCounters:
        # 64-byte bdCounterValue records, ID +32, Int64 +40; at most 63 IDs.
        count = struct.unpack("<I", read(symbols["gl_14461B1D0"], 4))[0]
        if count >= 64:
            raise RuntimeError("Native global-counter table bounds changed")

        def counter_rows(symbol):
            buffer = read(symbols[symbol], 64 * count)
            return [
                {
                    "id": struct.unpack_from("<I", buffer, offset + 32)[0],
                    "value": struct.unpack_from("<q", buffer, offset + 40)[0],
                }
                for offset in range(0, len(buffer), 64)
            ]

        slots = read(symbols["gl_14E6BFB38"], 32 * 32)
        # Follow the exact native DB_AssetEntryTable hash/chain reader
        # 0x140F5E010 for this single string table; no pool scan or mutation.
        asset_table = struct.unpack("<Q", read(symbols["gl_14C815C60"], 8))[0]
        asset_name = b"mp/globalcounters.csv"
        asset_type = 54
        hashed = asset_type
        for byte in asset_name:
            hashed = (byte + 31 * hashed) & 0xFFFFFFFF
        index = struct.unpack(
            "<I", read(asset_table - base + 7212808 + 4 * (hashed % 0x57800), 4)
        )[0]
        visited = set()
        csv_rows = []
        asset_lookup = []
        while index:
            if index in visited or index >= 383488 or len(visited) >= 10000:
                raise RuntimeError("Native counter asset chain bounds changed")
            visited.add(index)
            entry = read(asset_table - base + 20 * index, 20)
            header = struct.unpack_from("<Q", entry)[0]
            asset_lookup.append({"index": index, "type": entry[17]})
            if entry[17] == asset_type and header:
                table = read(header - base, 48)
                name_pointer = struct.unpack_from("<Q", table)[0]
                if read(name_pointer - base, 64).split(b"\0")[0] == asset_name:
                    columns, rows, strings = struct.unpack_from("<3I", table, 8)
                    if not 2 <= columns <= 16 or rows != count or strings > 8192:
                        raise RuntimeError("Native counter CSV bounds changed")
                    indices_pointer, hash_pointer, strings_pointer = struct.unpack_from(
                        "<3Q", table, 24
                    )
                    indices = read(indices_pointer - base, 2 * columns * rows)
                    pointers = read(strings_pointer - base, 8 * strings)
                    for row in range(rows):
                        values = []
                        for column in range(columns):
                            string_index = struct.unpack_from(
                                "<H", indices, 2 * (row * columns + column)
                            )[0]
                            if string_index >= strings:
                                raise RuntimeError("Native counter CSV index invalid")
                            pointer = struct.unpack_from(
                                "<Q", pointers, 8 * string_index
                            )[0]
                            values.append(
                                read(pointer - base, 128)
                                .split(b"\0")[0]
                                .decode("utf-8")
                            )
                        csv_rows.append(values)
                    break
            index = struct.unpack_from("<I", entry, 8)[0]
        counter_state = {
            "initialized": bool(read(symbols["gl_14E6BFB23"], 1)[0]),
            "write_pending": bool(read(symbols["gl_14E6BFB29"], 1)[0]),
            "read_requested": bool(read(symbols["gl_14E6BFB2A"], 1)[0]),
            "table_available": bool(read(symbols["gl_14E6BFB28"], 1)[0]),
            "count": count,
            "download": counter_rows("gl_14E6BEB20"),
            "pending": counter_rows("gl_14E6BFF50"),
            "upload": counter_rows("gl_14E6BDB20"),
            "write_interval": dvar_current("gl_14E6BDB10", "<i"),
            "read_interval": dvar_current("gl_14E6BDB18", "<i"),
            "write_interval_registration": dvar_details("gl_14E6BDB10"),
            "read_interval_registration": dvar_details("gl_14E6BDB18"),
            "csv_rows": csv_rows,
            "asset_lookup": asset_lookup,
            "active_tasks": [
                {
                    "slot": offset // 32,
                    "type": struct.unpack_from("<I", slots, offset + 16)[0],
                    "controller": slots[offset + 21],
                }
                for offset in range(0, len(slots), 32)
                if slots[offset + 20]
            ],
        }
    auth_rva = global_from_getter("func_141660280")
    connection_rva = global_from_getter("func_141662FC0")
    user_rva = symbols["gl_14E5C0730"]
    user = read(user_rva, 232)
    # Same-Replay ExecuteTask reads each queued file's XUID at +216 and
    # platform byte at +224; Frame establishes 16 slots with stride 1720.
    # Report identities only, never profile payloads or session credentials.
    storage = read(symbols["gl_1444973E0"] + 64, 16 * 1720)
    storage_files = []
    for slot in range(16):
        task = storage[slot * 1720 : (slot + 1) * 1720]
        for entry in range(16):
            offset = 136 + 96 * entry
            name_bytes = task[offset : offset + 64].split(b"\0")[0]
            if not name_bytes or any(c < 32 or c > 126 for c in name_bytes):
                continue
            storage_files.append(
                {
                    "slot": slot,
                    "entry": entry,
                    "name": name_bytes.decode(),
                    "xuid": struct.unpack_from("<Q", task, offset + 80)[0],
                    "platform": task[offset + 88],
                }
            )
    hsm = read(symbols["g_dwLogonHSMs"], 136)
    state_count = struct.unpack_from("<i", hsm, 132)[0]
    if not 0 <= state_count <= 29:
        raise RuntimeError("Native HSM stack bounds changed")
    hsm_states = list(struct.unpack_from("<" + "i" * state_count, hsm, 16))
    account_address = pointer_from_getter("func_1416702C0")
    if account_address < 65536 or account_address % 8:
        raise RuntimeError("Native account service pointer is invalid")
    account = read(account_address - base, 152)
    # Same-build PubVar initializer/callbacks use seven 16-byte records. State
    # 3 plus the applied byte is native callback success, not server acceptance.
    namespace_names = (
        "general",
        "pc",
        "f2p",
        "general_8_19",
        "pc_8_19",
        "f2p_8_19",
        "autobuild",
    )
    publisher = read(symbols["gl_14C3C0160"], 7 * 16)
    publisher_states = []
    for index, namespace in enumerate(namespace_names):
        state, major, minor, requested_major, requested_minor, critical, applied = (
            struct.unpack_from("<I4H2B", publisher, index * 16)
        )
        publisher_states.append(
            dict(
                namespace=namespace,
                state=state,
                major=major,
                minor=minor,
                requested_major=requested_major,
                requested_minor=requested_minor,
                critical=bool(critical),
                applied=bool(applied),
            )
        )
    services_rva = global_from_getter("DWServicesAccess::GetInstance")
    lobby_wrapper = read(services_rva + 904, 16)
    lobby_owner = struct.unpack_from("<Q", lobby_wrapper, 8)[0]
    commands = []
    # Same-Replay Cmd_ExecuteSingleCommand walks cmd_function_s: next +0,
    # name +8, callback +32. Record only relevant registered commands.
    for head in ("gl_14D216D90", "gl_14D216D98"):
        address = struct.unpack("<Q", read(symbols[head], 8))[0]
        visited = set()
        while address and len(visited) < 4096:
            if address in visited:
                raise RuntimeError("Native command list contains a cycle")
            visited.add(address)
            entry = read(address - base, 40)
            next_address, name_address = struct.unpack_from("<2Q", entry)
            callback = struct.unpack_from("<Q", entry, 32)[0]
            label = (
                read(name_address - base, 128).split(b"\0")[0].decode(errors="replace")
            )
            if args.commands or label.lower() in (
                "startgamemode",
                "sys_restart",
                "disconnect",
                "quit",
                "onlinegame",
                "xstartprivateparty",
                "xstartlobby",
            ):
                commands.append(
                    {"name": label, "callback_rva": callback - base, "list": head}
                )
            address = next_address
    fences = []
    platform_services = []
    manager_symbol = "func_1416703E0"
    if manager_symbol in symbols:
        # Same-Replay service manager: inline pointers +64, count +184.
        manager_rva = global_from_getter(manager_symbol)
        count = struct.unpack("<Q", read(manager_rva + 184, 8))[0]
        if count > 15:
            raise RuntimeError("Native platform service count exceeds its inline table")
        for pointer in struct.unpack(
            "<" + "Q" * count, read(manager_rva + 64, count * 8)
        ):
            if pointer < base:
                raise RuntimeError("Native platform service pointer invalid")
            header = read(pointer - base, 32)
            name_pointer = struct.unpack_from("<Q", header, 8)[0]
            label = (
                read(name_pointer - base, 64).split(b"\0")[0].decode(errors="replace")
            )
            entry = {
                "name": label,
                "rva": pointer - base,
                "state": struct.unpack_from("<I", header, 16)[0],
                "group": struct.unpack_from("<I", header, 20)[0],
                "initialized": bool(header[24]),
            }
            if label == "PROFANITY":
                entry["filter_required"] = bool(read(pointer - base + 64, 1)[0])
                entry["filter_loaded"] = bool(read(pointer - base + 65, 1)[0])
                entry["filter_object_present"] = (
                    struct.unpack("<Q", read(pointer - base + 72, 8))[0] != 0
                )
            platform_services.append(entry)
    fence_objects = read(symbols["s_fenceObjects"], 27 * 8)
    fence_names = read(symbols["s_fenceNames"], 27 * 8)
    for index in range(27):
        address = struct.unpack_from("<Q", fence_objects, index * 8)[0]
        name_address = struct.unpack_from("<Q", fence_names, index * 8)[0]
        if address < base or name_address < base:
            continue  # manager may not have initialized yet
        flags = read(address - base + 8, 8)
        label = read(name_address - base, 64).split(b"\0")[0].decode(errors="replace")
        controller = struct.unpack_from("<I", flags)[0]
        if controller != 0:
            raise RuntimeError("Same-Replay fence controller layout changed")
        vtable = struct.unpack("<Q", read(address - base, 8))[0]
        methods = []
        if base <= vtable < base + 0x200000000:
            for method in struct.unpack("<6Q", read(vtable - base, 48)):
                if base <= method < base + 0x200000000:
                    methods.append(
                        {
                            "rva": method - base,
                            "symbols": symbol_names.get(method - base, []),
                        }
                    )
        fences.append(
            {
                "index": index,
                "name": label,
                "dependencies_met": bool(flags[4]),
                "passing": bool(flags[5]),
                "failed": bool(flags[6]),
                "native_methods": methods,
            }
        )
    with urllib.request.urlopen("http://127.0.0.1:8085/status", timeout=3) as response:
        status = json.load(response)
    client_path = path.parent / "replay-dw-client.log"
    with client_path.open("rb") as log:
        log.seek(
            connection["client_log_offset"]
            if connection
            else max(0, client_path.stat().st_size - 8192)
        )
        lines = log.read().decode(errors="replace").splitlines()
    counters = (
        "auth_successes",
        "legacy_logins",
        "lobby_authenticated",
        "tasks",
        "lobby_failures",
    )
    baseline = connection["server_baseline"] if connection else None
    delta = (
        {name: status.get(name, 0) - baseline.get(name, 0) for name in counters}
        if baseline
        else None
    )
    server_lines = []
    server_log_reset = False
    server_log_file_size = None
    if connection and "server_log_offset" in connection:
        with (root / "data" / "server.log").open("rb") as log:
            server_log_reset = (
                root / "data" / "server.log"
            ).stat().st_size < connection["server_log_offset"]
            log.seek(0 if server_log_reset else connection["server_log_offset"])
            server_lines = log.read().decode(errors="replace").splitlines()
            server_log_file_size = log.tell()
        if server_log_reset:
            cutoff = datetime.fromisoformat(
                connection.get("requested_utc", connection.get("launched_utc")).replace(
                    "Z", "+00:00"
                )
            ).replace(microsecond=0)

            def since_launch(line):
                try:
                    return (
                        datetime.fromisoformat(
                            line.split(" ", 1)[0].replace("Z", "+00:00")
                        )
                        >= cutoff
                    )
                except (ValueError, TypeError):
                    return False

            server_lines = [line for line in server_lines if since_launch(line)]
    chats = []
    if "gl_14B6D19E0" in symbols:
        # Native CreateChatCallback scans 38 records, each 5214 UInt32s.
        # The joined record has type/status followed by its channel ID at +24.
        for index in range(38):
            item = read(symbols["gl_14B6D19E0"] + index * 20856, 32)
            chat_type, chat_state = struct.unpack_from("<2I", item)
            if chat_state:
                chats.append(
                    {
                        "slot": index,
                        "type": chat_type,
                        "state": chat_state,
                        "channel_id": struct.unpack_from("<Q", item, 24)[0],
                    }
                )
    friend_lists = []
    if "gl_14B8BDDF0" in symbols:
        # Same-Replay ClearList 0x140F54480 and Crossplay_GetFriends /
        # GetOutgoingFriendRequests: three 40-byte list records per client,
        # pointer +8, capacity +16, count +20, fetch state +24; entries are
        # 80 bytes with XUID +0 and the 64-byte display name +8.
        for client_index in range(2):
            # Crossplay_OnSignedIn (0x140F55760) sets handler +8 before
            # initializing that client's lists. Inactive slots have no cache.
            if (
                "gl_14B8BDDD0" not in symbols
                or read(symbols["gl_14B8BDDD0"] + 16 * client_index + 8, 1)[0] != 1
            ):
                continue
            for list_index in range(3):
                record = read(
                    symbols["gl_14B8BDDF0"] + 120 * client_index + 40 * list_index, 40
                )
                pointer = struct.unpack_from("<Q", record, 8)[0]
                capacity, count, state = struct.unpack_from("<3I", record, 16)
                if count > capacity or capacity > 10000:
                    raise RuntimeError(
                        f"Native crossplay friend-list bounds changed: client={client_index} list={list_index} capacity={capacity} count={count} state={state}"
                    )
                entries = []
                if count:
                    if pointer < 65536:
                        raise RuntimeError("Native friend-list pointer is invalid")
                    rows = read(pointer - base, count * 80)
                    for offset in range(0, len(rows), 80):
                        item = rows[offset : offset + 80]
                        entries.append(
                            {
                                "user": struct.unpack_from("<Q", item)[0],
                                "name": item[8:72]
                                .split(b"\0")[0]
                                .decode(errors="replace"),
                            }
                        )
                friend_lists.append(
                    {
                        "local_client": client_index,
                        "list_index": list_index,
                        "capacity": capacity,
                        "count": count,
                        "fetch_state": state,
                        "entries": entries,
                    }
                )
    clans = []
    if "gl_14B7A5E10" in symbols:
        # Same-Replay OnlineClan::Activate uses a 19648-byte active-clan
        # record per local client, with its clan pointer at +19640. Native
        # JoinClanDataChannelCallback finishes activation by setting state 4.
        for client in range(2):
            pointer = struct.unpack(
                "<Q", read(symbols["gl_14B7A5E10"] + client * 19648 + 19640, 8)
            )[0]
            if not pointer:
                continue
            record = read(pointer - base, 96)
            # Exact AddPlayerNotification (140F3F6D0) / GetMemberRole
            # (140F415C0): 250 records of 56 bytes, count at +19600.
            # Name[36], XUID +40, role UInt16 +48, active-clan bool +50.
            active_data = read(symbols["gl_14B7A5E10"] + client * 19648, 19648)
            member_count = struct.unpack_from("<I", active_data, 19600)[0]
            if member_count > 250:
                raise RuntimeError(
                    f"Native active clan member count {member_count} exceeds 250 for client {client}"
                )
            members = []
            for index in range(member_count):
                member = active_data[index * 56 : (index + 1) * 56]
                members.append(
                    {
                        "user": struct.unpack_from("<Q", member, 40)[0],
                        "name": member[:36].split(b"\0")[0].decode(errors="replace"),
                        "role": struct.unpack_from("<H", member, 48)[0],
                        "active_clan": bool(member[50]),
                    }
                )
            clans.append(
                {
                    "client": client,
                    "state": struct.unpack_from("<I", record)[0],
                    "controller": struct.unpack_from("<i", record, 8)[0],
                    "clan_id": struct.unpack_from("<Q", record, 16)[0],
                    "name": record[48:79].split(b"\0")[0].decode(errors="replace"),
                    "tag": record[79:85].split(b"\0")[0].decode(errors="replace"),
                    "member_count": member_count,
                    "members": members,
                    "native_activation_complete": struct.unpack_from("<I", record)[0]
                    == 4,
                }
            )
    clan_invitations = []
    if "gl_14B7AB280" in symbols:
        # Exact Replay CacheIncomingInvite/GetClanInvites: 1440-byte stride
        # for mapped clients, state +0, count +4, refresh flag +8, ten records of 120
        # bytes from +16; group ID +88, timestamp +96, decline flag +113.
        client_mapping = struct.unpack(
            "<" + "i" * client_map_count,
            read(symbols["s_clientControllerMap"], 4 * client_map_count),
        )
        for client in sorted({value for value in client_mapping if 0 <= value < 2}):
            pool = read(symbols["gl_14B7AB280"] + 1440 * client, 1216)
            state, count = struct.unpack_from("<II", pool)
            if count > 10:
                raise RuntimeError(
                    f"Native clan invitation pool bounds changed: client={client}, state={state}, count={count}"
                )
            entries = []
            for index in range(count):
                record = pool[16 + 120 * index : 136 + 120 * index]
                entries.append(
                    {
                        "clan_id": struct.unpack_from("<Q", record, 88)[0],
                        "updated": struct.unpack_from("<Q", record, 96)[0],
                        "decline": bool(record[113]),
                    }
                )
            clan_invitations.append(
                {
                    "client": client,
                    "state": state,
                    "count": count,
                    "refresh_pending": bool(pool[8]),
                    "entries": entries,
                }
            )
    presence_subscriptions = None
    presence_symbols = (
        "gl_14C38CDC0",
        "gl_14C3A51B0",
        "gl_14C3A51B4",
        "gl_14C3A51B8",
        "gl_14C3A3230",
    )
    if all(name in symbols for name in presence_symbols):
        # Exact Replay 1410587C0/141058C50: controller record 91240 bytes,
        # 950 subscribed records (64 bytes), two 950-entry pending queues
        # (16 bytes each), then their counts. Shared batch <=100 users.
        counts = [
            struct.unpack("<I", read(symbols["gl_14C38CDC0"] + offset, 4))[0]
            for offset in (60800, 76008, 91216)
        ]
        batch = struct.unpack("<I", read(symbols["gl_14C3A51B0"], 4))[0]
        error_count = struct.unpack("<I", read(symbols["gl_14C3A3230"] + 8040, 4))[0]
        if max(counts) > 950 or batch > 100 or error_count > 100:
            raise RuntimeError("Native presence queue/response capacity changed")
        presence_subscriptions = dict(
            controller=0,
            subscribed_count=counts[0],
            pending_subscribe=counts[1],
            pending_unsubscribe=counts[2],
            batch_count=batch,
            start_failures=struct.unpack("<I", read(symbols["gl_14C3A51B4"], 4))[0],
            last_start_failure_time=struct.unpack(
                "<I", read(symbols["gl_14C3A51B8"], 4)
            )[0],
            unsubscribe_error_count=error_count,
            unsubscribe_response_vtable_rva=struct.unpack(
                "<Q", read(symbols["gl_14C3A3230"], 8)
            )[0]
            - base,
        )
    relay_client_auth = None
    relay_transport = None
    if "s_instance_1" in symbols:
        instance = struct.unpack("<Q", read(symbols["s_instance_1"], 8))[0]
        if instance:
            record = read(instance - base, 304)
            state = struct.unpack_from("<I", record, 296)[0]
            token = record[192:280] if state == 2 else None
            native_wire = (
                token[64:65] + token[8:64] + token[72:88] + token[68:72]
                if token
                else None
            )
            relay_client_auth = dict(
                state=state,
                expiry_clock_seconds=struct.unpack_from("<I", record, 300)[0],
                version=token[64] if token else None,
                expiry_delta=struct.unpack_from("<I", token, 68)[0] if token else None,
                native_wire_sha256=(
                    hashlib.sha256(native_wire).hexdigest() if native_wire else None
                ),
                opaque_sha256=(
                    hashlib.sha256(token[8:64]).hexdigest() if token else None
                ),
                native_completion_callback_observed=state == 2,
                udp_transport_verified=False,
            )
            transport_state = struct.unpack_from("<I", record, 20)[0]
            relay_transport = dict(
                state=transport_state,
                relay_id=struct.unpack_from("<Q", record, 168)[0],
                datacenter=record[72:161].split(b"\0")[0].decode(errors="replace"),
                native_connected_callback_observed=transport_state == 6,
                server_transport_correlation_verified=False,
            )
    relay_server_auth = None
    if (
        "gl_14B890F10" in symbols
        and struct.unpack("<I", read(symbols["gl_14B890F04"], 4))[0] == 3
    ):
        record = read(symbols["gl_14B890F10"], 240)
        relay_id = struct.unpack_from("<Q", record, 216)[0]
        if record[60] == 1 and relay_id:
            # Replay bdSockAddr is Windows sockaddr_in in memory; its wire
            # serializer uses IPv4 bytes then a little-endian HOST port.
            port = struct.unpack_from(">H", record, 66)[0]
            address = record[68:72] + struct.pack("<H", port)
            native_wire = (
                record[60:61]
                + record[8:60]
                + record[224:240]
                + address
                + record[216:224]
            )
            relay_server_auth = dict(
                version=1,
                relay_id=relay_id,
                port=port,
                ipv4=".".join(str(b) for b in record[68:72]),
                native_wire_sha256=hashlib.sha256(native_wire).hexdigest(),
            )
    relay_association = None
    if "gl_152EA3250" in symbols:
        # Exact Replay 1414EEBA0 -> 14217A520 -> 14218C910 -> 142195760:
        # net singleton +640 socket router, +184 routing layer, +32 bound ref.
        net = struct.unpack("<Q", read(symbols["gl_152EA3250"], 8))[0]
        router = struct.unpack("<Q", read(net - base + 640, 8))[0] if net else 0
        association = (
            struct.unpack("<Q", read(router - base + 216, 8))[0] if router else 0
        )
        if association:
            record = read(association - base, 1216)
            state = struct.unpack_from("<I", record, 1208)[0]
            relay_association = dict(
                state=state,
                type=struct.unpack_from("<I", record, 1212)[0],
                title=struct.unpack_from("<I", record, 344)[0],
                user=struct.unpack_from("<Q", record, 352)[0],
                route=struct.unpack_from("<I", record, 1024)[0] if state == 3 else None,
                relay_id=(
                    struct.unpack_from("<Q", record, 1016)[0] if state == 3 else None
                ),
                join_id=(
                    struct.unpack_from("<Q", record, 1032)[0] if state == 3 else None
                ),
                verification_sha256=(
                    hashlib.sha256(record[1192:1208]).hexdigest()
                    if state == 3
                    else None
                ),
                ipv4=(
                    ".".join(str(b) for b in record[1044:1048]) if state == 3 else None
                ),
                port=struct.unpack_from(">H", record, 1042)[0] if state == 3 else None,
            )
    result = {
        "schema": 6,
        "pid": pid,
        "executable": str(path),
        "sha256": deployment["sha256"],
        "server_process_verified": server_deployment,
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "method": "read-only state from the verified live process, ASLR module base and linked native getter/global symbols",
        "platform_auth_state": struct.unpack("<I", read(auth_rva, 4))[0],
        "platform_auth_failure": struct.unpack("<I", read(auth_rva + 456, 4))[0],
        "native_platform_signin_notification": {
            "callback_rva": struct.unpack("<Q", read(auth_rva + 792, 8))[0] - base,
            "callback_count": struct.unpack("<Q", read(auth_rva + 800, 8))[0],
        },
        "platform_connection_state": struct.unpack("<I", read(connection_rva, 4))[0],
        "native_platform_services": platform_services,
        "native_platform_sdk_error": (
            struct.unpack("<I", read(symbols["gl_14F05AD24"], 4))[0]
            if "gl_14F05AD24" in symbols
            else None
        ),
        "native_profile_sign_in_state": struct.unpack("<i", read(user_rva, 4))[0],
        "native_user_xuid": struct.unpack_from("<Q", user, 144)[0],
        "native_user_xuid_text": user[152:173].split(b"\0")[0].decode(errors="replace"),
        "native_user_platform_id": struct.unpack_from("<Q", user, 184)[0],
        "native_user_platform_id_text": user[192:213]
        .split(b"\0")[0]
        .decode(errors="replace"),
        "native_auth_game_account_id": struct.unpack("<I", read(auth_rva + 224, 4))[0],
        "native_platform_universal_id": struct.unpack(
            "<Q", read(symbols["gl_14F05ACE8"], 8)
        )[0],
        "native_storage_file_identities": storage_files,
        "native_dw_hsm_states": hsm_states,
        "native_dw_hsm_connected_state_33": 33 in hsm_states,
        "native_publisher_namespaces": publisher_states,
        "native_publisher_required_applied": all(
            s["state"] == 3 and s["applied"] for s in publisher_states if s["critical"]
        ),
        "native_lobby_wrapper_owner_present": lobby_owner != 0,
        "native_joined_chats": chats,
        "native_active_clans": clans,
        "native_clan_invitations": clan_invitations,
        "native_presence_subscriptions": presence_subscriptions,
        "native_crossplay_friend_lists": friend_lists,
        "native_matchmaking_token_cached": (
            bool(struct.unpack("<Q", read(symbols["gl_14C27E490"], 8))[0])
            if "gl_14C27E490" in symbols
            else None
        ),
        # Verified native instance header, GetCurrentLobbyId (+79656),
        # and UpdateLobbyDocument (+79664/+79672) for this Replay build.
        "native_matchmaking_lobby": (
            {
                "state": struct.unpack(
                    "<I", read(symbols["OnlineMatchmakerOmniscient::ms_instance"], 4)
                )[0],
                "lobby_state": struct.unpack(
                    "<I",
                    read(symbols["OnlineMatchmakerOmniscient::ms_instance"] + 4, 4),
                )[0],
                "lobby_id": struct.unpack(
                    "<Q",
                    read(symbols["OnlineMatchmakerOmniscient::ms_instance"] + 79656, 8),
                )[0],
                "update_id": struct.unpack(
                    "<Q",
                    read(symbols["OnlineMatchmakerOmniscient::ms_instance"] + 79664, 8),
                )[0],
                "host_user": struct.unpack(
                    "<Q",
                    read(symbols["OnlineMatchmakerOmniscient::ms_instance"] + 79672, 8),
                )[0],
                "document_received": bool(
                    read(
                        symbols["OnlineMatchmakerOmniscient::ms_instance"] + 1071095, 1
                    )[0]
                ),
            }
            if "OnlineMatchmakerOmniscient::ms_instance" in symbols
            else None
        ),
        "native_party_test_settings": {
            "private_match": dvar_current("gl_14D386820", "<?"),
            "maximum_players": dvar_current("gl_14D386840", "<i"),
            "private_match_registration": dvar_details("gl_14D386820"),
        },
        "native_tournament_request": (
            {
                "pending_task": struct.unpack("<I", read(symbols["gl_14C3BBBB4"], 4))[
                    0
                ],
                "retry_count": struct.unpack("<I", read(symbols["gl_14C3B0880"], 4))[0],
                "operation": read(symbols["gl_14C3B0888"], 1)[0],
                "state": read(symbols["gl_14C3BBB75"], 1)[0],
                "registration_time": struct.unpack(
                    "<I", read(symbols["gl_14C3BFC78"], 4)
                )[0],
                "schedule_anchor": struct.unpack(
                    "<I", read(symbols["gl_14C3BBC04"], 4)
                )[0],
                "schedule_count": struct.unpack("<I", read(symbols["gl_14C3BBC08"], 4))[
                    0
                ],
                "schedule_interval": dvar_current("gl_14EE562A8", "<i"),
                "parsed_search_offset": struct.unpack(
                    "<i", read(symbols["gl_14C3BFC18"], 4)
                )[0],
                "rejoin_tournament_id": struct.unpack(
                    "<Q", read(symbols["gl_14C3BFC10"], 8)
                )[0],
                # Same-Replay 0x141074530: the native parser fills these fields
                # from the delivered document. Resolve them through linked globals.
                "current_bracket": (
                    {
                        "tournament_id": struct.unpack(
                            "<Q", read(symbols["gl_14C3B3230"], 8)
                        )[0],
                        "participant_count": struct.unpack(
                            "<I", read(symbols["gl_14C3B34B8"], 4)
                        )[0],
                        "team_size": struct.unpack(
                            "<I", read(symbols["gl_14C3B34B8"] + 4, 4)
                        )[0],
                        "team_count": struct.unpack(
                            "<I", read(symbols["gl_14C3B34C0"], 4)
                        )[0],
                        "round_count": struct.unpack(
                            "<I", read(symbols["gl_14C3B34C8"], 4)
                        )[0],
                        "local_team": struct.unpack(
                            "<i", read(symbols["gl_14C3BFC68"], 4)
                        )[0],
                        "local_round": struct.unpack(
                            "<H", read(symbols["gl_14C3BFC6C"], 2)
                        )[0],
                        "local_match": struct.unpack(
                            "<H", read(symbols["gl_14C3BFC6C"] + 4, 2)
                        )[0],
                    }
                    if all(
                        name in symbols
                        for name in (
                            "gl_14C3B3230",
                            "gl_14C3B34B8",
                            "gl_14C3B34C0",
                            "gl_14C3B34C8",
                            "gl_14C3BFC68",
                            "gl_14C3BFC6C",
                        )
                    )
                    else None
                ),
                "state_result_buffer": native_string_buffer(
                    "gl_14C3B36D0", "gl_14C3B36D8"
                ),
                "result_buffer": native_string_buffer("gl_14C3BBB50", "gl_14C3BBB58"),
            }
            if all(
                n in symbols for n in ("gl_14C3BBBB4", "gl_14C3B0880", "gl_14C3B0888")
            )
            else None
        ),
        "native_marketing_messages": native_marketing(),
        "native_registered_test_commands": commands,
        "native_frontend_active": bool(read(symbols["gl_14C4EBE6C"], 1)[0]),
        "native_selected_dvars": selected_dvars,
        "native_global_counters": counter_state,
        # Replay's real publisher download callback 141B3CD00 sets
        # loaded and clears in-flight; no backend success is substituted.
        "native_content_creator_list": (
            {
                "loaded": bool(read(symbols["gl_145A0532C"], 1)[0]),
                "in_flight": bool(read(symbols["gl_145A05324"], 1)[0]),
            }
            if all(n in symbols for n in ("gl_145A0532C", "gl_145A05324"))
            else None
        ),
        # Same-Replay CL_IsLocalClientConnectedToGameServer reads the
        # 440-byte static client record: state +8, frontend byte +36.
        "native_game_connection": {
            "state": struct.unpack("<I", read(symbols["gl_14EEF1280"] + 8, 4))[0],
            "frontend_scene": bool(read(symbols["gl_14EEF1280"] + 36, 1)[0]),
            "local_server_running": dvar_current("gl_14D385FB0", "<?"),
        },
        "native_ui_input": {
            "key_catchers": struct.unpack("<I", read(symbols["gl_14EEF1284"], 4))[0],
            "keys": {
                label: {
                    "binding": read(symbols["gl_14EEAF0E8"] + 16 * key + 8, 1)[0],
                    "repeats": read(symbols["gl_14EEAF0E8"] + 16 * key + 10, 1)[0],
                    "down": read(symbols["gl_14EEAF0E8"] + 16 * key + 12, 1)[0],
                }
                for label, key in (("enter", 13), ("escape", 27), ("space", 32))
            },
        },
        "native_client_mapping": {
            "mode": struct.unpack("<I", read(symbols["s_clientMgrMode"], 4))[0],
            "controller_to_client": struct.unpack(
                "<" + "i" * client_map_count,
                read(symbols["s_clientControllerMap"], 4 * client_map_count),
            ),
        },
        "native_dcqos": {
            "state": struct.unpack("<I", read(symbols["gl_14B7B57A0"], 4))[0],
            "requested": read(symbols["gl_14B7B57A4"], 1)[0],
            "full_requested": read(symbols["gl_14B7B57A4"] + 1, 1)[0],
            "result_states": list(
                struct.unpack("<2I", read(symbols["gl_14B890F04"], 8))
            ),
            "result_mask": struct.unpack("<I", read(symbols["gl_14B890F00"], 4))[0],
        },
        # Same-Replay NetRelay::FetchAuthToken/Callback/Reset prove
        # instance +176 result, +192 token, +296 task state, +300 expiry.
        # Positive state 2 is set only after SDK task completion and
        # bdSocketRouter::setClientAuthToken. Report hashes, not secrets.
        "native_relay_client_auth": relay_client_auth,
        "native_relay_server_auth": relay_server_auth,
        "native_relay_transport": relay_transport,
        "native_relay_association": relay_association,
        "native_fences_controller_0": fences,
        "native_reconciliation": {
            "passing": bool(read(symbols["gl_144493DE0"] + 64, 1)[0]),
            "state": struct.unpack("<I", read(symbols["gl_144493DE0"] + 68, 4))[0],
            "credential_received": bool(
                struct.unpack("<Q", read(symbols["gl_144493DE0"] + 112, 8))[0]
            ),
        },
        "native_account_service_state": struct.unpack_from("<I", account, 16)[0],
        "native_account_service_group": struct.unpack_from("<I", account, 20)[0],
        "native_account_country": struct.unpack_from("<I", account, 140)[0],
        "native_account_age": struct.unpack_from("<I", account, 144)[0],
        "native_account_play_policy_ready": struct.unpack_from("<I", account, 128)[0],
        "native_account_fastfile_policy_processed": read(symbols["gl_14F05ABFB"], 1)[0],
        "platform_license_count": struct.unpack("<I", read(auth_rva + 716, 4))[0],
        "platform_tokens_processed": read(auth_rva + 720, 1)[0],
        "client_markers": lines,
        "server": status,
        "server_baseline": baseline,
        "server_counter_changes_since_launch": delta,
        "server_log_since_launch": server_lines,
        "server_log_file_size": server_log_file_size,
        "server_log_reset_detected": server_log_reset,
        "native_encrypted_lobby_task_completion": "not observed by this state reader",
        "connection_receipt": connection,
        "launch_correlation": (
            "verified dw_restart dispatch and server receipt"
            if connection and connection is not launch
            else (
                "verified launch receipt"
                if launch
                else "manual PID attachment; no launch baseline or per-launch log attribution available"
            )
        ),
        "evidence_scope": "Server acceptance/replies are separate from native client task completion.",
    }
    (args.output or root / "data" / "latest-runtime-observation.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result, indent=2))
finally:
    kernel.CloseHandle(process)
