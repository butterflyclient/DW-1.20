"""Export shipped Replay leaderboard layouts from a verified, read-only game.

The loader and native column builder are verified in the untouched image first.
The live process supplies asset data, not addresses for another game version.
No process memory, game files, identity, or player statistics are modified.
"""

import argparse
import ctypes
from ctypes import wintypes as w
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
ORIGINAL_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def target_contract():
    image = ORIGINAL.read_bytes()
    assert digest(image) == ORIGINAL_SHA256
    pe = pefile.PE(data=image, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    functions = {}
    for va, size in ((0x140DFD590, 346), (0x140F61530, 46),
                     (0x140F62050, 46), (0x1419B5070, 447),
                     (0x1419B5D80, 298), (0x14150E900, 181),
                     (0x140F75830, 404), (0x140F755B0, 404),
                     (0x142128100, 520), (0x142128500, 488)):
        code = pe.get_data(va - base, size)
        functions[hex(va)] = {
            "sha256": digest(code), "size": size,
            "instructions": [(i.mnemonic, i.op_str) for i in decoder.disasm(code, va)],
        }
    loader = functions["0x140dfd590"]["instructions"]
    assert ("mov", "r8d, 0x38") in loader
    assert any("0x14]" in operands for _, operands in loader)
    assert ("mov", "ecx, 0x37") in functions["0x140f61530"]["instructions"]
    assert ("mov", "ecx, 0x38") in functions["0x140f62050"]["instructions"]
    builder = functions["0x1419b5070"]["instructions"]
    assert any("0x38" in operands for _, operands in builder)
    assert any("0xf0" in operands for _, operands in builder)
    assert any("0xa" in operands for _, operands in builder)
    assert any("0x142127ea0" == operands for mnemonic, operands in
               functions["0x140f75830"]["instructions"] if mnemonic == "call")
    assert any("0x142127ba0" == operands for mnemonic, operands in
               functions["0x140f755b0"]["instructions"] if mnemonic == "call")
    assert ("mov", "r8b, 0x10") in functions["0x142128100"]["instructions"]
    assert ("mov", "r8b, 0x11") in functions["0x142128500"]["instructions"]
    assert ("call", "0x14214aee0") in functions["0x14150e900"]["instructions"]
    assert ("call", "0x1420ef840") in functions["0x14150e900"]["instructions"]
    return {"original_image": str(ORIGINAL), "sha256": ORIGINAL_SHA256,
            "functions": functions, "asset_types": {"leaderboard": 55, "virtual": 56},
            "root_bytes": {"leaderboard": 56, "virtual": 48},
            "column_bytes": {"leaderboard": 56, "virtual": 24},
            "native_response_column_capacity": 10,
            "native_virtual_column_id_limit": 240,
            "included_entity_task": "4/16", "included_rank_task": "4/17"}


class GameMemory:
    def __init__(self, pid, deployment):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = (w.HANDLE,)
        self.kernel.ReadProcessMemory.argtypes = (
            w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        )
        self.kernel.QueryFullProcessImageNameW.argtypes = (
            w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD),
        )
        self.handle = self.kernel.OpenProcess(0x410, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            name, length = ctypes.create_unicode_buffer(32768), w.DWORD(32768)
            assert self.kernel.QueryFullProcessImageNameW(
                self.handle, 0, name, ctypes.byref(length))
            path = Path(name.value)
            assert path.resolve() == Path(deployment["executable"]).resolve()
            assert digest(path.read_bytes()) == deployment["sha256"]
            ps = ctypes.WinDLL("psapi")
            ps.EnumProcessModulesEx.argtypes = (
                w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD,
            )
            modules, needed = (w.HMODULE * 1024)(), w.DWORD()
            assert ps.EnumProcessModulesEx(
                self.handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3)
            self.base = modules[0]
            self.symbols = json.loads((Path(deployment["build_directory"]) /
                                       "build-report.json").read_bytes())["symbols"]
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def read(self, address, size):
        assert 0 <= size <= 2 * 1024 * 1024
        buffer, count = ctypes.create_string_buffer(size), ctypes.c_size_t()
        if not self.kernel.ReadProcessMemory(
                self.handle, address, buffer, size, ctypes.byref(count)) or count.value != size:
            raise ValueError("Unreadable native asset memory")
        return buffer.raw

    def text(self, address, limit=256):
        if address < 65536:
            raise ValueError("Invalid native string pointer")
        data = self.read(address, limit)
        end = data.find(b"\0")
        if end < 0:
            raise ValueError("Unterminated native asset string")
        return data[:end].decode("utf-8")

    def pool(self, asset_type, expected_size):
        def global_read(name, offset, fmt):
            return struct.unpack(fmt, self.read(self.base + self.symbols[name] + offset,
                                                struct.calcsize(fmt)))[0]
        count = global_read("gl_1423FBBA0", asset_type * 4, "<I")
        size = global_read("gl_142458160", asset_type * 4, "<I")
        address = global_read("gl_14B8F5A80", asset_type * 8, "<Q")
        assert size == expected_size and 0 < count <= 1024
        records = self.read(address, count * size)
        return [records[i * size:(i + 1) * size] for i in range(count)]


def assets(memory, virtual):
    out = []
    for index, header in enumerate(memory.pool(56 if virtual else 55, 48 if virtual else 56)):
        name_pointer = struct.unpack_from("<Q", header)[0]
        try:
            name = memory.text(name_pointer)
        except (ValueError, UnicodeError):
            continue  # Unallocated slots contain allocator links, not XAssets.
        if not name.startswith(("lb_", "default_")):
            continue
        if virtual:
            source_pointer, board, source, pointer, count = struct.unpack_from("<QIIQI", header, 8)
            assert count <= 32
            rows = memory.read(pointer, count * 24)
            columns = []
            for i in range(count):
                label, column, numerator, denominator, reserved = struct.unpack_from("<QIIII", rows, i * 24)
                columns.append({"name": memory.text(label), "id": column,
                                "numerator": numerator, "denominator": denominator,
                                "reserved": reserved})
            out.append({"index": index, "name": name, "id": board,
                        "source_id": source, "source_name": memory.text(source_pointer),
                        "columns": columns, "tail": header[36:].hex()})
        else:
            board, source, width, count, xp, prestige, pointer, update, tracks = struct.unpack_from(
                "<IIIIiiQII", header, 8)
            assert width <= 240 and count <= 256
            rows = memory.read(pointer, count * 56)
            columns = []
            for i in range(count):
                label, column, flags, hidden, precision, stat, kind, aggregation, group, a, b, reserved = \
                    struct.unpack_from("<QiiiiQiiiiii", rows, i * 56)
                columns.append({"name": memory.text(label), "id": column, "flags": flags,
                                "hidden": hidden, "precision": precision,
                                "stat_name": memory.text(stat), "type": kind,
                                "aggregation": aggregation, "stats_group": group,
                                "ui_a": a, "ui_b": b, "reserved": reserved})
            out.append({"index": index, "name": name, "id": board, "source_id": source,
                        "width": width, "xp_column": xp, "prestige_column": prestige,
                        "update_type": update, "track_mask": tracks, "columns": columns,
                        "tail": header[48:].hex()})
    assert out and len({row["name"] for row in out}) == len(out)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, default=ROOT / "data/current-remote-deployment.json")
    parser.add_argument("--launch", type=Path, default=ROOT / "data/current-runtime-launch.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contract = target_contract()
    deployment = json.loads(args.deployment.read_bytes())
    launch = json.loads(args.launch.read_text(encoding="utf-8-sig"))
    assert launch["sha256"] == deployment["sha256"]
    memory = GameMemory(launch["pid"], deployment)
    try:
        regular, virtual = assets(memory, False), assets(memory, True)
    finally:
        memory.close()
    result = {"schema": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
              "pid": launch["pid"], "game_sha256": deployment["sha256"],
              "tool_sha256": digest(Path(__file__).read_bytes()), "target_contract": contract,
              "leaderboards": regular, "virtual_leaderboards": virtual,
              "native_task_completion_verified": False, "read_only": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Exported {len(regular)} leaderboard and {len(virtual)} virtual assets; {args.output}")


if __name__ == "__main__":
    main()
