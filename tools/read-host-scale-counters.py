"""Read the counters of the exact linked host-scaling build without game writes."""

import argparse
import bisect
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import struct
import time

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--bot-positions", action="store_true")
    args = parser.parse_args()
    if not 2 <= args.samples <= 15:
        parser.error("samples must be between 2 and 15")
    report = json.loads((args.build / "build-report.json").read_bytes())
    proof = json.loads((Path(report["source_root"]) / "generated/host-scale-integration.json").read_bytes())
    image = pefile.PE(report["executable"], fast_load=True)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    def rip_fields(name):
        rows = []
        for instruction in decoder.disasm(image.get_data(report["symbols"][name], 512),
                                            report["symbols"][name]):
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    rows.append((instruction.address + instruction.size + operand.mem.disp,
                                 operand.size, instruction.mnemonic, instruction.op_str))
            if instruction.mnemonic == "ret":
                break
        return rows

    fields = {}
    brain = rip_fields("?RecordBotFrame@HostScale@@YAXII_K0@Z")
    assert len(brain) == 7 and brain[5][:2] == brain[6][:2]
    for name, row in zip(("frames", "thought", "reused", "brain_ticks", "move_ticks", "peak_ticks"), brain):
        fields[name] = row[:2]
    for symbol, names in (
        ("?RecordSight@HostScale@@YAXIII@Z", ("sight", "candidates", "evaluations", "deferred")),
        ("?RecordMovement@HostScale@@YAXII@Z", ("queued", "serial")),
        ("SV_HostNav_RecordClosest", ("closest_queries", "closest_fallbacks")),
    ):
        rows = rip_fields(symbol)
        assert len(rows) == len(names), symbol
        fields.update((name, row[:2]) for name, row in zip(names, rows))
    frequency = [r for r in rip_fields("SV_HostScale_Frame")
                 if r[2] == "mov" and r[3].startswith("qword ptr [rip")]
    assert len(frequency) == 1
    fields["frequency"] = frequency[0][:2]
    ranges = report["rva_map"]["ranges"]
    starts = [r["begin"] for r in ranges]
    bindings = {r["name"]: r for r in proof["bindings"]}

    def mapped(name):
        rva = bindings[name]["original_rva"]
        row = ranges[bisect.bisect_right(starts, rva) - 1]
        assert row["begin"] <= rva < row["end"]
        return row["mapped_begin"] + rva - row["begin"]

    fields.update(leveltime=(mapped("SVHS_LevelTime"), 4),
                  frame_duration=(mapped("SVHS_FrameDuration"), 4),
                  capacity=(mapped("SVHS_ClientCount"), 4),
                  mode=(report["symbols"]["s_comOptimizedMode"], 4))
    if "gl_145FA47B0" in report["symbols"]:
        fields["tactical_graphs"] = (report["symbols"]["gl_145FA47B0"], 4)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    psapi = c.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    kernel.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    psapi.EnumProcessModulesEx.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), w.DWORD]
    process = kernel.OpenProcess(0x410, False, args.pid)
    if not process:
        raise c.WinError(c.get_last_error())
    try:
        path = c.create_unicode_buffer(32768)
        length = w.DWORD(len(path))
        assert kernel.QueryFullProcessImageNameW(process, 0, path, c.byref(length))
        with Path(path.value).open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == report["sha256"]
        modules = (w.HMODULE * 1024)()
        needed = w.DWORD()
        assert psapi.EnumProcessModulesEx(process, modules, c.sizeof(modules), c.byref(needed), 3)
        base = modules[0]

        def read(address, size):
            buffer = c.create_string_buffer(size)
            received = c.c_size_t()
            if not kernel.ReadProcessMemory(process, address, buffer, size, c.byref(received)) or received.value != size:
                raise c.WinError(c.get_last_error())
            return buffer.raw

        snapshots = []
        for index in range(args.samples):
            row = {name: int.from_bytes(read(base + rva, size), "little")
                   for name, (rva, size) in fields.items()}
            clients = struct.unpack("<200Q", read(base + mapped("SVHS_Clients"), 1600))
            occupied = bots = humans = pending = 0
            positions = []
            for slot, pointer in enumerate(clients[:min(row["capacity"], 200)]):
                if not pointer or read(pointer + 8, 1)[0] < 3:
                    continue
                occupied += 1
                if int.from_bytes(read(pointer + 214756, 4), "little") == 2:
                    bots += 1
                    pending += bool(int.from_bytes(read(pointer + 1368 + 8988, 4), "little"))
                    if args.bot_positions:
                        entity = int.from_bytes(read(pointer + 280, 8), "little")
                        if entity:
                            navigator = int.from_bytes(read(pointer + 1368 + 360, 8), 'little')
                            sentient = int.from_bytes(read(entity + 344, 8), 'little')
                            nav = read(navigator + 1364, 16) if navigator else bytes(16)
                            area_ref, space = struct.unpack('<QQ', nav)
                            positions.append(dict(slot=slot, origin=struct.unpack('<3f', read(entity + 304, 12)),
                                avoidance=read(pointer + 1368 + 408, 1)[0],
                                goal=struct.unpack('<3f', read(pointer + 1368 + 536, 12)),
                                failed_path_time=int.from_bytes(read(pointer + 1368 + 640, 4), 'little', signed=True),
                                health=int.from_bytes(read(entity + 440, 4), 'little', signed=True),
                                navigator=hex(navigator), area_reference=hex(area_ref), space=hex(space),
                                area=hex(int.from_bytes(read(area_ref, 8), 'little')) if area_ref else None,
                                tactical_reference=read(sentient + 148, 6).hex() if sentient else None,
                                script_flags=hex(int.from_bytes(read(pointer + 1368 + 8984, 4), 'little'))))
                else:
                    humans += 1
            row.update(time=time.time(),monotonic=time.perf_counter(),occupied=occupied,
                       bots=bots,humans=humans,bot_pending_actions=pending)
            snapshots.append(row)
            if args.bot_positions:
                row['bot_positions'] = positions
            if index + 1 < args.samples:
                time.sleep(2)
        first, last = snapshots[0], snapshots[-1]
        elapsed = last["monotonic"] - first["monotonic"]
        frames = last["frames"] - first["frames"]
        frequency = last["frequency"]
        summary = dict(wall_seconds=elapsed,server_frames=frames,
                       server_hz=frames / elapsed,simulation_ms=last["leveltime"] - first["leveltime"],
                       full_decisions=last["thought"] - first["thought"],
                       reused_decisions=last["reused"] - first["reused"],
                       closest_queries=last["closest_queries"] - first["closest_queries"],
                       closest_fallbacks=last["closest_fallbacks"] - first["closest_fallbacks"])
        if frames > 0 and frequency > 0:
            summary.update(brain_ms_per_frame=(last["brain_ticks"] - first["brain_ticks"]) * 1000 / frequency / frames,
                           movement_ms_per_frame=(last["move_ticks"] - first["move_ticks"]) * 1000 / frequency / frames)
        result = dict(pid=args.pid,executable_sha256=report["sha256"],read_only=True,
                      fields=fields,samples=snapshots,summary=summary)
        args.output.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(dict(first=first,last=last,summary=summary),indent=2))
    finally:
        kernel.CloseHandle(process)


if __name__ == "__main__":
    main()
