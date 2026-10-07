"""Capture native Windows debug output from receipt-verified Replay processes.

Uses the standard DBWIN listener rather than attaching a debugger, injecting a
DLL, or changing the executable. Run before launching the owned game processes.
Other applications' messages are discarded. Only one DBWIN listener may run in
the Windows session at a time.
"""

import argparse
import ctypes
from ctypes import wintypes as w
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch-receipt", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=1800)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 7200:
        parser.error("Capture duration must be between 1 and 7200 seconds")

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = (ctypes.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR)
    kernel.CreateEventW.restype = w.HANDLE
    kernel.CreateFileMappingW.argtypes = (
        w.HANDLE, ctypes.c_void_p, w.DWORD, w.DWORD, w.DWORD, w.LPCWSTR
    )
    kernel.CreateFileMappingW.restype = w.HANDLE
    kernel.MapViewOfFile.argtypes = (w.HANDLE, w.DWORD, w.DWORD, w.DWORD, ctypes.c_size_t)
    kernel.MapViewOfFile.restype = ctypes.c_void_p
    kernel.UnmapViewOfFile.argtypes = (ctypes.c_void_p,)
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    kernel.SetEvent.argtypes = (w.HANDLE,)
    kernel.WaitForSingleObject.argtypes = (w.HANDLE, w.DWORD)
    kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
    kernel.OpenProcess.restype = w.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = (
        w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)
    )
    kernel.GetProcessTimes.argtypes = (
        w.HANDLE, ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME),
        ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME)
    )

    handles = []
    view = None
    verified = {}
    receipts = {}
    next_receipt_refresh = 0
    try:
        for name in ("DBWIN_BUFFER_READY", "DBWIN_DATA_READY"):
            handle = kernel.CreateEventW(None, False, False, name)
            error = ctypes.get_last_error()
            if not handle:
                raise ctypes.WinError(error)
            handles.append(handle)
            if error == 183:
                raise RuntimeError("Another DBWIN listener is already active")
        buffer_ready, data_ready = handles
        mapping = kernel.CreateFileMappingW(w.HANDLE(-1), None, 4, 0, 4096, "DBWIN_BUFFER")
        error = ctypes.get_last_error()
        if not mapping:
            raise ctypes.WinError(error)
        handles.append(mapping)
        if error == 183:
            raise RuntimeError("Another DBWIN buffer is already active")
        view = kernel.MapViewOfFile(mapping, 4, 0, 0, 4096)
        if not view:
            raise ctypes.WinError(ctypes.get_last_error())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        status = args.output.with_suffix(".status.json")
        status.write_text(json.dumps({"ready": True, "method": "DBWIN", "pid": os.getpid()}) + "\n")
        deadline = time.monotonic() + args.seconds
        count = 0
        # Native matchmaking logs include session credentials inside JSON. Keep
        # state and address diagnostics while removing credentials at capture.
        credentials = re.compile(
            r'("(?:security_key|security_id|auth_token|access_token|refresh_token|'
            r'client_ticket|server_ticket|session_token|mm_token|tokens)"\s*:\s*)'
            r'(?:"(?:\\.|[^"\\\r\n])*"|\[[^\]\r\n]*\]|[0-9]+)',
            re.IGNORECASE,
        )
        with args.output.open("a", encoding="utf-8", buffering=1) as output:
            kernel.SetEvent(buffer_ready)
            while time.monotonic() < deadline and not args.stop_file.exists():
                result = kernel.WaitForSingleObject(data_ready, 250)
                if result == 258:
                    continue
                if result != 0:
                    raise ctypes.WinError(ctypes.get_last_error())
                data = ctypes.string_at(view, 4096)
                # Free the shared buffer immediately. Receipt/hash validation
                # and disk writes must not hold the game's debug-output lock.
                kernel.SetEvent(buffer_ready)
                pid = int.from_bytes(data[:4], "little")
                text = data[4:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
                # Refresh receipts at most four times per second. The listener
                # may precede launch without reopening files for every line.
                if time.monotonic() >= next_receipt_refresh:
                    receipts = {}
                    for receipt in args.launch_receipt:
                        try:
                            record = json.loads(receipt.read_text(encoding="utf-8-sig"))
                            receipts[record["pid"]] = record
                        except (OSError, ValueError, KeyError):
                            continue
                    next_receipt_refresh = time.monotonic() + 0.25
                for record in (receipts[pid],) if pid in receipts else ():
                    key = (pid, record.get("sha256"), record.get("launched_utc"))
                    if key not in verified:
                        process = kernel.OpenProcess(0x1000, False, pid)
                        if not process:
                            continue
                        try:
                            path = ctypes.create_unicode_buffer(32768)
                            length = w.DWORD(len(path))
                            if not kernel.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(length)):
                                continue
                            image = Path(path.value)
                            if image.resolve() != Path(record["executable"]).resolve():
                                continue
                            if hashlib.sha256(image.read_bytes()).hexdigest() != record["sha256"]:
                                continue
                            created, exited, cpu_kernel, cpu_user = (w.FILETIME() for _ in range(4))
                            if not kernel.GetProcessTimes(process, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(cpu_kernel), ctypes.byref(cpu_user)):
                                continue
                            creation = created.dwHighDateTime << 32 | created.dwLowDateTime
                            created_seconds = creation / 10_000_000 - 11_644_473_600
                            expected = record.get("process_created_utc", record.get("launched_utc"))
                            expected_seconds = datetime.fromisoformat(expected.replace("Z", "+00:00")).timestamp()
                            tolerance = 0.01 if "process_created_utc" in record else 2
                            if abs(created_seconds - expected_seconds) > tolerance:
                                continue
                            verified[key] = (process, creation)
                            process = None
                        finally:
                            if process:
                                kernel.CloseHandle(process)
                    process, creation = verified[key]
                    times = [w.FILETIME() for _ in range(4)]
                    if not kernel.GetProcessTimes(process, *(ctypes.byref(value) for value in times)):
                        continue
                    if times[1].dwHighDateTime or times[1].dwLowDateTime:
                        continue
                    output.write(json.dumps({
                        "utc": datetime.now(timezone.utc).isoformat(),
                        "pid": pid,
                        "message": credentials.sub(r'\1"<redacted>"', text),
                    }, ensure_ascii=False) + "\n")
                    count += 1
                    break
        status.write_text(json.dumps({"ready": False, "complete": True, "messages": count}) + "\n")
    finally:
        for process, _ in verified.values():
            kernel.CloseHandle(process)
        if view:
            kernel.UnmapViewOfFile(view)
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


if __name__ == "__main__":
    main()
