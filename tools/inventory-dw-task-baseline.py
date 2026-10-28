"""Build the Replay DW coverage baseline from the original image, then probe a backend.

Native lobby tasks are started through a small set of SDK entry points that take
literal service/task bytes: bdTaskParams::bdTaskParams (dl/r8b),
bdRemoteTaskManager::initTaskBuffer (dl/r8b, older byte-buffer writers),
bdRemoteTaskManager::startStructTask (r8d/r9d) and three service wrappers that
fix the service and forward the task. Every direct call site in the untouched
image is decoded with capstone and its argument registers are traced backwards
through the linear predecessors of the call. Pass-through arguments are resolved
at the wrapper's own call sites. REST writers come from the existing exact-image
REST inventory (data/native-rest-callgraph.json).

--server runs a disposable backend with isolated data/ports, sends every route
with an empty payload and classifies the logged operation:
  unhandled  -> service-unimplemented / *-task-unimplemented / 108 with no handler
  handled    -> any other operation (including task-parameters-invalid)
A service whose handler rejects an impossible task with the same operation as a
real route is reported as ambiguous instead of handled.
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

ROOT = Path(__file__).resolve().parents[1]
# One JSON profile per game build keeps this tool version-independent: a new
# title/build supplies its image, symbol database and SDK task entry points.
PROFILE_PATH = ROOT / "tools/dw-build-profiles/replay120.json"
for index, value in enumerate(sys.argv):
    if value == "--profile" and index + 1 < len(sys.argv):
        PROFILE_PATH = Path(sys.argv[index + 1])
PROFILE = json.loads(PROFILE_PATH.read_text())
IMAGE = Path(PROFILE["image"])
DATABASE = Path(PROFILE["symbols"])
IMAGE_SHA256 = PROFILE["image_sha256"]
STARTERS = {int(row["address"], 16): (row["name"], row["service"], row["task"]) for row in PROFILE["starters"]}
WRAPPERS = {int(row["address"], 16) for row in PROFILE["starters"] if row.get("wrapper")}
FORWARDERS = set(PROFILE.get("forwarders", ()))
ARGUMENTS = ("rcx", "rdx", "r8", "r9")
FAMILY = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
}
for n in range(8, 16):
    for suffix in ("", "d", "w", "b"):
        FAMILY[f"r{n}{suffix}"] = f"r{n}"
VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
UNHANDLED = re.compile(r"(^service-unimplemented$|-task-unimplemented$|^objectstore-task-unimplemented$)")


def direct_references(pe, starts, targets):
    """Every rel32 call/jmp in executable sections whose target is in targets.

    The exported callgraph table is incomplete, so callers come from the image.
    Returns {target: {containing function start}} and the unowned sites.
    """
    from bisect import bisect_right
    base = pe.OPTIONAL_HEADER.ImageBase
    found = defaultdict(set)
    unowned = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        data = section.get_data()
        origin = base + section.VirtualAddress
        for opcode in (b"\xe8", b"\xe9"):
            position = data.find(opcode)
            while 0 <= position <= len(data) - 5:
                rel = int.from_bytes(data[position + 1:position + 5], "little", signed=True)
                target = origin + position + 5 + rel
                if target in targets:
                    site = origin + position
                    index = bisect_right(starts, site) - 1
                    if index >= 0:
                        found[target].add(starts[index])
                    else:
                        unowned.append(site)
                position = data.find(opcode, position + 1)
    return found, unowned


def load():
    raw = IMAGE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != IMAGE_SHA256:
        raise ValueError("Unexpected original Replay image")
    pe = pefile.PE(data=raw, fast_load=True)
    with sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True) as db:
        db.execute("pragma query_only=on")
        functions = {int(a): (n, int(s)) for n, a, s in db.execute("select name,address,size from functions")}
    starts = sorted(functions)
    callers, _ = direct_references(pe, starts, set(STARTERS))
    return pe, functions, starts, callers


def decode(pe, start, size):
    base = pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_data(start - base, size)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    return list(decoder.disasm(code, start))


def written(instruction):
    """Register family written by a simple data move, or None."""
    if instruction.mnemonic in ("mov", "movzx", "movsx", "movsxd", "xor", "lea", "or", "and",
                                "add", "sub", "inc", "dec", "pop", "cmove", "cmovne", "cmovz",
                                "cmovnz", "cmova", "cmovb", "cmovae", "cmovbe", "cmovg", "cmovl",
                                "cmovge", "cmovle", "cmovs", "cmovns", "setne", "sete"):
        ops = instruction.operands
        if ops and ops[0].type == X86_OP_REG:
            return FAMILY.get(instruction.reg_name(ops[0].reg))
    return None


def resolve(instructions, index, register, depth=0):
    """Trace one argument register backwards from instructions[index] (the call)."""
    alternatives = []
    for position in range(index - 1, max(-1, index - 64), -1):
        instruction = instructions[position]
        if instruction.mnemonic == "call":
            if register in VOLATILE:
                return [("clobbered", instruction.address)]
            continue
        if instruction.mnemonic == "ret":
            # Nothing before a return reaches the call on the linear path.
            return alternatives + [("control-flow", instruction.address)]
        if instruction.mnemonic == "jmp":
            # Forward diamonds (if/else allocation paths) rejoin before the
            # call; the value is still set on the shared prefix before them.
            continue
        if written(instruction) != register:
            continue
        ops = instruction.operands
        name = instruction.mnemonic
        if name.startswith("cmov"):
            # Both the moved value and the previous value are possible.
            source = FAMILY.get(instruction.reg_name(ops[1].reg)) if ops[1].type == X86_OP_REG else None
            if source and depth < 4:
                alternatives += resolve(instructions, position, source, depth + 1)
            else:
                alternatives.append(("unresolved", instruction.address))
            continue
        if name == "xor" and ops[1].type == X86_OP_REG and FAMILY.get(instruction.reg_name(ops[1].reg)) == register:
            return alternatives + [("const", 0)]
        if name in ("mov", "movzx", "movsx", "movsxd") and len(ops) == 2:
            if ops[1].type == X86_OP_IMM:
                return alternatives + [("const", ops[1].imm & 0xFFFFFFFF)]
            if ops[1].type == X86_OP_REG:
                source = FAMILY.get(instruction.reg_name(ops[1].reg))
                if source and depth < 8:
                    return alternatives + resolve(instructions, position, source, depth + 1)
            if (ops[1].type == X86_OP_MEM and instruction.reg_name(ops[1].mem.base) == "rsp"
                    and not ops[1].mem.index and depth < 8):
                # A spilled local (e.g. a cmov-selected task id kept across
                # allocation calls): follow the latest store to the same slot.
                slot = ops[1].mem.disp
                for earlier in range(position - 1, -1, -1):
                    store = instructions[earlier]
                    sops = store.operands
                    if (store.mnemonic == "mov" and len(sops) == 2 and sops[0].type == X86_OP_MEM
                            and store.reg_name(sops[0].mem.base) == "rsp"
                            and sops[0].mem.disp == slot and not sops[0].mem.index):
                        if sops[1].type == X86_OP_IMM:
                            return alternatives + [("const", sops[1].imm & 0xFFFFFFFF)]
                        if sops[1].type == X86_OP_REG:
                            source = FAMILY.get(store.reg_name(sops[1].reg))
                            if source:
                                return alternatives + resolve(instructions, earlier, source, depth + 1)
                        break
                    if store.mnemonic in ("push", "pop") or (
                            store.mnemonic in ("sub", "add") and sops and sops[0].type == X86_OP_REG
                            and store.reg_name(sops[0].reg) == "rsp"):
                        break
        return alternatives + [("unresolved", instruction.address)]
    if register in ARGUMENTS:
        return alternatives + [("param", ARGUMENTS.index(register))]
    return alternatives + [("unresolved", instructions[index].address)]


def sites(pe, functions, caller, target):
    name, size = functions[caller]
    instructions = decode(pe, caller, size)
    found = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic not in ("call", "jmp"):
            continue
        ops = instruction.operands
        if ops and ops[0].type == X86_OP_IMM and ops[0].imm == target:
            found.append((index, instructions))
    return found


def value(results, label):
    constants = sorted({v for kind, v in results if kind == "const"})
    other = [(kind, v) for kind, v in results if kind != "const"]
    return constants, other


def native_routes(pe, functions, starts, callers):
    routes = defaultdict(list)
    unresolved = []
    params = []
    for target, (label, service_source, task_source) in STARTERS.items():
        for caller in sorted(callers[target]):
            # Wrappers are resolved at their own call sites; starters that call
            # each other (ctor -> initTaskBuffer) only forward their arguments.
            if caller in WRAPPERS or caller in STARTERS or functions[caller][0] in FORWARDERS:
                continue
            for index, instructions in sites(pe, functions, caller, target):
                site = instructions[index].address
                service = [("const", service_source)] if isinstance(service_source, int) else \
                    resolve(instructions, index, service_source)
                task = resolve(instructions, index, task_source)
                services, service_other = value(service, "service")
                tasks, task_other = value(task, "task")
                record = dict(writer=functions[caller][0], writer_address=hex(caller),
                              call_site=hex(site), starter=label)
                pending = [(kind, v) for kind, v in service_other + task_other if kind == "param"]
                if pending and not (services and tasks):
                    params.append((caller, record, service, task))
                    continue
                if not services or not tasks:
                    unresolved.append(dict(record, service=service, task=task))
                    continue
                for s in services:
                    for t in tasks:
                        routes[(s & 0xFF, t & 0xFF)].append(record)
    # Resolve pass-through service/task arguments at the forwarding function's callers.
    forwarders, _ = direct_references(pe, starts, {caller for caller, *_ in params})
    if True:
        for caller, record, service, task in params:
            outer = sorted(forwarders.get(caller, ()))
            resolved = False
            for parent in outer:
                if parent not in functions:
                    continue
                for index, instructions in sites(pe, functions, parent, caller):
                    def at(source):
                        out = []
                        for kind, v in source:
                            if kind == "param":
                                out += resolve(instructions, index, ARGUMENTS[v])
                            else:
                                out.append((kind, v))
                        return out
                    services, _ = value(at(service), "service")
                    tasks, _ = value(at(task), "task")
                    if services and tasks:
                        resolved = True
                        for s in services:
                            for t in tasks:
                                routes[(s & 0xFF, t & 0xFF)].append(dict(
                                    record, forwarded_by=functions[parent][0],
                                    forwarded_site=hex(instructions[index].address)))
            if not resolved:
                unresolved.append(dict(record, service=service, task=task, note="pass-through unresolved"))
    return routes, unresolved


def rest_routes():
    path = ROOT / PROFILE.get("rest_inventory", "data/native-rest-callgraph.json")
    if not path.exists():
        return []
    document = json.loads(path.read_text())
    out = []
    for request in document["requests"]:
        services = request["services"]
        if not services and request["function"].startswith("bdObjectStore"):
            # Shared objectstore host builder (resolved separately by the REST
            # inventory); the same three environment hosts as the vector routes.
            services = ["objectstore.dev.demonware.net", "objectstore.cert.demonware.net",
                        "objectstore.prod.demonware.net"]
        for resource, operation in request["resource_operations"]:
            out.append(dict(writer=request["function"], services=services,
                            resource=resource, operation=operation))
    return out


def probe(server, routes, rest):
    sys.path.insert(0, str(ROOT / "tools"))
    from native_wire_client import NativeClient, binary, integer, text, u32
    results = {}
    with tempfile.TemporaryDirectory(prefix="dw-baseline-") as temporary:
        fixture = Path(temporary)
        data = fixture / "data"
        data.mkdir()
        kdf = ROOT / "data/replay-traffic-kdf.bin"
        if kdf.exists():
            shutil.copy2(kdf, data / "replay-traffic-kdf.bin")
        for offset in range(24200, 24400):
            channels = []
            try:
                for port in (8085, 8443, 3075):
                    channel = socket.socket()
                    channels.append(channel)
                    channel.bind(("127.0.0.1", port + offset))
                break
            except OSError:
                continue
            finally:
                for channel in channels:
                    channel.close()
        else:
            raise RuntimeError("No disposable probe ports available")
        log_path = data / "server.log"
        with (fixture / "stdout.log").open("wb") as log:
            process = subprocess.Popen([str(server), str(data), "--port-offset", str(offset)],
                                       stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                for _ in range(200):
                    if process.poll() is not None:
                        raise RuntimeError("Disposable backend exited")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=.3):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("Disposable backend readiness timeout")

                def logged(service, task):
                    pattern = re.compile(rf"TASK service={service} task={task} operation=(\S+) error=(\d+)")
                    for line in reversed(log_path.read_text(errors="replace").splitlines()):
                        match = pattern.search(line)
                        if match:
                            return match.group(1), int(match.group(2))
                    return None, None

                client = NativeClient(fixture, port_offset=offset)

                def send(service, task, params):
                    nonlocal client
                    error = 0
                    try:
                        client.task(service, task, params)
                    except RuntimeError as failure:
                        error = int(str(failure).rsplit(" ", 1)[1])
                    except (ValueError, OSError, ConnectionError):
                        client.close()
                        client = NativeClient(fixture, port_offset=offset)
                        error = -1
                    time.sleep(.01)
                    operation, logged_error = logged(service, task)
                    return operation, logged_error if logged_error is not None else error

                services = sorted({s for s, _ in routes})
                impossible = {}
                for service in services:
                    impossible[service] = send(service, 251, b"")
                for (service, task) in sorted(routes):
                    if all(site["starter"] == "bdRemoteTaskManager::startLSGTask"
                           for site in routes[(service, task)]):
                        # LSG records are raw [service, task, data] frames, not
                        # 0x86 task records; lobby.cpp dispatches them directly.
                        source = (ROOT / "src/lobby.cpp").read_text()
                        handled = f"payload[0] == {service} && payload[1] == {task}" in source
                        results[(service, task)] = dict(operation="lsg-dispatch" if handled else None,
                                                        error=0, status="handled" if handled else "unhandled")
                        continue
                    operation, error = send(service, task, b"")
                    if operation is None or UNHANDLED.search(operation):
                        status = "unhandled"
                    elif impossible[service][0] == operation and not UNHANDLED.search(operation or ""):
                        status = "ambiguous"
                    else:
                        status = "handled"
                    results[(service, task)] = dict(operation=operation, error=error, status=status)
                rest_results = []
                for row in rest:
                    for service in row["services"] or [""]:
                        for method in (0x474554, 0x505554):
                            params = (integer(1, 1) + integer(2, 0) + integer(3, 1) + integer(100, 10000)
                                      + binary(200, bytes(256)) + text(300, row["resource"])
                                      + text(301, row["operation"]))
                            message = (binary(1, params) + integer(2, 1) + integer(10, method)
                                       + text(11, "/probe") + text(101, service) + integer(102, 1))
                            blob = lambda v: b"\x13" + u32(len(v)) + v
                            packet = u32(713) + blob(message) + b"\x01\x00" + blob(b"")
                            operation, error = send(255, 10, packet)
                            # rest-route-not-configured is the 503 LocalServiceUnavailable
                            # fallback; an envelope rejection never reached routing.
                            status = ("unhandled" if operation in (None, "rest-route-not-configured")
                                      else "inconclusive" if operation == "rest-envelope-invalid"
                                      else "handled")
                            rest_results.append(dict(row, service=service, method=method, operation=operation,
                                                     error=error, status=status))
                client.close()
            finally:
                process.terminate()
                process.wait(timeout=10)
    return results, rest_results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=PROFILE_PATH, help="game build profile JSON")
    parser.add_argument("--server", type=Path, help="backend executable to probe (optional)")
    parser.add_argument("--output", type=Path, default=ROOT / "validation/dw-task-baseline.json")
    args = parser.parse_args()
    pe, functions, starts, callers = load()
    routes, unresolved = native_routes(pe, functions, starts, callers)
    rest = rest_routes()
    probed, rest_probed = ({}, [])
    if args.server:
        probed, rest_probed = probe(args.server.resolve(strict=True), routes, rest)
    rows = []
    for (service, task), writers in sorted(routes.items()):
        row = dict(service=service, task=task,
                   writers=sorted({w["writer"] for w in writers}),
                   sites=[{k: v for k, v in w.items() if k != "writer"} for w in writers])
        if probed:
            row.update(probed[(service, task)])
        rows.append(row)
    summary = dict(native_routes=len(rows), unresolved_call_sites=len(unresolved), rest_operations=len(rest))
    if probed:
        for status in ("handled", "unhandled", "ambiguous"):
            summary[status] = sum(1 for r in rows if r.get("status") == status)
        for status in ("unhandled", "inconclusive"):
            summary["rest_" + status] = sorted({(r["writer"], r["service"], r["resource"])
                                                for r in rest_probed if r["status"] == status})
    document = dict(schema=1, generated_utc=datetime.now(timezone.utc).isoformat(),
                    build=PROFILE["build"], titles=PROFILE["titles"],
                    target_image_sha256=IMAGE_SHA256,
                    server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest() if args.server else None,
                    starters={hex(k): v[0] for k, v in STARTERS.items()},
                    summary=summary, routes=rows, unresolved=unresolved, rest=rest_probed or rest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, default=str) + "\n")
    print(json.dumps(summary, indent=2, default=str))
    for row in rows:
        mark = row.get("status", "")
        print(f"{row['service']:>3}/{row['task']:<3} {mark:<9} {row.get('operation') or '':<44} {', '.join(row['writers'])[:110]}")
    for row in unresolved:
        print("UNRESOLVED", row["writer"], row["call_site"], row["starter"], row.get("note", ""))


if __name__ == "__main__":
    main()
