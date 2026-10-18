"""Compare the real Replay worker instructions with the DW production COFF body.

Only native job execution, platform waits and initialization are modeled. Both
schedulers execute their actual instructions, TLS reads and atomic operations.
No game executable is built or launched.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = Path(__file__).resolve().parents[1]
COMPILER = Path(r"E:\replay-compiler")
sys.path.insert(0, str(COMPILER / "tools"))
from coff import read as read_coff


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--build", type=Path,
                        help="Also compare the linked EXE's worker and actual relocated globals")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    catalog = json.loads((COMPILER / "generated/function-catalog.json").read_bytes())
    assert hashlib.sha256(original.read_bytes()).hexdigest() == catalog["image_sha256"]
    pe = pefile.PE(str(original), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    native = json.loads((COMPILER / "generated/native-symbols.json").read_bytes())
    obj = read_coff(args.object)
    minimum, queues, preferences = base+0xD57EE44, base+0xD53F300, base+0x45ADBB8
    waiters = base+0xD57EE48
    NONE = 0x7FFFFFFF
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    linked_report = linked_pe = None
    if args.build:
        linked_report = json.loads((args.build / "build-report.json").read_bytes())
        linked_image = Path(linked_report["executable"])
        assert hashlib.sha256(linked_image.read_bytes()).hexdigest() == linked_report["sha256"]
        assert linked_report["unresolved_symbols"] == 0
        linked_pe = pefile.PE(str(linked_image), fast_load=True)
        assert linked_pe.OPTIONAL_HEADER.ImageBase == base
        ranges = linked_report["rva_map"]["ranges"]
        range_starts = [row["begin"] for row in ranges]
    externals = {}
    for symbol in obj["symbols"].values():
        if symbol["section"] != 0:
            continue
        name = symbol["name"]
        if name in native:
            externals[name] = base + native[name]
        elif name.startswith("func_") or name.startswith("gl_"):
            externals[name] = int(name.split("_")[1], 16)
        elif name == "Com_Optimized_IsEnabled":
            externals[name] = 0x180800000
        else:
            raise AssertionError(f"Unmodeled external: {name}")

    def run(edited, mode, case):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        active_pe = linked_pe if edited and linked_pe else pe
        def address_of(rva):
            if not (edited and linked_report):
                return base+rva
            for name in (f"func_{base+rva:X}", f"gl_{base+rva:X}"):
                if name in linked_report["symbols"]:
                    return base+linked_report["symbols"][name]
            row = ranges[bisect.bisect_right(range_starts,rva)-1]
            return base+row["mapped_begin"]+rva-row["begin"]
        minimum, queues, preferences = map(address_of,(0xD57EE44,0xD53F300,0x45ADBB8))
        waiters = address_of(0xD57EE48)
        pages = set()
        def page(address):
            address &= ~4095
            if address in pages:
                return
            vm.mem_map(address, 4096)
            if base <= address < base + active_pe.OPTIONAL_HEADER.SizeOfImage:
                data = active_pe.get_data(address-base, 4096)
                if data:
                    vm.mem_write(address, data)
            pages.add(address)
        def write(address, value, fmt="<i"):
            data = struct.pack(fmt, value)
            page(address); page(address+len(data)-1)
            vm.mem_write(address, data)
        def integer(address):
            page(address)
            return struct.unpack("<i", vm.mem_read(address, 4))[0]
        def missing(machine, access, address, size, value, context):
            page(address); page(address+size-1)
            return True
        if edited and linked_report:
            entry = base+linked_report["symbols"]["func_1412CE8A0"]
        elif edited:
            section_addresses = {i+1: 0x180000000+i*0x10000 for i in range(len(obj["sections"]))}
            symbols = {index: section_addresses[row["section"]]+row["value"]
                       if row["section"] > 0 else externals.get(row["name"], row["value"])
                       for index,row in obj["symbols"].items()}
            for section in obj["sections"]:
                address = section_addresses[section["number"]]
                data = bytearray(section["data"])
                for offset, index, kind in section["relocations"]:
                    target = symbols[index]
                    if 4 <= kind <= 9:
                        value = struct.unpack_from("<i", data, offset)[0]+target-address-offset-4-(kind-4)
                        struct.pack_into("<i", data, offset, value)
                    elif kind == 1:
                        struct.pack_into("<Q", data, offset, struct.unpack_from("<Q", data, offset)[0]+target)
                    elif kind == 3:  # image-relative unwind metadata is not executed here
                        struct.pack_into("<I", data, offset, (target-0x180000000)&0xFFFFFFFF)
                    else:
                        raise AssertionError((section["name"], kind))
                for at in range(address, address+max(1,len(data)), 4096): page(at)
                if data: vm.mem_write(address, bytes(data))
            entry = next(symbols[i] for i,s in obj["symbols"].items() if s["name"] == "func_1412CE8A0")
        else:
            entry = base+0x12CE8A0
        for i in range(147): write(queues+192*i+20, 0)
        for index, value in enumerate(case.get("preferences", [-1,-1,-1])):
            write(preferences+4*index, value)
        for kind, count in case.get("jobs", {}).items(): write(queues+192*kind+20, count)
        write(minimum, case.get("minimum", NONE)); write(waiters, 0)
        write(address_of(native["TlsIndex"]), 0, "<I")
        teb, slots, tls, stack, jump_buffer = 0x50000000, 0x50001000, 0x50002000, 0x40010008, 0x50003000
        write(teb+0x58, slots, "<Q"); write(slots, tls, "<Q")
        write(tls+336, case.get("tls", -1))
        for at in range(stack-0x10000, stack+0x1000, 4096): page(at)
        vm.reg_write(UC_X86_REG_GS_BASE, teb)
        vm.reg_write(UC_X86_REG_RSP, stack)
        vm.reg_write(UC_X86_REG_RCX, 19)
        hooks = {address_of(rva):name for name,rva in (
            ("jump-buffer",0x12CEF90), ("context",0x108F230), ("initialize",0x1090870),
            ("fatal",0x12AAC10), ("wait",0x12D04E0), ("reset",0x12CF460), ("claim",0x12CDA80))}
        hooks[address_of(native["__intrinsic_setjmp"])] = "setjmp"
        hooks[base+linked_report["symbols"]["Com_Optimized_IsEnabled"]
              if edited and linked_report else 0x180800000] = "optimized"
        events, completed, atomic_ops = [], [], []
        waits = 0
        injected = False
        def returned(value=0):
            sp = vm.reg_read(UC_X86_REG_RSP)
            address = struct.unpack("<Q", vm.mem_read(sp,8))[0]
            vm.reg_write(UC_X86_REG_RAX, value)
            vm.reg_write(UC_X86_REG_RSP, sp+8)
            vm.reg_write(UC_X86_REG_RIP, address)
        def boundary(machine, address, size, context):
            nonlocal waits, injected
            kind = hooks.get(address)
            a = vm.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
            if kind == "optimized": returned(mode != 0); return
            if kind:
                if kind == "jump-buffer":
                    assert a == 2; returned(jump_buffer)
                elif kind == "setjmp":
                    assert vm.reg_read(UC_X86_REG_RCX) == jump_buffer
                    assert vm.reg_read(UC_X86_REG_RDX) == vm.reg_read(UC_X86_REG_RSP)+8
                    returned(int(case.get("error", False)))
                elif kind == "context":
                    assert a == 19; returned(7)
                elif kind == "initialize":
                    assert a == 7; returned()
                elif kind == "fatal":
                    vm.emu_stop()
                elif kind == "wait":
                    waits += 1
                    assert integer(waiters) == 1
                    if waits == 2: vm.emu_stop()
                    else: returned()
                elif kind == "reset":
                    assert integer(waiters) == 0
                    if case.get("enqueue_on_reset"):
                        write(queues+192*6+20,1); write(minimum,6)
                    returned()
                elif kind == "claim":
                    assert 0 <= a < 147 and integer(waiters) == 0
                    available = integer(queues+192*a+20)
                    success = available > 0 and a not in case.get("blocked", [])
                    if success:
                        write(queues+192*a+20,available-1); completed.append(a)
                        if integer(minimum) > a: write(minimum,a)
                        if case.get("earlier_after_claim") and not injected:
                            write(queues+192*2+20,1); write(minimum,2); injected = True
                    events.append(("claim",a,bool(success))); returned(success); return
                events.append((kind,)); return
            raw = bytes(vm.mem_read(address,size))
            if raw[:1] == b"\xf0":
                instruction = next(cs.disasm(raw,address))
                if "cmpxchg" in instruction.mnemonic:
                    atomic_ops.append(address)
                    if case.get("race_clear") and not injected and (vm.reg_read(UC_X86_REG_RAX)&0xFFFFFFFF)==8:
                        write(minimum,1); write(queues+192+20,1); injected = True
        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        vm.hook_add(UC_HOOK_CODE, boundary)
        vm.emu_start(entry, 0, count=500000)
        assert waits == 2 or case.get("error"), (edited, mode, case, events[-10:])
        return dict(events=events,completed=completed,minimum=integer(minimum),
                    remaining=[integer(queues+192*i+20) for i in range(147)],atomics=len(atomic_ops))

    cases = [{}, {"error":True}, {"jobs":{13:2},"minimum":13},
        {"jobs":{7:1,9:1},"tls":7,"preferences":[-1,9,-1]},
        {"jobs":{13:1},"minimum":13,"earlier_after_claim":True},
        {"jobs":{8:1},"blocked":[8]}, {"enqueue_on_reset":True},
        {"minimum":8,"race_clear":True}]
    rng = random.Random(120)
    for _ in range(100):
        types = rng.sample(range(147),5)
        cases.append(dict(jobs={t:rng.randint(1,3) for t in types},
            minimum=rng.choice([NONE,*types]), tls=rng.choice([-1,*types]),
            preferences=[rng.choice([-1,*types]),-1,-1], blocked=rng.sample(types,2)))
    results = []
    for case in cases:
        baseline = run(False,0,case)
        for mode in (0,1,2):
            changed = run(True,mode,case)
            for key in ("events","completed","minimum","remaining"):
                assert changed[key] == baseline[key], (case,mode,key,changed[key],baseline[key])
            assert changed['atomics'] <= baseline['atomics']
            results.append(dict(case=case,mode=mode,baseline_atomics=baseline['atomics'],changed_atomics=changed['atomics']))
    result = dict(passed=True,cases=len(results),original_sha256=catalog['image_sha256'],
        object_sha256=hashlib.sha256(args.object.read_bytes()).hexdigest(),results=results,
        scope=__doc__,linked_game_sha256=linked_report["sha256"] if linked_report else None,
        game_runtime_tested=False)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    target = "linked EXE" if linked_report else "production object"
    print(f"PASS: {len(results)} {target} versus native-worker cases, including startup/error ABI")


if __name__ == "__main__":
    main()
