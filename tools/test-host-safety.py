"""Native instruction checks for streamed glass damage and simulation FPS."""

import argparse
import importlib.util
import json
import math
from pathlib import Path
import struct

from unicorn.x86_const import UC_X86_REG_XMM0
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "host_safety_vm", ROOT / "tools/test-host-navigation.py"
)
navigation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(navigation)


class Machine(navigation.Machine):
    def boundary(self, machine, address, size, user):
        kind = self.hooks.get(address)
        if kind in ("qpc", "qpf"):
            target = machine.reg_read(navigation.UC_X86_REG_RCX)
            self.put(target, self.ticks if kind == "qpc" else 1000, "<Q")
            self.ret(1)
        elif kind in ("main-thread", "register-command"):
            self.ret(1)
        elif kind and kind.startswith("SVHS_Glass"):
            a, b, c = [
                machine.reg_read(register)
                for register in (
                    navigation.UC_X86_REG_RCX,
                    navigation.UC_X86_REG_RDX,
                    navigation.UC_X86_REG_R8,
                )
            ]
            if kind == "SVHS_GlassSystem":
                self.put(b, 22, "<I")
                self.ret(self.glass_system)
            elif kind == "SVHS_GlassCenter":
                assert a, "Native center dereferenced the absent FX transient"
                self.put(c, struct.pack("<3f", 10, 20, 30))
                self.ret()
            elif kind == "SVHS_GlassAxis":
                assert a
                self.put(c, struct.pack("<9f", 1, 0, 0, 0, 1, 0, 0, 0, 1))
                self.ret()
            elif kind == "SVHS_GlassDirectionByte":
                self.ret(99)
            elif kind == "SVHS_GlassPackImpact":
                value = struct.unpack(
                    "<f",
                    struct.pack("<I", machine.reg_read(UC_X86_REG_XMM0) & 0xFFFFFFFF),
                )[0]
                self.ret(max(0, min(63, int(value + 32))))
            elif kind == "SVHS_GlassRandom":
                value = self.random_values.pop(0)
                machine.reg_write(
                    UC_X86_REG_XMM0, struct.unpack("<I", struct.pack("<f", value))[0]
                )
                self.ret()
            elif kind == "SVHS_GlassRemoveObstacle":
                self.events.append(("remove-obstacle", a))
                self.ret()
            elif kind == "SVHS_GlassScriptContext":
                self.ret(0x5100F000)
            elif kind == "SVHS_GlassAddInt":
                self.events.append(("script-piece", a, b))
                self.ret()
            elif kind == "SVHS_GlassNotify":
                self.events.append(("notify", a, b, c))
                self.ret()
            else:
                raise AssertionError(kind)
        else:
            super().boundary(machine, address, size, user)


navigation.Machine = Machine
navigation.SOURCES = ("G_Glass_PieceStateChanged", "SV_HostScale")


def glass(
    vm,
    damage,
    old_state,
    resident=True,
    direction=(1, 0, 0),
    random_choice=0.5,
    geometry=True,
    local_count=23,
):
    data, pieces, weaken, destroy = 0x51000000, 0x51001000, 0x51002000, 0x51003000
    position, vector, system = 0x51004000, 0x51005000, 0x51006000
    vm.put(data, bytes(40))
    vm.put(data, pieces, "<Q")
    vm.put(data + 8, 1, "<I")
    vm.put(pieces, struct.pack("<HHiBBBB", damage, 123, 777, 12, 13, 14, 15))
    vm.put(vm.symbols["SVHS_GlassData"], data, "<Q")
    for symbol, pointer, threshold in (
        ("SVHS_GlassWeakenDvar", weaken, 100),
        ("SVHS_GlassDestroyDvar", destroy, 500),
    ):
        vm.put(pointer, bytes(112))
        vm.put(pointer + 40, threshold, "<H")
        vm.put(vm.symbols[symbol], pointer, "<Q")
    vm.put(vm.symbols["SVHS_GlassDestroyedString"], 456, "<I")
    vm.put(vm.symbols["SVHS_LevelTime"], 9000, "<i")
    vm.put(system, bytes(144))
    vm.put(system + 132, local_count, "<I")
    vm.put(system + 136, 0x51010000 if geometry else 0, "<Q")
    vm.put(position, struct.pack("<3f", 17, 12, 35))
    vm.put(vector, struct.pack("<3f", *direction))
    vm.glass_system = system if resident else 0
    vm.random_values = [random_choice, 0.25]
    vm.call("G_Glass_PieceStateChanged", 0, old_state, position, vector)
    return bytes(vm.uc.mem_read(pieces, 12)), vm.events


def fps(vm):
    vm.call("SV_HostScale_GetSimulationFPS")
    return struct.unpack(
        "<f", struct.pack("<I", vm.uc.reg_read(UC_X86_REG_XMM0) & 0xFFFFFFFF)
    )[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runner = navigation.Runner(args.snapshot, args.build)
    cases = 0
    for damage in (0, 99, 100, 499, 500, 65534, 65535):
        for old_state in (0, 1, 2, 3):
            native = glass(runner.machine(False), damage, old_state)
            edited = glass(runner.machine(True), damage, old_state)
            assert native == edited, (damage, old_state, native, edited)
            cases += 1
    for choice in (0.1, 0.3, 0.699, 0.7, 0.9):
        native = glass(runner.machine(False), 100, 0, random_choice=choice)
        edited = glass(runner.machine(True), 100, 0, random_choice=choice)
        assert native == edited, (choice, native, edited)
        cases += 1
    zero_native = glass(runner.machine(False), 500, 1, direction=(0, 0, 0))
    zero_edited = glass(runner.machine(True), 500, 1, direction=(0, 0, 0))
    assert zero_native == zero_edited
    for options in (dict(resident=False), dict(geometry=False), dict(local_count=22)):
        repaired = glass(runner.machine(True), 500, 1, **options)
        assert repaired == zero_native, (options, repaired, zero_native)
        cases += 1
    try:
        glass(runner.machine(False), 500, 1, resident=False)
    except AssertionError as error:
        assert "absent FX transient" in str(error)
    else:
        raise AssertionError(
            "Native negative control did not reproduce the null glass-system dereference"
        )

    vm = runner.machine(True)
    vm.ticks = 1000
    vm.call("SV_HostScale_Frame")
    assert fps(vm) == -1
    for name in ("SVHS_BotSystemAllocated", "SVHS_LevelClientsAllocated"):
        vm.put(vm.symbols[name], 1, "<I")
    assert fps(vm) == 0
    record = "?RecordBotFrame@HostScale@@YAXII_K0@Z"
    for _ in range(63):
        vm.call(record, 0, 0, 0, 0)
    vm.ticks = 1500
    assert fps(vm) == 0  # Do not mistake 20 render frames for a measurement interval.
    vm.ticks = 2000
    assert fps(vm) == 63
    for _ in range(80):
        vm.call(record, 0, 0, 0, 0)
    vm.ticks = 4000
    assert fps(vm) == 40
    vm.ticks = 5000
    assert fps(vm) == 0  # Renderer can run while simulation is stopped.
    vm.ticks = 900
    assert fps(vm) == 0  # Clock rollback discards the previous interval.
    vm.put(vm.symbols["SVHS_BotSystemAllocated"], 0, "<I")
    assert fps(vm) == -1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = dict(
        passed=True,
        glass_differential_cases=cases,
        native_missing_transient_failure_reproduced=True,
        checks=[
            "Resident glass retains native state thresholds, collapse timing, impact bytes, obstacle removal and script notifications",
            "Absent FX transient, missing initial geometry and invalid local index use the native no-impact encoding while destruction remains authoritative",
            "Simulation FPS uses completed server ticks over wall time; handles low tick rate, stalled simulation, absent local server and clock rollback",
        ],
        game_runs_performed=False,
    )
    if runner.report:
        result["executable_sha256"] = runner.report["sha256"]
        symbols = runner.report["symbols"]
        capture = symbols["Com_DebugStates_Capture"]
        sampler = runner.base + symbols["SV_HostScale_GetSimulationFPS"]
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        calls = [
            i.operands[0].imm
            for i in decoder.disasm(
                runner.linked.get_data(capture, 16384), runner.base + capture
            )
            if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
        ]
        assert (
            sampler in calls
        ), "Debug capture does not call the linked simulation sampler"
        assert runner.linked.__data__.find(b"Simulation FPS: %.1f (local server)\0") >= 0
        assert runner.linked.__data__.find(b"Simulation FPS: N/A (no local server)\0") >= 0
        result["checks"].append(
            "Linked com_debugStates capture calls the exact sampler and contains both display rows"
        )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS", cases, "glass cases and native simulation FPS samples; no game run")


if __name__ == "__main__":
    main()
