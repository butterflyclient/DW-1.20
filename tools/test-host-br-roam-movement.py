"""Execute compiled BR native-validation and exact reachable-fallback wrappers.
GPU coordinator/engine boundaries are modeled; no game calls or process writes.
"""

import argparse, importlib.util, json, shutil, tempfile, struct, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify_native_goal_priorities(module, runner):
    """Execute the original string-to-goal-priority mapper, including its table."""
    pe = runner.original
    base = pe.OPTIONAL_HEADER.ImageBase
    function_rva = 0x133ED60
    table_rva = 0x45BF1F0
    expected = ["none", "hunt", "guard", "camp", "objective", "critical", "tactical"]
    table = pe.get_data(table_rva, 64)
    names = []
    for pointer in struct.unpack("<8Q", table):
        names.append(pe.get_data(pointer - base, 64).split(b"\0")[0].decode() if pointer else None)
    assert names == expected + [None]
    vm = module.Uc(module.UC_ARCH_X86, module.UC_MODE_64)
    mapped = set()

    def page(address):
        address &= -4096
        if address in mapped:
            return
        assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(address, 4096)
        vm.mem_write(address, pe.get_data(address - base, 4096))
        mapped.add(address)

    def missing(_vm, _access, address, size, _value, _data):
        page(address)
        page(address + size - 1)
        return True

    vm.hook_add(module.UC_HOOK_MEM_UNMAPPED, missing)
    point, stack, stop = 0x50000000, 0x70000000, 0x71000000
    for address in (point, stack, stop):
        vm.mem_map(address, 4096)
    rows = []
    for name, expected_value in [(n, i) for i, n in enumerate(expected)] + [
        ("HUNT", 1),
        ("unknown", 0),
    ]:
        vm.mem_write(point, name.encode() + b"\0")
        vm.mem_write(stack + 0x808, struct.pack("<Q", stop))
        vm.reg_write(module.UC_X86_REG_RCX, point)
        vm.reg_write(module.UC_X86_REG_RSP, stack + 0x808)
        vm.emu_start(base + function_rva, stop, count=10000)
        assert vm.reg_read(module.UC_X86_REG_RIP) == stop
        value = vm.reg_read(module.UC_X86_REG_RAX)
        assert value == expected_value, (name, value)
        rows.append({"name": name, "native_priority": value})
    return {
        "function_rva": function_rva,
        "table_rva": table_rva,
        "table_hex": table.hex(),
        "cases": rows,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--current-source", action="store_true")
    p.add_argument("--build", type=Path)
    a = p.parse_args()
    if a.build and a.current_source:
        p.error("--build requires frozen sources")
    if a.build:
        report = json.loads((a.build / "build-report.json").read_bytes())
        assert Path(report["source_root"]).resolve() == a.snapshot.resolve()
        assert (
            hashlib.sha256(Path(report["executable"]).read_bytes()).hexdigest() == report["sha256"]
        )
        for name in ("Bot_UpdateMove_OffPathGrid", "Scr_GetClosestReachablePointOnNavmesh"):
            row = next(x for x in report["cpp"] if Path(x["source"]).name == name + ".cpp")
            assert (
                row["source_sha256"]
                == hashlib.sha256((a.snapshot / "src" / (name + ".cpp")).read_bytes()).hexdigest()
            )
            assert (
                row["object_sha256"] == hashlib.sha256(Path(row["object"]).read_bytes()).hexdigest()
            )
    spec = importlib.util.spec_from_file_location("nav", ROOT / "tools/test-host-navigation.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    original = m.Machine

    class Machine(original):
        def boundary(self, machine, address, size, user):
            kind = self.hooks.get(address, "")
            if kind == "SVHS_BotPathToGoal" and getattr(self, "assert_roam_tls", False):
                assert self.get(self.roam_tls + 16, "<Q") == self.get(
                    self.symbols["SVHS_GameStatics"], "<Q"
                )
            sp = self.uc.reg_read(m.UC_X86_REG_RSP)
            if kind == "planner-consumenativeroamfallback":
                allowed = getattr(self, "roam_permit", False)
                self.roam_permit = False
                self.ret(allowed)
                return
            if kind == "planner-admitroamvalidation":
                self.ret(1)
                return
            if kind == "planner-requestroam":
                out = self.get(sp + 120, "<Q")
                self.put(
                    out, struct.pack("<3f", *getattr(self, "roam_destination", (2000.0, 0.0, 0.0)))
                )
                self.ret(getattr(self, "roam_status", 2))
                return
            if kind == "planner-roamcandidateallowed":
                dest = struct.unpack(
                    "<3f", self.uc.mem_read(self.uc.reg_read(m.UC_X86_REG_RDX), 12)
                )
                self.ret(dest[0] > 1056 and getattr(self, "roam_safe", True))
                return
            if kind == "planner-finishroam":
                self.events.append(("roam-finish", bool(self.uc.reg_read(m.UC_X86_REG_RDX))))
                self.ret()
                return
            if kind == "roam-clock":
                self.ret(1)
                return
            return super().boundary(machine, address, size, user)

    m.Machine = Machine
    checks = []
    with tempfile.TemporaryDirectory(prefix="br-roam-native-", dir=ROOT / "data") as td:
        f = Path(td)
        for folder in ("src", "generated", "tools"):
            (f / folder).mkdir()
        for folder in [a.snapshot / "src"] + (
            [ROOT / "integration/host-scale"] if a.current_source else []
        ):
            for path in folder.glob("*.h"):
                shutil.copy2(path, f / "src" / path.name)
        for name in m.SOURCES:
            shutil.copy2(
                (ROOT / "integration/host-scale" if a.current_source else a.snapshot / "src")
                / (name + ".cpp"),
                f / "src" / (name + ".cpp"),
            )
        for name in ("function-catalog.json", "host-scale-integration.json"):
            shutil.copy2(a.snapshot / "generated" / name, f / "generated" / name)
        shutil.copy2(a.snapshot / "tools/coff.py", f / "tools/coff.py")
        runner = m.Runner(f, a.build)
        goal_priority_proof = verify_native_goal_priorities(m, runner)
        for mode in (1, 2):
            vm = runner.machine(True, mode)
            m.script(vm)
            vm.roam_permit = True
            vm.population = 150
            vm.call("Scr_GetClosestReachablePointOnNavmesh", 0x1234, 0)
            assert (
                struct.unpack("<3f", vm.output) == (91.0, 92.0, 93.0) and ("native",) in vm.events
            )
            assert not any(e[0] == "closest" for e in vm.events)
            checks.append("admitted-fallback-real-native-mode" + str(mode))
            vm.events = []
            vm.call("Scr_GetClosestReachablePointOnNavmesh", 0x1234, 0)
            assert ("native",) not in vm.events
            checks.append("fallback-permit-one-use-mode" + str(mode))
            for failure in (
                "success",
                "path",
                "projection",
                "unsafe",
                "near",
                "gulag",
                "airborne",
                "skydiving",
                "dead",
                "locked",
                "human",
                "unmapped",
                "gas",
                "critical",
            ):
                vm = runner.machine(True, mode)
                m.mesh_bot(vm, "normal")
                m.map_mesh_bot(vm)
                vm.events = []
                vm.roam_tls = m.install_bot_tls(vm)
                vm.assert_roam_tls = True
                vm.gpu_enabled = True
                vm.route_success = failure != "path"
                vm.found = failure != "projection"
                vm.roam_safe = failure != "unsafe"
                if failure == "near":
                    vm.roam_destination = (1000.0, 0.0, 0.0)
                if failure == "gulag":
                    vm.gulag = True
                if failure == "airborne":
                    vm.put(0x5B030000 + 626, 2047, "<H")
                if failure == "skydiving":
                    vm.put(0x5B030000 + 12072, 1, "<B")
                if failure == "dead":
                    vm.put(0x5B010000 + 440, 0, "<i")
                if failure == "locked":
                    vm.put(0x5B030000 + 364, 0x20, "<I")
                if failure == "human":
                    vm.put(0x5B000000 - 1368 + 214756, 1, "<i")
                if failure == "unmapped":
                    vm.mapped_profile = False
                if failure == "gas":
                    vm.gas_required = True
                if failure == "critical":
                    vm.put(0x5B000000 + 516, 5, "<I")
                for name, at in vm.symbols.items():
                    if name.startswith("?Clock@HostScale@@"):
                        vm.hooks[at] = "roam-clock"
                name = "SV_HostBot_RequestRoamGoal"
                circle, out = 0x5E100000, 0x5E101000
                vm.put(circle, struct.pack("<3f", 0.0, 0.0, 0.0))
                vm.put(out, b"X" * 12)
                stack, stop = 0x70080008, 0x190000000
                vm.put(stack - 0x20000, bytes(0x22000))
                vm.put(stack, stop, "<Q")
                vm.put(stack + 40, 0x1234, "<Q")
                vm.page(stop)
                for at in vm.hooks:
                    vm.page(at)
                for reg, value in zip(
                    (m.UC_X86_REG_RCX, m.UC_X86_REG_RDX, m.UC_X86_REG_R8, m.UC_X86_REG_R9),
                    (0x5B000000, circle, 0, out),
                ):
                    vm.uc.reg_write(reg, value)
                vm.uc.reg_write(
                    m.UC_X86_REG_XMM2, struct.unpack("<I", struct.pack("<f", 4000.0))[0]
                )
                vm.uc.reg_write(m.UC_X86_REG_RSP, stack)
                vm.uc.emu_start(vm.entries[name], stop, count=3000000)
                assert vm.uc.reg_read(m.UC_X86_REG_RIP) == stop
                assert vm.get(vm.roam_tls + 16, "<Q") == 0x5D004000
                result = vm.uc.reg_read(m.UC_X86_REG_RAX)
                accepted = failure == "success"
                exempt = failure in (
                    "gulag",
                    "airborne",
                    "skydiving",
                    "dead",
                    "locked",
                    "human",
                    "unmapped",
                    "gas",
                    "critical",
                )
                assert result == (0 if exempt else 2 if accepted else 1), (
                    failure,
                    result,
                    vm.events,
                )
                assert (
                    (not any(e[0] == "roam-finish" for e in vm.events))
                    if exempt
                    else ("roam-finish", accepted) in vm.events
                ), (failure, vm.events)
                assert bytes(vm.uc.mem_read(out, 12)) == (
                    struct.pack("<3f", 2000.0, 0.0, 0.0) if accepted else b"X" * 12
                )
                if failure in ("projection", "unsafe", "near"):
                    assert not any(e[0] == "path-request" for e in vm.events)
                checks.append("native-validation-" + failure + "-mode" + str(mode))
        hashes = {
            name: hashlib.sha256((f / "src" / (name + ".cpp")).read_bytes()).hexdigest()
            for name in ("Bot_UpdateMove_OffPathGrid", "Scr_GetClosestReachablePointOnNavmesh")
        }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(
        json.dumps(
            {
                "passed": True,
                "checks": checks,
                "source_sha256": hashes,
                "native_goal_priority_proof": goal_priority_proof,
                "limitation": "Actual compiled wrappers; GPU result, area projection and native path engine boundaries modeled.",
            },
            indent=2,
        )
    )
    print("PASS BR roam compiled native wrappers:", len(checks), "cases")


if __name__ == "__main__":
    main()
