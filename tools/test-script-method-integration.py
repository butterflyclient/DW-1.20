"""Compare compiled and linked script-method registration with native Replay."""

import sys, importlib.util, json, struct, random, argparse, hashlib, bisect, subprocess, tempfile
from pathlib import Path
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *

ROOT = Path(__file__).resolve().parents[1]
stop = 0x180F00000
ctx = 0x190000000
stack = 0x70000000
report = None
linked = None
obj = None


def mapped(address):
    if not report:
        return address
    rva = address - base
    row = ranges[bisect.bisect_right(range_starts, rva) - 1]
    assert row["begin"] <= rva < row["end"], hex(address)
    return base + row["mapped_begin"] + rva - row["begin"]


class Harness:
    def __init__(self, edited, seed=1):
        self.pe = linked if edited and report else pe
        self.aliases = {
            name: mapped(at) if edited else at for name, at in aliases.items()
        }
        self.callback = (
            callback
            if not edited or not report
            else base + report["symbols"]["DW_BotStyleWeaponMethod"]
        )
        self.survival = (
            stop + 64
            if not edited or not report
            else base + report["symbols"]["DW_BotSurvivalAllowedMethod"]
        )
        self.mp_class = (
            stop + 96 if not edited or not report
            else base + report["symbols"]["DW_BotMPClassReadyMethod"]
        )
        self.gas_state = (
            stop + 128 if not edited or not report
            else base + report["symbols"]["DW_BotGasStateMethod"]
        )
        self.roam_callbacks = {
            name: (base + report["symbols"][name] if edited and report else stop + 160 + index * 32)
            for index, name in enumerate(
                row["callback_symbol"] for row in proof["registry"]
                if row["callback_symbol"].startswith("DW_BotRoam")
            )
        }
        self.vm = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pages = set()
        self.trace = []
        self.early = None
        self.result_slot = None
        self.edited = edited

        def unmapped(vm, access, address, size, value, data):
            self.page(address)
            return True

        self.vm.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)
        self.vm.hook_add(UC_HOOK_CODE, self.hook)
        self.put(ctx, random.Random(seed).randbytes(153640))
        self.put(self.aliases["SM_ContextInstances"], struct.pack("<QQ", ctx, ctx))
        self.symbols = {}
        if edited:
            if report:
                self.symbols = {
                    name: base + report["symbols"][name]
                    for name in ["DW_ScriptContextInitialize", "DW_GScriptMPGetMethod"]
                }
            else:
                self.link_object()

    def page(self, at):
        at &= -4096
        if at in self.pages:
            return
        self.vm.mem_map(at, 4096)
        self.pages.add(at)
        if base <= at < base + self.pe.OPTIONAL_HEADER.SizeOfImage:
            data = self.pe.get_data(at - base, 4096)
            if data:
                self.vm.mem_write(at, data)

    def put(self, at, data):
        for page in range(at & -4096, (at + len(data) + 4095) & -4096, 4096):
            self.page(page)
        self.vm.mem_write(at, data)

    def get(self, at, size):
        for page in range(at & -4096, (at + size + 4095) & -4096, 4096):
            self.page(page)
        return bytes(self.vm.mem_read(at, size))

    def u64(self, at):
        return struct.unpack("<Q", self.get(at, 8))[0]

    def link_object(self):
        sections = {
            i + 1: 0x180000000 + i * 0x10000 for i in range(len(obj["sections"]))
        }
        external = {
            **self.aliases,
            **self.roam_callbacks,
            "DW_BotStyleWeaponMethod": self.callback,
            "DW_BotSurvivalAllowedMethod": self.survival,
            "DW_BotMPClassReadyMethod": self.mp_class,
            "DW_BotGasStateMethod": self.gas_state,
        }
        addresses = {
            i: (
                sections[s["section"]] + s["value"]
                if s["section"] > 0
                else external[s["name"]] if s["section"] == 0 else s["value"]
            )
            for i, s in obj["symbols"].items()
        }
        for section in obj["sections"]:
            at = sections[section["number"]]
            data = bytearray(section["data"])
            for offset, index, kind in section["relocations"]:
                target = addresses[index]
                if 4 <= kind <= 9:
                    struct.pack_into(
                        "<i",
                        data,
                        offset,
                        struct.unpack_from("<i", data, offset)[0]
                        + target
                        - at
                        - offset
                        - 4
                        - (kind - 4),
                    )
                elif kind == 1:
                    struct.pack_into(
                        "<Q",
                        data,
                        offset,
                        struct.unpack_from("<Q", data, offset)[0] + target,
                    )
                elif kind == 3:
                    struct.pack_into(
                        "<I", data, offset, (target - 0x180000000) & 0xFFFFFFFF
                    )
                else:
                    raise AssertionError(kind)
            self.put(
                at,
                bytes(data) if data else bytes(section.get("virtual_size", 0) or 4096),
            )
        self.symbols = {s["name"]: addresses[i] for i, s in obj["symbols"].items()}

    def return_value(self, value):
        self.vm.reg_write(UC_X86_REG_RAX, value)
        rsp = self.vm.reg_read(UC_X86_REG_RSP)
        self.vm.reg_write(UC_X86_REG_RIP, self.u64(rsp))
        self.vm.reg_write(UC_X86_REG_RSP, rsp + 8)

    def hook(self, vm, address, size, data):
        if address == stop:
            vm.emu_stop()
            return
        if address == self.aliases["SM_ServerContext"]:
            self.return_value(ctx)
            return
        slot_helper = base + proof["add_bool_slot_helper_rva"]
        if self.edited:
            slot_helper = mapped(slot_helper)
        if self.result_slot is not None and address == slot_helper:
            self.return_value(self.result_slot)
            return
        if address == self.aliases["SM_RegisterMethodTable"]:
            table = vm.reg_read(UC_X86_REG_R9)
            self.trace.append(table)
            if self.early is not None and len(self.trace) - 1 == self.early:
                self.return_value(101 + self.early)

    def call(self, entry, args):
        self.put(stack, bytes(65536))
        rsp = stack + 32760
        self.put(rsp, struct.pack("<Q", stop))
        self.vm.reg_write(UC_X86_REG_RSP, rsp)
        for reg, value in zip(
            [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9], args
        ):
            self.vm.reg_write(reg, value)
        self.vm.emu_start(entry, stop, count=200000)
        return self.vm.reg_read(UC_X86_REG_RAX)

    def initialize(self, instance):
        return self.call(
            (
                self.symbols["DW_ScriptContextInitialize"]
                if self.edited
                else native["initializer"]
            ),
            [instance],
        )

    def register(self):
        # First two stock headers are runtime-populated; model valid native rows.
        for i, row in enumerate(proof["native_method_tables"][:2]):
            at = 0x190080000 + i * 4096
            self.put(at, struct.pack("<IIQII", 0x8000 + i, 0, 0x170000000 + i, 0, 0))
            self.put(
                (
                    mapped(base + row["original_rva"])
                    if self.edited
                    else base + row["original_rva"]
                ),
                struct.pack("<QQ", at, 1),
            )
        for off, count in [
            (3216, 1048),
            (3224, proof["bounds"]["extended_count"] if self.edited else 1927),
        ]:
            self.put(self.u64(ctx + off), bytes(count * 8))
        typeat = ctx + 154000
        self.put(typeat, b"\xff" * 4)
        return self.call(
            (
                self.symbols["DW_GScriptMPGetMethod"]
                if self.edited
                else native["dispatcher"]
            ),
            [0, 0, typeat],
        )


def run_checks():
    checks = []
    for instance in [0, 1]:
        for seed in range(50):
            original, edited = Harness(False, seed), Harness(True, seed)
            a = original.initialize(instance)
            b = edited.initialize(instance)
            before, after = bytearray(original.get(ctx, 153640)), bytearray(
                edited.get(ctx, 153640)
            )
            if instance == 0:
                assert (
                    struct.unpack_from("<I", after, 3204)[0]
                    == proof["bounds"]["extended_end"]
                    and struct.unpack_from("<I", after, 3208)[0]
                    == proof["bounds"]["extended_count"]
                )
                for off, size in [(3204, 4), (3208, 4), (3216, 8), (3224, 8)]:
                    after[off : off + size] = before[off : off + size]
                assert (
                    a == original.u64(ctx + 3224)
                    and b == edited.u64(ctx + 3224)
                    and edited.u64(ctx + 3216) == mapped(original.u64(ctx + 3216))
                )
            else:
                assert a == b == 0
            assert before == after
            checks.append(f"initializer-{instance}-{seed}")
    for seed in range(5):
        original, edited = Harness(False, seed), Harness(True, seed)
        original.initialize(0)
        edited.initialize(0)
        assert original.register() == edited.register() == 0
        assert [mapped(at) for at in original.trace] == edited.trace[:19] and len(
            edited.trace
        ) == 20
        assert original.get(original.u64(ctx + 3216), 1048 * 8) == edited.get(
            edited.u64(ctx + 3216), 1048 * 8
        )
        expected = struct.unpack(
            "<1927Q", original.get(original.u64(ctx + 3224), 1927 * 8)
        )
        actual = struct.unpack("<1927Q", edited.get(edited.u64(ctx + 3224), 1927 * 8))
        assert (
            tuple(
                mapped(at) if base <= at < base + pe.OPTIONAL_HEADER.SizeOfImage else at
                for at in expected
            )
            == actual
        )
        assert edited.u64(edited.u64(ctx + 3224) + 1927 * 8) == edited.callback
        assert edited.u64(edited.u64(ctx + 3224) + 1928 * 8) == edited.survival
        assert edited.u64(edited.u64(ctx + 3224) + 1929 * 8) == edited.mp_class
        assert edited.u64(edited.u64(ctx + 3224) + 1930 * 8) == edited.gas_state
        checks.append(f"registration-{seed}")
    for early in range(19):
        original, edited = Harness(False), Harness(True)
        original.initialize(0)
        edited.initialize(0)
        original.early = edited.early = early
        assert original.register() == edited.register() == 101 + early
        assert [mapped(at) for at in original.trace] == edited.trace and len(
            edited.trace
        ) == early + 1
        checks.append(f"early-return-{early}")
    # Execute actual fixed-arity method2 decode + object self conversion + indirect call.
    # Stop at the callback boundary; VM result/ref cleanup belongs to callback tests.
    for registry in proof["registry"]:
        for entity_num in [0, 33, 2047]:
            edited = Harness(True)
            edited.initialize(0)
            edited.register()
            frame, pub, value, objects, bytecode = (
                0x190100000,
                0x190101000,
                0x190102000,
                0x190103000,
                0x190104000,
            )
            for at in [frame, pub, value, objects, bytecode]:
                edited.put(at, bytes(4096))
            edited.put(ctx + 13480, struct.pack("<Q", objects))
            edited.put(objects + 7 * 12 + 4, struct.pack("<I", entity_num))
            edited.put(objects + 7 * 12 + 8, struct.pack("<I", 22))
            edited.put(value, struct.pack("<QB7x", 7, 1))
            edited.put(pub + 16, struct.pack("<Q", value))
            edited.put(frame + 24, struct.pack("<Q", frame + 256))
            edited.put(bytecode, struct.pack("<H", registry["id"]))
            captured = []

            def reached(vm, address, size, data):
                expected_callback = {**edited.roam_callbacks, "DW_BotStyleWeaponMethod": edited.callback,
                                     "DW_BotSurvivalAllowedMethod": edited.survival,
                                     "DW_BotMPClassReadyMethod": edited.mp_class,
                                     "DW_BotGasStateMethod": edited.gas_state}
                if address == expected_callback[registry["callback_symbol"]]:
                    captured.append(
                        (vm.reg_read(UC_X86_REG_RCX), vm.reg_read(UC_X86_REG_RDX))
                    )
                    vm.emu_stop()

            edited.vm.hook_add(UC_HOOK_CODE, reached)
            edited.put(stack, bytes(65536))
            edited.vm.reg_write(UC_X86_REG_RSP, stack + 32760)
            for reg, val in [
                (UC_X86_REG_RDX, registry["opcode"]),
                (UC_X86_REG_RSI, bytecode),
                (UC_X86_REG_RBX, bytecode),
                (UC_X86_REG_RDI, frame),
                (UC_X86_REG_R12, pub),
                (UC_X86_REG_R13, ctx),
                (UC_X86_REG_RBP, stack + 16384),
            ]:
                edited.vm.reg_write(reg, val)
            edited.vm.emu_start(
                mapped(base + proof["vm_method_handler_rva"]), stop, count=1000
            )
            assert (
                len(captured) == 1
                and captured[0][0] == ctx
                and (captured[0][1] & 0xFFFFFFFF) == entity_num
                and (captured[0][1] >> 32 & 255) == 0
            )
            assert (
                struct.unpack("<I", edited.get(frame + 48, 4))[0]
                == registry["argument_count"]
            )
            checks.append(f"VM-method{registry["argument_count"]}-self-{entity_num}")
    # Execute the native scalar result writer. IncInParam is the modeled VM
    # allocation boundary; the native helper writes the real type/value fields.
    for value in (0, 1):
        edited = Harness(True)
        edited.result_slot = ctx + 155000
        edited.put(edited.result_slot, b"\xff" * 16)
        edited.call(edited.aliases["SM_AddBool"], [ctx, value])
        assert struct.unpack("<i", edited.get(edited.result_slot, 4))[0] == value
        assert edited.get(edited.result_slot + 8, 1) == b"\x06"
        checks.append(f"native-bool-result-{value}")
    # Prove the native getter uses canonical name field zero rather than the
    # unrelated pointer at field24, including its exact alternate-mode behavior.
    for index in (1, 549):
        for alternate in (0, 1):
            edited = Harness(True)
            definition, weapon = ctx + 160000, ctx + 161000
            canonical, unrelated = ctx + 162000, ctx + 163000
            edited.put(definition, bytes(32))
            edited.put(definition, struct.pack("<Q", canonical))
            edited.put(definition + 24, struct.pack("<Q", unrelated))
            edited.put(
                edited.aliases["SM_WeaponCompleteDefinitions"] + index * 8,
                struct.pack("<Q", definition),
            )
            edited.put(weapon, struct.pack("<H", index) + bytes(58))
            assert (
                edited.call(edited.aliases["SM_GetWeaponBaseName"], [weapon, alternate])
                == canonical
            )
            checks.append(f"native-base-name-{index}-{alternate}")
    return dict(
        schema=1,
        passed=True,
        case_count=len(checks),
        checks=checks,
        source_sha256=proof["source_sha256"],
        method_id=proof["method_id"],
        argument_count=2,
        linked_image_sha256=report["sha256"] if report else None,
        exact_linked_image=bool(report),
        game_run_performed=False,
        modeled_boundaries=[
            "Server context return",
            "First two runtime initialized table headers",
            "Custom callback body; VM stops at callback entry",
            "IncInParam result-slot allocation; native scalar writer executed",
        ],
    )


def main():
    global proof, pe, base, aliases, native, report, linked, obj, callback, ranges, range_starts
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot_path", nargs="?", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    snapshot = args.snapshot or args.snapshot_path
    assert snapshot and not (args.snapshot and args.snapshot_path)
    proof = json.loads(
        (snapshot / "generated/bot-style-method-integration.json").read_bytes()
    )
    original = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    assert (
        hashlib.file_digest(original.open("rb"), "sha256").hexdigest()
        == proof["image_sha256"]
    )
    assert (
        hashlib.sha256((snapshot / proof["source"]).read_bytes()).hexdigest()
        == proof["source_sha256"]
    )
    assert (
        hashlib.sha256((snapshot / proof["header"]).read_bytes()).hexdigest()
        == proof["header_sha256"]
    )
    pe = pefile.PE(str(original), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    for row in proof["bodies"]:
        assert (
            hashlib.sha256(pe.get_data(row["original_rva"], row["bytes"])).hexdigest()
            == row["sha256"]
        )
    aliases = {r["name"]: base + r["original_rva"] for r in proof["bindings"]}
    native = {r["symbol"]: base + r["original_rva"] for r in proof["bodies"]}
    callback = stop + 32
    if args.build:
        report = json.loads((args.build / "build-report.json").read_bytes())
        path = Path(report["executable"])
        assert (
            hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
            == report["sha256"]
        )
        assert report["unresolved_symbols"] == 0
        linked = pefile.PE(str(path), fast_load=True)
        assert linked.OPTIONAL_HEADER.ImageBase == base
        ranges = report["rva_map"]["ranges"]
        range_starts = [r["begin"] for r in ranges]
    else:
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location(
            "script_method_coff", snapshot / "tools/coff.py"
        )
        coff = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(coff)
        with tempfile.TemporaryDirectory(
            prefix="script-method-test-", dir=ROOT / "data"
        ) as directory:
            object_path = Path(directory) / "DW_ScriptMethods.obj"
            subprocess.run(
                [
                    r"C:\Program Files\LLVM\bin\clang++.exe",
                    "--target=x86_64-pc-windows-msvc",
                    "-c",
                    str(snapshot / proof["source"]),
                    "-o",
                    str(object_path),
                    "-I" + str(snapshot / "src"),
                    "-O2",
                    "-std=c++20",
                    "-ffreestanding",
                    "-fno-exceptions",
                    "-fno-rtti",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                ],
                check=True,
            )
            obj = coff.read(object_path)
    result = run_checks()
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
