"""Execute compiled AB routing with original native URI and service-name helpers.

Explicit boundaries are DW enablement, JSON Accept, CRT formatting/search and
the native security-cookie check. This proves writer behavior, not transport,
response callbacks or live enrollment. Objects and linked images are supported.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RCX, X86_REG_R13
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--object", type=Path)
    parser.add_argument("--linked-image", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert bool(args.object) != bool(args.linked_image)
    snapshot = args.snapshot.resolve()
    assert snapshot.is_relative_to(ROOT) and args.output.resolve().is_relative_to(ROOT)
    bindings_path = snapshot / "generated/ab-rest-integration.json"
    bindings = json.loads(bindings_path.read_bytes())
    original = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
    assert hashlib.sha256(original).hexdigest() == bindings["original_image_sha256"]
    native = pefile.PE(data=original, fast_load=True)
    base = native.OPTIONAL_HEADER.ImageBase
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    native_symbols = {row["symbol"]: base + row["original_rva"] for row in bindings["bindings"]}
    writer = base + bindings["original_writer"]["rva"]
    sections, compiled_symbols = [], {}
    mapped = lambda rva: rva
    if args.object:
        spec = importlib.util.spec_from_file_location("ab_checked_coff", snapshot / "tools/coff.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        obj = module.read(args.object)
        area = base + 0x40000000
        addresses = {row["number"]: area + row["number"] * 0x10000 for row in obj["sections"]}
        external = {**native_symbols, "DW_LocalBackend_IsEnabled": area + 0xF00000}
        for row in obj["symbols"].values():
            if row["section"] > 0:
                compiled_symbols[row["name"]] = addresses[row["section"]] + row["value"]
        for section in obj["sections"]:
            content = bytearray(section["data"])
            for offset, symbol_index, kind in section["relocations"]:
                symbol = obj["symbols"][symbol_index]
                target = (addresses[symbol["section"]] + symbol["value"] if symbol["section"] > 0
                          else external[symbol["name"]])
                site = addresses[section["number"]] + offset
                if 4 <= kind <= 9:
                    value = target - (site + 4 + kind - 4) + struct.unpack_from("<i", content, offset)[0]
                    struct.pack_into("<i", content, offset, value)
                elif kind == 1:
                    value = target + struct.unpack_from("<Q", content, offset)[0]
                    struct.pack_into("<Q", content, offset, value)
                elif kind == 3:
                    # .pdata has image-relative section references and is not
                    # executed in this focused COFF VM. Linked unwind is tested
                    # by the normal private compiler's separate verifiers.
                    continue
                else:
                    raise AssertionError((section["name"], kind))
            sections.append((addresses[section["number"]], bytes(content)))
        enabled = external["DW_LocalBackend_IsEnabled"]
        compiled = compiled_symbols["bdABTestingEnrollRequest_RestSerializeRequest"]
        image = native
        symbols = native_symbols
    else:
        report = json.loads(args.report.read_bytes())
        assert hashlib.sha256(args.linked_image.read_bytes()).hexdigest() == report["sha256"]
        image = pefile.PE(str(args.linked_image), fast_load=True)
        sys.path.insert(0, str(snapshot / "tools"))
        layout_spec = importlib.util.spec_from_file_location("ab_linked_layout", snapshot / "tools/layout.py")
        layout_module = importlib.util.module_from_spec(layout_spec)
        layout_spec.loader.exec_module(layout_module)
        mapped = lambda rva: layout_module.from_report(rva, report)
        symbols = {name: image.OPTIONAL_HEADER.ImageBase + report["symbols"][name] for name in native_symbols}
        enabled = image.OPTIONAL_HEADER.ImageBase + report["symbols"]["DW_LocalBackend_IsEnabled"]
        compiled = image.OPTIONAL_HEADER.ImageBase + report["symbols"]["bdABTestingEnrollRequest_RestSerializeRequest"]
    # Derive the simple getters and URI-validity slot from original instructions.
    def member(name, mnemonic):
        address = native_symbols[name]
        decoded = list(decoder.disasm(native.get_data(address - base, 16), address))
        first = decoded[0]
        assert first.mnemonic == mnemonic and decoded[1].mnemonic == "ret"
        operand = first.operands[1]
        assert operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RCX and not operand.mem.index
        return operand.mem.disp

    lobby_slot = member("DW_AB_BuilderLobby", "mov")
    auth_slot = member("DW_AB_BuilderAuth", "lea")
    uri_slot = member("DW_AB_BuilderURI", "lea")
    valid_slot = member("DW_AB_URIIsOK", "movzx")
    number_address = native_symbols["DW_AB_AppendNumber"]
    number_code = list(decoder.disasm(native.get_data(number_address - base, 120), number_address))
    formatter = next(row.operands[0].imm for row in number_code if row.mnemonic == "call")
    formatter = image.OPTIONAL_HEADER.ImageBase + mapped(formatter - base)
    memchr = image.OPTIONAL_HEADER.ImageBase + mapped(0x21F7C70)
    cookie = image.OPTIONAL_HEADER.ImageBase + mapped(0x21CCF60)
    setter_code = list(decoder.disasm(native.get_data(native_symbols["DW_AB_SetService"] - base, 220), native_symbols["DW_AB_SetService"]))
    service_offsets = [row.operands[1].imm for row in setter_code if row.mnemonic == "add" and row.op_str.startswith("rbp,")]
    assert len(service_offsets) == 1
    service_slot = service_offsets[0]
    resource_address = native_symbols["DW_AB_SetResource"]
    resource_code = list(decoder.disasm(native.get_data(resource_address - base, 288), resource_address))
    resource_slots = [row.operands[1].mem.disp for row in resource_code if
                      row.mnemonic == "lea" and row.operands[1].type == X86_OP_MEM and
                      row.operands[1].mem.base == X86_REG_R13]
    assert len(resource_slots) == 2
    layouts = bindings["derived_layout"]
    results = []

    # Execute the original request validator against fields produced by the
    # replacement. POST/MIME enum utilities and the empty native header map
    # are explicit boundaries; the service/URI/resource checks are real code.
    native.parse_data_directories(directories=[3])
    validator_rva = 0x2169540
    validator_entry = next(row for row in native.DIRECTORY_ENTRY_EXCEPTION
                           if row.struct.BeginAddress == validator_rva)
    validator_bytes = native.get_data(validator_rva, validator_entry.struct.EndAddress - validator_rva)
    validator_address = base + validator_rva
    validator_calls = {row.address: row for row in decoder.disasm(validator_bytes, validator_address)
                       if row.mnemonic == "call"}
    assert {row.operands[0].imm for row in validator_calls.values()} == {
        base + 0x21F7C70, base + 0x21529B0, base + 0x2152A50, base + 0x2152C90}

    def preflight(value):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        vm.mem_map(validator_address & ~4095, 8192)
        vm.mem_write(validator_address, validator_bytes)
        heap, stack, stop = 0x1000000, 0x2000000, 0x3000000
        for address in (heap, stack, stop):
            vm.mem_map(address, 0x4000)
        params = heap + 0x1000
        vm.mem_write(heap, struct.pack("<QIIQQ", params, 1, layouts["method"], heap + 0x2000, heap + 0x2100))
        vm.mem_write(heap + 32, struct.pack("<I", layouts["mime"]))
        vm.mem_write(heap + 44, struct.pack("<I", layouts["mime"]))
        vm.mem_write(heap + 56, struct.pack("<Q", heap + 0x3000))
        for pointer, text_value in ((heap + 0x2000, value["service"]), (heap + 0x2100, value["uri"]),
                                    (params + 268, value["resource"]), (params + 332, value["operation"])):
            vm.mem_write(pointer, text_value.encode() + b"\0")
        rsp = stack + 0x3F08
        vm.mem_write(rsp, struct.pack("<Q", stop))
        vm.reg_write(UC_X86_REG_RSP, rsp)
        vm.reg_write(UC_X86_REG_RCX, heap)

        def boundary(machine, pc, size, _):
            if pc == stop:
                machine.emu_stop()
            elif pc in validator_calls:
                target = validator_calls[pc].operands[0].imm
                result = 1
                if target == base + 0x21F7C70:
                    pointer = machine.reg_read(UC_X86_REG_RCX)
                    data = bytes(machine.mem_read(pointer, machine.reg_read(UC_X86_REG_R8)))
                    index = data.find(bytes([machine.reg_read(UC_X86_REG_RDX) & 255]))
                    result = 0 if index < 0 else pointer + index
                elif target == base + 0x2152C90:
                    result = 0
                machine.reg_write(UC_X86_REG_RAX, result)
                machine.reg_write(UC_X86_REG_RIP, pc + size)

        vm.hook_add(UC_HOOK_CODE, boundary)
        vm.emu_start(validator_address, stop + 1, count=1000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        return vm.reg_read(UC_X86_REG_RAX) & 255

    def case(entry, local, account, user, accept=True, valid=True):
        machine = Uc(UC_ARCH_X86, UC_MODE_64)
        pages = set()
        heap, stack, stop = 0x60000000, 0x70000000, 0x71000000
        machine.mem_map(heap, 0x60000)
        machine.mem_map(stack, 0x10000)
        machine.mem_map(stop, 4096)
        if args.object:
            machine.mem_map(enabled & ~4095, 4096)
            machine.mem_write(enabled, b"\xC3")
            pages.add(enabled & ~4095)
        for address, data in sections:
            size = max(4096, (len(data) + 4095) & ~4095)
            machine.mem_map(address, size)
            if data:
                machine.mem_write(address, data)
            pages.update(range(address, address + size, 4096))
        builder, lobby = heap, heap + 0x10000
        auth, uri = lobby + auth_slot, builder + uri_slot
        machine.mem_write(builder + lobby_slot, struct.pack("<Q", lobby))
        machine.mem_write(auth + layouts["account_type"], account.encode() + b"\0")
        machine.mem_write(auth + layouts["user_id"], struct.pack("<Q", user))
        machine.mem_write(uri + valid_slot, bytes([valid]))
        rsp = stack + 0xF008
        machine.mem_write(rsp, struct.pack("<Q", stop))
        machine.reg_write(UC_X86_REG_RSP, rsp)
        machine.reg_write(UC_X86_REG_RCX, heap + 0x20000)
        machine.reg_write(UC_X86_REG_RDX, builder)
        observed = []

        def text(address, limit=5000):
            data = bytearray()
            for index in range(limit):
                try:
                    byte = bytes(machine.mem_read(address + index, 1))
                except UcError:
                    missing(machine, 0, address + index, 1, 0, None)
                    byte = bytes(machine.mem_read(address + index, 1))
                if byte == b"\0":
                    return data.decode()
                data += byte
            raise AssertionError("Unterminated native string")

        def returned(value):
            current = machine.reg_read(UC_X86_REG_RSP)
            target = struct.unpack("<Q", machine.mem_read(current, 8))[0]
            machine.reg_write(UC_X86_REG_RAX, value)
            machine.reg_write(UC_X86_REG_RSP, current + 8)
            machine.reg_write(UC_X86_REG_RIP, target)

        def missing(vm, access, address, size, value, _):
            for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
                if page in pages:
                    continue
                assert image.OPTIONAL_HEADER.ImageBase <= page < image.OPTIONAL_HEADER.ImageBase + image.OPTIONAL_HEADER.SizeOfImage
                machine.mem_map(page, 4096)
                data = image.get_data(page - image.OPTIONAL_HEADER.ImageBase, 4096)
                if data:
                    machine.mem_write(page, data)
                pages.add(page)
            return True

        def hook(vm, address, size, _):
            rcx, rdx, r8, r9 = [machine.reg_read(reg) for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
            if address == stop:
                machine.emu_stop()
            elif address == enabled:
                returned(int(local))
            elif address == symbols["DW_AB_SetAccept"]:
                assert rdx == layouts["mime"]
                observed.append("JSON Accept")
                returned(int(accept))
            elif address == formatter:
                format_string = text(r8)
                if format_string == "%I64u":
                    assert rdx == 64
                    value = str(r9).encode()
                elif format_string == "%%%02X":
                    value = ("%%%02X" % (r9 & 255)).encode()
                else:
                    raise AssertionError((format_string, rdx, r9))
                assert len(value) < rdx
                machine.mem_write(rcx, value + b"\0")
                observed.append("CRT uint64 formatting")
                returned(len(value))
            elif address == memchr:
                try:
                    data = bytes(machine.mem_read(rcx, r8))
                except UcError:
                    missing(machine, 0, rcx, r8, 0, None)
                    data = bytes(machine.mem_read(rcx, r8))
                index = data.find(bytes([rdx & 255]))
                returned(0 if index < 0 else rcx + index)
            elif address == cookie:
                returned(machine.reg_read(UC_X86_REG_RAX))

        machine.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        machine.hook_add(UC_HOOK_CODE, hook)
        machine.emu_start(entry, stop, count=1000000)
        assert machine.reg_read(UC_X86_REG_RIP) == stop
        value = dict(result=machine.reg_read(UC_X86_REG_RAX) & 255,
                     uri=text(uri + layouts["path_byte"]), service=text(builder + service_slot),
                     resource=text(builder + resource_slots[0]), operation=text(builder + resource_slots[1]),
                     boundaries=observed)
        return value

    for account, user in (("uno", 123), ("bnet", 0), ("bnet", (1 << 64) - 1), ("a/b", 9876)):
        baseline = case(writer, False, account, user) if args.object else None
        off = case(compiled, False, account, user)
        on = case(compiled, True, account, user)
        assert off["result"] == on["result"] == 1 and off["service"] == "" and on["service"] == "abtesting"
        assert off["uri"] == on["uri"]
        assert off["resource"] == on["resource"] == "abtesting"
        assert off["operation"] == on["operation"] == "enroll"
        off["native_preflight"] = preflight(off)
        on["native_preflight"] = preflight(on)
        assert off["native_preflight"] == 0 and on["native_preflight"] == 1
        if baseline:
            baseline["native_preflight"] = preflight(baseline)
            assert baseline == off
        for label, value in (("original", baseline), ("disabled", off), ("enabled", on)):
            if value:
                results.append(dict(case=label, account_type=account, user_id=user, **value))
    for accept, valid in ((False, True), (True, False)):
        value = case(compiled, True, "uno", 123, accept, valid)
        assert value["result"] == 0 and value["service"] == ""
        results.append(dict(case="native error propagation", accept=accept, uri_valid=valid, **value))
    args.output.write_text(json.dumps(dict(passed=True, cases=results,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        compiled_input_sha256=hashlib.sha256((args.object or args.linked_image).read_bytes()).hexdigest(),
        binding_receipt_sha256=hashlib.sha256(bindings_path.read_bytes()).hexdigest(),
        native_helpers_executed=True, headers_and_crt_boundaries_modeled=True,
        original_request_validator_executed=True,
        original_validator_sha256=hashlib.sha256(validator_bytes).hexdigest(),
        transport_and_native_completion_verified=False), indent=2) + "\n")
    print("PASS:", len(results), "original/compiled AB REST writer cases")


if __name__ == "__main__":
    main()
