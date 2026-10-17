"""Historical button-codec and current NCS count instructions without a build.

Codec round-trips prove serialization only. The candidate bit44 is occupied by
the shipped game and must not carry inspection; inspection uses a reliable
dw_inspect command and normal scripted-animation snapshot replication.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_RBP,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
RESEARCH = ROOT / "data/research/weapon-inspect-20261017"
MASK = (1 << 64) - 1
INSPECT = 1 << 44
FUNCTIONS = {
    0x12D6BE0: 153,
    0x12D6C80: 141,
    0x10F11B0: 559,
    0x12B8480: 21,
    0x10F0DA0: 18,
    0x10EFDA8: 28,
}


class Native:
    def __init__(self, pe):
        self.pe = pe
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.vm = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pages = set()
        self.arena = 0x200000000
        self.vm.mem_map(self.arena, 0x200000)
        self.stop = self.arena + 0x1FFFF0
        self.vm.mem_write(self.stop, b"\xc3")
        self.callbacks = {}
        self.vm.hook_add(UC_HOOK_MEM_UNMAPPED, self.missing)
        self.vm.hook_add(UC_HOOK_CODE, self.step)

    def page(self, address):
        page = address & ~4095
        if self.arena <= page < self.arena + 0x200000 or page in self.pages:
            return
        assert self.base <= page < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage, hex(
            address
        )
        self.vm.mem_map(page, 4096)
        body = self.pe.get_data(page - self.base, 4096)
        if body:
            self.vm.mem_write(page, body)
        self.pages.add(page)

    def put(self, address, data):
        for page in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
            self.page(page)
        self.vm.mem_write(address, data)

    def missing(self, vm, access, address, size, value, context):
        self.page(address)
        self.page(address + size - 1)
        return True

    def step(self, vm, address, size, context):
        if address == self.stop:
            vm.emu_stop()
        elif address in self.callbacks:
            result = self.callbacks[address]()
            vm.reg_write(UC_X86_REG_RAX, result & MASK)
            stack = vm.reg_read(UC_X86_REG_RSP)
            vm.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", vm.mem_read(stack, 8))[0])
            vm.reg_write(UC_X86_REG_RSP, stack + 8)
        else:
            assert any(
                self.base + rva <= address < self.base + rva + count
                for rva, count in FUNCTIONS.items()
            ), hex(address)

    def call(self, rva, *args):
        stack = self.arena + 0x1E0008
        self.put(stack, struct.pack("<Q", self.stop) + bytes(64))
        self.vm.reg_write(UC_X86_REG_RSP, stack)
        for register, value in zip(
            (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), args
        ):
            self.vm.reg_write(register, value)
        self.vm.emu_start(self.base + rva, self.stop + 1, count=4000000)
        assert (
            self.vm.reg_read(UC_X86_REG_RIP) == self.stop
        ), "Native function exceeded instruction bound"
        return self.vm.reg_read(UC_X86_REG_RAX)


def codec(pe, old, new, key):
    native = Native(pe)
    vm, arena, base = native.vm, native.arena, native.base
    msg, key_at, old_at, new_at, decoded_at = (
        arena + index * 256 for index in range(1, 6)
    )
    native.put(key_at, struct.pack("<Q", key))
    native.put(old_at, struct.pack("<Q", old))
    native.put(new_at, struct.pack("<Q", new))
    native.put(decoded_at, bytes([0xCC]) * 8)
    bits = []
    consumed = 0

    def write_bits():
        assert vm.reg_read(UC_X86_REG_RCX) == msg
        value, count = vm.reg_read(UC_X86_REG_RDX), vm.reg_read(UC_X86_REG_R8)
        assert count in (1, 63)
        bits.extend((value >> index) & 1 for index in range(count))
        return 0

    def read_bits(single=False):
        nonlocal consumed
        assert vm.reg_read(UC_X86_REG_RCX) == msg
        count = 1 if single else vm.reg_read(UC_X86_REG_RDX)
        assert count in (1, 63) and consumed + count <= len(bits)
        result = sum(bits[consumed + index] << index for index in range(count))
        consumed += count
        return result

    native.callbacks.update(
        {
            base + 0x12BA1D0: write_bits,
            base + 0x12BA180: lambda: (bits.append(1) or 0),
            base + 0x12BA130: lambda: (bits.append(0) or 0),
            base + 0x12B8BC0: read_bits,
            base + 0x12B8B50: lambda: read_bits(True),
        }
    )
    written = native.call(0x12D6BE0, msg, key_at, old_at, new_at) & 255
    read = native.call(0x12D6C80, msg, key_at, old_at, decoded_at) & 255
    decoded = struct.unpack("<Q", vm.mem_read(decoded_at, 8))[0]
    changed = int(old >> 1 != new >> 1)
    expected = [(new ^ key) & 1, changed]
    if changed:
        signed_key = struct.unpack("<i", struct.pack("<I", key & 0xFFFFFFFF))[0] & MASK
        obfuscator = (signed_key | (signed_key << 32)) & ((1 << 63) - 1)
        encoded = (new >> 1) ^ obfuscator
        expected += [(encoded >> index) & 1 for index in range(63)]
    assert bits == expected and decoded == new and consumed == len(bits)
    assert written == read == changed and len(bits) == (65 if changed else 2)
    return dict(
        old=hex(old),
        new=hex(new),
        key=hex(key),
        bits=len(bits),
        changed=bool(changed),
        decoded=hex(decoded),
    )


def ncs_case(pe, additions, restrictions):
    native = Native(pe)
    vm, base, arena = native.vm, native.base, native.arena
    # Only duplicate removal, hash-table insertion and diagnostic output are
    # modeled. Original count accumulation, static-cap comparison, CRC loop,
    # GetMinBitCountForNum and GetBitsNeededForType instructions execute.
    native.callbacks.update(
        {
            base + rva: (lambda: 0)
            for rva in (0x10F13E0, 0x10F07A0, 0x12B0820, 0x12B0570)
        }
    )
    native.put(base + 0xC6E0D2C, bytes([restrictions]))
    receipts = []
    total = 0
    for table_index, count in enumerate((11, 56, additions)):
        if not count:
            continue
        root = arena + 0x1000 + table_index * 64
        pointers = arena + 0x2000 + table_index * 0x4000
        strings = arena + 0x10000 + table_index * 0x10000
        encoded = bytearray()
        addresses = []
        for index in range(count):
            addresses.append(strings + len(encoded))
            encoded += f"table{table_index}_clip{index}".encode() + b"\0"
        native.put(strings, bytes(encoded))
        native.put(pointers, struct.pack("<" + "Q" * count, *addresses))
        native.put(root, struct.pack("<QIIIIQ", strings, 16, 1, 0, count, pointers))
        assert native.call(0x10F11B0, root) & 255 == 1
        total += count
        map_count = struct.unpack(
            "<I", vm.mem_read(base + 0xC6E0950 + 16 * 24 + 16, 4)
        )[0]
        bits = native.call(0x10F0DA0, 16)
        assert map_count == total and bits == total.bit_length()
        receipts.append(dict(table_entries=count, accumulated=total, dynamic_bits=bits))
    # BuildStringMap's original final loop clamps each dynamic width up to its
    # target default width. Run that exact loop for all 41 map records.
    vm.reg_write(UC_X86_REG_RDX, base + 0xC6E0964)
    vm.reg_write(UC_X86_REG_R8, base + 0x2436280)
    vm.reg_write(UC_X86_REG_RBP, 41)
    native.put(arena + 0x1E0008, struct.pack("<Q", native.stop))
    vm.reg_write(UC_X86_REG_RSP, arena + 0x1E0008)
    vm.emu_start(base + 0x10EFDA8, base + 0x10EFDC4, count=1000)
    final_bits = native.call(0x10F0DA0, 16)
    assert final_bits == max(16, total.bit_length())
    return dict(
        map_entries=additions,
        restrictions_enabled=bool(restrictions),
        tables=receipts,
        final_bits=final_bits,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with IMAGE.open("rb") as stream:
        image_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    assert image_sha == IMAGE_SHA
    pe = pefile.PE(str(IMAGE), fast_load=True)
    descriptor = struct.unpack("<QIIQQQQ", pe.get_data(0x2498FE0, 48))
    assert descriptor[1:5] == (
        8,
        0,
        pe.OPTIONAL_HEADER.ImageBase + 0x12D6C80,
        pe.OPTIONAL_HEADER.ImageBase + 0x12D6BE0,
    )
    cases = [
        (0, INSPECT),
        (INSPECT, 0),
        (INSPECT, INSPECT),
        (0, 0),
        (0, 1),
        (1, 0),
        (MASK ^ INSPECT, MASK),
        (MASK, MASK ^ INSPECT),
        (0, 1 << 63),
        (1 << 63, INSPECT),
        (0xAAAAAAAAAAAAAAAA, 0x5555555555555555),
    ]
    wire = [
        codec(pe, old, new, key)
        for key in (
            0,
            1,
            0x7FFFFFFF,
            0x80000000,
            0xFFFFFFFF,
            0x13579BDF,
            0xDEADBEEF13579BDF,
        )
        for old, new in cases
    ]
    static_cap = struct.unpack("<I", pe.get_data(0x24361D0 + 16 * 4, 4))[0]
    default_bits = struct.unpack("<I", pe.get_data(0x2436280 + 16 * 4, 4))[0]
    support = pe.get_data(0x2436328 + 16, 1)[0]
    assert static_cap == 0 and default_bits == 16 and support == 1
    metadata = pe.get_data(0x4598378, 41 * 24)
    name, asset_type, reserved, ncs_name = struct.unpack_from(
        "<QIIQ", metadata, 16 * 24
    )
    assert (
        pe.get_string_at_rva(name - pe.OPTIONAL_HEADER.ImageBase) == b"anm"
        and asset_type == 7
    )
    recipe = RESEARCH / "prepared-native-assets-final/manifest.json"
    manifest = json.loads(recipe.read_bytes())
    assert len({item["animation"] for item in manifest["packages"]}) == 56
    decoded = Path(manifest["replay"]["path"])
    with decoded.open("rb") as stream:
        assert (
            hashlib.file_digest(stream, "sha256").hexdigest()
            == manifest["replay"]["sha256"]
        )
        stream.seek(0x4E414)
        root = struct.unpack("<QIIIIQ", stream.read(32))
    assert root[1:5] == (16, 1, 0, 11)
    ncs = [
        ncs_case(pe, addition, restricted)
        for restricted in (0, 1)
        for addition in (0, 1, 128, 1024)
    ]
    report = dict(
        passed=True,
        image=str(IMAGE),
        image_sha256=image_sha,
        original_instruction_sha256={
            hex(rva): hashlib.sha256(pe.get_data(rva, count)).hexdigest()
            for rva, count in FUNCTIONS.items()
        },
        descriptor_rva="0x2498fe0",
        descriptor_bytes=8,
        descriptor_offset=0,
        historical_candidate_button_bit=44,
        candidate_bit_available=False,
        inspection_transport="native reliable dw_inspect command; normal scripted-state snapshots",
        codec_scope="Historical serialization evidence only; no button allocation or inspection delivery assurance",
        wire_cases=wire,
        wire_case_count=len(wire),
        modeled_wire_boundaries=[
            "MSG_WriteBits",
            "MSG_WriteBit0",
            "MSG_WriteBit1",
            "MSG_ReadBits",
            "MSG_ReadBit",
        ],
        ncs=dict(
            type=16,
            name="anm",
            native_metadata_rva="0x4598378",
            native_metadata_sha256=hashlib.sha256(metadata).hexdigest(),
            static_cap=static_cap,
            default_bits=default_bits,
            supported_in_restricted_mode=bool(support),
            stock_common_mp_entries=11,
            new_inspect_entries=56,
            actual_map_inventories_tested=False,
            recipe=str(recipe),
            recipe_sha256=hashlib.sha256(recipe.read_bytes()).hexdigest(),
            cases=ncs,
            scope="Original count/bit/static-cap instructions with duplicate removal/hash lookup/logging boundaries modeled; per-map and total loaded NCS inventory still needs owner-build validation",
        ),
        compiled_cpp=False,
        generated_fastfiles=False,
        game_modified=False,
        game_launched=False,
        live_network_tested=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "PASS",
        len(wire),
        "original button codec round-trips and",
        len(ncs),
        "original NCS count/width cases",
    )


if __name__ == "__main__":
    main()
