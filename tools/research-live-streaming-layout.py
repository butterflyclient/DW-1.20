"""Check Replay's extended streaming result consumer against the IW8 PDB oracle.

Only unchanged original instructions are executed. No deserializer, response
field order or positive native task completion is inferred from object offsets.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
)

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
oracle_path = ROOT / "data/oracle-bdLiveStreamingFileMetaData-20261008.json"
oracle = json.loads(oracle_path.read_bytes())
assert oracle["guid"] == "{910A7F7F-2DB0-4028-966A-F6BF38DD3ACC}" and oracle["age"] == 1
layout = next(
    item for item in oracle["types"] if item["name"] == "bdLiveStreamingFileMetaData"
)
assert layout["size"] == 28992 and layout["partial"]
fields = {item["name"]: item for item in layout["fields"]}
assert fields["m_urls"]["offset"] == 18700 and fields["m_urls"]["size"] == 10 * 1025
assert fields["m_numUrls"]["offset"] == 28952
assert fields["m_partOffset"]["offset"] == 28968
raw = image.read_bytes()
image_hash = hashlib.sha256(raw).hexdigest()
assert image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
pe.parse_data_directories(
    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True


def original_function(address):
    entries = {item.struct.BeginAddress: item for item in pe.DIRECTORY_ENTRY_EXCEPTION}

    def primary(item):
        visited = set()
        while item.unwindinfo and item.unwindinfo.UNW_FLAG_CHAININFO:
            start = item.struct.BeginAddress
            assert start not in visited, "Cyclic original unwind chain"
            visited.add(start)
            item = entries[item.unwindinfo.FunctionEntry]
        return item.struct.BeginAddress

    assert address - base in entries
    root = primary(entries[address - base])
    assert root == address - base, "Use the original primary function entry"
    chunks = sorted(
        (item.struct.BeginAddress, item.struct.EndAddress)
        for item in entries.values()
        if primary(item) == root
    )
    assert len(chunks) <= 64
    assert all(
        0 <= second[0] - first[1] <= 15 for first, second in zip(chunks, chunks[1:])
    )
    code = pe.get_data(address - base, chunks[-1][1] - root)
    decoded = list(decoder.disasm(code, address))
    assert decoded[-1].address + decoded[-1].size == address + len(code)
    return code, decoded


entry = 0x142130F70
code, instructions = original_function(entry)
anchors = []
for address in (entry, 0x142131550, 0x142132C10):
    body, decoded = original_function(address)
    accesses = [
        dict(
            address=hex(ins.address),
            mnemonic=ins.mnemonic,
            operands=ins.op_str,
            size=op.size,
            displacement=op.mem.disp,
        )
        for ins in decoded
        for op in ins.operands
        if op.type == CS_OP_MEM and op.mem.disp in (18700, 28952, 28968)
    ]
    anchors.append(
        dict(
            function_va=hex(address),
            function_size=len(body),
            bytes_sha256=hashlib.sha256(body).hexdigest(),
            accesses=accesses,
        )
    )
assert any(row["displacement"] == 28952 for row in anchors[0]["accesses"])
assert any(row["displacement"] == 28968 for row in anchors[2]["accesses"])

cases = []
for part in (0, 1, 9):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    start = entry & ~4095
    length = ((entry + len(code) + 4095) & ~4095) - start
    vm.mem_map(start, length)
    vm.mem_write(start, pe.get_data(start - base, length))
    stack, objects, halt = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x10000)
    vm.mem_map(objects, 0x30000)
    vm.mem_map(halt, 4096)
    stream, result, outputs = objects, objects + 0x18000, objects + 0x28000
    put = lambda address, fmt, *values: vm.mem_write(address, struct.pack(fmt, *values))
    put(stream + 0xFD30, "<Q", result)
    put(stream + 0xFD4E, "<B", 1)  # Native download discriminator.
    put(stream + 0x14AB8, "<H", part)
    put(stream + 0x14AEC, "<I", 102)  # Native extended live download mode.
    put(result + fields["m_fileID"]["offset"], "<Q", 0x123456789ABCDEF0)
    put(result + fields["m_fileSize"]["offset"], "<I", 123456)
    put(result + fields["m_numUrls"]["offset"], "<I", 10)
    for slot in range(10):
        vm.mem_write(
            result + 18700 + slot * 1025,
            f"http://fixture.invalid/part-{slot}\0".encode(),
        )
    put(stack + 0xF008, "<Q", halt)
    for register, value in (
        (UC_X86_REG_RCX, stream),
        (UC_X86_REG_RDX, outputs),
        (UC_X86_REG_R8, outputs + 8),
        (UC_X86_REG_R9, outputs + 16),
        (UC_X86_REG_RSP, stack + 0xF008),
    ):
        vm.reg_write(register, value)
    visited = []

    def step(machine, address, size, context):
        if address == halt:
            machine.emu_stop()
            return
        assert (
            entry <= address < entry + len(code)
        ), f"Unexpected original call {address:#x}"
        visited.append(address)

    vm.hook_add(UC_HOOK_CODE, step)
    vm.emu_start(entry, halt, count=1000)
    url, file_id = struct.unpack("<QQ", vm.mem_read(outputs, 16))
    size = struct.unpack("<I", vm.mem_read(outputs + 16, 4))[0]
    count = struct.unpack("<I", vm.mem_read(stream + 84668, 4))[0]
    assert url == result + 18700 + part * 1025
    assert file_id == 0x123456789ABCDEF0 and size == 123456 and count == 10
    expected_url = f"http://fixture.invalid/part-{part}\0".encode()
    assert vm.mem_read(url, len(expected_url)) == expected_url
    cases.append(
        dict(
            part_index=part,
            url_displacement=url - result,
            file_id=file_id,
            file_size=size,
            url_count=count,
            executed_instructions=len(visited),
            external_calls=0,
            passed=True,
        )
    )

proof = dict(
    schema=1,
    passed=True,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    original_image_sha256=image_hash,
    tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    oracle=dict(
        path=oracle_path.relative_to(ROOT).as_posix(),
        sha256=hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
        guid=oracle["guid"],
        age=oracle["age"],
        full_layout=layout,
        provenance="Xbox IW8 PDB type oracle; only listed original Replay consumer accesses are corroborated",
    ),
    original_consumer_accesses=anchors,
    unchanged_original_vm_cases=cases,
    target_consumer_layout_corroborated=True,
    response_wire_order_verified=False,
    extended_metadata_deserializer_verified=False,
    native_task_completion_verified=False,
    interpretation="Replay mode 102 selects a URL from an extended result using 1025-byte stride at +18700 and retains its file ID, size and URL count. Pump consumes the signed part offset at +28968. Ordinary bdFileMetaData serialization cannot establish this response contract.",
)
output = ROOT / "validation/20261008-live-streaming-target-layout.json"
output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
print(
    "PASS: three original live-download URL consumer cases; extended response wire reader remains open"
)
