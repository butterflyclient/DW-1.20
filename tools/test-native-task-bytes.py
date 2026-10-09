"""Check raw task tracing against volatile, partial-register and branch cases."""

import importlib.util
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = Path(__file__).with_name("inventory-native-task-bytes.py")
spec = importlib.util.spec_from_file_location("native_task_bytes", path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
start, constructor, unknown = 0x100000, 0x200000, 0x300000
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True


def branch(prefix, target, opcode=b"\xe8"):
    return opcode + struct.pack("<i", target - (start + len(prefix) + 5))


def check(name, code, expected, regions=None, expected_unresolved=False):
    def decode(address):
        return next(decoder.disasm(code[address - start :], address, count=1), None)

    found, unresolved = audit.trace(
        start,
        start + len(code),
        decode,
        {constructor: {("arg:rdx", "arg:r8", constructor)}},
        regions=regions,
    )
    actual = {(row[2], row[3]) for row in found}
    assert actual == expected, (name, actual, expected)
    assert bool(unresolved) == expected_unresolved, (name, unresolved)


prefix = bytes.fromhex("b2 1d 41 b0 04")
check("byte constants", prefix + branch(prefix, constructor) + b"\xc3", {(29, 4)})
prefix = bytes.fromhex("b2 1d 41 b0 04")
prefix += branch(prefix, unknown)
check(
    "volatile invalidation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(None, None)},
)
prefix = bytes.fromhex("31 d2 b6 1d 41 b0 04")
check(
    "high byte is not low byte",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29 << 8, 4)},
)
prefix = bytes.fromhex("bb 1d 00 00 00")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("89 da 41 b0 04")
check(
    "nonvolatile preservation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, 4)},
)
prefix = bytes.fromhex("ba 1d 00 00 00 48 85 c9 74 05 41 b0 07 eb 04 41 b0 09 90")
check(
    "separate branch states",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, 7), (29, 9)},
)
prefix = bytes.fromhex("ba 1d 00 00 00 41 b0 09")
check(
    "external constructor tail",
    prefix + branch(prefix, constructor, b"\xe9"),
    {(29, 9)},
)
prefix = bytes.fromhex("8b 11 41 b0 04")
check("memory is unresolved", prefix + branch(prefix, constructor) + b"\xc3", {(None, 4)})
prefix = bytes.fromhex("89 d3")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("89 da 41 b0 04")
check(
    "argument origin forwarding",
    prefix + branch(prefix, constructor) + b"\xc3",
    {("arg:rdx", 4)},
)
prefix = bytes.fromhex("bb 18 00 00 00 8d 53 05 41 b0 04")
check(
    "known address arithmetic",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, 4)},
)
prefix = bytes.fromhex("41 b0 04 45 6b c0 02 ba 1d 00 00 00")
check(
    "unhandled register write",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("41 b8 07 00 00 00 b8 09 00 00 00 48 85 c9 44 0f 45 c0 ba 1d 00 00 00")
check(
    "conditional move alternatives",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, 7), (29, 9)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("44 8b 44 24 40 ba 1d 00 00 00")
check(
    "saved local across calls",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, 9)},
)
prefix = bytes.fromhex("c7 44 24 08 09 00 00 00")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("44 8b 44 24 08 ba 1d 00 00 00")
check(
    "shadow space invalidation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00 c6 44 24 41 ff 44 8b 44 24 40 ba 1d 00 00 00")
check(
    "overlapping local write",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00 83 44 24 40 01 44 8b 44 24 40 ba 1d 00 00 00")
check(
    "unhandled local write",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00 48 8d 4c 24 40")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("44 8b 44 24 40 ba 1d 00 00 00")
check(
    "escaped local invalidation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("48 83 ec 28 c7 44 24 40 09 00 00 00")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("44 8b 44 24 40 48 83 c4 28 ba 1d 00 00 00")
check("stack adjustment", prefix + branch(prefix, constructor) + b"\xc3", {(29, 9)})
prefix = bytes.fromhex("48 89 e5 c7 45 40 09 00 00 00")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("44 8b 45 40 ba 1d 00 00 00")
check("frame pointer local", prefix + branch(prefix, constructor) + b"\xc3", {(29, 9)})
prefix = bytes.fromhex("48 89 e5 c7 45 40 09 00 00 00 31 ed 44 8b 45 40 ba 1d 00 00 00")
check(
    "partial frame register invalidation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00 48 8d 64 24 e0 44 8b 44 24 60 ba 1d 00 00 00")
check("LEA stack adjustment", prefix + branch(prefix, constructor) + b"\xc3", {(29, 9)})
prefix = bytes.fromhex("48 89 e5 c7 45 40 09 00 00 00 5d 44 8b 45 40 ba 1d 00 00 00")
check(
    "popped frame pointer invalidation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00 5c 44 8b 44 24 38 ba 1d 00 00 00")
check(
    "popped stack pointer invalidation",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex("c7 44 24 40 09 00 00 00 48 89 e1")
prefix += branch(prefix, unknown)
prefix += bytes.fromhex("44 8b 44 24 40 ba 1d 00 00 00")
check(
    "MOV stack pointer escape",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
prefix = bytes.fromhex(
    "c7 44 24 40 09 00 00 00 48 8d 44 24 40 c7 00 07 00 00 00 44 8b 44 24 40 ba 1d 00 00 00"
)
check(
    "write through escaped local pointer",
    prefix + branch(prefix, constructor) + b"\xc3",
    {(29, None)},
)
# Noncontiguous chained chunks retain facts only across actual branch edges.
# The bytes between them may belong to another function and cannot be traced.
prefix = bytes.fromhex("ba 1d 00 00 00 41 b0 09")
first = prefix + branch(prefix, start + 64, b"\xe9")
second = branch(b"\x90" * 64, constructor) + b"\xc3"
code = first.ljust(64, b"\xcc") + second
regions = [(start, start + len(first)), (start + 64, start + len(code))]
check("forward chained branch", code, {(29, 9)}, regions)

# A branch back into the first chunk still retains the task constants.
first = b"\xe9" + struct.pack("<i", 64 - 5)
return_site = len(first)
first += branch(first, constructor) + b"\xc3"
second = prefix + b"\xe9" + struct.pack("<i", return_site - (64 + len(prefix) + 5))
code = first.ljust(64, b"\xcc") + second
check(
    "backward chained branch",
    code,
    {(29, 9)},
    [(start, start + len(first)), (start + 64, start + len(code))],
)

# A constructor in an unrelated gap is not a call by the owning function.
first = prefix + branch(prefix, start + 32, b"\xe9")
gap = branch(b"\x90" * 32, constructor) + b"\xc3"
code = first.ljust(32, b"\xcc") + gap
code = code.ljust(64, b"\xcc") + b"\xc3"
check(
    "unowned gap branch rejected",
    code,
    set(),
    [(start, start + len(first)), (start + 64, start + len(code))],
    True,
)

# Even physically adjacent bytes cannot become an implicit cross-owner path.
first = prefix
code = first + branch(first, constructor) + b"\xc3"
check("fallthrough outside owned chunk excluded", code, set(), [(start, start + len(first))])
print("PASS: 28 independent x64 task-trace cases")
