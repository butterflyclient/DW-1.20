"""Compile channel services and execute original Replay whisper consumers.

Byte-buffer reads, blocklist/online getters, chat allocation and final history
insertion are modeled boundaries. The native push dispatcher, global callback,
application-header routing and whisper receiver execute their original bytes.
No game, backend service, account or chat state is changed.
"""

import argparse, hashlib, json, struct, subprocess, tempfile
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import *

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
BODIES = {
    "fn_baec217075dd0de0": "e5828e743f3d59abec57d43d008b311a0b7a45ed64602a859a1967c114ad7b7a",
    "fn_0c216dacd0229af7": "71b7e8c236ac536a3c38618f801eba0008bf7d593953f120b5207e85c0fcfb88",
    "fn_67d63766d8e3a279": "eb80cdebaf19760ce27d4adc7dee31454bf8f7d27ab2af4e63b79a76b4c9d86f",
    "fn_2945991d1e22ceb9": "6b307893a7118734e100f81fdc974b4ac3f8eb1b75621f3c379796a2fb01c9eb",
    "fn_85f1b52c43f5ca05": "de0bf51a9e793fe5eb809e59269f2392fb64f66634c71f1c1bec07af528b4ecd",
    "fn_bb49f311f0bd90e1": "f778825116c255bb276c84c077b9dbabb243816af2e4870e37e4651287fa3119",
}
SIZES = (10415, 450, 109, 279, 497, 634)


class Native:
    def __init__(
        self,
        pe,
        rows,
        push,
        blocked=False,
        connected=True,
        existing=False,
        friend=False,
        local_user=202,
    ):
        self.pe = pe
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.vm = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pages = set()
        self.offset = 0
        self.push = push
        self.blocked = blocked
        self.connected = connected
        self.existing = existing
        self.friend = friend
        self.local_user = local_user
        self.received = []
        self.history = 0
        self.aliases = {}
        self.rows = rows
        self.vm.hook_add(UC_HOOK_MEM_UNMAPPED, self.unmapped)
        self.vm.hook_add(UC_HOOK_CODE, self.step)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.call_targets = set()
        for row, size in zip(rows.values(), SIZES):
            body = pe.get_data(row["rva"], size)
            self.call_targets.update(
                int(i.op_str, 16)
                for i in self.cs.disasm(body, self.base + row["rva"])
                if i.mnemonic == "call" and i.op_str.startswith("0x")
            )
        self.stop = 0x200000000
        self.stack = 0x210000000
        self.put(self.stop, b"\xc3")
        self.put(self.stack - 0x20000, bytes(0x40000))
        self.lobby = 0x220000000
        self.handler = self.lobby + 0x1000
        self.hvt = self.lobby + 0x2000
        self.ref = self.lobby + 0x3000
        self.buffer = self.lobby + 0x4000
        self.put(self.lobby + 1792, struct.pack("<Q", self.handler))
        self.put(self.handler, struct.pack("<Q", self.hvt))
        self.put(self.hvt + 216, struct.pack("<Q", self.entry("fn_67d63766d8e3a279")))
        self.channel_callback = self.entry("fn_bb49f311f0bd90e1")
        self.put(self.hvt + 48, struct.pack("<Q", self.channel_callback))
        self.put(self.ref, struct.pack("<Q", self.buffer))
        self.put(self.buffer + 8, struct.pack("<I", 10))
        self.system = self.lobby + 0x5000
        self.svt = self.lobby + 0x6000
        self.put(self.system, struct.pack("<Q", self.svt))
        self.put(self.svt + 96, struct.pack("<Q", self.entry("fn_85f1b52c43f5ca05")))
        self.put(self.system + 8, bytes(8))
        self.put(self.system + 16, struct.pack("<I", 4))
        self.put(self.system + 53, b"CHAT:\0")
        self.put(0x14C3851A0 + 24456, struct.pack("<Q", self.system))
        self.put(0x14B6D19D0, struct.pack("<Q", 5))
        self.pool = 0x14B6D19E0
        self.put(self.pool, bytes(38 * 20856))
        if push[:5] == b"\x08\x17\0\0\0":
            self.put(self.pool, struct.pack("<II", 3, 1))
            self.put(self.pool + 24, struct.pack("<Q", 700))
            self.put(self.pool + 16, struct.pack("<I", 1))
            self.put(self.pool + 48, struct.pack("<Q", 101))
        if existing:
            self.create_chat(101)
        for address, kind in {
            0x1421CCEF0: "stack",
            0x1421CCF60: "cookie",
            0x1420EFC80: "u32",
            0x1420EFD00: "u64",
            0x1420EFA20: "text",
            0x1420EF3B0: "blob",
            0x1417EC930: "connected",
            0x14107E890: "xuid-copy",
            0x14107EA90: "xuid-read",
            0x14107EA80: "xuid-string",
            0x141B31010: "block-instance",
            0x141B31030: "blocked",
            0x140F3BB20: "create-chat",
            0x141B371E0: "friends",
            0x141B36C50: "friend-index",
            0x1413FD5E0: "local-xuid",
            0x141B316F0: "message",
            0x140F3B060: "history",
            0x140F1E480: "invite",
            0x142036A10: "strcpy",
            0x1412B0820: "print",
            0x140D66C50: "controller",
            0x1410AE340: "platform",
            0x140F55460: "crossplay-friend",
            0x141B31E40: "member",
        }.items():
            assert address in self.call_targets, (hex(address), kind)
            self.aliases[address] = kind

    def entry(self, key):
        return self.base + self.rows[key]["rva"]

    def page(self, address):
        page = address & ~4095
        if page in self.pages:
            return
        self.vm.mem_map(page, 4096)
        self.pages.add(page)
        if self.base <= page < self.base + self.pe.OPTIONAL_HEADER.SizeOfImage:
            self.vm.mem_write(
                page, self.pe.get_data(page - self.base, 4096).ljust(4096, b"\0")
            )

    def unmapped(self, vm, access, address, size, value, user):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            self.page(page)
        return True

    def put(self, address, value):
        for page in range(address & ~4095, (address + len(value) + 4095) & ~4095, 4096):
            self.page(page)
        self.vm.mem_write(address, value)

    def get(self, address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            self.page(page)
        return bytes(self.vm.mem_read(address, size))

    def q(self, address):
        return struct.unpack("<Q", self.get(address, 8))[0]

    def cstring(self, address):
        return self.get(address, 1024).split(b"\0", 1)[0]

    def create_chat(self, sender):
        self.put(self.pool, struct.pack("<II", 7, 1))
        self.put(self.pool + 24, struct.pack("<Q", sender))

    def ret(self, value=0):
        sp = self.vm.reg_read(UC_X86_REG_RSP)
        self.vm.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        self.vm.reg_write(UC_X86_REG_RIP, self.q(sp))
        self.vm.reg_write(UC_X86_REG_RSP, sp + 8)

    def read_wire(self, kind, output, capacity):
        try:
            tag = self.push[self.offset]
            self.offset += 1
            if kind in ("u32", "u64"):
                assert tag == (8 if kind == "u32" else 10)
                size = 4 if kind == "u32" else 8
                raw = self.push[self.offset : self.offset + size]
                assert len(raw) == size
                self.offset += size
            elif kind == "text":
                assert tag == 16
                end = self.push.index(0, self.offset)
                raw = self.push[self.offset : end + 1]
                self.offset = end + 1
                assert len(raw) <= capacity
            else:
                assert tag == 19 and self.push[self.offset] == 8
                self.offset += 1
                size = struct.unpack_from("<I", self.push, self.offset)[0]
                self.offset += 4
                assert size <= struct.unpack("<I", self.get(capacity, 4))[0]
                raw = self.push[self.offset : self.offset + size]
                assert len(raw) == size
                self.offset += size
                self.put(capacity, struct.pack("<I", size))
            self.put(output, raw)
            return 1
        except (AssertionError, ValueError, IndexError, struct.error):
            return 0

    def step(self, vm, address, size, user):
        if address == self.stop:
            vm.emu_stop()
            return
        kind = self.aliases.get(address)
        if not kind:
            return
        c = vm.reg_read(UC_X86_REG_RCX)
        d = vm.reg_read(UC_X86_REG_RDX)
        r8 = vm.reg_read(UC_X86_REG_R8)
        r9 = vm.reg_read(UC_X86_REG_R9)
        sp = vm.reg_read(UC_X86_REG_RSP)
        value = 0
        if kind == "stack":
            value = vm.reg_read(UC_X86_REG_RAX)
        elif kind in ("u32", "u64", "text", "blob"):
            value = self.read_wire(kind, d, r8)
        elif kind == "connected":
            value = 2 if self.connected else 0
        elif kind == "xuid-copy":
            self.put(c, struct.pack("<Q", d))
            value = c
        elif kind == "xuid-read":
            value = self.q(c)
        elif kind == "xuid-string":
            self.put(self.lobby + 0xA000, b"Fixture\0")
            value = self.lobby + 0xA000
        elif kind == "blocked":
            value = int(self.blocked)
        elif kind in ("block-instance", "friends"):
            value = self.lobby + 0x8000
        elif kind == "friend-index":
            value = 0xFFFFFFFF
        elif kind == "controller":
            value = 0
        elif kind == "platform":
            value = 2
        elif kind == "crossplay-friend":
            value = 0 if self.friend else 0xFFFFFFFF
        elif kind == "member":
            value = 0 if self.blocked else self.pool + 48
        elif kind == "create-chat":
            self.create_chat(r8)
            value = self.pool
        elif kind == "local-xuid":
            self.put(c, struct.pack("<Q", self.local_user))
            value = c
        elif kind == "strcpy":
            self.put(c, self.cstring(r8)[: d - 1] + b"\0")
            value = c
        elif kind == "message":
            self.received.append(
                dict(
                    chat=c,
                    sender=d,
                    recipient=r8,
                    name=self.cstring(r9).decode(),
                    body=self.cstring(self.q(sp + 40)).hex(),
                    state=self.q(sp + 48) & 0xFFFFFFFF,
                )
            )
            value = self.lobby + 0x9000
        elif kind == "history":
            self.history += 1
        elif kind in ("cookie", "invite", "print"):
            pass
        else:
            raise AssertionError(kind)
        self.ret(value)

    def run(self):
        sp = self.stack - 0x100
        self.put(sp, struct.pack("<Q", self.stop))
        self.vm.reg_write(UC_X86_REG_RSP, sp)
        self.vm.reg_write(UC_X86_REG_RCX, self.lobby)
        self.vm.reg_write(UC_X86_REG_RDX, self.ref)
        self.vm.emu_start(self.entry("fn_baec217075dd0de0"), self.stop, count=200000)
        assert self.vm.reg_read(UC_X86_REG_RIP) == self.stop, (
            "native execution did not return",
            hex(self.vm.reg_read(UC_X86_REG_RIP)),
            self.blocked,
            self.connected,
            self.existing,
        )
        return self.vm.reg_read(UC_X86_REG_RAX) & 255


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    assert hashlib.file_digest(IMAGE.open("rb"), "sha256").hexdigest() == IMAGE_SHA
    catalog = json.loads(a.catalog.read_bytes())
    byid = {r["id"]: r for r in catalog["functions"]}
    pe = pefile.PE(str(IMAGE), fast_load=True)
    rows = {key: byid[key] for key in BODIES}
    proof = []
    for (key, sha), size in zip(BODIES.items(), SIZES):
        row = rows[key]
        assert hashlib.sha256(pe.get_data(row["rva"], size)).hexdigest() == sha
        proof.append(dict(function_id=key, rva=row["rva"], size=size, sha256=sha))
    with tempfile.TemporaryDirectory(
        prefix="whisper-native-", dir=ROOT / "data"
    ) as temp:
        exe = Path(temp) / "fixture.exe"
        cmd = [
            r"C:\Program Files\LLVM\bin\clang++.exe",
            "-std=c++20",
            "-O2",
            "-I" + str(ROOT / "src"),
            str(ROOT / "tools/whisper_service_harness.cpp"),
            str(ROOT / "src/channel_services.cpp"),
            "-o",
            str(exe),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        service = json.loads(subprocess.check_output([str(exe)]))
    checks = 0
    for case in service["cases"]:
        raw = bytes.fromhex(case["push"])
        native = Native(pe, rows, raw)
        native.run()
        assert native.offset == len(raw)
        if case["event"] == 23:
            assert native.received == [
                dict(
                    chat=native.pool,
                    sender=101,
                    recipient=700,
                    name="Sender",
                    body="68656c6c6f",
                    state=2,
                )
            ], (native.received, native.offset, native.history)
            denied = bytearray(raw)
            struct.pack_into("<I", denied, len(denied) - 4, 1)
            policy = Native(pe, rows, bytes(denied))
            policy.run()
            assert (
                not policy.received
            ), "native crossplay privacy must reject incompatible visibility flags"
            checks += 1
            friends_only = bytearray(raw)
            struct.pack_into("<I", friends_only, len(friends_only) - 4, 0x203)
            for friend in (False, True):
                policy = Native(pe, rows, bytes(friends_only), friend=friend)
                policy.run()
                assert (
                    bool(policy.received) == friend
                ), "native friends-only privacy must be preserved"
                checks += 1
        elif bytes.fromhex(case["body"]).startswith(b"CHAT:"):
            assert native.history == 1 and native.received == [
                dict(
                    chat=native.pool,
                    sender=101,
                    recipient=202,
                    name="Sender",
                    body="68656c6c6f",
                    state=2,
                )
            ]
            for blocked, connected, existing in (
                (True, True, False),
                (False, False, False),
                (False, True, True),
            ):
                guarded = Native(pe, rows, raw, blocked, connected, existing)
                guarded.run()
                assert bool(guarded.received) == (not blocked and connected)
                checks += 1
        else:
            assert not native.received
        checks += 1
    receipt = dict(
        passed=True,
        native_consumer_cases=checks,
        service_checks=service["service_checks"],
        image_sha256=IMAGE_SHA,
        bodies=proof,
        channel_source_sha256=hashlib.sha256(
            (ROOT / "src/channel_services.cpp").read_bytes()
        ).hexdigest(),
        harness_sha256=hashlib.sha256(
            (ROOT / "tools/whisper_service_harness.cpp").read_bytes()
        ).hexdigest(),
        test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        live_game_tested=False,
        boundaries=__doc__,
        receiver_native_history_insertion_modeled=True,
    )
    a.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        "PASS",
        checks,
        "original native whisper consumer cases,",
        service["service_checks"],
        "compiled service checks",
    )


if __name__ == "__main__":
    main()
