"""Execute linked endpoint getters; platform filename lookup alone is simulated."""

import struct

import unicorn
import unicorn.x86_const as x


def verify(pe, report):
    if "DW_LocalBackend_IsEnabled" not in report["symbols"]:
        raise ValueError("DW integration was not linked")
    cases = []
    for executable, enabled, host in (
        ("game_dx12_ship_replay.exe", False, "127.0.0.1"),
        ("game_dx12_ship_replay_dw.exe", True, "127.0.0.1"),
        ("game_dx12_ship_replay_dw.exe", True, "203.0.113.12"),
    ):
        machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        base = pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            if section.Name.rstrip(b"\0") in (
                b".text",
                b".rdata",
                b".data",
                b".cpp",
                b".rwcpp",
            ):
                size = (
                    max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095
                ) & -4096
                machine.mem_map(base + section.VirtualAddress, size)
                machine.mem_write(base + section.VirtualAddress, section.get_data())
        arena = 0x100000000
        machine.mem_map(arena, 0x10000)
        config, rsp, sentinel, filename_thunk = (
            arena + 0x1000,
            arena + 0xE000 - 8,
            arena + 0xF000,
            arena + 0xF100,
        )
        symbols = {name: base + rva for name, rva in report["symbols"].items()}
        machine.mem_write(
            symbols["__imp_GetModuleFileNameA"], struct.pack("<Q", filename_thunk)
        )
        profile_thunk = arena + 0xF180
        machine.mem_write(
            symbols["__imp_CreateFileA"], struct.pack("<Q", profile_thunk)
        )
        read_thunk, close_thunk = arena + 0xF190, arena + 0xF1A0
        machine.mem_write(symbols["__imp_ReadFile"], struct.pack("<Q", read_thunk))
        machine.mem_write(symbols["__imp_CloseHandle"], struct.pack("<Q", close_thunk))
        remote = host != "127.0.0.1"
        ini = (
            f"host={host}\nprofile=remote-test-1\naccess_key={'a'*64}\n"
            f"public_address={host}\nlocal_address=192.168.1.124\ngame_port=3074\n"
        ).encode()
        native = bytearray(2088)
        native[:36] = bytes(range(36))
        auth, lobby = b"native.auth.invalid\0", b"native.lobby.invalid\0"
        native[36 : 36 + len(auth)] = auth
        native[1062 : 1062 + len(lobby)] = lobby
        struct.pack_into("<H", native, 1060, 443)
        struct.pack_into("<H", native, 2086, 3074)
        machine.mem_write(config, bytes(native))

        def platform(uc, address, size, data):
            if address == symbols["func_14223AD14"]:
                assert uc.reg_read(x.UC_X86_REG_RCX) == 0x20000
                stack = uc.reg_read(x.UC_X86_REG_RSP)
                target = struct.unpack("<Q", uc.mem_read(stack, 8))[0]
                uc.reg_write(x.UC_X86_REG_RAX, arena + 0x5000)
                uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
                uc.reg_write(x.UC_X86_REG_RIP, target)
                return
            if address in (profile_thunk, read_thunk, close_thunk):
                stack = uc.reg_read(x.UC_X86_REG_RSP)
                target = struct.unpack("<Q", uc.mem_read(stack, 8))[0]
                if address == read_thunk:
                    uc.mem_write(uc.reg_read(x.UC_X86_REG_RDX), ini)
                    uc.mem_write(
                        uc.reg_read(x.UC_X86_REG_R9), struct.pack("<I", len(ini))
                    )
                uc.reg_write(
                    x.UC_X86_REG_RAX,
                    (
                        (99 if remote else 0xFFFFFFFFFFFFFFFF)
                        if address == profile_thunk
                        else 1
                    ),
                )
                uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
                uc.reg_write(x.UC_X86_REG_RIP, target)
                return
            if address != filename_thunk:
                return
            assert uc.reg_read(x.UC_X86_REG_RCX) == 0
            output, capacity = uc.reg_read(x.UC_X86_REG_RDX), uc.reg_read(
                x.UC_X86_REG_R8
            )
            path = ("E:\\IW8\\Builds\\1.20-replay\\" + executable).encode()
            assert len(path) + 1 <= capacity
            uc.mem_write(output, path + b"\0")
            stack = uc.reg_read(x.UC_X86_REG_RSP)
            target = struct.unpack("<Q", uc.mem_read(stack, 8))[0]
            uc.reg_write(x.UC_X86_REG_RAX, len(path))
            uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)

        machine.hook_add(unicorn.UC_HOOK_CODE, platform)

        def run(name):
            machine.reg_write(x.UC_X86_REG_RSP, rsp)
            machine.mem_write(rsp, struct.pack("<Q", sentinel))
            machine.reg_write(x.UC_X86_REG_RCX, config)
            machine.emu_start(symbols[name], sentinel, count=20000)
            assert machine.reg_read(x.UC_X86_REG_RIP) == sentinel
            return machine.reg_read(x.UC_X86_REG_RAX)

        def string(address):
            return bytes(machine.mem_read(address, 128)).split(b"\0", 1)[0].decode()

        assert bool(run("DW_LocalBackend_IsEnabled")) == enabled
        auth_port = run("func_14212B110") & 0xFFFF
        lobby_address = string(run("func_14212B210"))
        lobby_port = run("func_14212B220") & 0xFFFF
        auth_address = string(config + 36)
        assert auth_port == (8443 if enabled else 443)
        assert lobby_port == (3075 if enabled else 3074)
        assert auth_address == (host if enabled else "native.auth.invalid")
        assert lobby_address == (host if enabled else "native.lobby.invalid")
        assert bytes(machine.mem_read(config, 36)) == bytes(native[:36])
        assert bytes(machine.mem_read(config + 1060, len(native) - 1060)) == bytes(
            native[1060:]
        )
        if not enabled:
            assert bytes(machine.mem_read(config, len(native))) == bytes(native)
        # The private DW image must reach the native CRT constructor's caller
        # without attempting private Windows DLL initialization. Execute its
        # linked C++ replacement; no platform API or game routine is stubbed.
        if "func_1403061A0" not in symbols:
            raise ValueError("DW startup compatibility source was not compiled")
        before_constructor = bytes(machine.mem_read(config, len(native)))
        run("func_1403061A0")
        assert bytes(machine.mem_read(config, len(native))) == before_constructor
        assert run("func_141489DA0") == 0
        assert (
            struct.unpack("<Q", machine.mem_read(symbols["gl_14E5C2A58"], 8))[0] + 4096
            == arena + 0x5000
        )
        # Execute the linked C++ payload validator. OS cryptography is checked
        # separately against this same source's actual Windows build.
        now, nonce_address = 1791136800, arena + 0x3000
        nonce = bytes(range(32))
        payload = bytearray(256)
        struct.pack_into("<II", payload, 0, 0x31505744, 2)
        payload[8:40] = nonce
        struct.pack_into(
            "<QQQII", payload, 40, now, now + 3600, 0x110000100000001, 1, 1
        )
        payload[72:81] = b"DWPlayer\0"
        struct.pack_into("<I", payload, 108, 1)
        payload[112:176] = b"a" * 64
        payload[177:241] = b"b" * 64
        payload[242] = 21
        struct.pack_into("<I", payload, 244, 1)
        machine.mem_write(nonce_address, nonce)

        def validate(value, expected):
            machine.mem_write(config, bytes(value))
            machine.reg_write(x.UC_X86_REG_RDX, nonce_address)
            machine.reg_write(x.UC_X86_REG_R8, now)
            assert bool(run("DW_LocalPlatform_ValidatePayload")) == expected

        validate(payload, True)
        for offset in (0, 8, 64, 72, 108, 112, 176, 241, 242, 243, 244, 255):
            invalid = bytearray(payload)
            invalid[offset] = 0 if offset in (64, 72) else 255
            validate(invalid, False)
        invalid = bytearray(payload)
        struct.pack_into("<Q", invalid, 48, now)
        validate(invalid, False)
        http, table, check_thunk, modulus = (
            arena + 0x4000,
            arena + 0x6000,
            arena + 0xF200,
            arena + 0x7000,
        )
        machine.mem_write(table, bytes(184))
        for slot in (9, 22):
            machine.mem_write(table + slot * 8, struct.pack("<Q", check_thunk))
        machine.mem_write(http, struct.pack("<Q", table) + bytes(1232))
        chosen_urls, imported_keys, disconnects, callbacks = [], [], [], []
        connection_address, file_thunk, callback_thunk = (
            arena + 0x8000,
            arena + 0xF400,
            arena + 0xF500,
        )
        web_callback_thunk = arena + 0xF600
        web_completions = []
        machine.mem_write(symbols["__imp_CreateFileA"], struct.pack("<Q", file_thunk))
        identity_notifications = []
        restart = {
            "active": False,
            "main": True,
            "frontend": False,
            "ticks": 100,
            "wait": 258,
            "status": 0,
            "calls": [],
            "threads": 0,
            "closed": 0,
        }
        restart_dvar = arena + 0xB000
        cached_crypto = {
            "active": False,
            "hash": 0,
            "import": 0,
            "result": 0,
            "valid": 1,
            "freed": 0,
            "errors": [],
        }

        def return_native(uc, value=0):
            stack = uc.reg_read(x.UC_X86_REG_RSP)
            target = struct.unpack("<Q", uc.mem_read(stack, 8))[0]
            uc.reg_write(x.UC_X86_REG_RAX, value)
            uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)

        def native_boundaries(uc, address, size, data):
            args = [
                uc.reg_read(reg)
                for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)
            ]
            restart_targets = {
                "func_141526B50": "cleanup",
                "func_141051740": "signed-out",
                "func_1417ECE20": "hsm-signout",
                "func_141614830": "hsm-drain",
                "func_1414F2FB0": "reset-logon",
                "func_141051630": "disconnected",
                "func_1417EC990": "logon",
            }
            if restart["active"] and address in (
                symbols["func_141526CE0"],
                symbols["func_1412BD8E0"],
            ):
                raise AssertionError(
                    "DW refresh must not transition the platform/network offline"
                )
            if restart["active"] and address == symbols["Sys_IsMainThread"]:
                return_native(uc, int(restart["main"]))
            elif restart["active"] and address == symbols["Cmd_Argc"]:
                return_native(uc, 1)
            elif restart["active"] and address == symbols["Com_FrontEnd_IsInFrontEnd"]:
                return_native(uc, int(restart["frontend"]))
            elif restart["active"] and address == symbols["Com_Printf"]:
                return_native(uc)
            elif restart["active"] and address == symbols["func_1417EC930"]:
                return_native(uc, restart["status"])
            elif restart["active"] and address == symbols["func_1412976C0"]:
                assert args[:2] == [0, 0] and string(args[2]) == "disconnect"
                restart["calls"].append("disconnect-command")
                return_native(uc)
            elif restart["active"] and address in [symbols[n] for n in restart_targets]:
                name = next(n for n in restart_targets if symbols[n] == address)
                if name in ("func_1417ECE20", "func_141614830"):
                    assert args[0] == symbols["g_dwLogonHSMs"]
                elif name == "func_141051630":
                    assert args[:2] == [symbols["gl_14C3851A0"], 0]
                elif name == "func_141051740":
                    assert args == [symbols["gl_14C3851A0"], 0, 1]
                else:
                    assert args[0] == 0
                restart["calls"].append(restart_targets[name])
                if name == "func_141526B50" and uc.mem_read(restart_dvar + 40, 1)[0]:
                    restart["calls"].append(
                        "signed-out"
                    )  # Native dvar-controlled notification.
                return_native(uc)
            elif restart["active"] and address == arena + 0xF700:
                return_native(uc, restart["ticks"])
            elif restart["active"] and address == arena + 0xF710:
                restart["threads"] += 1
                return_native(uc, 0x123456)
            elif restart["active"] and address == arena + 0xF720:
                assert args[:2] == [0x123456, 0]
                return_native(uc, restart["wait"])
            elif restart["active"] and address == arena + 0xF730:
                assert args[0] == 0x123456
                restart["closed"] += 1
                return_native(uc, 1)
            elif address == check_thunk:
                assert args[0] == http
                return_native(uc, 1)
            elif address == symbols["func_1420E3780"]:
                assert args[0] == http
                uc.mem_write(http + 64, struct.pack("<Q", 0x1234))
                return_native(uc)
            elif address == symbols["func_1422EACE0"]:
                assert args[0] == 0x1234
                if args[1] == 10002:
                    chosen_urls.append(string(args[2]))
                return_native(uc)
            elif address == symbols["func_142056C00"]:
                assert args[1] == (
                    294 if enabled or not cached_crypto["active"] else 270
                )
                imported_keys.append(bytes(uc.mem_read(args[0], args[1])))
                uc.mem_write(args[2] + 24, struct.pack("<Q", modulus))
                return_native(
                    uc, cached_crypto["import"] if cached_crypto["active"] else 0
                )
            elif cached_crypto["active"] and address == symbols["func_1420566F0"]:
                assert string(args[0]) == "sha256"
                return_native(uc, cached_crypto["hash"] & 0xFFFFFFFF)
            elif cached_crypto["active"] and address == symbols["func_142056870"]:
                assert args[:3] == [nonce_address, 256, config]
                assert uc.reg_read(x.UC_X86_REG_R9) == 32
                stack = uc.reg_read(x.UC_X86_REG_RSP)
                extra = [
                    struct.unpack("<Q", uc.mem_read(stack + 40 + 8 * i, 8))[0]
                    for i in range(5)
                ]
                assert [v & 0xFFFFFFFF for v in extra[:3]] == [
                    3,
                    cached_crypto["hash"],
                    8,
                ]
                assert struct.unpack("<Q", uc.mem_read(extra[4] + 24, 8))[0] == modulus
                uc.mem_write(extra[3], struct.pack("<i", cached_crypto["valid"]))
                return_native(uc, cached_crypto["result"])
            elif cached_crypto["active"] and address == symbols["func_142056820"]:
                cached_crypto["freed"] += 1
                return_native(uc)
            elif cached_crypto["active"] and address == symbols["func_14103D460"]:
                return_native(uc, arena + 0x9000)
            elif cached_crypto["active"] and address == symbols["func_14103D4A0"]:
                assert args[0] == arena + 0x9000
                cached_crypto["errors"].append(args[1])
                return_native(uc)
            elif address == arena + 0xF300:
                assert args[0] == modulus
                return_native(uc, 2048)
            elif address == file_thunk:
                return_native(uc, 0xFFFFFFFFFFFFFFFF)  # No filesystem work in the VM.
            elif address == symbols["func_141662FC0"]:
                return_native(uc, connection_address)
            elif address == symbols["func_1403E50B0"]:
                assert args[0] != 0, "Native SDK disconnect received a null object"
                disconnects.append(args[0])
                return_native(uc, 19)
            elif address == callback_thunk:
                callbacks.append(args[0])
                return_native(uc)
            elif address == web_callback_thunk:
                pointer, length = struct.unpack("<QQ", uc.mem_read(args[1], 16))
                token = bytes(uc.mem_read(pointer, length)) if length else b""
                web_completions.append((args[0], token, args[2]))
                return_native(uc)
            elif address == symbols["func_14038BAD0"]:
                assert args[2] < 16
                value = bytes(uc.mem_read(args[1], args[2]))
                uc.mem_write(
                    args[0],
                    struct.pack("<QQQ", args[0] + 24, len(value), 0x800000000000000F)
                    + value
                    + bytes(16 - len(value)),
                )
                return_native(uc, args[0])
            elif address == symbols["Com_sprintf"]:
                output = str(uc.reg_read(x.UC_X86_REG_R9)).encode() + b"\0"
                assert len(output) <= args[1]
                uc.mem_write(args[0], output)
                return_native(uc, len(output) - 1)
            elif address == symbols["func_14165FA60"]:
                assert struct.unpack("<I", uc.mem_read(args[0] + 716, 4))[0] == 1
                uc.mem_write(args[0], struct.pack("<I", 2))
                identity_notifications.append("native CompleteSignIn")
                return_native(uc)
            elif address == symbols["func_1413FDE80"]:
                assert args[0] == 0
                uc.mem_write(symbols["gl_14E5C0730"], struct.pack("<I", 2))
                identity_notifications.append("native profile sign-in transition")
                return_native(uc)
            elif address == symbols["func_1413E44F0"]:
                assert (
                    args[1] == 1
                    and struct.unpack("<I", uc.mem_read(args[0], 4))[0] == 51636
                )
                identity_notifications.append("native license notification")
                return_native(uc)

        machine.hook_add(unicorn.UC_HOOK_CODE, native_boundaries)
        machine.mem_write(symbols["gl_152E9F6D8"], struct.pack("<Q", arena + 0xF300))

        def invoke(name, a1, a2, a3, a4=0):
            machine.reg_write(x.UC_X86_REG_RSP, rsp)
            machine.mem_write(rsp, struct.pack("<Q", sentinel))
            for reg, value in zip(
                (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9),
                (a1, a2, a3, a4),
            ):
                machine.reg_write(reg, value)
            try:
                machine.emu_start(symbols[name], sentinel, count=20000)
            except unicorn.UcError as error:
                rip = machine.reg_read(x.UC_X86_REG_RIP)
                stack = machine.reg_read(x.UC_X86_REG_RSP)
                raise RuntimeError(
                    f"{name}: {error}; RIP={rip:#x}; stack={bytes(machine.mem_read(stack, 64)).hex()}"
                ) from error
            assert machine.reg_read(x.UC_X86_REG_RIP) == sentinel
            return machine.reg_read(x.UC_X86_REG_RAX)

        machine.mem_write(config, f"https://{host}:8443/auth/\0".encode())
        assert invoke("func_1420E34D0", http, 3, config, 15000) & 255 == 1
        assert chosen_urls[-1] == (
            f"http://{host}:8085/auth/" if enabled else f"https://{host}:8443/auth/"
        )
        machine.mem_write(config, b"https://native.auth.invalid/auth/\0")
        assert invoke("func_1420E34D0", http, 3, config, 15000) & 255 == 1
        assert chosen_urls[-1] == "https://native.auth.invalid/auth/"
        for environment in ("dev", "cert", "prod"):
            legacy = f"https://{environment}.umbrella.demonware.net/v1.0/tokens/lsg/?client=replaylocal"
            machine.mem_write(config, legacy.encode() + b"\0")
            assert invoke("func_1420E34D0", http, 3, config, 15000) & 255 == 1
            assert chosen_urls[-1] == (
                f"http://{host}:8085/v1.0/tokens/lsg/?client=replaylocal"
                if enabled
                else legacy
            )
        foreign = "https://prod.umbrella.demonware.net/v1.0/tokens/lsg/?client=another"
        machine.mem_write(config, foreign.encode() + b"\0")
        assert invoke("func_1420E34D0", http, 3, config, 15000) & 255 == 1
        assert chosen_urls[-1] == foreign
        original_der = bytes(machine.mem_read(symbols["gl_1426A84F0"], 294))
        machine.mem_write(config, bytes(96))
        assert invoke("func_1420F1AD0", config, symbols["gl_1426A84F0"], 294) & 255 == 1
        assert struct.unpack("<I", machine.mem_read(config, 4))[0] == 1
        assert struct.unpack("<I", machine.mem_read(config + 80, 4))[0] == 256
        assert (imported_keys[-1] != original_der) == enabled
        machine.mem_write(config, bytes(96))
        machine.mem_write(nonce_address, b"x" * 294)
        assert invoke("func_1420F1AD0", config, nonce_address, 294) & 255 == 1
        assert imported_keys[-1] == b"x" * 294
        # These boundary cases test compiled key selection, exact native PSS
        # parameters, failure handling and key lifetime. Cryptography is tested
        # independently during content preparation and by the live native gate.
        cached_crypto["active"] = True
        original_ccc = bytes(machine.mem_read(symbols["gl_142416200"], 270))
        machine.mem_write(config, b"d" * 32)
        machine.mem_write(nonce_address, b"s" * 256)
        assert invoke("func_141038500", 0, config, nonce_address) & 255 == 1
        assert (imported_keys[-1] != original_ccc) == enabled
        assert cached_crypto["freed"] == 1 and not cached_crypto["errors"]
        for result, valid in ((0, 0), (7, 0)):
            cached_crypto.update(result=result, valid=valid)
            assert invoke("func_141038500", 0, config, nonce_address) & 255 == 0
            assert cached_crypto["errors"][-1] == 0x4000
        assert cached_crypto["freed"] == 3
        cached_crypto["import"] = 6
        assert invoke("func_141038500", 0, config, nonce_address) & 255 == 0
        assert cached_crypto["errors"][-1] == 0x2000 and cached_crypto["freed"] == 3
        cached_crypto["hash"] = -1
        assert invoke("func_141038500", 0, config, nonce_address) & 255 == 0
        assert cached_crypto["errors"][-1] == 0x1000 and cached_crypto["freed"] == 3
        cached_crypto["active"] = False

        # Execute the exact newly linked replacement at the original symbol's
        # compiler-selected location. The confirmed null-client crash path must
        # preserve native DW disconnection while retaining the local provider.
        def connection(state, client=0, callback=0, count=0):
            value = bytearray(b"\xa5" * 192)
            struct.pack_into("<I", value, 0, state)
            struct.pack_into("<Q", value, 8, client)
            struct.pack_into("<I", value, 168, 0)
            struct.pack_into("<QQ", value, 176, callback, count)
            machine.mem_write(connection_address, bytes(value))
            return bytes(value)

        assert invoke("func_141662EE0", 0, 0x7FFFFE00, 0) == 0
        if enabled:
            for state in (1, 2):
                before = connection(state)
                assert invoke("func_141662EE0", connection_address, 0x7FFFFE00, 0) == 0
                assert bytes(machine.mem_read(connection_address, 192)) == before
                assert not disconnects and not callbacks
            connection(2, callback=callback_thunk, count=1)
            assert invoke("func_141662EE0", connection_address, 3027, 0) == 0
            assert struct.unpack("<I", machine.mem_read(connection_address, 4))[0] == 3
            assert callbacks == [3027] and not disconnects
            before = connection(3)
            assert invoke("func_141662EE0", connection_address, 3027, 0) == 2
            assert bytes(machine.mem_read(connection_address, 192)) == before
            connection(2, callback=callback_thunk, count=2)
            assert invoke("func_141662EE0", connection_address, 3027, 0) == 0
            assert callbacks == [3027]  # Reject unsupported callback array layout.
        else:
            connection(2, client=arena + 0x9000)
            assert invoke("func_141662EE0", connection_address, 0x7FFFFE00, 0) == 19
            assert disconnects == [arena + 0x9000]
            assert (
                struct.unpack("<I", machine.mem_read(connection_address + 168, 4))[0]
                == 0x7FFFFE00
            )
            before = connection(3)
            assert invoke("func_141662EE0", connection_address, 3027, 0) == 2
            assert bytes(machine.mem_read(connection_address, 192)) == before
        if enabled:
            # Reproduce the live failure: native auth already complete but no
            # license/platform-ID initialization. Run the linked C++ writer,
            # substituting only documented engine/API callback boundaries.
            # Use the real native auth singleton and execute the real platform-ID
            # getter. A fabricated callback that omits its getter hid the prior
            # ACCOUNT-vs-GAME ACCOUNT mistake.
            native_auth = invoke("func_141660280", 0, 0, 0)
            machine.mem_write(native_auth, bytes(808))
            machine.mem_write(native_auth, struct.pack("<I", 2))
            machine.mem_write(symbols["gl_14E5C0730"], bytes(232))
            machine.mem_write(symbols["gl_14E5C0730"], struct.pack("<I", 1))
            machine.mem_write(nonce_address, bytes(payload))
            assert (
                invoke(
                    "DW_LocalPlatform_InitializeNativeIdentity",
                    native_auth,
                    nonce_address,
                    0,
                )
                & 255
                == 1
            )
            user = bytes(machine.mem_read(symbols["gl_14E5C0730"], 232))
            assert struct.unpack_from("<i", user)[0] == 2
            assert struct.unpack_from("<Q", user, 144)[0] == 0x110000100000001
            assert (
                struct.unpack_from("<Q", user, 184)[0] == 1 and user[192:194] == b"1\0"
            )
            assert struct.unpack("<I", machine.mem_read(native_auth + 716, 4))[0] == 1
            assert struct.unpack("<I", machine.mem_read(native_auth + 192, 4))[0] == 1
            assert struct.unpack("<I", machine.mem_read(native_auth + 224, 4))[0] == 1
            assert invoke("func_141666030", 0, config, 0) & 255 == 1
            assert struct.unpack("<Q", machine.mem_read(config, 8))[0] == 1
            assert identity_notifications == [
                "native CompleteSignIn",
                "native profile sign-in transition",
                "native license notification",
            ]
            account = config + 0x500
            original_account = bytearray([0xA5] * 152)
            struct.pack_into("<II", original_account, 16, 0, 1)
            machine.mem_write(account, bytes(original_account))
            assert (
                invoke(
                    "DW_LocalPlatform_ApplyAccountProfile", account, nonce_address, 0
                )
                & 255
                == 1
            )
            received = bytes(machine.mem_read(account, 152))
            assert struct.unpack_from("<I", received, 16)[0] == 1
            assert struct.unpack_from("<I", received, 128)[0] == 1
            assert struct.unpack_from("<II", received, 140) == (0x5553, 21)
            for start, end in ((0, 16), (20, 128), (132, 140), (148, 152)):
                assert received[start:end] == original_account[start:end]
            invalid_policy = bytearray(payload)
            invalid_policy[242] = 12
            machine.mem_write(nonce_address, bytes(invalid_policy))
            assert (
                invoke(
                    "DW_LocalPlatform_ApplyAccountProfile", account, nonce_address, 0
                )
                & 255
                == 0
            )
            assert bytes(machine.mem_read(account, 152)) == received
            machine.mem_write(nonce_address, bytes(payload))
            web_manager = arena + 0x9000
            original_web = bytearray([0xA5] * 720)
            struct.pack_into("<I", original_web, 676, 41)
            machine.mem_write(web_manager, bytes(original_web))
            assert (
                invoke(
                    "func_140C859F0",
                    web_manager,
                    1329875278,
                    web_callback_thunk,
                    0x1234,
                )
                == 41
            )
            queued = bytes(machine.mem_read(web_manager, 720))
            assert struct.unpack_from("<I", queued, 676)[0] == 42
            assert (
                queued[:676] == original_web[:676]
                and queued[680:] == original_web[680:]
            )
            assert not web_completions, "SDK credential completion must be asynchronous"
            web_request = arena + 0xA000
            machine.mem_write(
                web_request,
                struct.pack("<IIQQ", 41, 1329875278, web_callback_thunk, 0x1234),
            )
            assert (
                invoke(
                    "DW_LocalPlatform_CompleteWebCredential",
                    web_request,
                    nonce_address,
                    1,
                )
                & 255
                == 1
            )
            assert web_completions[-1] == (0, bytes(payload[112:176]), 0x1234)
            assert (
                invoke(
                    "DW_LocalPlatform_CompleteWebCredential",
                    web_request,
                    nonce_address,
                    0,
                )
                & 255
                == 0
            )
            assert web_completions[-1] == (1, b"", 0x1234)
            # Execute the linked restart command and frame coordinator. Native
            # lifecycle/API boundaries are recorded, not replaced in the image.
            restart["active"] = True
            for api, thunk in (
                ("GetTickCount64", 0xF700),
                ("CreateThread", 0xF710),
                ("WaitForSingleObject", 0xF720),
                ("CloseHandle", 0xF730),
            ):
                machine.mem_write(
                    symbols["__imp_" + api], struct.pack("<Q", arena + thunk)
                )
            machine.mem_write(restart_dvar, bytes(112))
            machine.mem_write(
                symbols["DVARBOOL_online_signout_on_dw_disconnect_cleanup"],
                struct.pack("<Q", restart_dvar),
            )
            restart["main"] = False
            invoke("DW_LocalPlatform_Restart_f", 0, 0, 0)
            assert invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0) & 255 == 0
            assert not restart["calls"]
            restart["main"] = True
            connection(2)
            invoke("DW_LocalPlatform_Restart_f", 0, 0, 0)
            assert (
                invoke("func_1416659B0", 0, config, 0) & 255 == 1
            ), "Platform identity lost during drain"
            invoke("DW_LocalPlatform_Restart_f", 0, 0, 0)  # Coalesce duplicates.
            assert invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0) & 255 == 1
            assert invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0) & 255 == 1
            assert restart["calls"] == ["disconnect-command"]
            invoke(
                "func_140C859F0", web_manager, 1329875278, web_callback_thunk, 0x5678
            )
            assert web_completions[-1] == (1, b"", 0x5678)
            restart["frontend"] = True
            invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0)
            expected = [
                "disconnect-command",
                "signed-out",
                "cleanup",
                "hsm-signout",
                "hsm-drain",
                "reset-logon",
                "disconnected",
            ]
            assert restart["calls"] == expected and restart["threads"] == 1
            assert web_completions[-1] == (
                1,
                b"",
                0x1234,
            ), "Queued callback must fail before native teardown"
            assert struct.unpack("<I", machine.mem_read(native_auth, 4))[0] == 2
            assert struct.unpack("<I", machine.mem_read(connection_address, 4))[0] == 2
            assert (
                invoke("func_1416659B0", 0, config, 0) & 255 == 1
            ), "Platform identity lost during provider refresh"
            invoke("func_14165FFA0", native_auth, 0, 0)
            assert invoke("func_141662F00", connection_address, 0, 0) & 255 == 2
            assert invoke("func_14165E230", account, 0, 0) == 1
            assert struct.unpack("<I", machine.mem_read(native_auth, 4))[0] == 2
            token_task = arena + 0xC000
            native_token_task = bytearray(1072)
            struct.pack_into("<I", native_token_task, 8, 1)
            struct.pack_into("<Q", native_token_task, 32, config)
            struct.pack_into("<I", native_token_task, 40, 2)
            machine.mem_write(token_task, bytes(native_token_task))
            invoke("func_14216AEB0", token_task, 0, 0)
            assert bytes(machine.mem_read(token_task, 1072)) == bytes(
                native_token_task
            ), "Old tokens leaked into a new DW login"
            # A provider failure must allow another restart. Its old worker
            # may still be exiting: never reset shared buffers before join.
            connection(2)
            invoke("func_141662EE0", connection_address, 3027, 0)
            invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0)
            invoke("DW_LocalPlatform_Restart_f", 0, 0, 0)
            assert invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0) & 255 == 1
            assert restart["calls"] == expected and restart["closed"] == 0
            restart["wait"] = 0
            machine.mem_write(restart_dvar + 40, b"\1")
            invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0)
            assert restart["calls"] == expected + [
                "cleanup",
                "signed-out",
                "hsm-signout",
                "hsm-drain",
                "reset-logon",
                "disconnected",
            ]
            assert restart["threads"] == 2 and restart["closed"] == 1
            # Monitoring cannot hold the command busy forever when DW is down.
            restart["ticks"] += 90001
            invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0)
            invoke("DW_LocalPlatform_Restart_f", 0, 0, 0)
            restart["wait"] = 258
            assert invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0) & 255 == 1
            restart["ticks"] += 30001
            assert invoke("DW_LocalPlatform_RestartFrame", 0, 0, 0) & 255 == 0
            assert restart["closed"] == 1 and restart["threads"] == 2
            restart["active"] = False
            machine.mem_write(web_request + 4, struct.pack("<I", 123))
            assert (
                invoke(
                    "DW_LocalPlatform_CompleteWebCredential",
                    web_request,
                    nonce_address,
                    1,
                )
                & 255
                == 0
            )
            assert web_completions[-1] == (1, b"", 0x1234)
        # Execute native local/relay constructors and the 84-byte serializer.
        # The Tiger hash factory requires Windows SDK initialization; verify
        # its dispatch occurs after publication at that platform boundary.
        common, array, addresses, public, serialized = (
            arena + 0xC000,
            arena + 0xC700,
            arena + 0xC800,
            arena + 0xCA00,
            arena + 0xCB00,
        )
        local = bytearray(152)
        local[:8] = bytes([2, 0, 12, 2, 192, 168, 1, 124])
        original_public = bytearray(local)
        original_public[4:8] = bytes([192, 168, 1, 124])
        hash_calls = []

        def hash_boundary(uc, address, size, data):
            if address == symbols["func_1420EC5C0"]:
                assert uc.reg_read(x.UC_X86_REG_RCX) == common
                hash_calls.append(bytes(uc.mem_read(common + 784, 8)))
                return_native(uc)

        machine.hook_add(unicorn.UC_HOOK_CODE, hash_boundary)
        htons_thunk = arena + 0xF1B0
        for imported in ("__imp_htons", "__imp_ntohs"):
            if imported in symbols:
                machine.mem_write(symbols[imported], struct.pack("<Q", htons_thunk))

        def socket_api(uc, address, size, data):
            if address == htons_thunk:
                value = uc.reg_read(x.UC_X86_REG_RCX) & 0xFFFF
                return_native(uc, ((value & 255) << 8) | (value >> 8))

        machine.hook_add(unicorn.UC_HOOK_CODE, socket_api)
        machine.mem_write(addresses, bytes(local))
        machine.mem_write(public, bytes(original_public))
        machine.mem_write(array, struct.pack("<QII", addresses, 1, 1))
        machine.mem_write(rsp + 40, struct.pack("<Q", 101))
        assert invoke("func_1420EC390", common, array, public, 3) == common
        assert bytes(machine.mem_read(common + 16, 152)) == bytes(local)
        assert struct.unpack("<I", machine.mem_read(common + 776, 4))[0] == 1
        expected_ip = (
            bytes(map(int, host.split("."))) if remote else original_public[4:8]
        )
        assert bytes(machine.mem_read(common + 788, 4)) == expected_ip
        assert hash_calls == [bytes([2, 0, 12, 2]) + bytes(expected_ip)]
        assert struct.unpack("<I", machine.mem_read(common + 936, 4))[0] == (
            1 if remote else 3
        )
        machine.mem_write(serialized, bytes(84))
        assert invoke("func_1420ECA10", common, serialized, 0) & 255 == 1
        assert bytes(machine.mem_read(serialized + 30, 6)) == bytes(
            expected_ip
        ) + struct.pack("<H", 3074)
        cases.append(
            {
                "executable": executable,
                "enabled": enabled,
                "configured_host": host,
                "compiled_public_address_serialization": True,
                "compiled_startup_probe_returns": True,
                "auth_address": auth_address,
                "auth_port": auth_port,
                "lobby_address": lobby_address,
                "lobby_port": lobby_port,
                "compiled_startup_constructor_returns": True,
                "compiled_platform_payload_validation": {"valid": 1, "rejected": 13},
                "compiled_auth_url_and_key_selection": True,
                "compiled_publisher_key_selection_and_verification_lifetime": True,
                "compiled_legacy_url_selection": True,
                "compiled_connection_disconnect_lifecycle": True,
                "compiled_profile_license_and_account_metadata": enabled,
            }
        )
        cases[-1]["compiled_web_credential_queue_and_callback"] = enabled
        cases[-1]["compiled_dw_restart_lifecycle"] = enabled
        cases[-1]["compiled_dw_restart_preserves_platform_identity"] = enabled
    return cases
