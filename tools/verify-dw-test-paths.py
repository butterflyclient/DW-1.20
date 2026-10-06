"""Execute the linked private test home helper with explicit OS API boundaries."""

import struct

import unicorn
import unicorn.x86_const as x


def verify(pe, report):
    cases = []
    for label, enabled, flag, override, capacity, expected in (
        (
            "private-absolute-cache",
            True,
            True,
            r"E:\DW\cache\alpha",
            256,
            r"E:\DW\cache\alpha",
        ),
        (
            "no-environment",
            True,
            True,
            "",
            256,
            r"C:\Users\Tester\Documents\Call of Duty Modern Warfare",
        ),
        (
            "no-opt-in",
            True,
            False,
            r"E:\DW\cache\alpha",
            256,
            r"C:\Users\Tester\Documents\Call of Duty Modern Warfare",
        ),
        (
            "ordinary-replay",
            False,
            True,
            r"E:\DW\cache\alpha",
            256,
            r"C:\Users\Tester\Documents\Call of Duty Modern Warfare",
        ),
        ("relative-rejected", True, True, "cache", 256, ""),
        ("stream-rejected", True, True, r"E:\cache:stream", 256, ""),
        ("overflow-rejected", True, True, "E:\\" + "a" * 300, 256, ""),
        ("one-byte", True, True, "E:\\cache", 1, ""),
        ("zero-capacity", True, True, "E:\\cache", 0, "unchanged"),
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
        symbols = {name: base + rva for name, rva in report["symbols"].items()}
        functions = [
            "LoadLibraryA",
            "GetProcAddress",
            "FreeLibrary",
            "CreateFileA",
            "CloseHandle",
            "WideCharToMultiByte",
        ]
        thunks = {}
        for index, name in enumerate(functions):
            address = arena + 0x8000 + index * 16
            machine.mem_write(symbols["__imp_" + name], struct.pack("<Q", address))
            thunks[address] = name
        for index, name in enumerate(
            ("GetEnvironmentVariableA", "SHGetKnownFolderPath", "CoTaskMemFree")
        ):
            thunks[arena + 0x9000 + index * 16] = name
        destination, stack, sentinel = (
            arena + 0x1000,
            arena + 0xE000 - 8,
            arena + 0xF000,
        )
        control = arena + 0x4000
        machine.mem_write(control, b"replay-dw-test-alpha.enabled\0")
        machine.mem_write(destination - 8, b"canary01" + b"\xcc" * 312)
        if not capacity:
            machine.mem_write(destination, b"unchanged\0")
        documents = r"C:\Users\Tester\Documents"
        machine.mem_write(arena + 0x5000, (documents + "\0").encode("utf-16le"))
        base_root = r"E:\IW8\Builds\1.20-replay"
        machine.mem_write(arena + 0x6200, (base_root + "\0").encode())
        machine.mem_write(arena + 0x6128, struct.pack("<Q", arena + 0x6200))
        machine.mem_write(symbols["gl_14E36AAD8"], struct.pack("<Q", arena + 0x6100))
        machine.mem_write(symbols["gl_14E36A9C8"], struct.pack("<Q", 0))
        native_open = []
        current_thread = 0
        for identifier, meaning in (
            ("func_1412CF280", "main"),
            ("func_1412CF260", "database"),
            ("func_1412CF2C0", "render"),
            ("func_1412CF300", "server"),
            ("func_1413D8B10", "build-path"),
            ("func_1413DA2D0", "open-file"),
        ):
            thunks[symbols[identifier]] = meaning

        def string(address):
            return bytes(machine.mem_read(address, 512)).split(b"\0", 1)[0].decode()

        def hook(uc, address, size, data):
            name = thunks.get(address)
            if address == symbols["DW_LocalBackend_IsEnabled"]:
                result = int(enabled)
            elif address == symbols["DW_LocalConfig_TestEnabled"]:
                result = control
            elif name:
                args = [
                    uc.reg_read(register)
                    for register in (
                        x.UC_X86_REG_RCX,
                        x.UC_X86_REG_RDX,
                        x.UC_X86_REG_R8,
                        x.UC_X86_REG_R9,
                    )
                ]
                rsp = uc.reg_read(x.UC_X86_REG_RSP)
                if name in ("main", "database", "render", "server"):
                    result = int(
                        current_thread
                        == ("main", "database", "render", "server").index(name)
                    )
                elif name == "build-path":
                    assert string(args[1]) == ""
                    value = string(args[0]) + "\\" + string(args[2])
                    assert len(value) < 256
                    uc.mem_write(args[3], (value + "\0").encode())
                    result = args[3]
                elif name == "open-file":
                    native_open.append(
                        (string(args[0]), string(args[1]), args[2], args[3])
                    )
                    result = 77
                elif name == "LoadLibraryA":
                    assert string(args[0]) in (
                        "kernel32.dll",
                        "shell32.dll",
                        "ole32.dll",
                    )
                    result = 99
                elif name == "GetProcAddress":
                    wanted = string(args[1])
                    result = next(at for at, item in thunks.items() if item == wanted)
                elif name == "CreateFileA":
                    assert string(args[0]) == "replay-dw-test-alpha.enabled"
                    result = 100 if flag else 0xFFFFFFFFFFFFFFFF
                elif name == "GetEnvironmentVariableA":
                    assert string(args[0]) == "REPLAY_DW_TEST_HOME"
                    encoded = override.encode() + b"\0"
                    if len(encoded) <= args[2]:
                        uc.mem_write(args[1], encoded)
                        result = len(override)
                    else:
                        result = len(encoded)
                elif name == "SHGetKnownFolderPath":
                    assert bytes(uc.mem_read(args[0], 16)) == bytes.fromhex(
                        "d09ad3fd8f23af46adb46c85480369c7"
                    )
                    assert args[1:3] == [0, 0]
                    uc.mem_write(args[3], struct.pack("<Q", arena + 0x5000))
                    result = 0
                elif name == "WideCharToMultiByte":
                    assert args[:2] == [65001, 0] and args[2] == arena + 0x5000
                    target, available = struct.unpack("<QQ", uc.mem_read(rsp + 40, 16))
                    encoded = (documents + "\0").encode()
                    result = len(encoded) if len(encoded) <= available else 0
                    if result:
                        uc.mem_write(target, encoded)
                else:
                    assert name in ("CloseHandle", "CoTaskMemFree", "FreeLibrary")
                    result = 1
            else:
                return
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
            uc.reg_write(x.UC_X86_REG_RAX, result)
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)

        machine.hook_add(unicorn.UC_HOOK_CODE, hook)
        machine.reg_write(x.UC_X86_REG_RSP, stack)
        machine.mem_write(stack, struct.pack("<Q", sentinel))
        machine.reg_write(x.UC_X86_REG_RCX, destination)
        machine.reg_write(x.UC_X86_REG_RDX, capacity)
        machine.emu_start(symbols["func_1413FB0D0"], sentinel, count=20000)
        assert machine.reg_read(x.UC_X86_REG_RIP) == sentinel
        assert string(destination) == expected, (label, string(destination))
        assert bytes(machine.mem_read(destination - 8, 8)) == b"canary01"
        if capacity:
            assert bytes(machine.mem_read(destination + capacity, 1)) == b"\xcc"
        cases.append(
            dict(
                case=label,
                passed=True,
                compiled_body_executed=True,
                os_boundaries_simulated=True,
            )
        )

        def open_case(filename, thread, mode, expected_root, suffix):
            nonlocal current_thread
            current_thread = thread
            native_open.clear()
            machine.mem_write(arena + 0x6000, (filename + "\0").encode())
            machine.reg_write(x.UC_X86_REG_RSP, stack)
            machine.mem_write(stack, struct.pack("<Q", sentinel))
            machine.reg_write(x.UC_X86_REG_RCX, arena + 0x6000)
            machine.reg_write(x.UC_X86_REG_RDX, mode)
            machine.emu_start(symbols["func_1413D9900"], sentinel, count=20000)
            assert machine.reg_read(x.UC_X86_REG_RIP) == sentinel
            if expected_root is None:
                assert machine.reg_read(x.UC_X86_REG_RAX) == 0 and not native_open
            else:
                assert machine.reg_read(x.UC_X86_REG_RAX) == 77
                assert native_open == [
                    (filename, expected_root + "\\" + filename, thread, int(mode != 0))
                ]
            cases.append(
                dict(
                    case=label + ":" + suffix,
                    passed=True,
                    compiled_body_executed=True,
                    native_handle_boundary_simulated=True,
                )
            )

        cache_root = override if enabled and flag and override else base_root
        if (
            enabled
            and flag
            and override
            and (
                not override.startswith("E:\\")
                or ":" in override[2:]
                or len(override) >= 256
            )
        ):
            cache_root = None
        open_case("toc1.dcache", 0, 1, cache_root, "cache-open")
        if label == "private-absolute-cache":
            for leaf in ("toc0.dcache", "data0.dcache", "data1.dcache"):
                open_case(leaf, 0, 1, override, leaf)
            open_case("asset.ff", 0, 1, base_root, "asset-base-preserved")
            for thread in (1, 2, 3, 5):
                open_case("toc1.dcache", thread, 1, override, "thread-" + str(thread))
            for mode in (0, 3):
                open_case("toc1.dcache", 0, mode, override, "mode-" + str(mode))
    return cases
