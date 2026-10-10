"""Execute linked progression confirmation, unlock and Verdansk consumers."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as reg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    image = args.build / report["executable"]
    pe = pefile.PE(str(image), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    symbols = {name: base + rva for name, rva in report["symbols"].items()}
    checks = []

    def machine():
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        arena = 0x100000000
        vm.mem_map(arena, 0x20000)
        mapped = set()
        def page(address):
            target = address & ~4095
            if target in mapped:
                return
            assert base <= target < base + pe.OPTIONAL_HEADER.SizeOfImage
            vm.mem_map(target, 4096)
            data = pe.get_data(target - base, 4096)
            if data:
                vm.mem_write(target, data)
            mapped.add(target)
        def missing(vm, access, address, size, value, context):
            if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
                rip = vm.reg_read(reg.UC_X86_REG_RIP)
                nearest = max((target, key) for key, target in symbols.items() if target <= rip)
                print("Unmodeled reset boundary:", nearest[1], hex(rip - nearest[0]), hex(address), access)
                return False
            page(address)
            page(address + size - 1)
            return True
        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        def write(address, data):
            for at in range(address & ~4095, address + len(data), 4096):
                if not arena <= at < arena + 0x20000:
                    page(at)
            vm.mem_write(address, data)
        def call(name, *arguments):
            stack, stop = arena + 0x1DF88, arena + 0x1F000
            vm.mem_write(stack, struct.pack("<Q", stop))
            for target, value in zip((reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX,
                                      reg.UC_X86_REG_R8, reg.UC_X86_REG_R9), arguments):
                vm.reg_write(target, value)
            vm.reg_write(reg.UC_X86_REG_RSP, stack)
            vm.emu_start(name if isinstance(name, int) else symbols[name], stop, count=1000000)
            assert vm.reg_read(reg.UC_X86_REG_RIP) == stop
            return vm.reg_read(reg.UC_X86_REG_RAX)
        def returned(value=0):
            stack = vm.reg_read(reg.UC_X86_REG_RSP)
            target = struct.unpack("<Q", vm.mem_read(stack, 8))[0]
            vm.reg_write(reg.UC_X86_REG_RAX, value & (2**64 - 1))
            vm.reg_write(reg.UC_X86_REG_RSP, stack + 8)
            vm.reg_write(reg.UC_X86_REG_RIP, target)
        def string(address):
            out = bytearray()
            for at in range(1024):
                if base <= address + at < base + pe.OPTIONAL_HEADER.SizeOfImage:
                    page(address + at)
                byte = vm.mem_read(address + at, 1)[0]
                if not byte:
                    return out.decode()
                out.append(byte)
            raise AssertionError("Unterminated native text")
        return vm, arena, write, call, returned, string

    identifiers = ("NLOTNSOSKK", "OLKMKMTKRO", "LLQQNOO",
                   "MNLPOPMMSK", "LSPQSSPSOL", "NQRLNKMTSL")
    for unlock in (False, True):
        vm, arena, write, call, returned, string = machine()
        thunks, lookups, updates = {}, [], []
        imports = {}
        for index, name in enumerate(("LoadLibraryA", "GetProcAddress", "FreeLibrary")):
            thunk = arena + 0x17000 + index * 16
            write(symbols["__imp_" + name], struct.pack("<Q", thunk))
            imports[thunk] = name
        def boundary(vm, address, size, context):
            rcx, rdx, r8 = (vm.reg_read(r) for r in
                           (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX, reg.UC_X86_REG_R8))
            if imports.get(address) == "LoadLibraryA":
                assert string(rcx) == "kernel32.dll"
                returned(99)
            elif imports.get(address) == "GetProcAddress":
                name = string(rdx)
                thunk = arena + 0x18000 + len(thunks) * 16
                thunks[thunk] = name
                returned(thunk)
            elif imports.get(address) == "FreeLibrary":
                returned(1)
            elif address in thunks:
                name = thunks[address]
                assert name in ("GetTickCount", "GetEnvironmentVariableW"), name
                returned(1000 if name == "GetTickCount" else 0)
            elif address == symbols["DW_LocalPlatform_UserId"]:
                returned(42)
            elif address == symbols["Sys_IsMainThread"]:
                returned(1)
            elif address == symbols["Cmd_AddCommandInternal"]:
                assert string(rcx) == "dw_resetProgression"
                returned()
            elif address == symbols["DW_LocalConfig_Rank"]:
                returned(0)
            elif address == symbols["DW_LocalConfig_UnlockAll"]:
                returned(unlock)
            elif address == symbols["Dvar_FindVarByName"]:
                name = string(rcx)
                assert name in identifiers
                lookups.append(name)
                dvar = arena + 0x1000 + identifiers.index(name) * 128
                write(dvar, bytes(112))
                returned(dvar)
            elif address == symbols["Dvar_SetVariant"]:
                assert r8 == 0 and bytes(vm.mem_read(rdx, 1)) == bytes([unlock])
                updates.append(rcx)
                returned()
        vm.hook_add(UC_HOOK_CODE, boundary)
        call("DW_LocalProgression_Frame")
        assert tuple(lookups) == identifiers and len(set(updates)) == 6
        call("DW_LocalProgression_Frame")
        assert len(lookups) == 6
        checks.append(f"linked unlock_all={int(unlock)} applies all six encoded native controls and coalesces frame polling")

    vm, arena, write, call, returned, string = machine()
    enabled = True
    row_calls = []
    def boundary(vm, address, size, context):
        if address == symbols["DW_LocalBackend_IsEnabled"]:
            returned(enabled)
        elif address == symbols["Com_GameMode_GetActiveGameMode"]:
            returned(2)
        elif address == symbols["func_1413E2FE0"]:
            # The original row selector is unchanged. Model its result at the
            # API boundary to test the compiled complete-layout consumer.
            row_calls.append(vm.reg_read(reg.UC_X86_REG_RCX))
            returned(0)
        elif address == symbols["func_1412B0570"]:
            returned()
    vm.hook_add(UC_HOOK_CODE, boundary)
    table, name, value, pool, indices = (arena + n for n in (0x1000, 0x2000, 0x2100, 0x3000, 0x4000))
    write(name, b"mp/mapInfo.csv\0")
    write(value, b"mp_donetsk\0")
    write(pool, struct.pack("<Q", arena + 0x5000))
    write(arena + 0x5000, b"1\0")
    write(indices, bytes(29 * 2))
    write(table, struct.pack("<QiiiiQQQ", name, 29, 1, 1, 0, indices, 0, pool))
    before = bytes(vm.mem_read(table, 48))
    for selected, column, expected in ((True, 28, "0"), (False, 28, "1"), (True, 27, "1")):
        enabled = selected
        assert string(call("func_1413E2BA0", table, 0, value, column)) == expected
    write(value, b"mp_shipment\0")
    assert string(call("func_1413E2BA0", table, 0, value, 28)) == "1"
    assert string(call("func_1413E2BA0", table, 0, value, 29)) == ""
    assert string(call("func_1413E2BA0", 0, 0, value, 28)) == ""
    assert bytes(vm.mem_read(table, 48)) == before
    checks.append("linked Verdansk hide-column override preserves other maps, tables, bounds and the native table's bytes")
    info = symbols["gl_14C4FC330"]
    write(info, struct.pack("<I", 3))
    for i, gametype in enumerate(("war", "dm", "br")):
        write(info + 4 + 172*i, gametype.encode() + b"\0")
    write(info + 5512 + 32, b"mp_donetsk\0")
    write(info + 5512 + 208, b"br\0")
    assert string(call("func_141B9D400", 0)) == "war dm br"
    enabled = False
    assert string(call("func_141B9D400", 0)) == "br"
    enabled = True
    write(info + 5512 + 32, b"mp_shipment\0")
    assert string(call("func_141B9D400", 0)) == "br"
    checks.append("linked Verdansk local/custom selector advertises loaded native game types while preserving other map/default consumers")
    vm, arena, write, call, returned, string = machine()
    enabled, file_error, files, probes, logs = True, 2, {}, [], []
    imports = {}
    for i, name in enumerate(("GetFileAttributesW", "GetLastError")):
        thunk = arena + 0x17000 + i * 16
        write(symbols["__imp_" + name], struct.pack("<Q", thunk))
        imports[thunk] = name
    def collision_boundary(vm, address, size, context):
        if address == symbols["DW_LocalBackend_IsEnabled"]:
            returned(enabled)
        elif imports.get(address) == "GetFileAttributesW":
            pointer = vm.reg_read(reg.UC_X86_REG_RCX)
            value = bytearray()
            for offset in range(0, 2048, 2):
                location = pointer + offset
                pair = (pe.get_data(location - base, 2) if base <= location < base + pe.OPTIONAL_HEADER.SizeOfImage
                        else bytes(vm.mem_read(location, 2)))
                if pair == b"\0\0":
                    break
                value.extend(pair)
            else:
                raise AssertionError("Unterminated native file path")
            path = value.decode("utf-16-le")
            probes.append(path)
            returned(files.get(path, 0xffffffff))
        elif imports.get(address) == "GetLastError":
            returned(file_error)
        elif address == symbols["func_1412B0570"]:
            logs.append(string(vm.reg_read(reg.UC_X86_REG_RDX)))
            returned()
    vm.hook_add(UC_HOOK_CODE, collision_boundary)
    combined, tile = ("zone\\mp_donetsk_cg_ls_tr.ff", "zone\\mp_donetsk_cg_00000_tr.ff")
    cases = [
        (True, "mp_donetsk", 2, 2, {tile: 0}, 1, 2),
        (True, "mp_donetsk", 2, 3, {tile: 0}, 1, 2),
        (True, "mp_donetsk", 2, 2, {combined: 0, tile: 0}, 2, 1),
        (True, "mp_donetsk", 2, 5, {tile: 0}, 2, 1),
        (True, "mp_donetsk", 2, 2, {}, 2, 2),
        (True, "mp_donetsk", 2, 2, {tile: 0x10}, 2, 2),
        (False, "mp_donetsk", 2, 2, {tile: 0}, 2, 0),
        (True, "mp_shipment", 2, 2, {tile: 0}, 2, 0),
        (True, "MP_DONETSK", 2, 2, {tile: 0}, 1, 2),
        (True, "mp_donetsk", 0, 2, {tile: 0}, 0, 0),
        (True, "mp_donetsk", 1, 2, {tile: 0}, 1, 0),
        (True, "mp_donetsk", 3, 2, {tile: 0}, 3, 0),
    ]
    for selected, mapname, mode, error, paths, expected, count in cases:
        enabled, file_error, files = selected, error, paths
        probes.clear(); logs.clear()
        write(arena + 0x1000, mapname.encode() + b"\0")
        write(symbols["gl_145CC7538"], struct.pack("<Q", arena + 0x1000))
        call("CL_TransientsCollisionMP_SetTransientMode", mode)
        assert struct.unpack("<i", vm.mem_read(symbols["gl_145CC7534"], 4))[0] == expected
        assert len(probes) == count and len(logs) == int(mode == 2 and expected == 1)
    checks.append("linked Verdansk collision policy uses native numbered-tile mode only for absent combined packages with a present tile; 12 cases preserve other maps, modes, disabled DW and file errors")

    # Execute the compiled command and its real Lua 5.1 popup program against
    # the shipped PopupYesNo factory. Only rendering and Win32 storage are models.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".toolchains/lua-contract-tests"))
    from lupa.lua51 import LuaRuntime
    vm, arena, write, call, returned, string = machine()
    ini = "E:\\Fixture\\game.ini"
    original_ini = b"\xef\xbb\xbfhost=162.243.115.160\r\nplayer_name=FixturePlayer\r\nunlock_all=1\r\nrank=53\r\n"
    files, handles, imports, dynamic, commands, callbacks = {ini: original_ini}, {}, {}, {}, {}, {}
    operations, queued, popup = [], [], []
    state = dict(user=42, lobby=False, frontend=True, tick=1000, lua_error=False, file_error=2)
    source = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all\ui\widgets\popups.lua.2561.lua").read_text()
    factory = source[source.index("local function var_0_4("):source.index("local function var_0_5(")]
    factory = factory.replace("local function var_0_4(", "function ReplayPopupFactory(", 1)
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.globals().MenuBuilder = lua.table_from({"BuildRegisteredType": lambda kind, options: options})
    lua.execute(factory)

    def request_popup(parent, kind, modal, controller, replace, options):
        assert parent is None and kind == "PopupYesNo" and controller == 0
        dialog = lua.globals().ReplayPopupFactory(None, options)
        assert dialog.defaultFocusIndex == 2 and dialog.buttonsClosePopup and dialog.cancelClosesPopup
        assert dialog.buttons[1].label == "Yes" and dialog.buttons[2].label == "No"
        assert "Battle Pass" in dialog.message and "cannot be undone" in dialog.message
        popup.append(dialog)

    lua.globals().LUI = lua.table_from({"FlowManager": lua.table_from({"RequestPopupMenu": request_popup})})
    vm_pointer = arena + 0x6000
    write(symbols["gl_151868880"], struct.pack("<Q", vm_pointer))
    for i, name in enumerate(("GetModuleFileNameA", "CreateFileA", "ReadFile", "WriteFile", "FlushFileBuffers", "CloseHandle", "GetLastError", "LoadLibraryA", "GetProcAddress", "FreeLibrary")):
        thunk = arena + 0x15000 + i * 16
        imports[thunk] = name
        write(symbols["__imp_" + name], struct.pack("<Q", thunk))

    def wide(address):
        value = bytearray()
        for i in range(0, 2200, 2):
            pair = bytes(vm.mem_read(address + i, 2))
            if pair == b"\0\0":
                return value.decode("utf-16-le")
            value.extend(pair)
        raise AssertionError("Unterminated wide path")

    def reset_boundary(vm, address, size, context):
        a = [vm.reg_read(r) for r in (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX, reg.UC_X86_REG_R8, reg.UC_X86_REG_R9)]
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        name = imports.get(address) or dynamic.get(address)
        if address == symbols["sub_1421CCEF0"]:
            amount = vm.reg_read(reg.UC_X86_REG_RAX)
            assert arena <= rsp - amount < rsp < arena + 0x20000
            returned(amount)
        elif name in ("LoadLibraryA", "FreeLibrary", "CreateDirectoryW", "FlushFileBuffers", "CloseHandle"):
            returned(1)
        elif name == "GetProcAddress":
            thunk = arena + 0x17000 + len(dynamic) * 16
            dynamic[thunk] = string(a[1])
            returned(thunk)
        elif name == "GetModuleFileNameA":
            path = b"E:\\Fixture\\game.exe\0"
            write(a[1], path)
            returned(len(path) - 1)
        elif name == "GetTickCount":
            returned(state["tick"])
        elif name == "GetEnvironmentVariableW":
            assert wide(a[0]) == "LOCALAPPDATA"
            path = "E:\\Fixture"
            write(a[1], (path + "\0").encode("utf-16-le"))
            returned(len(path))
        elif name in ("CreateFileA", "CreateFileW"):
            path = string(a[0]) if name.endswith("A") else wide(a[0])
            creation = struct.unpack("<I", vm.mem_read(rsp + 40, 4))[0]
            if creation == 3 and path not in files:
                state["file_error"] = 2
                returned(2**64 - 1)
            else:
                handle = 100 + len(handles)
                if creation == 2:
                    files[path] = b""
                handles[handle] = [path, 0]
                returned(handle)
        elif name == "ReadFile":
            path, cursor = handles[a[0]]
            body = files[path][cursor:cursor + a[2]]
            write(a[1], body)
            write(a[3], struct.pack("<I", len(body)))
            handles[a[0]][1] += len(body)
            returned(1)
        elif name == "WriteFile":
            path = handles[a[0]][0]
            files[path] = bytes(vm.mem_read(a[1], a[2]))
            write(a[3], struct.pack("<I", a[2]))
            operations.append("write:" + path)
            returned(1)
        elif name in ("MoveFileExA", "MoveFileExW"):
            first, second = (string(a[i]) if name.endswith("A") else wide(a[i]) for i in range(2))
            assert a[2] == 9 and first.endswith(".pending"), (name, first, second, a[2])
            files[second] = files.pop(first)
            operations.append("publish:" + second)
            returned(1)
        elif name == "GetLastError":
            returned(state["file_error"])
        elif address == symbols["DW_LocalPlatform_UserId"]:
            returned(state["user"])
        elif address in (symbols["Sys_IsMainThread"], symbols["DW_LocalBackend_IsEnabled"]):
            returned(1)
        elif address == symbols["Com_FrontEnd_IsInFrontEnd"]:
            returned(state["frontend"])
        elif address == symbols["func_141187FA0"]:
            returned(state["lobby"])
        elif address == symbols["Cmd_Argc"]:
            returned(1)
        elif address == symbols["Cmd_AddCommandInternal"]:
            commands[string(a[0])] = a[1]
            returned()
        elif address == symbols["Dvar_FindVarByName"]:
            returned(0)
        elif address == symbols["DW_Progression_StatsSource"]:
            returned(1)
        elif address == symbols["DW_Progression_ResetStats"]:
            assert a[:2] == [0, 1]
            operations.append("native-full-stats-reset")
            returned()
        elif address == symbols["DW_Progression_SaveStats"]:
            assert a[0] == 0
            operations.append("native-stats-save")
            returned()
        elif address == symbols["DW_Progression_QueueCommand"]:
            queued.append(string(a[1]))
            operations.append("queued-restart")
            returned()
        elif address in (symbols["DW_Progression_LUILock"], symbols["DW_Progression_LUIUnlock"]):
            returned()
        elif address == symbols["DW_Progression_LuaTop"]:
            returned(11)
        elif address == symbols["DW_Progression_LuaClosure"]:
            callbacks["pending"] = a[1]
            returned()
        elif address == symbols["DW_Progression_LuaSetField"]:
            assert a[1] & 0xFFFFFFFF == (-10002 & 0xFFFFFFFF)
            pointer = callbacks["pending"]
            def callback(*unused, pointer=pointer):
                assert call(pointer, vm_pointer) == 0
            lua.globals()[string(a[2])] = callback
            returned()
        elif address == symbols["DW_Progression_LuaLoad"]:
            callbacks["source"] = bytes(vm.mem_read(a[1], a[2])).decode()
            returned(0)
        elif address == symbols["DW_Progression_LuaCall"]:
            assert a[1:] == [0, 0, 0]
            if state["lua_error"]:
                returned(1)
            else:
                lua.execute(callbacks["source"])
                returned(0)
        elif address == symbols["DW_Progression_LuaSetTop"]:
            assert a[1] == 11
            returned()
        elif address == symbols["Com_Printf"]:
            returned()

    vm.hook_add(UC_HOOK_CODE, reset_boundary)
    call("DW_LocalProgression_Frame")
    reset_command = commands["dw_resetProgression"]
    untouched = dict(files)
    call(reset_command)
    assert len(popup) == 1 and files == untouched and not queued
    popup[-1].buttons[2].action()
    call("DW_LocalProgression_Frame")
    assert files == untouched and not queued
    call(reset_command)
    popup[-1].cancelAction()
    call("DW_LocalProgression_Frame")
    assert files == untouched and not queued
    state["lua_error"] = True
    call(reset_command)
    call("DW_LocalProgression_Frame")
    assert files == untouched and not queued
    state["lua_error"] = False
    state["lobby"] = True
    count = len(popup)
    call(reset_command)
    assert len(popup) == count and files == untouched
    state["lobby"] = False
    call(reset_command)
    popup[-1].buttons[1].action()
    state["user"] = 43
    call("DW_LocalProgression_Frame")
    assert files == untouched and not queued
    state["user"] = 42
    call(reset_command)
    popup[-1].buttons[1].action()
    assert files == untouched and not queued # Callback never resets under the LUI lock.
    call("DW_LocalProgression_Frame")
    assert queued == ["sys_restart\n"] and operations[-3:] == ["native-full-stats-reset", "native-stats-save", "queued-restart"]
    assert files[ini] == original_ini.replace(b"unlock_all=1", b"unlock_all=0").replace(b"rank=53", b"rank=0")
    progression = files["E:\\Fixture\\ReplayDW\\player-progression.bin"]
    magic, version, owner, xp, rank, pending_reset, checksum = struct.unpack("<IIQQIIQ", progression)
    assert (magic, version, owner, xp, rank, pending_reset) == (0x31505852, 1, 42, 0, 0, 1)
    expected = 14695981039346656037
    for byte in progression[:32]:
        expected = ((expected ^ byte) * 1099511628211) & (2**64 - 1)
    assert checksum == expected
    saved_user, saved_xp, saved_rank = (arena + offset for offset in (0x7000, 0x7010, 0x7020))
    assert call("DW_LocalProgression_LoginFields", saved_user, saved_xp, saved_rank) == 1
    assert struct.unpack("<Q", vm.mem_read(saved_user, 8))[0] == 42
    assert bytes(vm.mem_read(saved_xp, 8)) == bytes(8)
    assert bytes(vm.mem_read(saved_rank, 4)) == bytes(4)
    assert call("DW_LocalProgression_ResetRequested") == 1
    reset_file = "E:\\Fixture\\ReplayDW\\player-progression.bin"
    call("DW_LocalProgression_ResetAuthenticated", 43)
    state["tick"] += 300
    call("DW_LocalProgression_Frame")
    assert files[reset_file] == progression and call("DW_LocalProgression_ResetRequested") == 1
    call("DW_LocalProgression_ResetAuthenticated", 42)
    assert files[reset_file] == progression # Worker publishes only an atomic acknowledgement.
    state["tick"] += 300
    call("DW_LocalProgression_Frame")
    assert struct.unpack("<IIQQIIQ", files[reset_file])[2:6] == (42, 0, 0, 0)
    assert call("DW_LocalProgression_ResetRequested") == 0 and queued == ["sys_restart\n"]
    checks.append("Compiled command executes real Lua 5.1 and shipped PopupYesNo factory with No default; No/cancel/failed popup/lobby/changed identity cause no reset; Yes queues main-thread full native reset, atomic BOM-preserving INI zeros, durable signed-reset marker and sys_restart in order; only matching authenticated reset acknowledgement clears the marker on the main thread")

    args.output.write_text(json.dumps(dict(schema=1, passed=True, checks=checks,
        executable_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        native_game_verified=False,
        modeled_boundaries=["Win32 loading/path/time/storage", "identity/frontend/lobby getters", "dvar lookup/set", "native row selector", "native stats reset/save/command queue", "Lua C closure and load/call boundary with real Lua 5.1 and shipped PopupYesNo factory", "native stack probe"],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()), indent=2) + "\n")
    print(f"PASS: {len(checks)} linked client integration groups; no game launched")


if __name__ == "__main__":
    main()
