"""Execute compiled debug-state command/frame code and native leaf getters."""
import re
import struct

import unicorn
import unicorn.x86_const as x
from layout import from_report


def verify(pe, report):
    base = pe.OPTIONAL_HEADER.ImageBase
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    ranges = []
    for section in pe.sections:
        if section.Name.rstrip(b"\0") in (b".text", b".rdata", b".data", b".cpp", b".rwcpp"):
            at = base + section.VirtualAddress
            size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & -4096
            machine.mem_map(at, size)
            machine.mem_write(at, section.get_data())
            ranges.append((at, at + size))
    arena = 0x100000000
    machine.mem_map(arena, 0x40000)
    ranges.append((arena, arena + 0x40000))
    frontend = arena + 0x100000
    machine.mem_map(frontend, 0x99c000)
    ranges.append((frontend, frontend + 0x99c000))
    symbols = {name: base + rva for name, rva in report["symbols"].items()}
    moved = lambda rva: base + from_report(rva, report)
    def write(address, value, format="<I"):
        machine.mem_write(address, struct.pack(format, value))

    def string(address, limit=2048):
        data = bytearray()
        for offset in range(limit):
            c = bytes(machine.mem_read(address + offset, 1))[0]
            if not c:
                return data.decode("ascii")
            data.append(c)
        raise ValueError("Unterminated debug string")

    state = symbols["s_comDebugStates"]
    write(moved(0x5CC4924), 1)
    write(moved(0x5CC4920), 0)
    write(moved(0xEF28AE0), 1, "<B")
    write(moved(0xEF28C10), 2)
    write(moved(0xC5244E0), 2, "<B")
    write(symbols["s_comDObjCount"], 2048)
    write(symbols["s_comDObjFreeCount"], 2000)
    write(symbols["s_comDObjBuffer"], arena + 0x1000, "<Q")
    write(symbols["s_dvarCount"], 1234)
    write(symbols["ui_serverFrameDuration"], arena + 0x2000, "<Q")
    write(arena + 0x201d, 5, "<B")
    write(arena + 0x2028, report["registration_default"])
    write(symbols["cls_smallDevFont"], arena + 0x3000, "<Q")
    write(arena + 0x3008, 14)
    viewport = (1920, 1080)
    def set_viewport(width, height):
        values = [1.0] * 27
        values[6:10] = [0.0, 0.0, float(width), float(height)]
        values[14:18] = [0.0, 0.0, float(width), float(height)]
        machine.mem_write(symbols["scrPlaceFull"], struct.pack("<27f", *values))
    set_viewport(*viewport)
    write(symbols["streamFrontendGlob"], frontend, "<Q")
    write(frontend + 0x98b0c0, 4)
    write(moved(0xD57FA40), 123, "<Q")
    modules = symbols["s_fastfileLoadModules"]
    write(modules + 0x24, 4, "<B")
    write(modules + 0x28, 0.25, "<f")
    machine.mem_write(modules + 0x38, b"global_mp\0")
    for index in range(6):
        queue = arena + 0x5000 + index * 64
        table = symbols["s_worldRequestQueue"] if index < 3 else symbols["s_clientRequestQueue"]
        write(table + index * 8, queue, "<Q")
        write(queue + 0x20, index + 1)
        write(queue + 0x24, (index + 1) * 2)
    for index in range(27):
        object_address = arena + 0x4000 + index * 96
        write(symbols["s_fenceObjects"] + index * 8, object_address, "<Q")
        write(object_address, arena + 0x6000, "<Q")
        machine.mem_write(object_address + 12, bytes((1, index % 2, 0)))
    write(arena + 0x6000, arena + 0x6100, "<Q")
    write(arena + 0x4010, 7)  # virtual error code differs from controller zero
    for mode in range(4):
        write(moved(0xC26A708 + mode * 12), mode + 10)

    calls, draws, placements, captures = [], [], [], []
    main_thread, argc, argv = True, 1, ["com_debugStates"]
    screen_mode = None
    screen_events = []
    simulation_row = int("SV_HostScale_GetSimulationFPS" in symbols)
    simulation_rate = 62.5
    sentinel = arena + 0x38000
    rsp = arena + 0x30000 - 8

    def ret(value=0):
        current_rsp = machine.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack("<Q", machine.mem_read(current_rsp, 8))[0]
        machine.reg_write(x.UC_X86_REG_RAX, value & 0xffffffffffffffff)
        machine.reg_write(x.UC_X86_REG_RSP, current_rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, target)

    def arguments():
        current_rsp = machine.reg_read(x.UC_X86_REG_RSP)
        return [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX,
                                             x.UC_X86_REG_R8, x.UC_X86_REG_R9)] + [
            struct.unpack("<Q", machine.mem_read(current_rsp + 0x28 + i * 8, 8))[0]
            for i in range(12)]

    def format_text(format_address, values):
        fmt = string(format_address)
        used = []
        for index, match in enumerate(re.finditer(r"%(?:[-0-9.]*)[sduf]", fmt)):
            kind = match.group()[-1]
            value = values[index]
            if kind == "s":
                value = string(value)
            elif kind == "d":
                value = struct.unpack("<i", struct.pack("<I", value & 0xffffffff))[0]
            elif kind == "f":
                value = struct.unpack("<d", struct.pack("<Q", value))[0]
            else:
                value &= 0xffffffff
            used.append(value)
        return fmt % tuple(used)

    intercepted = {symbols[name]: name for name in (
        "Sys_IsMainThread", "Cmd_Argc", "Cmd_Argv", "Com_sprintf", "Com_Printf",
        "CL_DrawText", "R_TextWidth", "Sys_EnterCriticalSection", "Sys_LeaveCriticalSection")}
    if report.get("frontend_freecam"):
        # Frame registration now also owns the camera string dvar. This VM
        # checks overlay/command lifecycle, not native dvar allocation or TLS.
        for name in ("Dvar_BeginPermanentRegistration", "Dvar_EndPermanentRegistration",
                     "Dvar_RegisterString"):
            intercepted[symbols[name]] = name
    if report.get("optimized"):
        for name in ("Dvar_BeginPermanentRegistration", "Dvar_EndPermanentRegistration", "Dvar_RegisterInt"):
            intercepted[symbols[name]] = name
    if "DW_LocalBackend_Frame" in symbols:
        filename_thunk = arena + 0x39200
        write(symbols["__imp_GetModuleFileNameA"], filename_thunk, "<Q")
        intercepted[filename_thunk] = "GetModuleFileNameA"
    intercepted[symbols["SV_HostScale_Frame"]] = "SV_HostScale_Frame"
    if simulation_row:
        intercepted[symbols["SV_HostScale_GetSimulationFPS"]] = "SV_HostScale_GetSimulationFPS"
    query = symbols["__imp_VirtualQuery"]
    query_thunk = arena + 0x39000
    write(query, query_thunk, "<Q")
    intercepted[query_thunk] = "VirtualQuery"
    intercepted[arena + 0x6100] = "FenceObject_GetErrorCode"
    wait_thunk = arena + 0x39100
    write(symbols["__imp_WaitForSingleObject"], wait_thunk, "<Q")
    intercepted[wait_thunk] = "WaitForSingleObject"
    # Execute the recovered CL_Screen_UpdateFrame submission tail, including
    # its real relocated call to the new C++ ScrPlace_EndFrame. Only platform
    # rendering/workers and the skinning callback are stand-ins.
    screen_calls = {moved(rva): name for rva,name in (
        (0x19CF160,"workers"), (0x13C6C40,"stream_end"),
        (0x1966950,"render_end"), (0x1967450,"submit"),
        (0x15B43A0,"game_mode"), (0x15B43B0,"application"),
        (0x21CCF60,"cookie"))}
    screen_calls[arena+0x6300] = "skinning"
    write(arena+0x6200,arena+0x6280,"<Q")
    write(arena+0x6280+0x30,arena+0x6300,"<Q")

    def on_code(uc, address, size, _):
        if address in (symbols.get("Sys_UpdateGameWindowTitle"), symbols.get("DW_LocalBackend_Frame")):
            # Window hashing/Win32 and the live backend's network/platform
            # calls have separate validation. This VM checks the overlay and
            # placement lifecycle; its IAT intentionally has no network APIs.
            ret()
            return
        if screen_mode is not None and address in screen_calls:
            name = screen_calls[address]
            screen_events.append(name)
            ret(screen_mode if name == "game_mode" else arena+0x6200 if name == "application" else 0)
            return
        if address == symbols["Com_DebugStates_Capture"]:
            captures.append(struct.unpack("<I", uc.mem_read(state + 8, 4))[0])
        if address == symbols["Cmd_AddCommandInternal"]:
            args = arguments()
            calls.append(("register", string(args[0]), args[1], args[2]))
            return  # exercise the real native command-list insertion
        name = intercepted.get(address)
        if name is None:
            return
        args = arguments()
        if name == "GetModuleFileNameA":
            path = b"game_dx12_ship_replay.exe"
            assert args[0] == 0 and args[2] > len(path)
            machine.mem_write(args[1], path + b"\0")
            ret(len(path))
        elif name == "Dvar_RegisterInt":
            assert string(args[0]) == "com_optimized" and args[1:4] == [1, 0, 2]
            write(arena + 0x7080 + 29, 5, "<B")
            ret(arena + 0x7080)
        elif name == "SV_HostScale_Frame":
            ret(0)  # Independently verified host-scale registration boundary.
        elif name == "SV_HostScale_GetSimulationFPS":
            machine.reg_write(x.UC_X86_REG_XMM0, struct.unpack("<I", struct.pack("<f", simulation_rate))[0])
            ret()
        elif name == "Sys_IsMainThread":
            ret(main_thread)
        elif name in ("Dvar_BeginPermanentRegistration", "Dvar_EndPermanentRegistration"):
            ret()
        elif name == "Dvar_RegisterString":
            assert string(args[0]) == "com_frontEndCamera" and string(args[1]) == ""
            assert args[2] == 0
            ret(arena + 0x7000)
        elif name == "Cmd_Argc":
            ret(argc)
        elif name == "Cmd_Argv":
            assert args[0] == 1
            machine.mem_write(arena + 0x100, argv[1].encode() + b"\0")
            ret(arena + 0x100)
        elif name == "Com_sprintf":
            text = format_text(args[2], args[3:])
            machine.mem_write(args[0], text.encode()[:args[1]-1] + b"\0")
            ret(len(text))
        elif name == "Com_Printf":
            calls.append(("print", format_text(args[1], args[2:])))
            ret()
        elif name == "CL_DrawText":
            if screen_mode is not None:
                screen_events.append("draw")
            assert args[0] != symbols["scrPlaceFull"] and args[2] == 95
            geometry = struct.unpack("<27f", uc.mem_read(args[0], 108))
            expected = (viewport[0]*0.05, viewport[1]*0.05,
                        viewport[0]*0.95, viewport[1]*0.95)
            assert all(abs(a-b) < 0.001 for a,b in zip(geometry[14:18], expected))
            assert args[3] == arena + 0x3000
            draws.append(string(args[1], 96))
            floats = lambda value: struct.unpack("<f", struct.pack("<I", value & 0xffffffff))[0]
            # Integer stack arguments occupy DWORDs; their upper halves can
            # retain an earlier caller's values after the common frame tail.
            placement = (floats(args[4]), floats(args[5]), args[6]&0xffffffff, args[7]&0xffffffff,
                         floats(args[8]), floats(args[9]), args[11]&0xffffffff)
            assert placement[4:] == (0.75, 0.75, 7), placement
            placements.append(placement)
            ret()
        elif name == "R_TextWidth":
            assert args[1:3] == [95, arena + 0x3000]
            ret(len(string(args[0], 96)) * 8)
        elif name == "FenceObject_GetErrorCode":
            assert arena + 0x4000 <= args[0] < arena + 0x4000 + 27 * 96
            ret(struct.unpack("<I", uc.mem_read(args[0] + 16, 4))[0])
        elif name == "WaitForSingleObject":
            assert args[:2] == [123, 0]  # native database readiness poll never waits
            ret(0)
        elif name.startswith("Sys_"):
            assert args[0] == 9
            calls.append((name,))
            ret()
        else:
            region = next(((a, b) for a, b in ranges if a <= args[0] < b), None)
            if region:
                a, b = region
                machine.mem_write(args[1], struct.pack("<QQIHHQIIII", a, a, 4, 0, 0,
                                  b-a, 0x1000, 4, 0x20000, 0))
                ret(48)
            else:
                ret(0)

    machine.hook_add(unicorn.UC_HOOK_CODE, on_code)

    def run(name, *args):
        machine.reg_write(x.UC_X86_REG_RSP, rsp)
        write(rsp, sentinel, "<Q")
        for register, value in zip((x.UC_X86_REG_RCX, x.UC_X86_REG_RDX,
                                    x.UC_X86_REG_R8, x.UC_X86_REG_R9), args):
            machine.reg_write(register, value)
        machine.emu_start(symbols[name], sentinel, count=200000)
        assert machine.reg_read(x.UC_X86_REG_RIP) == sentinel

    def snapshot():
        header = struct.unpack("<10I", machine.mem_read(state, 40))
        rows = [[string(state + 40 + (column * 32 + row) * 96, 96)
                 for row in range(header[8 + column])] for column in range(2)]
        return header, rows

    def command(argument=None):
        nonlocal argc, argv
        argv = ["com_debugStates"] + ([] if argument is None else [argument])
        argc = len(argv)
        run("Com_DebugStates_f")

    if report.get("optimized"):
        command("1")
    run("ScrPlace_EndFrame")
    expected_commands = {'com_debugStates'}
    if report.get('frontend_freecam'): expected_commands.add('toggle_frontend_freecam')
    if report.get('frontend_probe') and 'Com_FrontEndScene_RegisterCommands' in report['symbols']:
        expected_commands.update(('com_frontEndScene', 'com_frontEndAnimation', 'db_frontendMaterialInfo', 'db_frontendWeaponInfo'))
    registered_names = [c[1] for c in calls if c[0] == 'register']
    assert len(registered_names) == len(expected_commands) and set(registered_names) == expected_commands
    if report.get("frontend_freecam"):
        freecam = next(c for c in calls if c[0] == "register" and c[1] == "toggle_frontend_freecam")
        assert freecam[2] == symbols["Com_FrontEndScene_ToggleFreeCam_f"]
        assert struct.unpack("<Q", machine.mem_read(freecam[3] + 32, 8))[0] == freecam[2]

    assert snapshot()[0][1] == 1 and snapshot()[0][5] == 1
    assert captures == [1]  # automatic developer text before any command
    assert struct.unpack("<i",machine.mem_read(symbols["activeScreenPlacementMode"],4))[0] == 3
    assert draws[0] == "global_mp: 0.25 failed"
    assert placements[0][:4] == (15 - len(draws[0]) * 6, 20.5, 3, 1)
    fence = draws.index("Active 7 ")
    assert placements[fence][:4] == (25 - len(draws[fence]) * 6, 30.5, 1, 1)
    assert placements[fence + 1][:4] == (25, 30.5, 1, 1)
    assert placements[-1][2:4] == (1, 3) and abs(placements[-1][1] + 10) < 0.0001, placements[-1]
    per_frame_draws = len(draws)
    assert not any("Passing" in text or text.startswith("fastfile[") for text in draws)
    command("1")
    for _ in range(41):
        run("ScrPlace_EndFrame")
    header, rows = snapshot()
    assert captures == [1, 2, 22, 42], captures
    assert header[1] == 1 and header[4] == 4 and header[5] == 42
    assert header[8:] == (27 + simulation_row, 29) and header[7] == 0
    if simulation_row:
        assert "Simulation FPS: 62.5 (local server)" in rows[0]
    assert any("curDifficulty: 2" in r for r in rows[0])
    assert any("DObj used: 47" in r for r in rows[0])
    assert f"ui_serverFrameDuration: {report['registration_default']}" in rows[0]
    assert "OnlineData [none/SP/MP/CP]: 10/11/12/13" in rows[0]
    assert "global_mp: 0.25 failed" in rows[0]
    assert "ClStreaming: 21m 42i" in rows[0]
    assert "DB: Ready (database-ready event)" in rows[0]
    assert "Streamer level init: Done" in rows[0]
    assert len(draws) == 42 * per_frame_draws
    # Verify the actual engine registration links our native-sized record.
    registered = next(c for c in calls if c[0] == "register" and c[1] == "com_debugStates")
    assert registered[1] == "com_debugStates" and registered[2] == symbols["Com_DebugStates_f"]
    assert struct.unpack("<Q", machine.mem_read(moved(0xD216D98), 8))[0] == registered[3]
    assert struct.unpack("<Q", machine.mem_read(registered[3] + 32, 8))[0] == registered[2]
    registered_names = [c[1] for c in calls if c[0] == 'register']
    assert len(registered_names) == len(expected_commands) and set(registered_names) == expected_commands

    for mode, elapsed in ((0,16),(1,100),(2,2000)):
        screen_mode = mode
        screen_events.clear()
        count = snapshot()[0][5]
        write(symbols["activeScreenPlacementMode"],1)
        write(moved(0xD38654C),elapsed)  # native com_frameTime, including a stall
        body_rsp = rsp-0xf8
        machine.reg_write(x.UC_X86_REG_RSP,body_rsp)
        machine.reg_write(x.UC_X86_REG_RSI,0)
        machine.reg_write(x.UC_X86_REG_RBP,0xffffffffffffffff)
        write(rsp,sentinel,"<Q")
        machine.emu_start(moved(0x15CAE17),sentinel,count=200000)
        assert machine.reg_read(x.UC_X86_REG_RIP) == sentinel
        assert snapshot()[0][5] == count+1
        assert screen_events[0] == "workers"
        assert screen_events.index("draw") < screen_events.index("render_end") < screen_events.index("submit")
        assert struct.unpack("<i",machine.mem_read(symbols["activeScreenPlacementMode"],4))[0] == 3
    screen_mode = None

    before = bytes(machine.mem_read(state, 40))
    run("Com_DebugStates_Frame", 1)
    main_thread = False
    run("ScrPlace_EndFrame")
    command("off")
    assert bytes(machine.mem_read(state, 40)) == before
    main_thread = True
    command("bogus")
    assert snapshot()[0][1] == 1
    command("off")
    count = len(draws)
    for _ in range(21):
        run("ScrPlace_EndFrame")
    assert len(draws) == count and len(captures) == 4
    command("dump")
    simulation_rate = -1
    write(symbols["s_fenceObjects"], 0, "<Q")
    write(moved(0xEF28AE0), 0, "<B")
    write(symbols["s_comDObjCount"], 0)
    write(symbols["cls_smallDevFont"], 0, "<Q")
    run("ScrPlace_EndFrame")
    header, rows = snapshot()
    assert header[7] == 3 and header[8:] == (23 + simulation_row, 29)
    if simulation_row:
        assert "Simulation FPS: N/A (no local server)" in rows[0]
    assert len(draws) == count
    assert "profile settings: unavailable" in rows[0]
    assert "DObj pool: unavailable" in rows[0]
    assert "unavailable" in rows[1][1].lower()
    write(moved(0x5CC4920), 0xffffffff)
    run("Com_DebugStates_Capture", 0)
    assert "controller/profile/online data: unavailable" in snapshot()[1][0]
    assert snapshot()[0][7] == 3
    write(modules + 0x24, 255, "<B")
    write(symbols["streamFrontendGlob"], 0, "<Q")
    write(symbols["s_worldRequestQueue"], 0, "<Q")
    run("Com_DebugStates_Capture", 0)
    assert snapshot()[0][7] == 6
    assert "global_mp: unavailable" in snapshot()[1][0]
    assert "ClStreaming queues: unavailable" in snapshot()[1][0]
    assert "Streamer level init: unavailable" in snapshot()[1][0]
    write(arena + 0x4000 + 2 * 96, 0, "<Q")
    run("Com_DebugStates_Capture", 0)
    assert snapshot()[0][7] == 7 and "Unavailable" in snapshot()[1][1][3]
    write(symbols["cls_smallDevFont"], arena + 0x3000, "<Q")
    for viewport in ((1200, 900), (2560, 1080)):
        set_viewport(*viewport)
        run("ScrPlace_EndFrame")
        # Drawing uses a private placement; native UI borders remain untouched.
        geometry = struct.unpack("<27f", machine.mem_read(symbols["scrPlaceFull"],108))
        assert geometry[14:18] == (0,0,float(viewport[0]),float(viewport[1]))
    return dict(cases=23, refresh_frames=20, capture_frames=captures[1:4],
                automatic_startup=True,
                common_screen_submission=True, game_modes_tested=[0,1,2],
                stalled_frame_drawn=True,
                native_command_registry=True, native_leaf_getters=True,
                populated_rows=56 + simulation_row, guarded_unavailable_states=True,
                simulation_fps_row_verified=bool(simulation_row),
                fastfile_modules=11, pending_streaming_assets=True,
                native_database_event=True, game_test_corner_placement=True,
                right_aligned_loading=True, bottom_left_extra_states=True,
                developer_font_scale=0.75, line_height_factor=0.8,
                developer_safe_area=0.9, aspect_ratio_cases=3,
                native_placement_unchanged=True)
