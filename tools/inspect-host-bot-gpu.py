"""Read the exact built GPU metrics from a running game without calling or writing it."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import struct
import time

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_REG_RAX, X86_REG_RCX, X86_REG_RIP


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def metrics_address(report, image):
    """Prove all getter copies refer to one 104-byte native Metrics structure."""
    symbol = '?GetMetrics@HostBotGpu@@YA?AUMetrics@1@XZ'
    address = report['symbols'][symbol]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    pending = None
    bases, copied = set(), set()
    for instruction in decoder.disasm(image.get_data(address, 160), address):
        if instruction.mnemonic == 'ret':
            break
        operands = instruction.operands
        if len(operands) != 2:
            pending = None
            continue
        target, source = operands
        if (target.type == X86_OP_REG and source.type == X86_OP_MEM and
                source.mem.base == X86_REG_RIP):
            pending = (target.reg, instruction.address + instruction.size + source.mem.disp, source.size)
        elif (pending and target.type == X86_OP_MEM and target.mem.base == X86_REG_RAX and
                source.type == X86_OP_REG and source.reg == pending[0]):
            bases.add(pending[1] - target.mem.disp)
            copied.update(range(target.mem.disp, target.mem.disp + pending[2]))
            pending = None
        else:
            pending = None
    assert len(bases) == 1 and copied == set(range(104)), 'GPU getter layout changed'
    return bases.pop()


def sight_work_addresses(report, image):
    """Resolve each counter from the built value-only getter's output stores."""
    address = report['symbols'].get('SV_HostSight_GetWork')
    if address is None:
        return {}
    names = ('urgent_evaluations', 'urgent_native_trace_delta',
             'background_evaluations', 'background_native_trace_delta',
             'background_deferred', 'shared_calls', 'admitted_visits',
             'urgent_clock_ticks', 'background_clock_ticks')
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    pending = None
    fields = {}
    for instruction in decoder.disasm(image.get_data(address, 256), address):
        if instruction.mnemonic == 'ret':
            break
        operands = instruction.operands
        if instruction.mnemonic != 'mov' or len(operands) != 2:
            pending = None
            continue
        target, source = operands
        if (target.type == X86_OP_REG and source.type == X86_OP_MEM and
                source.mem.base == X86_REG_RIP and source.size == 8):
            pending = (target.reg, instruction.address + instruction.size + source.mem.disp)
        elif (pending and target.type == X86_OP_MEM and target.mem.base == X86_REG_RCX and
              target.size == 8 and source.type == X86_OP_REG and source.reg == pending[0]):
            assert target.mem.disp not in fields, 'Duplicate sight getter field'
            fields[target.mem.disp] = pending[1]
            pending = None
        else:
            pending = None
    assert set(fields) == set(range(0, 72, 8)), 'Sight getter layout changed'
    return {name: fields[index * 8] for index, name in enumerate(names)}


def planner_addresses(report, image):
    """Resolve the two status calls from their actual argument assignments.

    This is a small recognizer for the built status printer, not an assumption
    about adjacency or order of private globals. Fail closed if code generation
    changes the argument layout.
    """
    symbol = '?PrintStatus@HostBotPlanner@@YAXXZ'
    address = report['symbols'][symbol]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    rows = []
    for instruction in decoder.disasm(image.get_data(address, 512), address):
        if instruction.mnemonic == 'ret':
            break
        rows.append(instruction)
    calls = [index for index, row in enumerate(rows)
             if row.mnemonic == 'call' and row.op_str == hex(report['symbols']['Com_Printf'])]
    assert len(calls) == 2, 'Planner status call layout changed'
    expected = (
        (('esi', 'edi', 'ebx', 'ebp', 'r14d', 'r9d'),
         ('pending_batches', 'rejected', 'native_commits', 'committed', 'solved', 'queued'),
         ((0x40, 'esi'), (0x38, 'edi'), (0x30, 'ebx'), (0x28, 'ebp'), (0x20, 'r14d'))),
        (('eax', 'ecx', 'edx', 'r10d', 'r11d', 'esi', 'r9d', 'r8d'),
         ('captured_nodes', 'device_failures', 'last_gpu_us', 'gas_routes', 'stale',
          'no_route', 'search_budget', 'unsupported_graph'),
         ((0x48, 'eax'), (0x40, 'ecx'), (0x38, 'edx'), (0x30, 'r10d'),
          (0x28, 'r11d'), (0x20, 'esi'))),
    )
    result = {}
    start = 0
    for call, (registers, names, stack) in zip(calls, expected):
        section = rows[start:call]
        loads = []
        for row in section:
            operands = row.operands
            if row.mnemonic != 'mov' or len(operands) != 2:
                continue
            target, source = operands
            if (target.type == X86_OP_REG and source.type == X86_OP_MEM and
                    source.mem.base == X86_REG_RIP and source.size == 4):
                loads.append((row.reg_name(target.reg), row.address + row.size + source.mem.disp))
        # The first section also reads the initialization flag after its six
        # counters. Argument stores below prove the counters' call positions.
        assert tuple(register for register, _ in loads[:len(registers)]) == registers
        for offset, register in stack:
            assert any(row.mnemonic == 'mov' and
                       row.op_str == f'dword ptr [rsp + {hex(offset)}], {register}'
                       for row in section), 'Planner status stack arguments changed'
        for name, (_, rva) in zip(names, loads):
            result[name] = rva
        start = call + 1
    return result


def planner_work_fields(report, image):
    """Prove named fields from the value-only getter, without calling the game.

    The public result uses uint64 fields; some source counters are uint32 and
    are zero-extended by the compiler. Retain their actual read width so that
    interval deltas handle rollover correctly. Legacy builds use the older
    verified status-printer recognizer above.
    """
    address = report['symbols'].get('SV_HostBotGpu_GetPlannerWork')
    if address is None:
        return {name: (rva, 4) for name, rva in planner_addresses(report, image).items()}
    names = (
        'queued', 'solved', 'committed', 'native_commits', 'rejected',
        'unsupported_graph', 'search_budget', 'no_route', 'stale', 'gas_routes',
        'pending_batches', 'last_gpu_us', 'device_failures', 'captured_nodes',
        'roam_coalesced', 'roam_queued', 'roam_candidates', 'roam_accepted',
        'roam_rejected', 'roam_native_fallbacks', 'roam_cancelled',
        'roam_validation_ticks', 'capture_ticks',
    )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    registers, fields = {}, {}

    def family(instruction, register):
        name = instruction.reg_name(register)
        if name.startswith('e'):
            return 'r' + name[1:]
        return name.removesuffix('d')

    for instruction in decoder.disasm(image.get_data(address, 1024), address):
        if instruction.mnemonic == 'ret':
            break
        operands = instruction.operands
        if instruction.mnemonic != 'mov' or len(operands) != 2:
            registers.clear()
            continue
        target, source = operands
        if (target.type == X86_OP_REG and source.type == X86_OP_MEM and
                source.mem.base == X86_REG_RIP and source.size in (4, 8)):
            registers[family(instruction, target.reg)] = (
                instruction.address + instruction.size + source.mem.disp, source.size)
        elif (target.type == X86_OP_MEM and target.mem.base == X86_REG_RCX and
                target.size == 8 and source.type == X86_OP_REG):
            key = family(instruction, source.reg)
            assert key in registers, 'Unproven planner getter value'
            assert target.mem.disp not in fields, 'Duplicate planner getter field'
            fields[target.mem.disp] = registers.pop(key)
        else:
            registers.clear()
    assert set(fields) == set(range(0, len(names) * 8, 8)), 'Planner getter layout changed'
    return {name: fields[index * 8] for index, name in enumerate(names)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--frame-seconds', type=float, default=0)
    args = parser.parse_args()
    report = json.loads((args.build / 'build-report.json').read_bytes())
    assert not report['unresolved_symbols']
    assert digest(report['executable']) == report['sha256']
    image = pefile.PE(report['executable'], fast_load=True)
    metrics_rva = metrics_address(report, image)
    kernel = c.WinDLL('kernel32', use_last_error=True)
    psapi = c.WinDLL('psapi', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    kernel.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    psapi.EnumProcessModulesEx.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), w.DWORD]
    process = kernel.OpenProcess(0x410, False, args.pid)
    if not process:
        raise c.WinError(c.get_last_error())
    try:
        path = c.create_unicode_buffer(32768)
        length = w.DWORD(len(path))
        assert kernel.QueryFullProcessImageNameW(process, 0, path, c.byref(length))
        assert digest(path.value) == report['sha256'], 'Running image differs from verified build'
        modules = (w.HMODULE * 1024)()
        needed = w.DWORD()
        assert psapi.EnumProcessModulesEx(process, modules, c.sizeof(modules), c.byref(needed), 3)
        data = c.create_string_buffer(104)
        received = c.c_size_t()
        assert kernel.ReadProcessMemory(process, modules[0] + metrics_rva, data, 104, c.byref(received))
        assert received.value == 104
        values = struct.unpack('<6QIIiIIIi4x3Q', data.raw)
        names = ('submitted', 'completed', 'busy', 'invalid', 'timeouts', 'device_failures',
                 'pending', 'enabled', 'last_error', 'adapter_vendor', 'adapter_device',
                 'adapter_luid_low', 'adapter_luid_high', 'gpu_timestamp_frequency',
                 'last_gpu_microseconds', 'max_gpu_microseconds')
        metrics = dict(zip(names, values))
        planner_fields = planner_work_fields(report, image)
        def read_value(address, format):
            size = struct.calcsize(format)
            block = c.create_string_buffer(size)
            done = c.c_size_t()
            if not kernel.ReadProcessMemory(process, address, block, size, c.byref(done)):
                raise c.WinError(c.get_last_error())
            assert done.value == size
            return struct.unpack(format, block.raw)[0]

        def sample_planner():
            return {name: read_value(modules[0] + address, '<Q' if width == 8 else '<I')
                    for name, (address, width) in planner_fields.items()}

        planner = sample_planner()

        # These offsets are the same target-bound views used by the compiled
        # scheduler, not an inference from the lobby's displayed player count.
        population = dict(slots=0, connected_bots=0, health_positive_bots=0,
                          jail_bots=0, arena_bots=0, transition_bots=0, read_failures=0)
        count = read_value(modules[0] + report['symbols']['SVHS_ClientCount'], '<I')
        assert count <= 200, 'Client slot count escaped the target-build limit'
        population['slots'] = count
        for slot in range(count):
            try:
                client = read_value(modules[0] + report['symbols']['SVHS_Clients'] + slot * 8, '<Q')
                if not client or read_value(client + 8, '<B') < 5:
                    continue
                if read_value(client + 214756, '<i') != 2:
                    continue
                population['connected_bots'] += 1
                entity = read_value(client + 280, '<Q')
                if not entity or read_value(entity + 440, '<i') <= 0:
                    continue
                population['health_positive_bots'] += 1
                player = read_value(entity + 336, '<Q')
                phase = read_value(player + 22336, '<I') & 0x600 if player else 0
                if phase == 0x200:
                    population['jail_bots'] += 1
                elif phase == 0x400:
                    population['arena_bots'] += 1
                elif phase == 0x600:
                    population['transition_bots'] += 1
            except OSError:
                population['read_failures'] += 1
        frames = None
        sight_addresses = sight_work_addresses(report, image)
        def sample_sight():
            return {name: read_value(modules[0] + address, '<Q')
                    for name, address in sight_addresses.items()}
        sight = sample_sight()
        if args.frame_seconds:
            assert 0 < args.frame_seconds <= 30
            recorder = report['symbols']['?RecordBotFrame@HostScale@@YAXII_K0@Z']
            decoder = Cs(CS_ARCH_X86, CS_MODE_64)
            decoder.detail = True
            counters = []
            for instruction in decoder.disasm(image.get_data(recorder, 100), recorder):
                if instruction.mnemonic.startswith('lock '):
                    operand = instruction.operands[0]
                    assert operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
                    counters.append((instruction.address + instruction.size + operand.mem.disp, operand.size))
            assert [size for _, size in counters] == [4, 4, 4, 8, 8]
            def sample_counters():
                values = []
                for address, size in counters:
                    block = c.create_string_buffer(size)
                    done = c.c_size_t()
                    assert kernel.ReadProcessMemory(process, modules[0] + address, block, size, c.byref(done))
                    assert done.value == size
                    values.append(int.from_bytes(block.raw, 'little'))
                return values
            frequency = c.c_int64()
            assert kernel.QueryPerformanceFrequency(c.byref(frequency))
            before = sample_counters()
            sight_before = sample_sight()
            planner_before = sample_planner()
            start = time.perf_counter()
            time.sleep(args.frame_seconds)
            after = sample_counters()
            sight_after = sample_sight()
            planner_after = sample_planner()
            seconds = time.perf_counter() - start
            delta = [end - begin for begin, end in zip(before, after)]
            frames = dict(seconds=seconds, frames=delta[0], simulation_fps=delta[0] / seconds,
                          full_decisions=delta[1], reused_commands=delta[2],
                          bot_think_ms_per_frame=delta[3] * 1000 / frequency.value / max(delta[0], 1),
                          bot_move_ms_per_frame=delta[4] * 1000 / frequency.value / max(delta[0], 1),
                          scope='Native bot frame counters; think excludes other server work, move includes GPU submission.')
            planner_delta = {
                name: (planner_after[name] - planner_before[name]) & ((1 << (width * 8)) - 1)
                for name, (_, width) in planner_fields.items()
                if name not in ('pending_batches', 'last_gpu_us')
            }
            for counter in ('capture_ticks', 'roam_validation_ticks'):
                if counter in planner_delta:
                    planner_delta[counter.removesuffix('_ticks') + '_cpu_ms_per_frame'] = (
                        planner_delta[counter] * 1000 / frequency.value / max(delta[0], 1))
            frames['planner'] = planner_delta
            if sight_addresses:
                sight_delta = {name: (sight_after[name] - sight_before[name]) & ((1 << 64) - 1)
                               for name in sight_addresses}
                for group in ('urgent', 'background'):
                    sight_delta[group + '_cpu_ms_per_frame'] = (
                        sight_delta[group + '_clock_ticks'] * 1000 / frequency.value / max(delta[0], 1))
                frames['sight'] = sight_delta
        result = dict(read_only=True, atomic_snapshot=False, pid=args.pid,
                      executable=path.value, executable_sha256=report['sha256'],
                      metrics_rva=metrics_rva, metrics=metrics,
                      planner=planner,
                      sight_work=sight,
                      population=population,
                      frame_interval=frames,
                      hardware_initialized=bool(metrics['enabled'] and metrics['gpu_timestamp_frequency']),
                      limitation='Sequential live read; startup/queue evidence, not a 150-bot match benchmark.')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    finally:
        kernel.CloseHandle(process)


if __name__ == '__main__':
    main()
