"""Run the existing policy/scheduler harnesses plus native inventory equivalence.

Loads only an isolated test DLL, never the game. Temporary build files are removed.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
COMPILER = Path(r"E:\replay-compiler")
LLVM = Path(r"C:\Program Files\LLVM\bin")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sources = [COMPILER / "src" / name for name in (
        "Com_Optimized.cpp", "Dvar_WriteVariables.cpp", "LUI_CollectGarbageTask.cpp",
        "XModelGetDesiredLodForDist.cpp", "XModelGetBestUsableLod_Internal.cpp",
        "XAnimProceduralBones_Evaluate.cpp",
    )] + [COMPILER / "tests/optimized_runtime_harness.cpp",
          ROOT / "integration/replay/Sys_ProcessWorkerCmdsWithTimeoutAndFilter.cpp",
          ROOT / "tools/optimized_worker_harness.cpp"]
    inventory_source = ROOT / "integration/replay/DW_LocalProgression.cpp"
    with tempfile.TemporaryDirectory(prefix="type1-test-", dir=ROOT / "build") as directory:
        directory = Path(directory)
        harness = directory / "inventory.cpp"
        harness.write_text(f'''#include "{inventory_source.as_posix()}"
extern "C" uint32_t s_comOptimizedMode;
// Uncalled platform/Lua boundaries allow this complete source unit to link.
// The linked-image verifier separately executes the real binding with Lua inputs.
extern "C" {{
DWReplayLootInventoryPrefix gl_1459E05C0{{}};
int func_1420838B0(void*) {{ return 0; }}
int func_1420839E0(void*, int) {{ return 0; }}
double func_142084A10(void*, int) {{ return 0; }}
void func_142084100(void*, double) {{}}
int func_142089FB0(void*, const char*, ...) {{ return 0; }}
int func_140D66C20(int) {{ return 0; }}
bool DW_LocalBackend_IsEnabled() {{ return false; }}
bool DW_LocalConfig_UnlockAll() {{ return false; }}
unsigned DW_LocalConfig_Rank() {{ return 0; }}
uint64_t DW_LocalPlatform_UserId() {{ return 0; }}
void* func_14105BC30() {{ return nullptr; }}
void* __imp_LoadLibraryA = nullptr;
void* __imp_GetProcAddress = nullptr;
void* __imp_FreeLibrary = nullptr;
}}
extern "C" __declspec(dllexport) uint32_t Test_Inventory_Query(void* memory, uint32_t item, uint32_t mode) {{
    s_comOptimizedMode = mode;
    return InventoryQuantity(*static_cast<DWReplayLootInventoryPrefix*>(memory), item);
}}
extern "C" __declspec(dllexport) uint64_t Test_Inventory_Batch(void* memory, unsigned mode, unsigned repeats) {{
    s_comOptimizedMode = mode;
    uint64_t sum = 0;
    for (unsigned i = 0; i < repeats; ++i)
        sum += InventoryQuantity(*static_cast<DWReplayLootInventoryPrefix*>(memory), 10000 + i % 20000);
    return sum;
}}
''')
        objects = []
        for index, source in enumerate([*sources, harness]):
            obj = directory / f"{index}.obj"
            subprocess.run([str(LLVM / "clang++.exe"), "--target=x86_64-pc-windows-msvc",
                "-c", str(source), "-o", str(obj), "-std=c++20", "-O2", "-ffreestanding",
                "-fno-stack-protector", "-fno-exceptions", "-fno-rtti", "-ffunction-sections",
                "-fdata-sections", "-Wall", "-Wextra", "-Werror", "-DREPLAY_COMPILER_OPTIMIZED",
                "-DREPLAY_COMPILER_OPTIMIZED_TEST", "-I" + str(COMPILER / "src"),
                "-I" + str(ROOT / "integration/replay")], check=True)
            objects.append(obj)
        dll_path = directory / "type1.dll"
        subprocess.run([str(LLVM / "lld-link.exe"), "/dll", "/noentry", "/nodefaultlib",
            "/opt:ref", "/out:" + str(dll_path), *map(str, objects)], check=True)
        dll = ctypes.CDLL(str(dll_path))
        try:
            for name in ("Test_Run", "Test_Worker_Run"):
                result = getattr(dll, name)()
                assert result == 0, f"{name} failed at harness line {result}"
            worker_setup = dll.Test_Worker_BenchmarkSetup
            worker_setup.argtypes = [ctypes.c_uint]
            worker_batch = dll.Test_Worker_Benchmark
            worker_batch.argtypes = [ctypes.c_uint]
            worker_times = {0: [], 1: []}
            with ThreadPoolExecutor(max_workers=12) as workers:
                for repeat in range(6):
                    for mode in ((0, 1) if repeat % 2 == 0 else (1, 0)):
                        worker_setup(mode)
                        start = time.perf_counter()
                        list(workers.map(worker_batch, [3000] * 12))
                        worker_times[mode].append(time.perf_counter() - start)
            query = dll.Test_Inventory_Query
            query.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
            query.restype = ctypes.c_uint32
            batch = dll.Test_Inventory_Batch
            batch.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
            batch.restype = ctypes.c_uint64
            memory = ctypes.create_string_buffer(120072)
            slots = (ctypes.c_uint32 * 30000).from_buffer(memory, 64)
            count = ctypes.c_int32.from_buffer(memory, 120064)
            rng = random.Random(120)
            cases = 0
            for length in (-1, 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 255, 14999, 15000, 15001):
                count.value = length
                for i in range(min(max(length, 0), 15000)):
                    slots[2*i] = rng.randrange(1, 500)
                    slots[2*i+1] = rng.getrandbits(32)
                if length >= 4:
                    # Duplicate IDs, zero first quantity, and quantity-only hits.
                    slots[0], slots[1], slots[2], slots[3] = 111, 0, 111, 7
                    slots[4], slots[5] = 222, 0xFFFFFFFF
                before = memory.raw
                for item in [0, 0xFFFFFFFF, 111, 222, 777, *range(1, 501)]:
                    expected = next((slots[2*i+1] for i in range(length)
                        if slots[2*i] == item), 0) if 0 <= length <= 15000 else 0
                    for mode in (0, 1, 2):
                        assert query(memory, item, mode) == expected, (length, item, mode)
                        cases += 1
                assert memory.raw == before, "Inventory was modified"
            # No match in initialized records may read the excluded tail.
            for length in range(8):
                count.value = length
                for i in range(9):
                    slots[2*i], slots[2*i+1] = 1, 777
                slots[2*length], slots[2*length+1] = 777, 99
                for mode in (0, 1, 2):
                    assert query(memory, 777, mode) == 0
                    cases += 1
            count.value = 15000
            for i in range(15000):
                slots[2*i], slots[2*i+1] = 10000 + i, i + 1
            timings = {0: [], 1: []}
            sums = set()
            for repeat in range(6):
                for mode in ((0, 1) if repeat % 2 == 0 else (1, 0)):
                    start = time.perf_counter()
                    sums.add(batch(memory, mode, 20000))
                    timings[mode].append(time.perf_counter() - start)
            assert sums == {15000 * 15001 // 2}
            medians = {mode: statistics.median(values) for mode, values in timings.items()}
            result = dict(passed=True, inventory_cases=cases,
                policy_and_worker_harnesses_passed=True,
                dedicated_worker_benchmark=dict(threads=12, wake_cycles_per_thread=3000,
                    mode0_seconds=statistics.median(worker_times[0]),
                    mode1_seconds=statistics.median(worker_times[1]),
                    speedup=statistics.median(worker_times[0])/statistics.median(worker_times[1]),
                    scope="Contended empty-queue scan only, with event and dependency boundaries modeled; not an FPS benchmark"),
                inventory_benchmark=dict(queries=20000, entries=15000, rounds=6,
                    mode0_seconds=medians[0], mode1_seconds=medians[1],
                    speedup=medians[0]/medians[1], gameplay_benchmark=False),
                source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [*sources, inventory_source]}, runtime_tested=False)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(dll._handle)


if __name__ == "__main__":
    main()
