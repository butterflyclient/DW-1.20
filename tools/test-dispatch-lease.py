"""Exercise extracted production dispatch entry against a deterministic blocked store lock.

Only platform authorization and the post-entry handler are modeled. The actual
dispatch entry source is extracted verbatim, so the fixture catches moving lease
validation back before the store lock. No backend or game process is used.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>

struct Reply { unsigned error = 0; std::vector<int> results; std::string operation; };
namespace platform {
struct LobbyIdentity {};
std::atomic<bool> live{true};
std::atomic<unsigned> refreshes{0};
bool refreshLease(LobbyIdentity &) { ++refreshes; return live.load(); }
}
struct TrackedMutex {
    std::mutex storage, observation;
    std::condition_variable entered;
    unsigned attempts = 0;
    void lock() {
        { std::lock_guard lock(observation); ++attempts; entered.notify_all(); }
        storage.lock();
    }
    void unlock() { storage.unlock(); }
    bool waitBlocked() {
        std::unique_lock lock(observation);
        return entered.wait_for(lock, std::chrono::seconds(5), [&]{ return attempts >= 2; });
    }
} storeMutex;
std::atomic<unsigned> mutations{0};
Reply dispatch(const platform::LobbyIdentity &authenticatedIdentity) {
@@ENTRY@@
    ++mutations;
    return {};
}
int main() {
    storeMutex.lock();
    Reply response;
    std::thread queued([&]{ response = dispatch(platform::LobbyIdentity{}); });
    if (!storeMutex.waitBlocked()) {
        storeMutex.unlock(); queued.join();
        std::puts("FAIL: worker did not reach blocked store lock"); return 2;
    }
    platform::live = false;
    storeMutex.unlock();
    queued.join();
    if (response.error != 101 || mutations != 0 || platform::refreshes != 1) {
        std::printf("FAIL: error=%u mutations=%u refreshes=%u\n", response.error,
                    mutations.load(), platform::refreshes.load()); return 1;
    }
    std::puts("PASS: authorization revoked while dispatch waits; handler was not entered");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="cl")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = ROOT / "src/services.cpp"
    contents = source.read_text()
    begin = contents.index("        auto id = authenticatedIdentity;", contents.index("    Reply dispatch("))
    end = contents.index("        try\n", begin)
    entry = contents[begin:end]
    assert entry.count("platform::refreshLease(id)") == 1
    assert entry.count("std::lock_guard lock(storeMutex);") == 1
    # Keep a failing control for the previous production order. Its only
    # difference is whether the same lease check happens before the wait.
    control_entry = """        auto id = authenticatedIdentity;
        if (!platform::refreshLease(id))
            return Reply{101, {}, "service-session-expired-or-superseded"};
        std::lock_guard lock(storeMutex);
"""
    (ROOT / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dispatch-lease-", dir=ROOT / "build") as temporary:
        directory = Path(temporary)
        cpp, image = directory / "fixture.cpp", directory / "fixture.exe"
        compiler = Path(args.compiler).name.lower()
        if compiler in ("cl", "cl.exe", "clang-cl", "clang-cl.exe"):
            command = [args.compiler, "/nologo", "/std:c++20", "/EHsc", str(cpp), "/Fe:" + str(image), "/Fo:" + str(directory / "fixture.obj")]
        else:
            command = [args.compiler, "-std=c++20", "-pthread", str(cpp), "-o", str(image)]
        results = []
        for selected, expected in ((control_entry, 1), (entry, 0)):
            cpp.write_text(HARNESS.replace("@@ENTRY@@", selected))
            subprocess.run(command, cwd=directory, check=True)
            result = subprocess.run([str(image)], capture_output=True, text=True)
            assert result.returncode == expected, result.stdout + result.stderr
            results.append(result.stdout.strip())
    proof = dict(passed=True, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                 extracted_entry=entry, modeled_platform_boundary=True, native_game_verified=False,
                 old_order_control=results[0], check=results[1])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
