"""Link the delivery verifier against the already compiled Linux backend objects."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "tools/test-progression-delivery.cpp"
    objects = sorted((args.build / "CMakeFiles/iw8-dw-server.dir/src").glob("*.o"))
    objects = [path for path in objects if path.name != "server.cpp.o"]
    assert len(objects) >= 30, "Compiled backend objects are missing"
    binary = args.build / "iw8-progression-delivery-contract-test"
    subprocess.run(["g++", "-std=c++20", str(source), *map(str, objects),
                    "-lcrypto", "-pthread", "-o", str(binary)], check=True)
    fixture = root / "data" / f"progression-delivery-fixture-{time.time_ns()}"
    completed = subprocess.run([str(binary), str(fixture)], check=True,
                               capture_output=True, text=True)
    assert completed.stdout.strip() == "PASS: 13 compiled progression delivery checks"
    result = dict(
        schema=1, passed=True, checks=13,
        scope="Actual backend delivery validator linked from current compiled objects; no game or socket stubs",
        server_sha256=hashlib.sha256((args.build / "iw8-dw-server").read_bytes()).hexdigest(),
        verifier_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        linked_objects={str(p.relative_to(args.build)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in objects},
        native_game_verified=False,
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(completed.stdout.strip())


if __name__ == "__main__":
    main()
