"""Resolve process snapshot samples against their exact deployed DW build."""
import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    deployment = json.loads(args.deployment.read_bytes())
    with Path(deployment["executable"]).open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == deployment["sha256"]
    report = json.loads((Path(deployment["build_directory"]) / "build-report.json").read_bytes())
    assert report["sha256"] == deployment["sha256"]
    catalog = json.loads((Path(report["source_root"]) / "generated/function-catalog.json").read_bytes())
    ranges = report["rva_map"]["ranges"]
    starts = [row["begin"] for row in ranges]
    functions = {}
    def mapped(rva):
        row = ranges[bisect.bisect_right(starts, rva)-1]
        return row["mapped_begin"] + rva - row["begin"]
    def generic(name):
        return name.startswith(("sub_", "func_", "nullsub_"))
    for row in catalog["functions"]:
        if row.get("quarantined"):
            continue
        names = list(dict.fromkeys([row["name"], *row.get("aliases", [])]))
        symbol = next((name for name in names if name in report["symbols"]), None)
        rva = report["symbols"][symbol] if symbol else mapped(row["rva"])
        name = next((name for name in names if not generic(name)), row["name"])
        functions[rva] = dict(name=name, original_rva=row["rva"])
    for row in report["placements"]:
        functions[row["rva"]] = dict(name=row["symbol"], original_rva=None)
    addresses = sorted(functions)
    modules, samples, captures = [], [], []
    for line in args.samples.read_text().splitlines():
        fields = line.split(",")
        if fields[0] == "module":
            modules.append((int(fields[1], 16), int(fields[2]), fields[3]))
        elif fields[0] == "sample":
            samples.append(tuple(int(value, 16 if i == 4 else 10) for i, value in enumerate(fields) if i))
        elif fields[0] == "capture":
            captures.append(int(fields[2]))
    game = modules[0]
    assert Path(game[2]).resolve() == Path(deployment["executable"]).resolve()
    threads = collections.defaultdict(list)
    counts = collections.Counter()
    module_counts = collections.Counter()
    for sample, ms, tid, ip, user, kernel in samples:
        module = next((row for row in modules if row[0] <= ip < row[0]+row[1]), None)
        label = "unknown"
        original = None
        if module:
            label = Path(module[2]).name
            module_counts[label] += 1
            if module == game:
                rva = ip-game[0]
                index = bisect.bisect_right(addresses, rva)-1
                if index >= 0:
                    function = functions[addresses[index]]
                    label = function["name"]
                    original = function["original_rva"]
                    counts[(label, original)] += 1
        threads[tid].append((user+kernel, label))
    result = dict(executable_sha256=report["sha256"], samples=len(samples), captures=len(captures),
        duration_ms=max(row[1] for row in samples), max_capture_ms=max(captures),
        average_capture_ms=sum(captures)/len(captures), modules=module_counts,
        game_routines=[dict(name=name, original_rva=hex(rva) if rva is not None else None, samples=count)
            for (name,rva),count in counts.most_common(50)],
        threads=sorted([dict(tid=tid, cpu_ms=(rows[-1][0]-rows[0][0])/10000,
                            top_samples=collections.Counter(row[1] for row in rows).most_common(12))
                        for tid,rows in threads.items()], key=lambda row:-row["cpu_ms"]),
        scope="Periodic thread-context snapshots include waits and sampling overhead; counts are not CPU percentages. Native labels use nearest catalog function; validate candidate bounds before editing.")
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!='threads'},indent=2))
    print(json.dumps(result['threads'][:14],indent=2))


if __name__ == "__main__":
    main()
