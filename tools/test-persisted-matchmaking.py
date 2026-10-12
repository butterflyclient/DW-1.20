"""Read-only persisted lobby compatibility audit using isolated candidate recovery.

Only raw lobby snapshots are copied. Credentials, network settings, searches and
current-player indexes are never copied from the input data root. Candidate
processes therefore use their fresh scratch stores and default loopback binding.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import uuid


def source_snapshot(directory):
    records = []
    for path in sorted((directory / "matchmaking").glob("*/lobbies/*.json")):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        relative = path.relative_to(directory).as_posix()
        records.append(dict(title=path.parent.parent.name, name=path.name, raw=raw,
                            sha256=hashlib.sha256(raw).hexdigest(),
                            path_sha256=hashlib.sha256(relative.encode()).hexdigest()))
    return records


def snapshot_hash(records):
    digest = hashlib.sha256()
    for record in records:
        digest.update(bytes.fromhex(record["path_sha256"]))
        digest.update(bytes.fromhex(record["sha256"]))
    return digest.hexdigest()


def classification(record):
    try:
        state = json.loads(record["raw"])
        return "tournament" if "tournament" in state.get("backend_doc", {}) else "ordinary"
    except (ValueError, AttributeError, TypeError):
        return "malformed"


def spare_offset():
    for offset in range(12000, 14000):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("No isolated loopback ports available")


def chunks(records):
    # Each journal belongs to one title and stays within the 202-entry contract.
    # Valid document limits keep 202 entries below the 32 MiB journal limit.
    group, size, title = [], 0, None
    for record in records:
        if group and (record["title"] != title or len(group) == 202 or
                      size + len(record["raw"]) > 30 * 1024 * 1024):
            yield group
            group, size = [], 0
        title = record["title"]
        group.append(record)
        size += len(record["raw"])
    if group:
        yield group


def journal_bytes(records):
    try:
        title = int(records[0]["title"])
    except ValueError:
        title = 0  # Candidate startup also rejects the original invalid title directory.
    entries = []
    for record in records:
        # Embed original raw bytes instead of parsing/re-encoding the snapshot.
        # This preserves duplicate object keys for the candidate's own parser.
        path = json.dumps("lobbies/" + record["name"]).encode()
        entries.append(b'{"path":' + path + b',"document":' + record["raw"] + b'}')
    header = json.dumps(dict(schema=1, title=title, revision=1, phase="prepared")).encode()
    return header[:-1] + b',"writes":[' + b','.join(entries) + b']}'


def check_chunk(server, run_root, ordinal, records, timeout, processes):
    scratch = run_root / ("validation-" + str(ordinal))
    store = scratch / "matchmaking" / records[0]["title"]
    store.mkdir(parents=True)
    journal = store / "transaction.json"
    journal.write_bytes(journal_bytes(records))
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with (scratch / "candidate.log").open("wb") as log:
        process = subprocess.Popen([str(server), str(scratch), "--port-offset", str(spare_offset())],
                                   stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        processes.append(process)
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    if json.loads(journal.read_bytes())["phase"] == "applied":
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.025)
            published = sum((store / "lobbies" / record["name"]).is_file() for record in records)
            try:
                applied = json.loads(journal.read_bytes())["phase"] == "applied"
            except ValueError:
                applied = False
            if applied and published == len(records):
                return "accepted"
            if process.poll() is not None and published == 0:
                return "rejected"
            return "incomplete"
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True,
                        help="Explicit output root for all candidate process writes")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--cleanup-scratch", action="store_true",
                        help="Remove this invocation's scratch only; otherwise preserve it")
    args = parser.parse_args()
    server, source = args.server.resolve(strict=True), args.data.resolve(strict=True)
    output, scratch_root = args.output.resolve(), args.scratch_root.resolve()
    if output.is_relative_to(source) or scratch_root.is_relative_to(source):
        raise SystemExit("Audit outputs must be outside the input data root")
    if not source.is_dir() or args.timeout <= 0:
        raise SystemExit("Invalid input directory or timeout")
    # Never create/remove the supplied scratch root itself; own a fresh child.
    run_root = scratch_root / ("persisted-matchmaking-" + uuid.uuid4().hex)
    run_root.mkdir(parents=True, mode=0o700)
    before = source_snapshot(source)
    before_hash = snapshot_hash(before)
    server_hash = hashlib.sha256(server.read_bytes()).hexdigest()
    counts = Counter(classification(record) for record in before)
    results = Counter()
    rejected = []
    ordinal = 0
    chunk_count = 0
    error = False
    processes = []
    try:
        for batch in chunks(before):
            chunk_count += 1
            pending = [batch]
            while pending:
                group = pending.pop()
                result = check_chunk(server, run_root, ordinal, group, args.timeout, processes)
                ordinal += 1
                if result == "accepted":
                    results["accepted"] += len(group)
                elif len(group) > 1:
                    # A rejected chunk gives no per-record conclusion. Bisect
                    # it until complete valid groups or individual failures
                    # establish exact counts without restarting for every record.
                    middle = len(group) // 2
                    pending.extend((group[middle:], group[:middle]))
                else:
                    record = group[0]
                    results[result] += 1
                    rejected.append(dict(snapshot_sha256=record["sha256"],
                                         path_sha256=record["path_sha256"], result=result))
    except (OSError, RuntimeError, subprocess.SubprocessError):
        error = True
    finally:
        for process in processes:
            if process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    error = True
    after = source_snapshot(source)
    after_hash = snapshot_hash(after)
    unchanged = before_hash == after_hash and len(before) == len(after)
    server_after_hash = hashlib.sha256(server.read_bytes()).hexdigest()
    candidate_unchanged = server_hash == server_after_hash
    stopped = all(process.poll() is not None for process in processes)
    cleanup = "not_requested"
    if args.cleanup_scratch and stopped:
        if run_root.resolve().parent != scratch_root:
            raise SystemExit("Scratch containment check failed")
        try:
            shutil.rmtree(run_root)
            cleanup = "removed"
        except OSError:
            cleanup = "not_permitted_or_failed"
    passed = not error and unchanged and candidate_unchanged and stopped and results["accepted"] == len(before)
    report = dict(schema=1, passed=passed, candidate_sha256=server_hash,
                  candidate_after_sha256=server_after_hash, candidate_unchanged=candidate_unchanged,
                  source_snapshot_sha256=before_hash, source_after_sha256=after_hash,
                  source_records_unchanged=unchanged, source_lobby_count=len(before),
                  ordinary_lobby_count=counts["ordinary"], tournament_lobby_count=counts["tournament"],
                  malformed_lobby_count=counts["malformed"], accepted_count=results["accepted"],
                  rejected_count=results["rejected"], incomplete_count=results["incomplete"],
                  untested_count=len(before) - sum(results.values()), chunk_count=chunk_count,
                  candidate_processes_started=len(processes), candidate_processes_stopped=stopped,
                  cleanup=cleanup, audit_error=error, rejected_snapshot_hashes=rejected,
                  production_writes_performed=False, production_restarts=False, game_runs_performed=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("passed", "source_lobby_count", "ordinary_lobby_count", "tournament_lobby_count",
                       "accepted_count", "rejected_count", "incomplete_count", "untested_count",
                       "source_records_unchanged", "source_snapshot_sha256", "candidate_sha256")}))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
