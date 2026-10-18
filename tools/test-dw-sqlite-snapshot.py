"""Exercise complete job snapshots under concurrent SQLite writes and failures."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
from unittest.mock import patch

import dw_client
import dw_sqlite_snapshot as snapshots

ROOT = Path(__file__).resolve().parents[1]


def run_fixture(fixture):
    checks = []

    def check(name, condition=True):
        if not condition:
            raise AssertionError(name)
        checks.append(name)

    def rejects(name, operation):
        try:
            operation()
        except (ValueError, FileExistsError):
            check(name)
        else:
            raise AssertionError("Expected rejection: " + name)

    live = fixture / "live.sqlite"
    with closing(sqlite3.connect(live)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute(
            "CREATE TABLE functions(id INTEGER PRIMARY KEY, epoch INTEGER, payload BLOB)"
        )
        db.execute("CREATE TABLE globals(id INTEGER PRIMARY KEY, epoch INTEGER)")
        db.execute("CREATE INDEX global_epoch ON globals(epoch)")
        db.execute("CREATE VIEW current_globals AS SELECT id,epoch FROM globals")
        db.executemany(
            "INSERT INTO functions VALUES(?,?,?)",
            [(i, 0, bytes(8192)) for i in range(256)],
        )
        db.executemany("INSERT INTO globals VALUES(?,?)", [(i, 0) for i in range(256)])
        db.commit()
        original_schema = db.execute(
            "SELECT type,name,sql FROM sqlite_schema ORDER BY type,name"
        ).fetchall()

    start, stop = threading.Event(), threading.Event()
    writes, errors = [], []

    def writer():
        try:
            with closing(sqlite3.connect(live)) as db:
                if not start.wait(5):
                    raise RuntimeError("Backup never reached its progress callback")
                for epoch in range(1, 21):
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("UPDATE functions SET epoch=?", (epoch,))
                    db.execute("UPDATE globals SET epoch=?", (epoch,))
                    db.commit()
                    writes.append(epoch)
                    if stop.is_set():
                        break
        except Exception as error:
            errors.append(repr(error))

    thread = threading.Thread(target=writer)
    thread.start()

    def progress(_status, _remaining, _total):
        start.set()
        if not writes:
            thread.join(0.05)

    try:
        binding = snapshots.create_snapshot(
            live, fixture / "inputs/analysis.sqlite", progress
        )
    finally:
        start.set()
        stop.set()
        thread.join(5)
    check(
        "concurrent_writer_completed",
        not thread.is_alive() and not errors and bool(writes),
    )
    database = Path(binding["path"])

    def signature():
        return [
            (p.name, p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(database.parent.glob("analysis.sqlite*"))
        ]

    before = signature()
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        check(
            "pinned_transactions_are_consistent",
            db.execute("SELECT DISTINCT epoch FROM functions").fetchall() == [(0,)]
            and db.execute("SELECT DISTINCT epoch FROM globals").fetchall() == [(0,)],
        )
        check(
            "all_rows_preserved",
            db.execute("SELECT count(*) FROM functions").fetchone()[0] == 256
            and db.execute("SELECT count(*) FROM globals").fetchone()[0] == 256,
        )
        check(
            "complete_schema_preserved",
            db.execute(
                "SELECT type,name,sql FROM sqlite_schema ORDER BY type,name"
            ).fetchall()
            == original_schema,
        )
        check(
            "snapshot_uses_delete_journal",
            db.execute("PRAGMA journal_mode").fetchone()[0] == "delete",
        )
    check(
        "readonly_reopen_keeps_signature",
        signature() == before
        and not database.with_name("analysis.sqlite-wal").exists()
        and not database.with_name("analysis.sqlite-shm").exists(),
    )
    with closing(sqlite3.connect(live)) as db:
        check(
            "live_source_advanced_without_journal_change",
            db.execute("SELECT max(epoch) FROM functions").fetchone()[0] > 0
            and db.execute("PRAGMA journal_mode").fetchone()[0] == "wal",
        )
    check("binding_verifies", snapshots.verify_binding(binding) == database)
    rejects(
        "same_source_destination_rejected",
        lambda: snapshots.create_snapshot(live, live),
    )
    rejects(
        "existing_destination_rejected",
        lambda: snapshots.create_snapshot(live, database),
    )
    rejects(
        "incorrect_snapshot_hash_rejected",
        lambda: snapshots.verify_binding(dict(binding, sha256="0" * 64)),
    )
    rejects(
        "incorrect_proof_hash_rejected",
        lambda: snapshots.verify_binding(dict(binding, proof_sha256="0" * 64)),
    )

    previous = os.environ.get("REPLAY_SQLITE")
    for initial in (None, "owner-specified-live-path"):
        with patch.dict(os.environ):
            if initial is None:
                os.environ.pop("REPLAY_SQLITE", None)
            else:
                os.environ["REPLAY_SQLITE"] = initial
            try:
                with snapshots.scoped_sqlite(database):
                    check(
                        "nested_scope_active_" + str(initial is None),
                        os.environ["REPLAY_SQLITE"] == str(database),
                    )
                    with snapshots.scoped_sqlite(live):
                        assert os.environ["REPLAY_SQLITE"] == str(live)
                    assert os.environ["REPLAY_SQLITE"] == str(database)
                    raise RuntimeError("intentional environment-scope failure")
            except RuntimeError:
                pass
            check(
                "environment_restored_" + str(initial is None),
                os.environ.get("REPLAY_SQLITE") == initial,
            )

    job = fixture / "job"
    (job / "source").mkdir(parents=True)
    (job / "source/replay-project.local.json").write_text(
        json.dumps(dict(sqlite=str(database)))
    )
    (job / "source-receipt.json").write_text(
        json.dumps(dict(snapshot=str(job / "source"), sqlite_snapshot=binding))
    )

    def fail_inside(*_args, **_kwargs):
        assert os.environ["REPLAY_SQLITE"] == str(database)
        raise RuntimeError("expected delegated failure")

    with patch.object(dw_client, "_build", fail_inside), patch.object(
        dw_client, "_verify", fail_inside
    ):
        for name, function, arguments in (
            ("build", dw_client.build, (job,)),
            ("verify", dw_client.verify, (job, job / "unused.json")),
        ):
            try:
                function(*arguments)
            except RuntimeError as error:
                assert str(error) == "expected delegated failure"
            else:
                raise AssertionError("Delegated failure did not propagate")
            check(
                name + "_exception_restores_environment",
                os.environ.get("REPLAY_SQLITE") == previous,
            )

    base = fixture / "prepare-base"
    base.mkdir()
    (base / "replay-project.local.json").write_text(json.dumps(dict(sqlite=str(live))))
    prepared = []

    def fail_prepare(_directory, frozen, _pending):
        assert os.environ["REPLAY_SQLITE"] == frozen["path"]
        prepared.append(frozen)
        raise RuntimeError("expected preparation failure")

    with patch.object(
        dw_client, "settings", lambda: ({}, fixture / "prepare-state", base)
    ), patch.object(dw_client, "initialize", lambda: None), patch.object(
        dw_client, "_prepare", fail_prepare
    ):
        try:
            dw_client.prepare()
        except RuntimeError as error:
            assert str(error) == "expected preparation failure"
        else:
            raise AssertionError("Preparation failure did not propagate")
    check(
        "prepare_exception_restores_environment",
        len(prepared) == 1 and os.environ.get("REPLAY_SQLITE") == previous,
    )
    dw_client.require_current_sources(
        dict(sqlite_snapshot=prepared[0], source_inputs=[], tool_inputs=[])
    )
    check("source_receipt_binds_snapshot")
    return dict(
        passed=True,
        check_count=len(checks),
        checks=checks,
        concurrent_commits=len(writes),
        pinned_epoch=0,
        snapshot_sha256=binding["sha256"],
        proof_sha256=binding["proof_sha256"],
        helper_sha256=snapshots.digest(snapshots.__file__),
        game_execution=False,
        fixture_cleanup=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "validation/toolsbuild/sqlite-snapshot.json",
    )
    args = parser.parse_args()
    workspace = ROOT / "tools/build"
    workspace.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(
        prefix="sqlite-snapshot-test-", dir=workspace
    )
    fixture = Path(temporary.name).resolve()
    if not fixture.is_relative_to(workspace.resolve()):
        raise ValueError("Fixture directory escaped its intended workspace")
    try:
        result = run_fixture(fixture)
    finally:
        # Only this newly created fixture is cleaned; snapshots are read-only.
        for path in fixture.rglob("*"):
            if path.is_file():
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        temporary.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
