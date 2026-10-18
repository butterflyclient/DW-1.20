"""Pin one complete, read-only SQLite analysis snapshot for an entire DW job."""

from contextlib import contextmanager, closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@contextmanager
def scoped_sqlite(path):
    previous = os.environ.get("REPLAY_SQLITE")
    os.environ["REPLAY_SQLITE"] = str(Path(path).resolve())
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("REPLAY_SQLITE", None)
        else:
            os.environ["REPLAY_SQLITE"] = previous


def create_snapshot(source_path, destination_path, progress=None):
    """Backup a pinned read transaction; never trim or write the source DB.

    The first schema read establishes the source pager snapshot before backup.
    Keeping that read transaction open prevents the backup API from restarting
    against newer commits while live writers continue updating a WAL database.
    """
    source_path = Path(source_path).resolve(strict=True)
    destination_path = Path(destination_path).resolve()
    if source_path == destination_path or destination_path.exists():
        raise ValueError("Snapshot destination must be a new job-owned file")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    pending = destination_path.with_name(destination_path.name + ".pending")
    if pending.exists():
        raise FileExistsError(pending)
    started = time.monotonic()
    try:
        with closing(
            sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=30)
        ) as source:
            source.execute("PRAGMA query_only=ON")
            source.execute("BEGIN")
            schema = source.execute(
                "SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema ORDER BY type,name"
            ).fetchall()
            pinned_at = datetime.now(timezone.utc).isoformat()
            page_size = source.execute("PRAGMA page_size").fetchone()[0]
            page_count = source.execute("PRAGMA page_count").fetchone()[0]
            source_journal_mode = source.execute("PRAGMA journal_mode").fetchone()[0]
            with closing(sqlite3.connect(str(pending))) as destination:
                destination.execute("PRAGMA journal_mode=DELETE")
                source.backup(destination, pages=8192, progress=progress, sleep=0.01)
                # Backup copies the source page-one WAL format flags. Convert
                # after backup so later read-only opens never create sidecars
                # and trip the frozen database's signature guard.
                mode = destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
                if mode != "delete":
                    raise ValueError("Snapshot did not leave WAL journal mode")
                actual_schema = destination.execute(
                    "SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema ORDER BY type,name"
                ).fetchall()
                if actual_schema != schema:
                    raise ValueError(
                        "Backup schema differs from the pinned source transaction"
                    )
                integrity = destination.execute("PRAGMA quick_check(1)").fetchone()[0]
                if integrity != "ok":
                    raise ValueError(
                        "Analysis snapshot quick_check failed: " + str(integrity)
                    )
                actual_page_count = destination.execute("PRAGMA page_count").fetchone()[
                    0
                ]
                if actual_page_count != page_count:
                    raise ValueError(
                        "Backup page count differs from the pinned source transaction"
                    )
            source.rollback()
        pending.replace(destination_path)
        with destination_path.open("rb") as stream:
            header = stream.read(20)
        if header[18:20] != b"\x01\x01":
            raise ValueError("Snapshot retains WAL file-header flags")
        snapshot_sha = digest(destination_path)
        document = dict(
            schema=1,
            method="sqlite-backup-pinned-read-transaction-v1",
            source=str(source_path),
            path=str(destination_path),
            sha256=snapshot_sha,
            pinned_at_utc=pinned_at,
            finished_at_utc=datetime.now(timezone.utc).isoformat(),
            seconds=time.monotonic() - started,
            page_size=page_size,
            page_count=page_count,
            source_journal_mode=source_journal_mode,
            snapshot_journal_mode="delete",
            quick_check="ok",
            schema_sha256=hashlib.sha256(
                json.dumps(schema, separators=(",", ":")).encode()
            ).hexdigest(),
            table_count=sum(row[0] == "table" for row in schema),
            helper_sha256=digest(__file__),
            all_tables_preserved=True,
        )
        proof_path = destination_path.with_name("analysis-snapshot.json")
        proof_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        os.chmod(destination_path, stat.S_IREAD)
        return dict(
            path=str(destination_path),
            sha256=snapshot_sha,
            proof=str(proof_path),
            proof_sha256=digest(proof_path),
        )
    finally:
        if pending.exists():
            pending.unlink()


def verify_binding(binding):
    path = Path(binding["path"]).resolve(strict=True)
    proof_path = Path(binding["proof"]).resolve(strict=True)
    if digest(proof_path) != binding["proof_sha256"]:
        raise ValueError("Job SQLite snapshot proof changed")
    proof = json.loads(proof_path.read_bytes())
    if (
        proof.get("method") != "sqlite-backup-pinned-read-transaction-v1"
        or Path(proof["path"]).resolve() != path
        or proof["sha256"] != binding["sha256"]
        or not proof.get("all_tables_preserved")
        or proof.get("quick_check") != "ok"
        or proof.get("snapshot_journal_mode") != "delete"
        or digest(path) != binding["sha256"]
    ):
        raise ValueError("Job SQLite snapshot changed or lacks complete backup proof")
    return path
