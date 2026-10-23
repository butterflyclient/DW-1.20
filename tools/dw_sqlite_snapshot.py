"""Pin one complete, read-only SQLite analysis snapshot for an entire DW job."""

from contextlib import contextmanager, closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import shutil
import time
import atexit

_LOCKED_SNAPSHOTS = {}


def snapshot_digest(path):
    """A Windows read handle denies writes for the lifetime of the build."""
    if os.name != 'nt':
        return digest(path)
    import ctypes
    import msvcrt
    from ctypes import wintypes
    path = Path(path)
    info = path.stat()
    key = info.st_dev, info.st_ino
    if key in _LOCKED_SNAPSHOTS:
        return _LOCKED_SNAPSHOTS[key][1]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    handle = kernel.CreateFileW(str(path.resolve()), 0x80000000, 1, None, 3, 0x08000080, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), 'Cannot lock the immutable analysis snapshot', str(path))
    stream = os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), 'rb')
    try:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    except BaseException:
        stream.close()
        raise
    _LOCKED_SNAPSHOTS[key] = stream, sha
    return sha


@atexit.register
def close_snapshot_locks():
    for stream, _sha in _LOCKED_SNAPSHOTS.values():
        stream.close()
    _LOCKED_SNAPSHOTS.clear()


def source_version(source_path):
    """SQLite commits change the DB header or the WAL commit/checksum state."""
    result = []
    for path in (Path(source_path), Path(str(source_path)+'-wal')):
        if not path.exists():
            result.append(None)
            continue
        info = path.stat()
        with path.open('rb') as stream:
            head = stream.read(100)
            stream.seek(max(0, info.st_size-32))
            tail = stream.read(32)
        result.append([info.st_size, info.st_mtime_ns, head.hex(), tail.hex()])
    return result


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


def source_signature(source_path):
    """Hash the main database and WAL; a changing source cannot be reused."""
    version = source_version(source_path)
    result = []
    for path in (Path(source_path), Path(str(source_path) + '-wal')):
        if not path.exists():
            result.append(None)
            continue
        before = path.stat()
        sha = digest(path)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('Analysis database changed while checking snapshot reuse')
        result.append(dict(bytes=after.st_size, sha256=sha))
    if source_version(source_path) != version:
        raise RuntimeError('SQLite committed while checking snapshot reuse')
    return dict(files=result, version=version)


def create_snapshot(source_path, destination_path, progress=None, cache_directory=None):
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
    cache = Path(cache_directory).resolve() if cache_directory else None
    signature = source_signature(source_path) if cache else None
    key = hashlib.sha256(json.dumps([str(source_path), signature], sort_keys=True).encode()).hexdigest()
    cached = cache / (key + '.json') if cache else None
    if cached and cached.is_file():
        previous = json.loads(cached.read_bytes())
        binding = previous['binding']
        path = verify_binding(binding)
        if previous['source_signature'] == signature and source_version(source_path) == signature['version']:
            try:
                os.link(path, destination_path)
            except OSError:
                shutil.copyfile(path, destination_path)
            document = json.loads(Path(binding['proof']).read_bytes())
            document.update(path=str(destination_path), reused_from=str(path), seconds=time.monotonic()-started,
                            reuse_source_signature=signature, helper_sha256=digest(__file__))
            proof_path = destination_path.with_name('analysis-snapshot.json')
            proof_path.write_text(json.dumps(document, indent=2)+'\n', encoding='utf-8')
            return dict(path=str(destination_path), sha256=binding['sha256'], proof=str(proof_path), proof_sha256=digest(proof_path))
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
        os.chmod(destination_path, stat.S_IREAD)
        snapshot_sha = snapshot_digest(destination_path)
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
        binding = dict(
            path=str(destination_path),
            sha256=snapshot_sha,
            proof=str(proof_path),
            proof_sha256=digest(proof_path),
        )
        if cache and source_version(source_path) == signature['version']:
            cache.mkdir(parents=True, exist_ok=True)
            temporary = cached.with_suffix('.pending')
            temporary.write_text(json.dumps(dict(source_signature=signature, binding=binding), indent=2)+'\n')
            os.replace(temporary, cached)
        return binding
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
        or snapshot_digest(path) != binding["sha256"]
    ):
        raise ValueError("Job SQLite snapshot changed or lacks complete backup proof")
    return path
