#!/usr/bin/env python3
"""Daily storage maintenance for the Replay DW droplet. Dry run unless --apply.

Removes only well-defined, superseded or reproducible files:
  - abandoned publication staging (updates/map-incoming-<ns>) older than 24 h;
  - update blobs no client can be offered, once older than 48 h:
      images:  all but the catalog's latest and the two newest others;
      patches: those not listed in the v1 catalog;
      assets:  those referenced by no current catalog or retained map backup;
  - map publication backups beyond the newest three;
  - ad-hoc pre-deployment backups (before-*.tar.gz) older than seven days;
  - finished release build jobs (/tmp/replay-dw-*) older than two days;
  - server releases beyond the active one and the five newest others.
Daily state archives and update snapshots are pruned by backup-state.sh.

Update-store decisions are made under updates/publication.lock, the lock the
publishers hold, so a publication never races a prune. Missing or malformed
catalogs skip update pruning entirely. Removed update blobs stay recoverable
from the daily hard-link snapshots for seven days. backup-state.sh snapshots
updates under the same publication lock, so the two never interleave there.
--root remaps every path for fixtures.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time

DAY = 86400
DIGEST = re.compile('[0-9a-f]{64}')


def parse():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--apply', action='store_true', help='remove files (default: report only)')
    parser.add_argument('--root', type=Path, default=Path('/'), help='filesystem root (fixtures)')
    parser.add_argument('--now', type=float, default=None, help=argparse.SUPPRESS)
    return parser.parse_args()


class Maintenance:
    def __init__(self, args):
        self.apply = args.apply
        self.now = args.now if args.now is not None else time.time()
        root = args.root
        self.data = root / 'var/lib/replay-dw'
        self.updates = self.data / 'updates'
        self.backups = root / 'var/backups/replay-dw'
        self.releases = root / 'opt/replay-dw/releases'
        self.current = root / 'opt/replay-dw/current'
        self.tmp = root / 'tmp'
        self.lock = root / 'run/replay-dw-maintenance.lock'
        self.removed, self.skipped = [], []

    # -- removal -----------------------------------------------------------
    def size(self, path):
        """Bytes this removal frees now (hard-linked files free nothing yet)."""
        total = 0
        for item in [path] + (list(path.rglob('*')) if path.is_dir() and not path.is_symlink() else []):
            info = item.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                total += info.st_size
        return total

    def remove(self, path, reason):
        freed = self.size(path)
        self.removed.append(dict(path=str(path), reason=reason, freed_bytes=freed))
        if not self.apply:
            return
        if path.is_dir() and not path.is_symlink():
            # Releases are read-only (0555); restore owner write to remove them.
            for item in [path] + list(path.rglob('*')):
                if item.is_dir() and not item.is_symlink():
                    item.chmod(item.stat().st_mode | stat.S_IWUSR)
            shutil.rmtree(path)
        else:
            path.unlink()

    def old(self, path, seconds):
        return self.now - path.lstat().st_mtime > seconds

    # -- policies ----------------------------------------------------------
    def staging(self):
        for path in sorted(self.updates.glob('map-incoming-*')):
            stamp = path.name[len('map-incoming-'):]
            if path.is_dir() and not path.is_symlink() and stamp.isdigit() and \
                    self.now - int(stamp) / 1e9 > DAY:
                self.remove(path, 'abandoned publication staging older than 24 h')

    def catalogs(self):
        """Every digest a client can be offered, or None when uncertain."""
        def load(name):
            return json.loads((self.updates / name).read_bytes())
        try:
            full = load('full-image-catalog.json')
            assert full['schema'] == 1 and full['format'] == 'full-executable-v1'
            latest = full['latest']
            assert DIGEST.fullmatch(latest) and (self.updates / 'images' / (latest + '.exe')).is_file()
            assets = set(full.get('assets', {}).get('payloads', {}))
            maps = load('custom-map-catalog.json') if (self.updates / 'custom-map-catalog.json').exists() else None
            if maps is not None:
                assert maps['schema'] == 1 and maps['format'] == 'custom-map-package-v1'
                assets |= set(maps['payloads'])
            if 'maps' in full:
                assert maps is not None and maps['package_hash'] == full['maps']['package_hash']
            patches = set()
            if (self.updates / 'catalog.json').exists():
                legacy = load('catalog.json')
                assert legacy['schema'] == 1 and legacy['format'] == 'msdelta-raw-v1'
                patches = {entry['sha256'] for entry in legacy['patches'].values()}
            assert all(DIGEST.fullmatch(d) for d in assets | patches)
            return latest, assets, patches
        except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
            self.skipped.append('update stores: catalog unavailable or malformed: ' + repr(error))
            return None

    def map_backups(self):
        """Keep the newest three map backups; return the payloads they protect."""
        folder = self.updates / 'map-backups'
        if not folder.is_dir():
            return set()
        entries = sorted((p for p in folder.iterdir()
                          if p.is_dir() and re.fullmatch(r'\d+-[0-9a-f]{16}', p.name)),
                         key=lambda p: int(p.name.split('-')[0]), reverse=True)
        protected = set()
        for index, path in enumerate(entries):
            if index < 3:
                try:
                    record = json.loads((path / 'backup.json').read_bytes())
                    for catalog in (record.get('previous'), record.get('new_catalog')):
                        protected |= set((catalog or {}).get('payloads', {}))
                except (OSError, ValueError) as error:
                    self.skipped.append('map backup unreadable, kept: %s %r' % (path, error))
            elif self.old(path, 2 * DAY):
                self.remove(path, 'map publication backup beyond the newest three')
        return protected

    def blobs(self):
        reachable = self.catalogs()
        if reachable is None:
            return
        latest, assets, patches = reachable
        assets |= self.map_backups()
        images = sorted((p for p in (self.updates / 'images').glob('*.exe')
                         if DIGEST.fullmatch(p.stem) and p.stem != latest),
                        key=lambda p: p.stat().st_mtime, reverse=True)
        for path in images[2:]:
            if self.old(path, 2 * DAY):
                self.remove(path, 'superseded EXE image (latest and two previous kept)')
        for path in sorted((self.updates / 'patches').glob('*.delta')):
            if DIGEST.fullmatch(path.stem) and path.stem not in patches and self.old(path, 2 * DAY):
                self.remove(path, 'patch not listed in the v1 update catalog')
        for path in sorted((self.updates / 'assets').glob('*.bin')):
            if DIGEST.fullmatch(path.stem) and path.stem not in assets and self.old(path, 2 * DAY):
                self.remove(path, 'asset referenced by no current catalog or retained map backup')

    def update_stores(self):
        if not self.updates.is_dir():
            return
        with (self.updates / 'publication.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.staging()
            self.blobs()

    def ad_hoc_backups(self):
        for path in sorted(self.backups.glob('before-*.tar.gz')):
            if path.is_file() and self.old(path, 7 * DAY):
                self.remove(path, 'ad-hoc pre-deployment backup older than seven days')

    def busy(self):
        """Paths in use by a running process (cwd or arguments)."""
        used = set()
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                used.add(os.readlink(proc / 'cwd'))
                used.update(part.decode(errors='replace')
                            for part in (proc / 'cmdline').read_bytes().split(b'\0') if part)
            except OSError:
                pass
        return used

    def build_jobs(self):
        used = self.busy()
        for path in sorted(self.tmp.glob('replay-dw-*')):
            if not path.is_dir() or path.is_symlink() or not self.old(path, 2 * DAY):
                continue
            if any(item == str(path) or item.startswith(str(path) + '/') for item in used):
                self.skipped.append('build job in use, kept: ' + str(path))
                continue
            self.remove(path, 'finished release build job older than two days')

    def server_releases(self):
        if not self.releases.is_dir():
            return
        try:
            active = self.current.resolve(strict=True)
        except OSError:
            self.skipped.append('releases: active release unresolved; nothing removed')
            return
        candidates = sorted((p for p in self.releases.iterdir()
                             if p.is_dir() and not p.is_symlink() and (p / 'iw8-dw-server').is_file()
                             and p.resolve() != active),
                            key=lambda p: p.stat().st_mtime, reverse=True)
        for path in candidates[5:]:
            if self.old(path, 2 * DAY):
                self.remove(path, 'server release beyond the active one and five previous')

    def run(self):
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        with self.lock.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.update_stores()
            self.ad_hoc_backups()
            self.build_jobs()
            self.server_releases()
        usage = shutil.disk_usage(self.data if self.data.exists() else '/')
        summary = dict(applied=self.apply, removed=len(self.removed),
                       freed_bytes=sum(item['freed_bytes'] for item in self.removed),
                       disk_free_bytes=usage.free, disk_total_bytes=usage.total,
                       skipped=self.skipped, items=self.removed)
        print(json.dumps(summary, indent=2))
        # A failed unit is visible in `systemctl --failed`.
        return 2 if usage.free < 0.15 * usage.total else 0


if __name__ == '__main__':
    sys.exit(Maintenance(parse()).run())
