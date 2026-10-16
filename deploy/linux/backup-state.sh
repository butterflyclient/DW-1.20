#!/bin/sh
set -eu
# Daily consistent backup of the Replay DW runtime state.
#
# Mutable state is archived while the writer is briefly stopped. Published
# update content (EXE images, patches, map assets/manifests and their
# backups) is immutable and content-addressed, so it is snapshotted with hard
# links while the server keeps running: no recompression, no extra downtime
# and no extra space while the live copy exists. Abandoned publication
# staging (updates/map-incoming-*) is never archived.
#
# Restore: stop replay-dw, extract state-<stamp>.tar.gz into /var/lib/replay-dw,
# then copy each directory of updates-<stamp>/ back into
# /var/lib/replay-dw/updates/ (cp -al keeps them as links).
# These are on-droplet backups on the same disk, not offsite copies.
exec 9>/run/replay-dw-backup.lock
flock -n 9 || exit 0
data=/var/lib/replay-dw
backups=/var/backups/replay-dw
stores='assets images patches map-manifests asset-manifests map-backups'
umask 077
mkdir -p "$backups"
# Remove partial output of an interrupted earlier run.
find "$backups" -maxdepth 1 -name 'state-*.pending' -type f -delete
find "$backups" -maxdepth 1 -name 'updates-*.pending' -type d -exec rm -rf {} +
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="$backups/state-$stamp.tar.gz"
snapshot="$backups/updates-$stamp"

# Never stop the server for a backup the disk cannot hold. The uncompressed
# size plus 1 GiB is a conservative bound for the compressed archive.
need=$(du -sk --exclude=server.log --exclude='server.log.*' --exclude=updates "$data" | cut -f1)
need=$((need + 1048576))
free=$(df -Pk "$backups" | awk 'NR == 2 { print $4 }')
if [ "$free" -lt "$need" ]; then
    echo "replay-dw backup refused: ${free} KiB free, ${need} KiB required" >&2
    exit 1
fi

# Snapshot published content under the publishers' lock, before stopping.
if [ -d "$data/updates" ]; then
    (
        flock -w 600 8
        mkdir "$snapshot.pending"
        for store in $stores; do
            if [ -d "$data/updates/$store" ]; then
                cp -al "$data/updates/$store" "$snapshot.pending/$store"
            fi
        done
        mv "$snapshot.pending" "$snapshot"
    ) 8>>"$data/updates/publication.lock"
fi

active=0
if systemctl is-active --quiet replay-dw; then active=1; fi
restore() {
    rm -f "$name.pending"
    if [ "$active" = 1 ]; then systemctl start replay-dw; fi
}
trap restore EXIT HUP INT TERM
systemctl stop replay-dw
set -- --exclude=server.log --exclude='server.log.*' --exclude='./updates/map-incoming-*'
for store in $stores; do set -- "$@" "--exclude=./updates/$store"; done
tar "$@" -czf "$name.pending" -C "$data" .
# The archive is complete; restart before hashing and pruning.
trap - EXIT HUP INT TERM
if [ "$active" = 1 ]; then systemctl start replay-dw; fi
mv "$name.pending" "$name"
sha256sum "$name" > "$name.sha256"
# Retain seven days plus the initial migration snapshot stored separately.
find "$backups" -maxdepth 1 -type f -name 'state-*' -mtime +7 -delete
find "$backups" -maxdepth 1 -type d -name 'updates-*' -mtime +7 -exec rm -rf {} +
