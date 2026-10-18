#!/bin/sh
# Reviewed activation for the release-manifest server candidate. Same procedure as the
# 20261018 TLS-deadline activation: hash-pinned candidate, fresh mutable-state backup, one
# controlled stop, atomic symlink swap, HTTPS health + process-hash check, automatic rollback.
# Does not provision TLS, prune backups, or touch published updates/assets.
# Usage: sh activate-release-manifest-candidate.sh CANDIDATE EXPECTED_SHA EXPECTED_OLD_SHA
set -eu
[ "$#" = 3 ] || exit 2
candidate=$1
expected=$2
old_sha=$3
case "$candidate" in /tmp/replay-dw-release-manifest-candidate-*/build/iw8-dw-server) ;; *) exit 2;; esac
case "$expected:$old_sha" in *[!a-f0-9:]*|:*) exit 2;; esac
[ "${#expected}" = 64 ] && [ "${#old_sha}" = 64 ]
[ "$(id -u)" = 0 ]
exec 9>/run/replay-dw-backup.lock
flock -n 9
previous=$(readlink -f /opt/replay-dw/current)
case "$previous" in /opt/replay-dw/releases/*) ;; *) exit 2;; esac
[ "$(sha256sum "$previous/iw8-dw-server" | cut -d' ' -f1)" = "$old_sha" ]
[ "$(sha256sum "$candidate" | cut -d' ' -f1)" = "$expected" ]
stamp=$(date -u +%Y%m%dT%H%M%SZ)
pending=/opt/replay-dw/current.pending-"$stamp"-$$
rollback=/opt/replay-dw/current.rollback-"$stamp"-$$
[ ! -e "$pending" ] && [ ! -L "$pending" ]
[ ! -e "$rollback" ] && [ ! -L "$rollback" ]
release=/opt/replay-dw/releases/"$stamp"-release-manifest-$(printf '%s' "$expected" | cut -c1-12)
backup=/var/backups/replay-dw/state-pre-release-manifest-"$stamp".tar.gz
umask 077
mkdir "$release"
chmod 0755 "$release"
install -m 0755 "$candidate" "$release/iw8-dw-server"
[ "$(sha256sum "$release/iw8-dw-server" | cut -d' ' -f1)" = "$expected" ]
# Check capacity before the one controlled stop.
need=$(du -sk --exclude='server.log*' --exclude=updates /var/lib/replay-dw | cut -f1)
free=$(df -Pk /var/backups/replay-dw | awk 'NR==2 {print $4}')
[ "$free" -gt "$((need + 1048576))" ]
stopped=0
complete=0
restore() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$complete" != 1 ] && [ "$stopped" = 1 ]; then
        systemctl stop replay-dw || true
        ln -s "$previous" "$rollback"
        mv -Tf "$rollback" /opt/replay-dw/current
        systemctl start replay-dw
        echo "ACTIVATION_FAILED previous release restored: $previous" >&2
    fi
    exit "$result"
}
trap restore EXIT HUP INT TERM
stopped=1
systemctl stop replay-dw
# Keep metadata and all mutable stores. Published content stays untouched in place.
tar --exclude='./server.log' --exclude='./server.log.*' \
    --exclude='./updates/assets' --exclude='./updates/images' \
    --exclude='./updates/patches' --exclude='./updates/map-manifests' \
    --exclude='./updates/asset-manifests' --exclude='./updates/map-backups' \
    --exclude='./updates/map-incoming-*' \
    -czf "$backup.pending" -C /var/lib/replay-dw .
mv "$backup.pending" "$backup"
ln -s "$release" "$pending"
mv -Tf "$pending" /opt/replay-dw/current
systemctl start replay-dw
python3 - "$expected" <<'PY'
import hashlib,json,os,pathlib,subprocess,sys,time,urllib.request
for attempt in range(50):
    try:
        with urllib.request.urlopen('https://162.243.115.160:8443/health',timeout=2) as response:
            health=json.load(response)
        assert health['server']=='iw8-dw' and health['platform_auth']
        pid=int(subprocess.check_output(['systemctl','show','replay-dw','-p','MainPID','--value']))
        assert hashlib.sha256(pathlib.Path(f'/proc/{pid}/exe').read_bytes()).hexdigest()==sys.argv[1]
        # The new route must answer over verified TLS from the public address.
        nonce=os.urandom(32).hex()
        with urllib.request.urlopen('https://162.243.115.160:8443/updates/v2/manifest?nonce='+nonce,timeout=5) as response:
            body,_,signature=response.read().rpartition(b'\n')
        assert json.loads(body)['nonce']==nonce and len(signature)==512
        print(json.dumps(dict(active=True,pid=pid,sha256=sys.argv[1],https_health=200,release_manifest=200)))
        break
    except Exception:
        if attempt==49:raise
        time.sleep(.2)
PY
complete=1
trap - EXIT HUP INT TERM
# Hash after startup to minimize downtime. No backup pruning.
sha256sum "$backup" > "$backup.sha256"
echo "ACTIVATED release=$release backup=$backup previous=$previous"
