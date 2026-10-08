"""Publish verified executable deltas on the primary DW droplet, catalog last."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import time

import remote_backend


def publish(publication):
    catalog_bytes = (publication / "catalog.json").read_bytes()
    catalog = json.loads(catalog_bytes)
    valid_hash = lambda value: isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)
    if (
        catalog["schema"] != 1
        or catalog["format"] != "msdelta-raw-v1"
        or not valid_hash(catalog["latest"])
    ):
        raise ValueError("Invalid executable update publication")
    blobs = {}
    for base, row in catalog["patches"].items():
        if not valid_hash(base) or not valid_hash(row["sha256"]):
            raise ValueError("Unsafe update blob identity")
        file = publication / "patches" / (row["sha256"] + ".delta")
        if (
            file.stat().st_size != row["size"]
            or hashlib.sha256(file.read_bytes()).hexdigest() != row["sha256"]
        ):
            raise ValueError("Local patch no longer verifies")
        blobs[row["sha256"]] = file
    incoming = "/var/lib/replay-dw/updates/incoming-" + str(time.time_ns())
    with remote_backend.connect() as client:
        _, out, error = client.exec_command("install -d -m 0755 " + incoming, timeout=20)
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
        with client.open_sftp() as sftp:
            for digest, file in blobs.items():
                sftp.put(str(file), incoming + "/" + digest + ".delta")
            with sftp.file(incoming + "/catalog.json", "wb") as file:
                file.write(catalog_bytes)
        # Validate every blob and all historical source hashes before making the
        # new catalog visible. An interrupted transfer cannot advertise a patch.
        script = r"""
import hashlib,json,os,pathlib,shutil
incoming=pathlib.Path(INCOMING)
root=incoming.parent
new=json.loads((incoming/'catalog.json').read_bytes())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(incoming/'catalog.json')==CATALOG_SHA
old=root/'catalog.json'
if old.exists():
 prior=json.loads(old.read_bytes())
 if prior==new:
  for p in incoming.iterdir():
   assert p.is_file() and (p.name=='catalog.json' or p.suffix=='.delta')
   p.unlink()
  incoming.rmdir()
  print(json.dumps(dict(published=True,already_current=True,release=new['release'])))
  raise SystemExit(0)
 assert new['release']>prior['release'],'Release rollback rejected'
 required=set(prior['patches'])|{prior['latest']}
 assert required.issubset(new['patches']),'A previously released executable lost its upgrade path'
for base,row in new['patches'].items():
 p=incoming/(row['sha256']+'.delta')
 assert p.stat().st_size==row['size'] and sha(p)==row['sha256']
patches=root/'patches';patches.mkdir(exist_ok=True)
for row in new['patches'].values():
 p=incoming/(row['sha256']+'.delta');target=patches/p.name
 if not p.exists():continue
 if target.exists():assert sha(target)==row['sha256'];p.unlink()
 else:os.chmod(p,0o644);os.replace(p,target)
os.chmod(incoming/'catalog.json',0o644)
os.replace(incoming/'catalog.json',root/'catalog.json')
directory=os.open(root,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
incoming.rmdir()
print(json.dumps(dict(published=True,release=new['release'],latest=new['latest'],supported_older_releases=len(new['patches']),catalog_sha256=sha(root/'catalog.json'))))
""".replace("INCOMING", repr(incoming)).replace(
            "CATALOG_SHA", repr(hashlib.sha256(catalog_bytes).hexdigest())
        )
        _, out, error = client.exec_command("python3 - <<'PY'\n" + script + "\nPY", timeout=60)
        raw = out.read()
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
    result = json.loads(raw)
    (publication / "droplet-publication.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--publication", type=Path, default=Path("data/executable-update-publication")
    )
    print(json.dumps(publish(parser.parse_args().publication), indent=2))
