"""Repair publication of the current verified client without recompiling it."""

import dw_client
import dw_publication


def main():
    with dw_client.pipeline_lock():
        _, state, _ = dw_client.settings()
        latest = dw_client.read(state / "latest-job.json")
        path = dw_client.inside(latest["readiness"])
        ready = dw_client.read(path)
        if (
            not ready["passed"]
            or dw_client.digest(ready["executable"]) != ready["sha256"]
        ):
            raise ValueError("Latest client is not a verified ready image")
        for proof in ready["proofs"]:
            if dw_client.digest(proof["path"]) != proof["sha256"]:
                raise ValueError("Exact-image verification receipt changed")
        receipt = dw_client.read(ready["source_receipt"])
        if dw_client.digest(ready["source_receipt"]) != ready["source_receipt_sha256"]:
            raise ValueError("Frozen source receipt changed")
        for item in receipt["source_inputs"]:
            if (
                dw_client.digest(dw_client.ROOT / item["source"])
                != item["source_sha256"]
            ):
                raise ValueError(
                    "Current source differs from the ready build: " + item["source"]
                )
        ready["publication"] = dw_publication.publish(
            ready["executable"],
            ready["build_report"],
            ready["source_root"],
            path.parent / "updater.json",
            path.parent / "publication",
        )
        dw_client.save(path, ready)
        current_path = dw_client.ROOT / "data/current-remote-deployment.json"
        current = dw_client.read(current_path)
        current.update(
            public_release=ready["publication"]["release"],
            public_client_publication=ready["publication"],
            public_executable_update_publication_changed=True,
        )
        if current.get("sha256") == ready["sha256"]:
            current["readiness"] = dict(
                path=path.relative_to(dw_client.ROOT).as_posix(),
                sha256=dw_client.digest(path),
            )
        dw_client.save(current_path, current)
        print("PASS current verified client and public updater agree", flush=True)


if __name__ == "__main__":
    main()
