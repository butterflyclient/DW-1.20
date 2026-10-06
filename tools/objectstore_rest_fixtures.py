"""Replay REST vectors share durable object data with the struct-buffer transport."""

import base64
import json
import struct


def exercise(
    client, peer, directory, title, user, peer_user, request, response, helpers, checks
):
    blob, structure, text, binary, integer, fields = helpers
    host = "objectstore.prod.demonware.net"
    resource = "ObjectsVectorizedResourceUsers"
    route = "/v2/core/users/objects/?client=iw8&context=restfixture"
    owner = f"uno-{user}"
    objects = [
        {
            "metadata": {"owner": owner, "name": "rest-private.dat", "acl": "private"},
            "content": base64.b64encode(b"private profile bytes").decode(),
        },
        {
            "metadata": {"owner": owner, "name": "rest-public.dat", "acl": "public"},
            "content": base64.b64encode(bytes(range(256))).decode(),
            "tags": [{"key": "kind", "value": "fixture"}],
        },
    ]
    ids = [{"owner": owner, "name": item["metadata"]["name"]} for item in objects]

    def packet(
        operation,
        body=None,
        selected=None,
        url=route,
        service=host,
        method=None,
        headers=None,
    ):
        raw = request(
            service,
            resource,
            operation,
            method=method or (0x505554 if operation == "put_objects" else 0x474554),
            body=body,
            uri=url,
        )
        if headers is None:
            headers = (
                []
                if selected is None
                else [("DW-Objectstore-ObjectIDs", json.dumps(selected))]
            )
        size = struct.unpack_from("<I", raw, 7)[0]
        message = raw[11 : 11 + size]
        for key, value in headers:
            message += binary(14, text(1, key) + text(2, value))
        return raw[:5] + blob(message) + raw[11 + size :]

    def get(selected=ids, actor=client, **options):
        return response(
            actor.task(255, 10, packet("get_objects", selected=selected, **options))
        )

    status, uploaded = response(
        client.task(
            255,
            10,
            packet(
                "put_objects",
                {"objects": objects},
                url=route.replace("/v2/core/", "/v2/") + "&extra=validationToken",
            ),
        )
    )
    assert status == 200 and uploaded["errors"] == uploaded["validationTokens"] == []
    assert len(uploaded["objects"]) == 2
    status, downloaded = get(ids + [dict(ids[0], name="missing.dat")])
    assert status == 200 and [
        item["requestIndex"] for item in downloaded["objects"]
    ] == [0, 1]
    assert [item["content"] for item in downloaded["objects"]] == [
        o["content"] for o in objects
    ]
    assert downloaded["errors"] == [
        {
            "requestIndex": 2,
            "owner": owner,
            "name": "missing.dat",
            "error": "Error:ClientError:NotFound",
        }
    ]
    assert downloaded["objects"][1]["tags"] == objects[1]["tags"]
    for environment in ("dev", "cert", "prod"):
        assert get(service=f"objectstore.{environment}.demonware.net") == (
            200,
            {"objects": downloaded["objects"], "errors": []},
        )

    # Read the same files through Replay's older task 193/6, without duplication.
    envelope = (
        text(1, "GET")
        + text(2, route)
        + binary(4, text(1, "DW-Objectstore-ObjectIDs") + text(2, json.dumps(ids)))
    )
    decoded = dict(
        (tag, value)
        for tag, kind, value in fields(
            client.task(193, 6, structure(envelope), structured=True)
        )
    )
    assert decoded[2] == 200 and json.loads(decoded[3]) == {
        "objects": downloaded["objects"],
        "errors": [],
    }
    checks.append(
        "Target REST object vectors: all three environment hosts, shared struct-buffer storage, complete content/metadata/tags and exact request-index accounting"
    )

    metadata = downloaded["objects"][0]["metadata"]
    for hint in (
        {"objectVersion": metadata["objectVersion"]},
        {"checksum": metadata["checksum"]},
        {"objectVersion": metadata["objectVersion"], "checksum": metadata["checksum"]},
    ):
        status, cached = get([{**ids[0], **hint}])
        assert status == 200 and cached == {
            "objects": [],
            "errors": [
                {**ids[0], "requestIndex": 0, "error": "Error:ClientError:NotModified"}
            ],
        }
    assert len(get([{**ids[0], "objectVersion": "different"}])[1]["objects"]) == 1
    assert (
        len(
            get(
                [
                    {
                        **ids[0],
                        "objectVersion": metadata["objectVersion"],
                        "checksum": "different",
                    }
                ]
            )[1]["objects"]
        )
        == 1
    )
    status, other = get(actor=peer)
    assert status == 200 and len(other["objects"]) == len(other["errors"]) == 1
    assert other["objects"][0]["requestIndex"] == 1
    assert other["errors"][0]["error"] == "Error:ClientError:Forbidden:ACLError"
    peer.task(255, 10, packet("put_objects", {"objects": objects}), error=101)
    checks.append(
        "REST cache-aware reads return the native NotModified DTO; stale or inconsistent hints return verified content, private ACLs and signed upload ownership remain enforced"
    )

    saved = (
        directory
        / "objectstore/users"
        / str(title)
        / "restfixture"
        / owner
        / "rest-private.dat.object.json"
    )
    before = saved.read_bytes()
    for selected in (
        [dict(ids[0], checksum=0)],
        [dict(ids[0], checksum="x" * 33)],
        [dict(ids[0], objectVersion=None)],
        [dict(ids[0], extra=1)],
    ):
        client.task(255, 10, packet("get_objects", selected=selected), error=106)
    for url in (
        route + "&context=",
        route + "&client=iw8",
        route + "&other=1",
        route + "&",
        route.replace("context=restfixture", "context=../escape"),
        route.replace("context=restfixture", "context=%00"),
        route.replace("/v2/core/", "/v1/core/"),
    ):
        client.task(255, 10, packet("get_objects", selected=ids, url=url), error=106)
    client.task(255, 10, packet("get_objects", selected=ids, body={}), error=106)
    client.task(
        255, 10, packet("get_objects", selected=ids, method=0x504F5354), error=106
    )
    client.task(255, 10, packet("get_objects"), error=106)
    client.task(
        255,
        10,
        packet(
            "get_objects",
            headers=[
                ("DW-Objectstore-ObjectIDs", json.dumps(ids)),
                ("dw-objectstore-objectids", json.dumps(ids)),
            ],
        ),
        error=106,
    )
    client.task(
        255,
        10,
        packet(
            "put_objects",
            {"objects": objects},
            headers=[("Content-Type", "text/plain")],
        ),
        error=106,
    )
    assert saved.read_bytes() == before
    checks.append(
        "REST vector envelope rejects duplicate retained headers, unsupported paths/queries/method/body/content type and malformed cache hints without altering stored objects"
    )

    # REST has a 256 KiB body window; the older struct response stops at 65535.
    large = [
        {
            "metadata": {"owner": owner, "name": f"rest-window-{i}.dat"},
            "content": base64.b64encode(bytes([i]) * 30000).decode(),
        }
        for i in range(2)
    ]
    assert (
        response(client.task(255, 10, packet("put_objects", {"objects": large})))[0]
        == 200
    )
    status, body = get([{"owner": owner, "name": o["metadata"]["name"]} for o in large])
    assert status == 200 and len(json.dumps(body).encode()) > 65535
    assert [o["content"] for o in body["objects"]] == [o["content"] for o in large]
    checks.append(
        "REST vector payload windows exceed the struct transport's 64 KiB limit while retaining the native 256 KiB cap and full checksum-verified data"
    )
    return {
        "packet": packet("get_objects", selected=ids),
        "body": {"objects": downloaded["objects"], "errors": []},
    }


def check_restart(client, fixture, response, checks):
    assert response(client.task(255, 10, fixture["packet"])) == (200, fixture["body"])
    checks.append(
        "REST vector content/metadata/tags survive process restart in the shared account-owned object store"
    )
