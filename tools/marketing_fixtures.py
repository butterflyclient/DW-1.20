"""Independent full Replay marketing-message DTO and publication checks."""

import base64
import copy
import json
import time


def exercise(client, directory, title, helpers, checks):
    structure, integer, text, blob = helpers
    path = directory / "marketing" / str(title) / "iw8" / "catalog.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    row = dict(
        id=(1 << 62) + 10406,
        assignment=(1 << 63) + 19,
        language="en",
        location=1,
        enabled=True,
        starts=0,
        expires=0,
        content=base64.b64encode(b'{"title":"Local {{name}}"}\0').decode(),
        metadata=base64.b64encode(b'{"name":"Replay"}\0').decode(),
        payload=base64.b64encode(b"opaque\0bytes").decode(),
        signature=base64.b64encode(bytes(range(65))).decode(),
    )
    catalog = dict(schema=1, title=title, context="iw8", messages=[row])
    secondary = dict(row, id=row["id"] + 1, location=2)
    catalog["messages"].extend(
        [
            secondary,
            dict(row, id=row["id"] + 2, enabled=False),
            dict(row, id=row["id"] + 3, expires=stamp - 1),
            dict(row, id=row["id"] + 4, starts=stamp + 3600),
            dict(row, id=row["id"] + 5, language="fr"),
        ]
    )

    def publish(value=catalog):
        path.write_text(json.dumps(value), encoding="utf-8")

    def query(locations=((1, 10),), language="en", context="iw8"):
        return structure(
            text(1, context)
            + text(2, language)
            + b"".join(
                blob(3, integer(1, location) + integer(2, count))
                for location, count in locations
            )
        )

    def expected(message):
        fields = integer(1, message["id"]) + text(2, message["language"])
        for tag, key in enumerate(("content", "metadata", "payload", "signature"), 3):
            fields += blob(tag, base64.b64decode(message[key]))
        fields += integer(7, message["assignment"]) + integer(8, message["location"])
        return blob(1, fields)

    publish()
    assert client.task(104, 6, query(), structured=True) == expected(row)
    assert client.task(104, 6, query(((2, 1), (1, 1))), structured=True) == expected(
        secondary
    ) + expected(row)
    assert client.task(104, 6, query(((1, 0),)), structured=True) == b""
    assert client.task(104, 6, query(language="de"), structured=True) == b""
    assert client.task(104, 6, query(context="other"), structured=True) == b""
    assert client.task(104, 6, query(language="fr"), structured=True) == expected(
        catalog["messages"][-1]
    )
    before = path.read_bytes()
    for request in (
        query(((1, 1), (1, 1))),
        query(((1, 101),)),
        query(context=".."),
        query(context="a/b"),
        query(language="x" * 20),
    ):
        client.task(104, 6, request, error=106)
        assert path.read_bytes() == before
    checks.append(
        "Complete native eight-field marketing DTO, binary blob/signature and UInt64 assignment, location request order/count, exact language/context and publication time/enabled filtering"
    )

    for mutate in (
        lambda value: value.update(title=title + 1),
        lambda value: value.update(context="wrong"),
        lambda value: value["messages"].append(copy.deepcopy(row)),
        lambda value: value["messages"][0].update(location=1 << 32),
        lambda value: value["messages"][0].update(id=-1),
        lambda value: value["messages"][0].update(language="x" * 20),
        lambda value: value["messages"][0].update(
            signature=base64.b64encode(bytes(66)).decode()
        ),
        lambda value: value["messages"][0].update(
            content=base64.b64encode(bytes(4097)).decode()
        ),
        lambda value: value["messages"][0].update(
            metadata=base64.b64encode(bytes(2049)).decode()
        ),
        lambda value: value["messages"][0].update(
            payload=base64.b64encode(bytes(1025)).decode()
        ),
        lambda value: value["messages"][1].update(metadata="bad=="),
    ):
        damaged = copy.deepcopy(catalog)
        mutate(damaged)
        publish(damaged)
        client.task(104, 6, query(), error=102)
        assert json.loads(path.read_bytes()) == damaged
    bounded = copy.deepcopy(catalog)
    bounded["messages"] = [
        dict(
            row,
            content=base64.b64encode(bytes(4096)).decode(),
            metadata=base64.b64encode(bytes(2048)).decode(),
            payload=base64.b64encode(bytes(1024)).decode(),
        )
    ]
    publish(bounded)
    assert client.task(104, 6, query(), structured=True) == expected(
        bounded["messages"][0]
    )
    oversized = copy.deepcopy(bounded)
    oversized["messages"] = [
        dict(oversized["messages"][0], id=index + 1) for index in range(100)
    ]
    publish(oversized)
    client.task(104, 6, query(((1, 100),)), error=102)
    publish()
    checks.append(
        "Native marketing blob capacities at and above bounds, all-row corruption validation, duplicate/overflow/malformed publication rejection, bounded full reply and no mutation"
    )
    viewed = structure(
        text(1, "")
        + blob(
            2,
            integer(1, row["id"])
            + integer(2, 1)
            + integer(3, row["assignment"])
            + text(4, "en"),
        )
    )
    assert client.task(104, 7, viewed, structured=True) == b""
    owner = json.loads(
        next(
            (directory / "marketing" / str(title) / "_default").glob("*.views.json")
        ).read_bytes()
    )
    owner_path = (
        directory
        / "marketing"
        / str(title)
        / "_default"
        / f'{owner["owner"]}.views.json'
    )
    viewed_bytes = owner_path.read_bytes()
    assert len(owner["views"]) == 1 and next(iter(owner["views"].values()))["view"] == {
        "1": row["id"],
        "2": 1,
        "3": row["assignment"],
        "4": "en",
    }
    assert client.task(104, 7, viewed, structured=True) == b""
    assert owner_path.read_bytes() == viewed_bytes
    checks.append(
        "Actual Replay empty-context viewed-message request, default-realm owner-bound journal, full 64-bit message/assignment fields and exact retry deduplication"
    )
    return {
        "query": query(),
        "result": expected(row),
        "path": path,
        "bytes": path.read_bytes(),
        "viewed": viewed,
        "view_path": owner_path,
        "view_bytes": viewed_bytes,
    }


def check_restart(client, fixture, checks):
    assert client.task(104, 6, fixture["query"], structured=True) == fixture["result"]
    assert fixture["path"].read_bytes() == fixture["bytes"]
    assert client.task(104, 7, fixture["viewed"], structured=True) == b""
    assert fixture["view_path"].read_bytes() == fixture["view_bytes"]
    checks.append(
        "Published marketing messages and empty-context owned view receipts remain byte-exact across process restart and exact retry"
    )
