"""Independent native 80/58 framing, publication isolation and retry checks."""

import base64
import copy
import hashlib
import json
import struct
import time


def exercise(client, directory, title, user, text, blob, checks):
    path = directory / "inventory-validation" / str(title) / "catalog.json"
    token = b"local issuer inventory token"
    output = b"authorized local validation result"
    context, filename = "iw8", "inventory.bin"
    request = text(context) + text(filename) + blob(token)
    client.task(80, 58, request, error=108)
    client.task(80, 58, text(context) + text(filename) + blob(b""), error=106)
    client.task(80, 58, text(context) + text(filename) + blob(b"x" * 10241), error=106)
    client.task(80, 58, request + b"\x03\x01", error=106)
    client.task(80, 58, text(context) + text("") + blob(token), error=106)
    client.task(80, 58, text("x" * 16) + text(filename) + blob(token), error=106)
    checks.append(
        "inventory validation rejects absent publication, malformed framing and SDK input bounds"
    )

    row = dict(
        context=context,
        filename=filename,
        token_sha256=hashlib.sha256(token).hexdigest(),
        owner=user,
        enabled=True,
        starts=0,
        expires=0,
        result_prefix_i64=[-17, 9223372036854775807],
        result_token_base64=base64.b64encode(output).decode(),
    )
    catalog = dict(schema=1, title=title, authorizations=[row])
    path.parent.mkdir(parents=True)

    def publish(value):
        pending = path.with_suffix(".json.pending")
        pending.write_text(json.dumps(value))
        pending.replace(path)

    def decode(result):
        # Match the untouched target reader's typed Int64/Int64/blob sequence,
        # not the request's unsigned IDs. Check the complete consumed record.
        assert result[0] == result[9] == 9
        assert result[18:20] == b"\x13\x08"
        length = struct.unpack_from("<I", result, 20)[0]
        assert len(result) == 24 + length and 0 < length <= 10240
        return [
            struct.unpack_from("<q", result, offset)[0] for offset in (1, 10)
        ], result[24:]

    publish(catalog)
    original = path.read_bytes()
    result = client.task(80, 58, request)
    assert decode(result) == (row["result_prefix_i64"], output)
    assert client.task(80, 58, request) == result
    assert path.read_bytes() == original
    for scope, name, data in (
        ("other", filename, token),
        (context, "other.bin", token),
        (context, filename, b"unknown"),
    ):
        client.task(80, 58, text(scope) + text(name) + blob(data), error=108)
    foreign = copy.deepcopy(catalog)
    foreign["authorizations"][0]["owner"] = user + 1
    publish(foreign)
    client.task(80, 58, request, error=101)
    checks.append(
        "inventory validation returns complete signed Int64/Int64/blob DTO with exact retries and owner/context/filename/token isolation"
    )

    for field, value in (
        ("enabled", False),
        ("starts", int(time.time()) + 600),
        ("expires", 1),
    ):
        inactive = copy.deepcopy(catalog)
        inactive["authorizations"][0][field] = value
        publish(inactive)
        client.task(80, 58, request, error=108)
    publish({**catalog, "authorizations": []})
    client.task(80, 58, request, error=108)
    checks.append(
        "inventory validation rechecks publication removal, disablement and time windows per request"
    )

    corruptions = [
        {**catalog, "title": title + 1},
        {**catalog, "authorizations": [row, row]},
        {**catalog, "authorizations": [row, {**row, "token_sha256": "A" * 64}]},
        {**catalog, "authorizations": [{**row, "owner": 0}]},
        {**catalog, "authorizations": [{**row, "result_prefix_i64": [0]}]},
        {
            **catalog,
            "authorizations": [{**row, "result_prefix_i64": [0, 9223372036854775808]}],
        },
        {
            **catalog,
            "authorizations": [{**row, "result_prefix_i64": [0, -9223372036854775809]}],
        },
        {**catalog, "authorizations": [{**row, "result_token_base64": "%%%"}]},
        {**catalog, "authorizations": [{**row, "result_token_base64": ""}]},
        {
            **catalog,
            "authorizations": [
                {**row, "result_token_base64": base64.b64encode(b"x" * 10241).decode()}
            ],
        },
    ]
    for corrupt in corruptions:
        publish(corrupt)
        before = path.read_bytes()
        client.task(80, 58, request, error=102)
        assert path.read_bytes() == before
    path.write_text("{invalid")
    client.task(80, 58, request, error=102)
    # Valid JSON followed by excessive whitespace still exceeds the publication
    # capacity. Check the actual bytes read, not only an expected schema size.
    path.write_bytes(json.dumps(catalog).encode() + b" " * (4 * 1024 * 1024))
    client.task(80, 58, request, error=102)
    checks.append(
        "inventory validation rejects corrupt whole publications, duplicate grants, signed prefix overflow and invalid output blobs without overwriting data"
    )

    boundary_token, boundary_output = b"i" * 10240, b"o" * 10240
    boundary = {
        **row,
        "context": "",
        "filename": "f" * 127,
        "token_sha256": hashlib.sha256(boundary_token).hexdigest(),
        "result_prefix_i64": [-9223372036854775808, 0],
        "result_token_base64": base64.b64encode(boundary_output).decode(),
    }
    publish({**catalog, "authorizations": [boundary]})
    boundary_request = text("") + text(boundary["filename"]) + blob(boundary_token)
    assert decode(client.task(80, 58, boundary_request)) == (
        boundary["result_prefix_i64"],
        boundary_output,
    )
    checks.append(
        "inventory validation supports empty native context, 127-byte filename, signed Int64 limits and 10240-byte input/output tokens"
    )

    publish(catalog)
    assert client.task(80, 58, request) == result
    return dict(
        path=path, request=request, result=result, publication=path.read_bytes()
    )


def check_restart(client, fixture, checks):
    assert client.task(80, 58, fixture["request"]) == fixture["result"]
    assert fixture["path"].read_bytes() == fixture["publication"]
    checks.append(
        "inventory validation published result persists byte-for-byte across backend restart"
    )
