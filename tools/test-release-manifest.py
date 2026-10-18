"""Exercise GET /updates/v2/manifest on a candidate Linux server with disposable keys and state.

Runs beside production (``--port-offset``) and never writes to the live data directory. With
``--catalog-from`` it copies the real published catalog and manifest blobs (read-only) so the route is
checked against the actual current release; the large executable is replaced by a sparse file of the
same size because the route only checks its size.

    python3 test-release-manifest.py --server build/iw8-dw-server --output proof.json \
        [--catalog-from /var/lib/replay-dw/updates]
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import struct
import subprocess
import tempfile
import time

OFFSET = 16000
HTTP_PORT, HTTPS_PORT = 8085 + OFFSET, 8443 + OFFSET


def sha(data):
    return hashlib.sha256(data).hexdigest()


def public_pem(blob_path, folder):
    """BCRYPT_RSAKEY_BLOB (platform-public.blob) -> PEM, for openssl verification."""
    blob = Path(blob_path).read_bytes()
    assert len(blob) == 283 and struct.unpack_from("<6I", blob) == (0x31415352, 2048, 3, 256, 0, 0)
    der = bytes.fromhex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100") \
        + blob[27:] + bytes.fromhex("0203010001")
    (folder / "pub.der").write_bytes(der)
    subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(folder / "pub.der"),
                    "-out", str(folder / "pub.pem")], check=True, stdout=subprocess.DEVNULL)
    return folder / "pub.pem"


def verify_signature(pem, body, signature, folder):
    (folder / "body.bin").write_bytes(body)
    (folder / "sig.bin").write_bytes(signature)
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss",
                             "-sigopt", "rsa_pss_saltlen:32", "-verify", str(pem),
                             "-signature", str(folder / "sig.bin"), str(folder / "body.bin")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0 and b"Verified OK" in result.stdout


def fixture(updates, source):
    """Populate updates/ from the real publication (read-only) or a small synthetic one."""
    (updates / "images").mkdir(parents=True)
    (updates / "map-manifests").mkdir()
    (updates / "asset-manifests").mkdir()
    if source:
        source = Path(source)
        catalog_bytes = (source / "full-image-catalog.json").read_bytes()
        catalog = json.loads(catalog_bytes)
        (updates / "full-image-catalog.json").write_bytes(catalog_bytes)
        if "maps" in catalog:
            name = catalog["maps"]["manifest_sha256"] + ".bin"
            shutil.copyfile(source / "map-manifests" / name, updates / "map-manifests" / name)
        if "assets" in catalog:
            name = catalog["latest"] + ".bin"
            shutil.copyfile(source / "asset-manifests" / name, updates / "asset-manifests" / name)
    else:
        blob = b"REPLAYDWASSET02\0" + os.urandom(64)
        catalog = dict(schema=1, format="full-executable-v1", release=1, latest="ab" * 32, target_size=4096,
                       assets=dict(manifest_sha256=sha(blob), manifest_size=len(blob), files=2, payloads={}))
        (updates / "asset-manifests" / (catalog["latest"] + ".bin")).write_bytes(blob)
        (updates / "full-image-catalog.json").write_text(json.dumps(catalog))
    with open(updates / "images" / (catalog["latest"] + ".exe"), "wb") as image:
        image.truncate(catalog["target_size"])   # sparse: the route checks only the size
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--catalog-from", type=Path)
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix="dw-manifest-") as folder:
        data = Path(folder)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(data / "key.pem"), "-out", str(data / "cert.pem"),
                        "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (data / "tls.json").write_text(json.dumps(dict(schema=1, certificate_chain="cert.pem",
                                                       private_key="key.pem", require_remote_tls=True)))
        catalog = fixture(data / "updates", args.catalog_from)
        log = (data / "server.log.txt").open("wb")
        server = subprocess.Popen([str(args.server.resolve()), str(data), "--port-offset", str(OFFSET)],
                                  stdout=log, stderr=log)
        context = ssl.create_default_context(cafile=str(data / "cert.pem"))

        def request(secure, path, method="GET", body=None, remote=False):
            options = dict(timeout=10, source_address=("127.0.0.2" if remote else "127.0.0.1", 0))
            connection = (http.client.HTTPSConnection("127.0.0.1", HTTPS_PORT, context=context, **options)
                          if secure else http.client.HTTPConnection("127.0.0.1", HTTP_PORT, **options))
            try:
                connection.request(method, path, body)
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        try:
            for _ in range(80):
                if server.poll() is not None:
                    raise RuntimeError((data / "server.log.txt").read_text())
                try:
                    if request(False, "/health")[0] == 200:
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("fixture startup timeout")
            pem = public_pem(data / "platform-public.blob", data)

            nonce = os.urandom(32).hex()
            status, raw = request(True, "/updates/v2/manifest?nonce=" + nonce, remote=True)
            assert status == 200, status
            body, _, signature_hex = raw.rpartition(b"\n")
            assert len(signature_hex) == 512
            assert verify_signature(pem, body, bytes.fromhex(signature_hex.decode()), data)
            document = json.loads(body)
            assert document["schema"] == 1 and document["nonce"] == nonce
            assert document["expires"] - document["issued"] == 3600 and abs(document["issued"] - time.time()) < 120
            executable = document["executable"]
            assert (executable["sha256"], executable["size"], executable["release"]) == \
                (catalog["latest"], catalog["target_size"], catalog["release"])
            for section, key in (("maps", "maps"), ("overlays", "assets")):
                if key in catalog:
                    blob = base64.b64decode(document[section]["manifest_b64"], validate=True)
                    assert sha(blob) == catalog[key]["manifest_sha256"] == document[section]["manifest_sha256"]
                    assert len(blob) == catalog[key]["manifest_size"]
                else:
                    assert document[section] is None
            checks.append("Remote HTTPS request returns a document signed by the server key (RSA-PSS/SHA-256, "
                          "salt 32) that echoes the nonce and embeds manifests matching the catalog hashes")

            assert request(False, "/updates/v2/manifest?nonce=" + nonce, remote=True)[0] == 403
            checks.append("Remote plaintext request is refused (https_required)")
            assert request(False, "/updates/v2/manifest?nonce=" + nonce)[0] == 200
            checks.append("Loopback plaintext request is served")

            for bad in ("/updates/v2/manifest", "/updates/v2/manifest?nonce=abcd",
                        "/updates/v2/manifest?nonce=" + "AB" * 32, "/updates/v2/manifest?nonce=" + nonce + "&x=1",
                        "/updates/v2/manifest?n=" + nonce):
                assert request(True, bad, remote=True)[0] == 400, bad
            assert request(True, "/updates/v2/manifest?nonce=" + nonce, "POST", b"x", remote=True)[0] == 400
            checks.append("Malformed nonces, extra parameters and POST are rejected with 400")

            if "assets" in catalog:
                path = data / "updates" / "asset-manifests" / (catalog["latest"] + ".bin")
                original = path.read_bytes()
                path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                assert request(True, "/updates/v2/manifest?nonce=" + nonce, remote=True)[0] == 503
                path.write_bytes(original)
                assert request(True, "/updates/v2/manifest?nonce=" + nonce, remote=True)[0] == 200
                checks.append("An altered published manifest blob yields 503, never a partial document")
            catalog_path = data / "updates" / "full-image-catalog.json"
            saved = catalog_path.read_bytes()
            catalog_path.unlink()
            assert request(True, "/updates/v2/manifest?nonce=" + nonce, remote=True)[0] == 503
            catalog_path.write_bytes(saved)
            checks.append("A missing catalog yields 503")

            plan_request = struct.pack("<QII", 0x3155505744594C50, 2, 0) + os.urandom(32) + bytes(32)
            status, reply = request(True, "/updates/v2/check", "POST", plan_request, remote=True)
            assert status == 200 and len(reply) == 448
            plan, plan_signature = reply[:192], reply[192:]
            assert verify_signature(pem, plan, plan_signature, data)
            assert plan[96:128].hex() == executable["sha256"]
            assert struct.unpack_from("<Q", plan, 184)[0] == executable["release"]
            checks.append("Existing signed update plan is unchanged and agrees with the manifest")
            assert json.loads(request(True, "/health", remote=True)[1])["server"] == "iw8-dw"
            checks.append("Health unchanged")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
            log.close()
    proof = dict(passed=True, checks=checks, check_count=len(checks),
                 server_sha256=sha(args.server.read_bytes()),
                 catalog_source=str(args.catalog_from) if args.catalog_from else "synthetic",
                 release=catalog["release"], utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    main()
