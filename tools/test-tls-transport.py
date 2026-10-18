"""Exercise the Linux TLS listener with disposable keys and server state."""
import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import select
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix="dw-tls-") as folder:
        data = Path(folder)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(data / "key.pem"), "-out", str(data / "cert.pem"),
            "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (data / "tls.json").write_text(json.dumps(dict(schema=1,
            certificate_chain="cert.pem", private_key="key.pem", require_remote_tls=True)))
        log = (data / "server.log.txt").open("wb")
        server = subprocess.Popen([str(args.server.resolve()), str(data), "--port-offset", "15000"], stdout=log, stderr=log)
        context = ssl.create_default_context(cafile=str(data / "cert.pem"))
        http_port, https_port = 23085, 23443

        def request(secure, path="/health", method="GET", body=None, remote=False, headers=None):
            options = dict(timeout=5, source_address=("127.0.0.2" if remote else "127.0.0.1", 0))
            connection = (http.client.HTTPSConnection("127.0.0.1", https_port, context=context, **options)
                          if secure else http.client.HTTPConnection("127.0.0.1", http_port, **options))
            try:
                connection.request(method, path, body, headers or {})
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        try:
            for attempt in range(50):
                if server.poll() is not None:
                    raise RuntimeError((data / "server.log.txt").read_text())
                try:
                    if request(False)[0] == 200:
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("TLS fixture startup timeout")
            assert json.loads(request(True, remote=True)[1])["server"] == "iw8-dw"
            assert request(False, remote=True)[0] == 403
            assert request(False, "/platform/client/login", "POST", b"secret", remote=True)[0] == 403
            assert request(False, "/updates/v2/check", "POST", b"secret", remote=True)[0] == 403
            checks.append("Verified TLS works; remote plaintext health, login and updater rejected")
            assert request(True, "/platform/login", "POST", b"x" * 32, remote=True)[0] == 403
            assert request(True, "/platform/login", "POST", b"x" * 32, remote=True,
                           headers={"X-Forwarded-For": "127.0.0.1"})[0] == 403
            status, signed = request(True, "/platform/login", "POST", b"x" * 32)
            assert status == 200 and len(signed) == 512
            checks.append("TLS preserves real-peer authorization; spoofed forwarding header cannot acquire loopback login")
            for bad_context, name in ((ssl.create_default_context(), "untrusted certificate"),):
                try:
                    with socket.create_connection(("127.0.0.1", https_port), timeout=5) as sock:
                        bad_context.wrap_socket(sock, server_hostname="127.0.0.1")
                except ssl.SSLCertVerificationError:
                    checks.append(name + " rejected")
                else:
                    raise AssertionError(name + " accepted")
            try:
                with socket.create_connection(("127.0.0.1", https_port), timeout=5) as sock:
                    context.wrap_socket(sock, server_hostname="wrong.invalid")
            except ssl.SSLCertVerificationError:
                checks.append("Wrong certificate hostname rejected")
            else:
                raise AssertionError("Wrong certificate hostname accepted")
            with socket.create_connection(("127.0.0.1", https_port), timeout=5) as sock:
                sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                try:
                    response = sock.recv(128)
                    assert not response.startswith(b"HTTP/1.1 200")
                except ConnectionResetError:
                    pass
            checks.append("HTTPS listener never falls back to plaintext")
            with socket.create_connection(("127.0.0.1", https_port), timeout=10) as delayed:
                time.sleep(4)
                with context.wrap_socket(delayed, server_hostname="127.0.0.1") as secure:
                    secure.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    assert secure.recv(4096).startswith(b"HTTP/1.1 200")
            checks.append("Verified TLS client delayed beyond the former three-second budget succeeds")
            with socket.create_connection(("127.0.0.1", https_port), timeout=12) as idle:
                start = time.perf_counter()
                assert idle.recv(1) == b""
                elapsed = time.perf_counter() - start
                assert 8.5 <= elapsed < 11
            assert "TLS handshake rejected: deadline" in (data / "server.log").read_text()
            checks.append("Idle TLS handshake closed within its absolute deadline")
            # A TCP timeout alone cannot bound SSL_read: a peer can drip pieces
            # of one encrypted record without ever producing application bytes.
            trickle_context = ssl.create_default_context(cafile=str(data / "cert.pem"))
            trickle_context.minimum_version = trickle_context.maximum_version = ssl.TLSVersion.TLSv1_2
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            engine = trickle_context.wrap_bio(incoming, outgoing, server_side=False, server_hostname="127.0.0.1")
            with socket.create_connection(("127.0.0.1", https_port), timeout=5) as trickle:
                while True:
                    try:
                        engine.do_handshake()
                        if outgoing.pending:
                            trickle.sendall(outgoing.read())
                        break
                    except ssl.SSLWantReadError:
                        if outgoing.pending:
                            trickle.sendall(outgoing.read())
                        incoming.write(trickle.recv(16384))
                engine.write(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                record = outgoing.read()
                trickle.sendall(record[:5])
                began, cursor, closed = time.monotonic(), 5, False
                while time.monotonic() - began < 17:
                    if select.select([trickle], [], [], 1)[0]:
                        packet = trickle.recv(16384)
                        if not packet:
                            closed = True
                            break
                        incoming.write(packet)
                        try:
                            if engine.read(1) == b"":
                                closed = True
                                break
                        except ssl.SSLWantReadError:
                            pass
                    try:
                        trickle.sendall(record[cursor:cursor + 1])
                        cursor += 1
                    except (BrokenPipeError, ConnectionResetError):
                        closed = True
                        break
                assert closed, "Encrypted record trickling bypassed the absolute HTTP header deadline"
            checks.append("Encrypted-record trickling cannot bypass the absolute HTTP header deadline")
            versions = {}
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                test_context = ssl.create_default_context(cafile=str(data / "cert.pem"))
                test_context.minimum_version = test_context.maximum_version = version
                with socket.create_connection(("127.0.0.1", https_port), timeout=5) as sock:
                    with test_context.wrap_socket(sock, server_hostname="127.0.0.1") as secure:
                        versions[secure.version()] = secure.cipher()[0]
            checks.append("TLS 1.2 and 1.3 negotiate authenticated encryption")
            existing = context.wrap_socket(socket.create_connection(("127.0.0.1", https_port), timeout=5), server_hostname="127.0.0.1")
            try:
                previous_cert = (data / "cert.pem").read_bytes()
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(data / "key.pem"), "-out", str(data / "cert.pem"),
                    "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                assert (data / "cert.pem").read_bytes() != previous_cert
                context = ssl.create_default_context(cafile=str(data / "cert.pem"))
                assert request(True)[0] == 200
                existing.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                assert existing.recv(4096).startswith(b"HTTP/1.1 200")
            finally:
                existing.close()
            checks.append("Certificate reload accepts new connections and preserves an existing TLS connection")
            # Measures complete local TCP+request setup, not an internet latency claim.
            timings = {}
            for secure in (False, True):
                samples = []
                for _ in range(20):
                    start = time.perf_counter()
                    assert request(secure)[0] == 200
                    samples.append((time.perf_counter() - start) * 1000)
                timings["https" if secure else "http"] = dict(median_ms=statistics.median(samples), max_ms=max(samples))
            server.terminate()
            server.wait(timeout=15)
            settings = json.loads((data / "tls.json").read_bytes())
            settings["allow_legacy_public_updates"] = True
            (data / "tls.json").write_text(json.dumps(settings))
            server = subprocess.Popen([str(args.server.resolve()), str(data), "--port-offset", "15000"], stdout=log, stderr=log)
            for attempt in range(50):
                try:
                    if request(False)[0] == 200:
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("Legacy-update fixture startup timeout")
            assert request(False, "/updates/v2/check", "POST", b"invalid", remote=True)[0] == 400
            assert request(False, "/updates/v2/image/" + "0" * 64, remote=True)[0] != 403
            for route in ("/auth/", "/platform/client/login", "/operator/start-match", "/%75pdates/v2/check"):
                assert request(False, route, "POST", b"secret", remote=True)[0] == 403
            assert request(False, "/updates/v2/image/../../platform-private.blob", remote=True)[0] != 200
            checks.append("Legacy public bootstrap stays reachable; credentials, operator routes and encoded bypasses stay blocked")
        finally:
            server.terminate()
            server.wait(timeout=15)
            log.close()
    result = dict(passed=True, checks=checks, versions=versions, loopback_request_timings=timings)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
