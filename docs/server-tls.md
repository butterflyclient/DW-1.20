# Native HTTPS for an internet server

Local play on the same PC does not need a certificate. Follow the README and keep
`host=127.0.0.1`. For a server reached over the internet, use the TLS-capable
client and Linux server together. The client verifies the certificate with
Windows trust and checks the server address. Do not disable certificate checks.

## Server setup

1. Build the Linux server as described in the README. OpenSSL 3 development files
   are required. Keep your existing runtime data and signing keys.
2. Obtain a publicly trusted certificate for the address players put in `host`.
   For the maintained droplet layout, with service account `replay-dw`, runtime
   directory `/var/lib/replay-dw`, and an available inbound TCP port 80, run:

   ```sh
   sudo sh tools/install-server-tls.sh YOUR_PUBLIC_IPV4
   ```

   This installs Certbot in a dedicated virtual environment, obtains a free IP
   certificate, and enables twice-daily renewal checks. Port 80 must remain
   reachable for renewal. Check `systemctl status replay-dw-cert-renew.timer`.
   The deploy hook gives the server read access to its certificate and key;
   players receive neither the TLS private key nor the server signing keys.
3. Create `tls.json` inside the server runtime data directory:

   ```json
   {
     "schema": 1,
     "certificate_chain": "tls/current/fullchain.pem",
     "private_key": "tls/current/privkey.pem",
     "require_remote_tls": true,
     "allow_legacy_public_updates": true
   }
   ```

4. Allow inbound TCP 8443 alongside the game's existing lobby and UDP ports.
   Start the new server, or restart `replay-dw` after replacing its executable.
   Open `https://YOUR_PUBLIC_IPV4:8443/health`; the browser must accept the
   certificate without an exception. The dashboard is at `/stats` on this origin.
5. Configure the TLS-capable client with that same address in its existing INI.
   Preserve the client's matching server public keys. For a server with its own
   signing identity, use the README's local-client setup with that server's
   public key files; keep the generated client local and set its `host` as needed.

For a different deployment layout, provide your own certificate and readable
key paths in `tls.json`. Relative paths resolve under the runtime data folder.
Certificate renewal is loaded on the next connection without a server restart.
The Windows server build supports the README's loopback setup; the OpenSSL TLS
listener is supplied by the Linux build.

## Existing installed clients

The public plaintext compatibility path serves only signed update plans and
hash-addressed update files. This lets older installed EXEs obtain the current
client, whose helper then fetches required assets and maps. Early delta-only
clients receive a compatible signed RAW-delta bootstrap first. Plaintext login,
session, authentication, and operator requests remain blocked. Update signatures
and file hashes are checked before installation. The intentional
`bypass_update_restart=1` override still skips automatic updating.

Leave `require_remote_tls` enabled for normal use. Setting it to `false` is only
a temporary migration setting and permits remote plaintext authentication.
Without `tls.json`, the server still permits local HTTP and rejects remote
plaintext requests.

## What is protected

HTTPS protects platform identity proofs and sessions, native authentication and
its lobby-key bootstrap, legacy tokens, HTTP content, and updater traffic.
The listener supports TLS 1.2 ECDHE with authenticated encryption and TLS 1.3;
it rejects older protocols and plaintext fallback. The existing encrypted native
lobby protocol remains in use. This does not add TLS to UDP gameplay, NAT probes,
or relay datagrams. It is not a claim that every game packet is encrypted.

Fresh TLS connections have a handshake cost. Certificate validation and request
deadlines remain enabled. The transport fixture checks trust failures, protocol
versions, certificate renewal, real peer attribution, plaintext rejection, and a
slow encrypted-record deadline:

```sh
python3 tools/test-tls-transport.py --server ./build/iw8-dw-server --output /tmp/dw-tls-check.json
```
