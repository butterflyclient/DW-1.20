# Owner-hosted Replay DW test

The complete backend implementation is paused while the owner tests one remote
guest. This mode uses the existing native services and listen-server protocol.
It does not emulate the game's network packets or manufacture completed tasks.

## Configuration and ownership

`data/network.json` is private runtime data. Schema 1 sets `bind_address`,
`advertised_address`, `qos_port`, `relay_port`, `bandwidth_port` and the
`clients` map of provisioned profile names to 64-character access keys.
When it is absent, the backend retains its original loopback behavior.
An external caller cannot select the default host account. Signed platform
sessions, native tickets, encrypted lobby identities and datagram authentication
remain required. Never distribute backend signing or relay issuer keys.

The DW executable reads an executable-specific `.ini` first, then
`replay-dw.ini` from its required game-folder working directory. Supported keys
are `host`, `profile`, `access_key`, `public_address`, `local_address` and
`game_port`. IPv4 addresses and credential lengths are validated. The host uses
loopback for backend transport and publishes the router's mapped IPv4 address
for game traffic. Guests select their own provisioned identities. Restart the
process to reload configuration.

Host example (`game_dx12_ship_replay_dw.ini` beside the EXE):

```ini
host=127.0.0.1
public_address=YOUR_ROUTER_PUBLIC_IPV4
local_address=YOUR_HOST_LAN_IPV4
game_port=3074
```

Guest example (the package supplies the real profile key):

```ini
host=YOUR_HOST_PUBLIC_IPV4
profile=remote-test-1
access_key=YOUR_PROVISIONED_64_CHARACTER_KEY
```

`host` accepts an IPv4 address. The current transport ports are TCP 8085 for
platform/auth/content and TCP 3075 for the encrypted lobby. The generated guest
package uses the executable-specific INI, so an older same-name INI cannot
silently override its connection settings.

## Native address handling

The C++ replacement for Replay's `bdCommonAddr` constructor retains the native
152-byte address representation, five local slots, public address, NAT/platform
fields, relay construction and native hash dispatch. The host publication is
changed only when a PC local address matches the configured LAN address and
game port. Native serialization, sockets, session documents and DTLS credentials
consume that same object. Other common-address instances retain native behavior.
The linked VM verifies constructor fields and native 84-byte serialization with
WinSock byte-order and SDK hash boundaries supplied explicitly. Live networking
is a separate gate.

## Proxy-free Windows startup

Replay's generated import-probe worker executes `MOV CR0` in user mode on this
Windows version. Its C++ replacement keeps the exact native CRT allocation and
offset ownership published to the parent, then returns its normal zero result.
The complete native bootstrap, other initialization, thread join and CRT cleanup
are retained. The earlier experiment that removed the whole bootstrap was
discarded because it also removed WinMain's required state initialization.

## Ports and running the test

The owner router maps TCP 8085/3075 and UDP 3074/3076/3077/3078 to the host.
8085 serves signed platform/auth and immutable content, 3075 serves the encrypted
lobby, 3074 is the native game socket, and the other UDP ports serve QoS, relay
and bandwidth. UPnP mapping ownership is checked before modification. The
administrator firewall script restricts rules to the backend and DW game paths.
It changes no unrelated programs' firewall settings.

Endpoint publication follows the actual connection peer. Loopback clients receive
loopback HTTP, QoS, relay and bandwidth endpoints; other clients receive the
configured public address. Each connection/datagram has a scoped thread-local
publication context. Immutable resource handles have separate local/public
variants, and relay credentials retain the selected endpoint in their signed
native representation. The owner can therefore use the same external backend
without requiring the router to support NAT loopback. This does not change the
host's public native game address.

Run the host's normal `Run_Replay_DW.cmd` from the root game folder. Give the
guest only the generated guest ZIP. The guest extracts it into their compatible
Replay root, keeps normal game data/dependencies, removes any local proxy from
the DLL search path, and runs `Run_Replay_DW_Guest.cmd`.

Both players enter Multiplayer. The host creates a private party and selects
Shipment. The guest joins DWPlayer through Social. Reciprocal native invitation
tasks establish the host/guest relationship before either game signs in.
Do not reuse one guest profile on two computers at the same time. Use controlled
full restarts instead of `dw_leave`.

## Validation scope

Protocol fixtures, router mappings and a running window do not establish
two-network playability. The handoff records the current image/server hashes,
native menu/fence evidence, address publication and any remaining owner-run
remote gate. A failed local connection to the public address does not distinguish
an inbound failure from a router without NAT loopback support.

Two native processes using the same Replay root contend for the exclusively
opened `toc1.dcache`. The controlled second-instance test reached native account
and relay authentication, then reported that cache lock. Validate their startup
sequentially, or use separate computers for the party test. Do not weaken the
game's cache locking to manufacture a local two-process success.
