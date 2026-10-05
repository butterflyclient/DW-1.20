"""Expose only Replay's backend/game ports and save a repeatable host config."""

import importlib.util
import ipaddress
import json
from pathlib import Path
import secrets
import time

ROOT = Path(__file__).resolve().parents[1]
# Reuse the owner's working dependency-free IGD implementation. Keep a local
# copy so this backend remains usable without the compiler checkout later.
helper = ROOT / "tools/igd.py"
if not helper.exists():
    helper.write_bytes(Path(r"E:\replay-compiler\workstation\network.py").read_bytes())
spec = importlib.util.spec_from_file_location("replay_igd", helper)
igd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(igd)
try:
    gateway = igd.discover_gateway()
except igd.GatewayError:
    # Discovery multicast may select the virtual VPN adapter. Revalidate the
    # already discovered owner router with fresh SOAP calls before mapping.
    cached = json.loads(
        Path(
            r"C:\Users\achar\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\ReplayCompilerWorkstation\network.json"
        ).read_text()
    )
    gateway = igd.Gateway(
        cached["control_url"], "urn:schemas-upnp-org:service:WANIPConnection:1"
    )
public = gateway.call("GetExternalIPAddress")["NewExternalIPAddress"]
ipaddress.IPv4Address(public)
description = "Replay DW host test"
mappings = []
for protocol, ports in (("TCP", (8085, 3075)), ("UDP", (3074, 3076, 3077, 3078))):
    for port in ports:
        try:
            current = gateway.call(
                "GetSpecificPortMappingEntry",
                NewRemoteHost="",
                NewExternalPort=port,
                NewProtocol=protocol,
            )
        except igd.GatewayError as error:
            if error.code != 714:
                raise
            current = None
        if current and (
            current.get("NewInternalClient") != gateway.lan_address
            or int(current["NewInternalPort"]) != port
            or current.get("NewPortMappingDescription") != description
        ):
            raise RuntimeError(f"{protocol}/{port} is owned by another mapping")
        arguments = dict(
            NewRemoteHost="",
            NewExternalPort=port,
            NewProtocol=protocol,
            NewInternalPort=port,
            NewInternalClient=gateway.lan_address,
            NewEnabled=1,
            NewPortMappingDescription=description,
            NewLeaseDuration=604800,
        )
        try:
            gateway.call("AddPortMapping", **arguments)
        except igd.GatewayError as error:
            if error.code != 725:
                raise
            arguments["NewLeaseDuration"] = 0
            gateway.call("AddPortMapping", **arguments)
        confirmed = None
        for attempt in range(10):
            try:
                confirmed = gateway.call(
                    "GetSpecificPortMappingEntry",
                    NewRemoteHost="",
                    NewExternalPort=port,
                    NewProtocol=protocol,
                )
                break
            except igd.GatewayError as error:
                if error.code != 714:
                    raise
                time.sleep(0.2)
        if confirmed is None:
            # This IGD sometimes misses a freshly added specific entry while
            # its generic enumeration already reflects the committed mapping.
            for index in range(128):
                try:
                    entry = gateway.call(
                        "GetGenericPortMappingEntry", NewPortMappingIndex=index
                    )
                except igd.GatewayError as error:
                    if error.code == 713:
                        break
                    raise
                if (
                    entry.get("NewExternalPort") == str(port)
                    and entry.get("NewProtocol") == protocol
                    and entry.get("NewInternalClient") == gateway.lan_address
                ):
                    confirmed = entry
                    break
        if confirmed is None:
            raise RuntimeError(f"Router did not publish {protocol}/{port}")
        if (
            confirmed.get("NewInternalClient") != gateway.lan_address
            or int(confirmed["NewInternalPort"]) != port
        ):
            raise RuntimeError("Router did not retain the requested mapping")
        mappings.append(dict(protocol=protocol, port=port, verified=True))
path = ROOT / "data/network.json"
previous = json.loads(path.read_text()) if path.exists() else {}
clients = previous.get("clients", {"remote-test-1": secrets.token_hex(32)})
config = dict(
    schema=1,
    bind_address="0.0.0.0",
    advertised_address=public,
    qos_port=3076,
    relay_port=3077,
    bandwidth_port=3078,
    clients=clients,
    game_host_user=76561199317547464,
    game_port=3074,
)
path.write_text(json.dumps(config, indent=2) + "\n")
receipt = dict(
    schema=1,
    public_address=public,
    lan_address=gateway.lan_address,
    gateway_control=gateway.control,
    service=gateway.service,
    mappings=mappings,
)
(ROOT / "data/host-network-receipt.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    f"Router mappings verified for {public}; private guest access key retained in data/network.json"
)
