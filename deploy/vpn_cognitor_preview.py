"""Read-only preflight for an add-only Cognitor WireGuard peer.

No subprocesses, files, private keys or writes. Privileged wrapper supplies
fresh kernel snapshots and root-owned persisted wg0.conf. This is NOT Apply.
"""
import base64
import binascii
import hashlib
import ipaddress
import json
import re


class CognitorPreflightError(ValueError):
    pass


def _public_key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise CognitorPreflightError("Invalid client public key")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CognitorPreflightError("Invalid client public key") from exc
    if len(data) != 32 or base64.b64encode(data).decode() != value:
        raise CognitorPreflightError("Invalid client public key")
    return value


def validate_plan(plan, expected_name):
    required = {"node_name", "address", "client_name", "client_address", "public_key"}
    if not isinstance(plan, dict) or set(plan) != required:
        raise CognitorPreflightError("Invalid Cognitor preview schema")
    if plan["node_name"] != expected_name:
        raise CognitorPreflightError("Parent Magos mismatch")
    if not isinstance(plan["client_name"], str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_-]{0,49}", plan["client_name"]):
        raise CognitorPreflightError("Invalid client name")
    try:
        parent = ipaddress.ip_interface(plan["address"])
        child = ipaddress.ip_interface(plan["client_address"])
    except (TypeError, ValueError) as exc:
        raise CognitorPreflightError("Invalid VPN address") from exc
    if (parent.version != 4 or child.version != 4
            or parent.network.prefixlen != 32 or child.network.prefixlen != 32
            or parent.ip == child.ip or parent.ip.is_multicast
            or child.ip.is_multicast or parent.ip.is_unspecified
            or child.ip.is_unspecified or child.ip.is_loopback):
        raise CognitorPreflightError("Expected distinct unicast IPv4 /32 addresses")
    key = _public_key(plan["public_key"])
    return {"node_name": expected_name, "address": str(parent),
            "client_name": plan["client_name"],
            "client_address": str(child), "public_key": key}


def persisted_inventory(text):
    """Validate only stable peer identities and host routes; never expose secrets."""
    if not isinstance(text, str) or not text.startswith("# Managed by Omnissiah VPN v2\n"):
        raise CognitorPreflightError("Unmanaged WireGuard configuration")
    section, address = None, None
    current = None
    peers = {}

    def finish_peer():
        if current is None:
            return
        if set(current) != {"PublicKey", "AllowedIPs"}:
            raise CognitorPreflightError("Incomplete persisted peer")
        key = _public_key(current["PublicKey"])
        try:
            cidrs = [str(ipaddress.ip_network(value.strip(), strict=True))
                     for value in current["AllowedIPs"].split(",")]
        except ValueError as exc:
            raise CognitorPreflightError("Invalid persisted peer route") from exc
        if not cidrs or any(
                ipaddress.ip_network(item).version != 4 or
                ipaddress.ip_network(item).prefixlen != 32 for item in cidrs):
            raise CognitorPreflightError("Non-host persisted peer route")
        if key in peers:
            raise CognitorPreflightError("Duplicate persisted peer")
        peers[key] = sorted(cidrs)

    for raw in text.splitlines()[1:]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in ("[Interface]", "[Peer]"):
            finish_peer()
            section = line
            current = {} if line == "[Peer]" else None
            continue
        if "=" not in line or section is None:
            raise CognitorPreflightError("Invalid persisted configuration")
        field, value = (part.strip() for part in line.split("=", 1))
        if section == "[Interface]" and field == "Address":
            if address is not None:
                raise CognitorPreflightError("Repeated interface address")
            address = value
        if section == "[Peer]" and field in ("PublicKey", "AllowedIPs"):
            if field in current:
                raise CognitorPreflightError("Repeated persisted peer field")
            current[field] = value
    finish_peer()
    if not address:
        raise CognitorPreflightError("Persisted address missing")
    try:
        canonical = str(ipaddress.ip_interface(address))
    except ValueError as exc:
        raise CognitorPreflightError("Invalid persisted interface address") from exc
    return canonical, peers


def preview_add(plan, *, current_peers, routes, persisted_config,
                protected_addresses=()):
    """Fail closed on drift, collisions, invalid config or unknown route owners."""
    data = validate_plan(plan, plan.get("node_name") if isinstance(plan, dict) else None)
    address, disk_peers = persisted_inventory(persisted_config)
    if address != data["address"]:
        raise CognitorPreflightError("On-disk Magos address does not match")
    if not isinstance(current_peers, list) or not isinstance(routes, list):
        raise CognitorPreflightError("Missing kernel observation")
    running = {}
    for p in current_peers:
        if not isinstance(p, dict) or set(("public_key", "allowed_ips")) - set(p):
            raise CognitorPreflightError("Malformed kernel peer")
        key = _public_key(p["public_key"])
        allowed = p["allowed_ips"]
        if not isinstance(allowed, list) or any(not isinstance(x, str) for x in allowed):
            raise CognitorPreflightError("Malformed kernel peer routes")
        try:
            normalized = sorted(str(ipaddress.ip_network(x, strict=True)) for x in allowed)
        except ValueError as exc:
            raise CognitorPreflightError("Invalid kernel route") from exc
        if key in running:
            raise CognitorPreflightError("Duplicate kernel peer")
        running[key] = normalized
    if running != disk_peers:
        raise CognitorPreflightError("Persisted and running peer inventories differ")
    requested = data["client_address"]
    if data["public_key"] in running:
        raise CognitorPreflightError("Client public key already installed")
    if any(requested in cidrs for cidrs in running.values()):
        raise CognitorPreflightError("VPN address already belongs to another peer")
    target = ipaddress.ip_network(requested)
    try:
        for value in protected_addresses:
            if ipaddress.ip_address(value) in target:
                raise CognitorPreflightError("VPN client address overlaps protected management")
    except ValueError as exc:
        raise CognitorPreflightError("Invalid protected management address") from exc
    for route in routes:
        if not isinstance(route, dict):
            raise CognitorPreflightError("Invalid kernel route record")
        dst = route.get("dst")
        if not isinstance(dst, str):
            raise CognitorPreflightError("Missing kernel route destination")
        try:
            network = ipaddress.ip_network("0.0.0.0/0" if dst == "default" else dst, strict=False)
        except ValueError as exc:
            raise CognitorPreflightError("Invalid kernel route destination") from exc
        # A more-specific route through a foreign device or an equal /32 owned
        # by something else is not safe to overwrite with ip route add.
        if network.version == 4 and target.subnet_of(network) and network.prefixlen == 32:
            raise CognitorPreflightError("Destination /32 route already exists")
        if network.version == 4 and network.subnet_of(target):
            raise CognitorPreflightError("Route overlaps client host")
    digest = hashlib.sha256(json.dumps({
        "plan": data,
        "peers": sorted((key, allowed) for key, allowed in running.items()),
        "routes": routes,
        "persisted": hashlib.sha256(persisted_config.encode()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"safe_to_plan": True, "writes_performed": False, "action": "add_only",
            "client_name": data["client_name"],
            "client_address": requested,
            "parent_node": data["node_name"], "existing_peers": len(running),
            "revision": digest}
