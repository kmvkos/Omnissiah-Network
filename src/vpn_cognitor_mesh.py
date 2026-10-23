"""Read-only desired VPN inventory: Magos Mesh peers + committed Cognitor peers.

Never suppresses unknown peers: only *applied* CognitorDraft rows owned by the
target Magos are recognized. No routes, WireGuard, database or filesystem writes.
"""
from ipaddress import ip_interface, ip_network

from vpn_change_preview import preview
from vpn_reconcile import compare


class CognitorMeshError(ValueError):
    pass


def compose_expected(plan, cognitors):
    """Return complete desired public WG peers and separate class counts."""
    if not isinstance(plan, dict) or not isinstance(plan.get("peers"), list):
        raise CognitorMeshError("Invalid Mesh plan")
    try:
        own = ip_interface(plan["address"])
    except (TypeError, ValueError, KeyError) as exc:
        raise CognitorMeshError("Invalid Magos VPN address") from exc
    if own.version != 4 or own.network.prefixlen != 32:
        raise CognitorMeshError("Magos address must be IPv4 /32")
    expected = []
    used_keys = set()
    used_routes = set()

    def add(key, address, keepalive, *, name, peer_type):
        if not isinstance(key, str) or not key:
            raise CognitorMeshError("Empty registered WireGuard public key")
        try:
            ip = ip_network(address, strict=True)
        except (TypeError, ValueError) as exc:
            raise CognitorMeshError("Invalid registered WireGuard route") from exc
        if (ip.version != 4 or ip.prefixlen != 32
                or ip.network_address == own.ip
                or ip.network_address.is_multicast or ip.network_address.is_unspecified
                or ip.network_address.is_loopback):
            raise CognitorMeshError("Unsafe registered host route")
        if key in used_keys or str(ip) in used_routes:
            raise CognitorMeshError("Overlapping Magos/Cognitor identity or VPN address")
        if type(keepalive) is not int or not 0 <= keepalive <= 65535:
            raise CognitorMeshError("Invalid WireGuard keepalive")
        used_keys.add(key)
        used_routes.add(str(ip))
        expected.append({"name": name, "public_key": key,
                         "allowed_ips": [str(ip)], "keepalive": keepalive,
                         "peer_type": peer_type})

    for item in plan["peers"]:
        if not isinstance(item, dict) or not isinstance(item.get("allowed_ips"), list) or len(item["allowed_ips"]) != 1:
            raise CognitorMeshError("Invalid expected Mesh peer")
        add(item.get("public_key"), item["allowed_ips"][0], item.get("keepalive"),
            name=item.get("name", ""), peer_type="magos")
    mesh_count = len(expected)

    for item in cognitors:
        if getattr(item, "status", None) != "applied" or getattr(item, "parent_magos_id", None) != plan.get("node_id"):
            raise CognitorMeshError("Cognitor registry does not match selected Magos")
        try:
            address = ip_interface(item.vpn_address)
        except (TypeError, ValueError, AttributeError) as exc:
            raise CognitorMeshError("Invalid Cognitor VPN address") from exc
        if address.version != 4 or address.network.prefixlen != 32:
            raise CognitorMeshError("Cognitor must have IPv4 /32")
        add(item.public_key, str(address), 0, name=item.name, peer_type="cognitor")

    return expected, mesh_count, len(expected) - mesh_count


def observe_managed(plan, cognitors, observation):
    """Compare the complete desired inventory to kernel peers, without keys in result."""
    expected, mesh_count, client_count = compose_expected(plan, cognitors)
    actual = observation.get("peers") if isinstance(observation, dict) else None
    active = observation.get("active") is True if isinstance(observation, dict) else None
    if actual is None:
        diff = {"state": "unknown", "reason": "no_observation"}
    elif not active:
        diff = {"state": "drift", "reason": "interface_inactive"}
    else:
        diff = compare(expected, actual)
    key_types = {entry["public_key"]: entry["peer_type"] for entry in expected}
    if isinstance(actual, list) and all(isinstance(p, dict) for p in actual):
        actual_mesh = sum(key_types.get(p.get("public_key")) == "magos" for p in actual)
        actual_clients = sum(key_types.get(p.get("public_key")) == "cognitor" for p in actual)
        unexpected = len(actual) - actual_mesh - actual_clients
    else:
        actual_mesh = actual_clients = unexpected = None
    return {
        "node_id": plan["node_id"], "node_name": plan["node_name"],
        "desired_peers": len(expected),
        "desired_mesh_peers": mesh_count,
        "desired_cognitor_peers": client_count,
        "observed_peers": len(actual) if isinstance(actual, list) else None,
        "observed_mesh_peers": actual_mesh,
        "observed_cognitor_peers": actual_clients,
        "unregistered_peers": unexpected,
        "interface_active": active,
        "state": diff["state"], "reason": diff.get("reason"),
        "missing_peers": len(diff.get("missing_peer_keys", [])),
        "unexpected_peers": len(diff.get("unexpected_peer_keys", [])),
        "different_peers": len(diff.get("different_peers", [])),
    }


def preview_managed(plan, cognitors, observation):
    """No Mesh transaction can be offered when this Magos has applied Cognitors."""
    expected, mesh_count, client_count = compose_expected(plan, cognitors)
    actual = observation.get("peers") if isinstance(observation, dict) else None
    active = observation.get("active") is True if isinstance(observation, dict) else False
    result = preview(expected, actual, active=active)
    if client_count and result["decision"] != "no_change":
        # A legacy Mesh write plan does not include client routes: any offer to
        # apply it might remove the registered Cognitor. Fail closed.
        result["decision"] = "blocked"
        result["reason"] = "cognitor_managed_drift_requires_review"
    result["transaction_available"] = False
    result["desired_mesh_peers"] = mesh_count
    result["desired_cognitor_peers"] = client_count
    return result
