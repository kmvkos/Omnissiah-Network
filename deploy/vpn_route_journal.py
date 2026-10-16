"""Pure, fail-closed journal blueprint for WireGuard host-route changes.

This module cannot modify routes or WireGuard. A privileged executor must
separately validate and durably journal each operation before permitting writes.
"""
import hashlib
import json

from vpn_route_tx import normalize_route, plan_route_delta, RouteConflict


def _snapshot(peers, routes):
    """Canonical state for an optimistic concurrency check, without secrets."""
    peer_rows = sorted(
        (str(peer["public_key"]), tuple(sorted(peer["allowed_ips"])), int(peer["keepalive"]))
        for peer in peers
    )
    route_rows = [r for r in (normalize_route(item) for item in routes) if r is not None]
    route_rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
    return {"peers": peer_rows, "routes": route_rows}


def snapshot_digest(peers, routes):
    encoded = json.dumps(_snapshot(peers, routes), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def prepare_transaction(desired_peers, actual_peers, main_routes, *, iface="wg0"):
    """Build reversible steps from an exact kernel snapshot, without side effects."""
    delta = plan_route_delta(desired_peers, actual_peers, main_routes, iface=iface)
    steps = ([{"op": "add", "dst": dst, "dev": iface} for dst in delta["add"]]
             + [{"op": "delete", "dst": dst, "dev": iface} for dst in delta["remove"]])
    inverse = {"add": "delete", "delete": "add"}
    rollback = [{"op": inverse[step["op"]], "dst": step["dst"], "dev": iface}
                for step in reversed(steps)]
    return {"schema_version": 1, "iface": iface,
            "snapshot_sha256": snapshot_digest(actual_peers, main_routes),
            "delta": delta, "steps": steps, "rollback": rollback,
            "writes_performed": False, "executable": False}


def assert_snapshot_unchanged(transaction, actual_peers, main_routes):
    """Refuse execution when kernel state moved since preview."""
    if transaction.get("schema_version") != 1 or transaction.get("executable") is not False:
        raise RouteConflict("Unsupported or executable transaction plan")
    current = snapshot_digest(actual_peers, main_routes)
    if current != transaction.get("snapshot_sha256"):
        raise RouteConflict("Stale route transaction: kernel state changed")
    return True
