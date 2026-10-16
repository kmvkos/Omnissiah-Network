"""Side-effect-free VPN change preview with conservative route safety checks."""
from ipaddress import ip_address, ip_network


def preview_change(desired, current, management_ip):
    """Return a plan, NEVER execute networking commands.

    current must contain a verified active interface and observed peer list.
    Changes to local addresses, interface or listen port are not previewed here.
    """
    if not isinstance(current, dict) or current.get("active") is not True:
        return {"safe": False, "reason": "interface_not_verified_active", "changes": []}
    observed = current.get("peers")
    if not isinstance(observed, list):
        return {"safe": False, "reason": "actual_peer_inventory_unavailable", "changes": []}
    if not isinstance(management_ip, str):
        return {"safe": False, "reason": "management_address_unavailable", "changes": []}
    try:
        mgmt = ip_address(management_ip)
        if mgmt.version != 4 or mgmt.is_unspecified or mgmt.is_multicast:
            raise ValueError("Bad management address")
    except ValueError:
        return {"safe": False, "reason": "management_address_invalid", "changes": []}
    before = {p["public_key"]: p for p in observed}
    after = {p["public_key"]: p for p in desired.get("peers", [])}
    if len(before) != len(observed) or len(after) != len(desired.get("peers", [])):
        return {"safe": False, "reason": "duplicate_peer_keys", "changes": []}
    changes = []
    routes = set()
    for peer in desired.get("peers", []):
        try:
            nets = [ip_network(r, strict=True) for r in peer["allowed_ips"]]
            if not nets or any(n.version != 4 or n.prefixlen != 32 or
                               mgmt in n for n in nets):
                return {"safe": False, "reason": "unsafe_or_management_route", "changes": []}
            if any(n in routes for n in nets):
                return {"safe": False, "reason": "duplicate_route", "changes": []}
            routes.update(nets)
        except (TypeError, ValueError, KeyError):
            return {"safe": False, "reason": "invalid_allowed_ips", "changes": []}
    for key in sorted(set(before) | set(after)):
        if key not in before:
            op = "add_peer"
        elif key not in after:
            op = "remove_peer"
        else:
            a, b = before[key], after[key]
            op = "update_peer" if (sorted(a["allowed_ips"]) != sorted(b["allowed_ips"])
                                  or int(a["keepalive"]) != int(b["keepalive"])) else None
        if op:
            changes.append({"operation": op, "peer_key_suffix": key[-8:]})
    previous_routes = {r for peer in observed for r in peer["allowed_ips"]}
    desired_routes = {r for peer in desired.get("peers", []) for r in peer["allowed_ips"]}
    return {"safe": True, "reason": "read_only_preview", "changes": changes,
            "routes_to_add": sorted(desired_routes - previous_routes),
            "routes_to_remove": sorted(previous_routes - desired_routes),
            "requires_route_reconciliation": previous_routes != desired_routes,
            "apply_permitted": False}
