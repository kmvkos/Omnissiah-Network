"""Pure preflight planner for VPN changes; no network or filesystem writes."""
from ipaddress import ip_network


def _route_set(peers):
    return sorted(str(ip_network(route, strict=True))
                  for peer in peers for route in peer["allowed_ips"])


def preview(desired, actual, *, active):
    """Compute safe-change verdict without ever exposing public keys in UI.

    Existing helper supports wg syncconf only when AllowedIPs set is unchanged.
    Changing routes requires an independent route-aware transaction and must fail closed.
    """
    if actual is None:
        return {"decision": "blocked", "reason": "actual_state_unavailable",
                "add": 0, "remove": 0, "update": 0}
    if not active:
        return {"decision": "blocked", "reason": "interface_inactive",
                "add": 0, "remove": 0, "update": 0}
    old = {p["public_key"]: p for p in actual}
    new = {p["public_key"]: p for p in desired}
    if len(old) != len(actual) or len(new) != len(desired):
        return {"decision": "blocked", "reason": "duplicate_peer_keys",
                "add": 0, "remove": 0, "update": 0}
    add = set(new) - set(old)
    remove = set(old) - set(new)
    update = {
        key for key in set(new) & set(old)
        if (sorted(new[key]["allowed_ips"]) != sorted(old[key]["allowed_ips"])
            or int(new[key]["keepalive"]) != int(old[key]["keepalive"]))
    }
    routes_change = _route_set(desired) != _route_set(actual)
    if routes_change:
        decision, reason = "blocked", "route_change_requires_transaction"
    elif not (add or remove or update):
        decision, reason = "no_change", "already_in_sync"
    else:
        decision, reason = "eligible", "same_routes_only"
    # An 'eligible' verdict is NOT authorization to apply. The controller must
    # separately check user intent, stable desired revision and current state.
    return {"decision": decision, "reason": reason, "add": len(add),
            "remove": len(remove), "update": len(update)}
