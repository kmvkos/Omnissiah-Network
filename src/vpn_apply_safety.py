"""Safety gates for first-stage live VPN apply.

Only changes peer endpoint/keepalive on an already-active interface.
Linux route-set changes must use a separate transactional route engine.
"""
from ipaddress import ip_network


def routes(peers):
    return sorted(str(ip_network(route, strict=True))
                  for peer in peers for route in peer["allowed_ips"])


def preview(desired, observed, *, active):
    if not active or observed is None:
        return {"allowed": False, "reason": "interface_not_observed",
                "changed": False}
    before, after = routes(observed), routes(desired)
    if before != after:
        return {"allowed": False, "reason": "route_change_requires_transaction",
                "changed": True, "current_routes": before,
                "desired_routes": after}
    current = {p["public_key"]: p for p in observed}
    wanted = {p["public_key"]: p for p in desired}
    if set(current) != set(wanted):
        return {"allowed": False, "reason": "peer_identity_change_requires_transaction",
                "changed": True}
    changed = []
    for key in sorted(wanted):
        a, b = current[key], wanted[key]
        if int(a["keepalive"]) != int(b["keepalive"]):
            changed.append("keepalive")
        # A roaming endpoint is not treated as a configuration change:
        # it is runtime data and may differ from the configured endpoint.
    return {"allowed": True, "reason": "same_route_safe_update",
            "changed": bool(changed), "changes": sorted(set(changed))}
