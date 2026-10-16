"""Strict WireGuard /32 route ownership and conflict preflight.

No subprocess, filesystem or network changes in this module. Route changes
must be explicit and are never inferred from the mere existence of a peer.
"""
from ipaddress import ip_address, ip_network


class RouteConflict(ValueError):
    pass


def desired_routes(peers):
    """Accept only unique unicast host routes to remote WG peers."""
    routes = set()
    for peer in peers:
        for entry in peer["allowed_ips"]:
            network = ip_network(entry, strict=True)
            if network.version != 4 or network.prefixlen != 32:
                raise RouteConflict("Only IPv4 /32 host routes are supported")
            if network.network_address.is_unspecified or network.network_address.is_multicast:
                raise RouteConflict("Invalid host route")
            route = str(network)
            if route in routes:
                raise RouteConflict("Duplicate desired host route")
            routes.add(route)
    return routes


def normalize_route(item):
    """Extract only main-table, kernel-reported IPv4 unicast route attributes."""
    if not isinstance(item, dict):
        raise RouteConflict("Invalid kernel route record")
    destination = item.get("dst", "default")
    if destination == "default":
        return None
    try:
        net = ip_network(destination, strict=False)
    except (TypeError, ValueError) as exc:
        raise RouteConflict("Invalid kernel route destination") from exc
    if net.version != 4:
        return None
    return {
        "dst": str(net),
        "dev": item.get("dev"),
        "gateway": item.get("gateway"),
        "table": item.get("table", "main"),
        "protocol": item.get("protocol"),
        "scope": item.get("scope"),
        "type": item.get("type", "unicast"),
        "metric": item.get("metric"),
    }


def plan_route_delta(desired_peers, actual_wg_peers, main_routes, *, iface="wg0"):
    """Reject ambiguous route ownership. Return a simple, reproducible delta.

    Requires complete main-table snapshot supplied by a privileged caller.
    Does not authorize non-main routing tables, policy routing or foreign
    routes even when the target host matches.
    """
    desired = desired_routes(desired_peers)
    previous = desired_routes(actual_wg_peers)
    records = [normalize_route(r) for r in main_routes]
    records = [r for r in records if r is not None]
    relevant = [r for r in records if r["dst"] in desired | previous]
    occupied = {r["dst"] for r in relevant}
    if any(r["table"] not in ("main", 254) for r in relevant):
        raise RouteConflict("Non-main route requires manual review")
    for route in relevant:
        if route["type"] != "unicast" or route["gateway"]:
            raise RouteConflict("Host route has unsupported type or gateway")
        if route["dev"] != iface:
            raise RouteConflict("Host route conflicts with a foreign interface")
        if route["metric"] not in (None, 0):
            raise RouteConflict("Metric-bearing host route requires manual review")
    if len(relevant) != len(occupied):
        raise RouteConflict("Ambiguous duplicate kernel routes")
    # A current WG AllowedIPs host route must have a corresponding Linux
    # route. Otherwise the operator must repair pre-existing drift first.
    if not previous <= occupied:
        raise RouteConflict("Missing route for existing WireGuard peer")
    # A new destination already routed by wg0 but not owned by existing peers
    # is a foreign route: do not take ownership of it.
    if (desired - previous) & occupied:
        raise RouteConflict("Target route already exists and is not owned")
    return {
        "add": sorted(desired - previous),
        "remove": sorted(previous - desired),
        "unchanged": sorted(desired & previous),
    }
