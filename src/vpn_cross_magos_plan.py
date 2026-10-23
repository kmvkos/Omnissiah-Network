"""Cross-Magos one-hop policy routing intentions, with no network writes.

A route to another Magos is NOT proof of end-to-end connectivity.
Build a symmetric, strictly scoped plan only when an explicit direct mesh
edge connects the Cognitor's Magos and the protected resource's Magos.
"""
from ipaddress import ip_address, ip_interface, ip_network
import re

PUBLIC_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class CrossPathRejected(ValueError):
    pass


def _host(value, label):
    try:
        obj = ip_interface(value)
        if obj.version != 4 or obj.network.prefixlen != 32:
            raise ValueError
        return str(obj.network)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CrossPathRejected(label + " must be an IPv4 /32") from exc


def plan_cross_magos(client, resource, magos, edges):
    source = magos.get(getattr(client, "parent_magos_id", None))
    target = magos.get(getattr(resource, "parent_magos_id", None))
    if source is None or target is None or source.id == target.id:
        raise CrossPathRejected("Cross-Magos requires two different registered Magos")
    if source.role != "Magos" or target.role != "Magos":
        raise CrossPathRejected("Only Magos nodes can forward VPN traffic")
    expected = {source.id, target.id}
    direct = sum(1 for edge in edges
                 if {edge.node1_id, edge.node2_id} == expected
                 and edge.node1_id != edge.node2_id)
    if direct != 1:
        raise CrossPathRejected("No unique direct mesh link. Multi-hop requires separate planning.")
    client_net = _host(getattr(client, "vpn_address", None), "Cognitor address")
    source_net = _host(source.ip_pool, "Source Magos address")
    target_net = _host(target.ip_pool, "Target Magos address")
    try:
        dest = ip_network(resource.network, strict=True)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CrossPathRejected("Invalid protected resource CIDR") from exc
    if (dest.version != 4 or dest.prefixlen == 0 or dest.is_multicast
            or dest.is_loopback or dest.is_link_local or dest.is_reserved
            or any(ip_address(n.split("/")[0]) in dest
                   for n in (client_net, source_net, target_net))):
        raise CrossPathRejected("Unsafe or overlapping protected resource network")
    if not PUBLIC_KEY.fullmatch(getattr(source, "public_key", "") or ""):
        raise CrossPathRejected("Invalid source Magos WireGuard public key")
    if not PUBLIC_KEY.fullmatch(getattr(target, "public_key", "") or ""):
        raise CrossPathRejected("Invalid target Magos WireGuard public key")
    if not PUBLIC_KEY.fullmatch(getattr(client, "public_key", "") or ""):
        raise CrossPathRejected("Invalid Cognitor WireGuard public key")
    if getattr(client, "status", None) != "applied":
        raise CrossPathRejected("Cognitor WireGuard registration not confirmed")
    # Each hop uses the *other* Magos as the peer; no full-tunnel AllowedIPs.
    common = {
        "client_cidr": client_net, "client_public_key": client.public_key,
        "resource_cidr": str(dest),
    }
    source_plan = {
        **common, "node_name": source.name, "address": source.ip_pool, "role": "source",
        "own_vpn_cidr": source_net, "peer_name": target.name,
        "peer_public_key": target.public_key, "peer_vpn_cidr": target_net,
        "required_peer_allowed_ip": str(dest),
        "required_route": str(dest),
    }
    dest_plan = {
        **common, "node_name": target.name, "address": target.ip_pool, "role": "destination",
        "own_vpn_cidr": target_net, "peer_name": source.name,
        "peer_public_key": source.public_key, "peer_vpn_cidr": source_net,
        "required_peer_allowed_ip": client_net,
        "required_route": client_net,
    }
    return source, target, source_plan, dest_plan
