"""Read-only Cognitor WireGuard AllowedIPs expectations derived from policies.

Cognitor is a client without an Omnissiah-managed agent. Server-side nftables
cannot forward client packets that do not enter its wg0 interface first.
"""
from ipaddress import ip_network, ip_interface


def expected_client_allowed_ips(client, rules):
    """Generate only host Magos + explicit protected destinations, never default."""
    if not client.parent_magos:
        raise ValueError("Cognitor is missing its upstream Magos")
    gateway = ip_interface(client.parent_magos.ip_pool)
    if gateway.version != 4 or gateway.network.prefixlen != 32:
        raise ValueError("Expected explicit Magos /32 address")
    networks = {str(gateway.network)}
    for rule in rules:
        if rule.source_cognitor_id != client.id or rule.status == "pending_delete":
            continue
        obj = rule.target_object
        if not obj:
            raise ValueError("Referenced protected object is missing")
        network = ip_network(obj.network, strict=True)
        if network.version != 4 or network.prefixlen == 0 or network.is_multicast:
            raise ValueError("Unsafe resource CIDR in route plan")
        networks.add(str(network))
    return sorted(networks, key=lambda c: (
        ip_network(c).network_address.packed, ip_network(c).prefixlen))
