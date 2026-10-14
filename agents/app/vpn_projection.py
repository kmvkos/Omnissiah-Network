"""Read-only mesh topology projection from database-like node/link records.

This module never changes DB, SSH, routes, interfaces or private keys.
"""
from ipaddress import ip_interface, ip_address
from app.vpn_plan import Peer, VPNPlanError, plan_vpn


def project_magos_mesh(nodes, connections):
    """Map only explicit Magos-Magos edges to strict host-route plans.

    nodes: objects exposing id, name, role, ip_pool, endpoint,
    listen_port, public_key.
    connections: objects exposing node1_id, node2_id.
    """
    magos = {n.id: n for n in nodes if n.role == "Magos"}
    adjacency = {node_id: set() for node_id in magos}
    for connection in connections:
        a, b = connection.node1_id, connection.node2_id
        if a in magos and b in magos:
            if a == b:
                raise VPNPlanError("Self-links are forbidden")
            adjacency[a].add(b)
            adjacency[b].add(a)
    result = []
    for node_id, node in sorted(magos.items(), key=lambda pair: pair[1].name):
        try:
            address = ip_interface(node.ip_pool)
            if address.version != 4 or address.network.prefixlen != 32:
                raise VPNPlanError("Magos VPN address must be /32")
            peers = []
            for peer_id in sorted(adjacency[node_id]):
                peer = magos[peer_id]
                if not peer.public_key:
                    raise VPNPlanError("Missing public key for " + peer.name)
                peer_ip = ip_interface(peer.ip_pool)
                if peer_ip.version != 4 or peer_ip.network.prefixlen != 32:
                    raise VPNPlanError("Peer VPN address must be /32")
                endpoint_ip = ip_address(peer.endpoint)
                if endpoint_ip.version != 4:
                    raise VPNPlanError("Endpoint must be IPv4")
                peers.append(Peer(peer.name, peer.public_key,
                                  str(endpoint_ip) + ":" + str(peer.listen_port),
                                  (str(peer_ip.ip) + "/32",)))
            plan = plan_vpn(node.name, str(address), peers,
                            listen_port=node.listen_port)
            result.append({"node_id": node.id, "node_name": plan.node_name,
                           "interface": plan.interface, "address": plan.address,
                           "listen_port": plan.listen_port,
                           "peers": [{"name": p.name, "public_key": p.public_key,
                                      "endpoint": p.endpoint,
                                      "allowed_ips": list(p.allowed_ips),
                                      "keepalive": p.keepalive} for p in plan.peers]})
        except (ValueError, TypeError, AttributeError) as exc:
            raise VPNPlanError("Invalid node " + str(node.name) + ": " + str(exc)) from exc
    return result
