"""Side-effect-free validation of a WireGuard desired configuration.

The planner does not write files, generate private keys or change network state.
A future privileged helper must revalidate the same model before applying it.
"""
import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable

_INTERFACE = re.compile(r"^[a-zA-Z0-9_=+.-]{1,15}$")


class VPNPlanError(ValueError):
    """Desired VPN state failed validation."""


def _key(value: str) -> str:
    if not isinstance(value, str):
        raise VPNPlanError("WireGuard public key must be a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VPNPlanError("Invalid WireGuard public key") from exc
    if len(raw) != 32:
        raise VPNPlanError("WireGuard public key must decode to 32 bytes")
    return value


@dataclass(frozen=True)
class Peer:
    name: str
    public_key: str
    endpoint: str
    allowed_ips: tuple[str, ...]
    keepalive: int = 25


@dataclass(frozen=True)
class VPNPlan:
    node_name: str
    interface: str
    address: str
    listen_port: int
    peers: tuple[Peer, ...]


def plan_vpn(node_name: str, address: str, peers: Iterable[Peer], *,
             interface: str = "wg0", listen_port: int = 51820) -> VPNPlan:
    """Reject ambiguous routes and unexpected changes to host routing.

    AllowedIPs is intentionally restricted to explicit host routes in the
    first stage. Protected subnets will require a separate policy evaluator.
    """
    if not isinstance(node_name, str) or not _INTERFACE.fullmatch(node_name):
        raise VPNPlanError("Invalid node name")
    if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface):
        raise VPNPlanError("Invalid interface name")
    if not isinstance(listen_port, int) or not 1 <= listen_port <= 65535:
        raise VPNPlanError("Invalid UDP listen port")
    try:
        local = ipaddress.ip_interface(address)
    except ValueError as exc:
        raise VPNPlanError("Invalid local VPN address") from exc
    if local.version != 4 or local.ip.is_multicast or local.ip.is_unspecified:
        raise VPNPlanError("Local address must be unicast IPv4")
    # /32 on each Magos prevents accidental implicit routing of the whole pool.
    if local.network.prefixlen != 32:
        raise VPNPlanError("Use a /32 interface address (not a network pool)")

    normalized = []
    keys = set()
    routes = set()
    names = set()
    for peer in peers:
        if not isinstance(peer, Peer):
            raise VPNPlanError("Invalid peer")
        if not isinstance(peer.name, str) or not _INTERFACE.fullmatch(peer.name) or peer.name == node_name:
            raise VPNPlanError("Invalid peer name")
        if peer.name in names:
            raise VPNPlanError("Duplicate peer name")
        names.add(peer.name)
        _key(peer.public_key)
        if peer.public_key in keys:
            raise VPNPlanError("Duplicate WireGuard public key")
        keys.add(peer.public_key)
        if not isinstance(peer.keepalive, int) or not 0 <= peer.keepalive <= 65535:
            raise VPNPlanError("Invalid keepalive")
        if not isinstance(peer.endpoint, str) or peer.endpoint.count(":") != 1:
            raise VPNPlanError("Endpoint must be IPv4:port")
        ip_part, port_part = peer.endpoint.split(":")
        try:
            ep_ip = ipaddress.IPv4Address(ip_part)
            ep_port = int(port_part)
        except ValueError as exc:
            raise VPNPlanError("Invalid endpoint") from exc
        if ep_ip.is_multicast or ep_ip.is_unspecified or not 1 <= ep_port <= 65535:
            raise VPNPlanError("Invalid endpoint")
        if not peer.allowed_ips:
            raise VPNPlanError("Peer needs an explicit AllowedIPs host route")
        safe_routes = []
        for network in peer.allowed_ips:
            try:
                net = ipaddress.ip_network(network, strict=True)
            except ValueError as exc:
                raise VPNPlanError("Invalid AllowedIPs route") from exc
            if net.version != 4 or net.prefixlen != 32:
                raise VPNPlanError("Only explicit IPv4 /32 routes allowed (no default route)")
            if net.network_address == local.ip:
                raise VPNPlanError("Cannot route the local VPN address via a peer")
            if net in routes:
                raise VPNPlanError("Overlapping AllowedIPs between peers")
            routes.add(net)
            safe_routes.append(str(net))
        normalized.append(Peer(peer.name, peer.public_key, str(ep_ip) + ":" + str(ep_port),
                               tuple(safe_routes), peer.keepalive))
    return VPNPlan(node_name, interface, str(local), listen_port, tuple(normalized))


def render_peer_sections(plan: VPNPlan) -> str:
    """Render non-secret [Peer] sections; never render or move private keys."""
    sections = []
    for peer in plan.peers:
        sections.append("[Peer]\nPublicKey = " + peer.public_key +
                        "\nAllowedIPs = " + ", ".join(peer.allowed_ips) +
                        "\nEndpoint = " + peer.endpoint +
                        "\nPersistentKeepalive = " + str(peer.keepalive))
    return "\n\n".join(sections) + ("\n" if sections else "")
