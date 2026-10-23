"""Strict read-only verification of both gateway halves of a cross-Magos path.

No write operations and no credentials returned. Root RPC observes wg0,
kernel forwarding and effective route plus the persisted, root-owned wg0.conf.
No claim that the protected host itself has a return route is ever made.
"""
from ipaddress import ip_address, ip_interface, ip_network
import os
from pathlib import Path
import re
import stat
import subprocess
import json

KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,49}$")


class CrossPathCheckError(ValueError):
    pass


def validate(plan, node_name, trusted_addresses):
    fields = {
        "client_cidr", "client_public_key", "resource_cidr", "node_name", "address",
        "role", "own_vpn_cidr", "peer_name", "peer_public_key",
        "peer_vpn_cidr", "required_peer_allowed_ip", "required_route",
    }
    if not isinstance(plan, dict) or set(plan) != fields:
        raise CrossPathCheckError("Invalid cross-Magos plan schema")
    if (plan["node_name"] != node_name
            or not all(isinstance(plan[k], str) and NAME.fullmatch(plan[k])
                       for k in ("node_name", "peer_name"))
            or plan["role"] not in ("source", "destination")):
        raise CrossPathCheckError("Magos identity/role mismatch")
    if any(not isinstance(plan[k], str) or not KEY.fullmatch(plan[k])
           for k in ("client_public_key", "peer_public_key")):
        raise CrossPathCheckError("Invalid peer identity")
    try:
        client = ip_interface(plan["client_cidr"])
        own = ip_interface(plan["own_vpn_cidr"])
        if plan["address"] != plan["own_vpn_cidr"]:
            raise CrossPathCheckError("Installed Magos address mismatch")
        peer = ip_interface(plan["peer_vpn_cidr"])
        resource = ip_network(plan["resource_cidr"], strict=True)
        needed = ip_network(plan["required_peer_allowed_ip"], strict=True)
        route = ip_network(plan["required_route"], strict=True)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CrossPathCheckError("Invalid protected IPv4 network") from exc
    if any(host.version != 4 or host.network.prefixlen != 32
           for host in (client, own, peer)) or resource.version != 4:
        raise CrossPathCheckError("Only IPv4, Magos/Cognitor /32 supported")
    if any(host.ip.is_multicast or host.ip.is_loopback or host.ip.is_unspecified
           for host in (client, own, peer)):
        raise CrossPathCheckError("Invalid tunnel host address")
    if (resource.prefixlen == 0 or resource.is_multicast or resource.is_loopback
            or resource.is_link_local or resource.is_reserved
            or any(host.ip in resource for host in (client, own, peer))):
        raise CrossPathCheckError("Unsafe protected network")
    if len({str(v.ip) for v in (client, own, peer)}) != 3:
        raise CrossPathCheckError("Duplicate tunnel addresses")
    expected = resource if plan["role"] == "source" else client.network
    if needed != expected or route != expected:
        raise CrossPathCheckError("Directionally inconsistent route requirement")
    for value in trusted_addresses:
        if not value:
            continue
        try:
            mgmt = ip_address(value)
        except ValueError as exc:
            raise CrossPathCheckError("Invalid trusted management address") from exc
        if mgmt.version != 4 or mgmt in needed:
            raise CrossPathCheckError("Tunnel capture of management IP forbidden")
    return {
        **plan, "required_peer_allowed_ip": str(needed),
        "required_route": str(route),
    }


def parse_peer_dump(text):
    data = {}
    for line in text.splitlines()[1:]:
        values = line.split("\t")
        if len(values) < 8 or not KEY.fullmatch(values[0]):
            raise CrossPathCheckError("Corrupt WireGuard peer snapshot")
        if values[0] in data:
            raise CrossPathCheckError("Duplicate public key in kernel")
        try:
            cidrs = [] if values[3] in ("", "(none)") else [
                str(ip_network(v, strict=True)) for v in values[3].split(",")]
        except ValueError as exc:
            raise CrossPathCheckError("Invalid WireGuard AllowedIPs") from exc
        data[values[0]] = cidrs
    return data


def parse_persisted_peers(contents):
    peers = {}
    current = None
    for raw in contents.splitlines():
        row = raw.split("#", 1)[0].strip()
        if row == "[Peer]":
            if current is not None and current["public_key"]:
                key = current["public_key"]
                if key in peers:
                    raise CrossPathCheckError("Duplicate persisted peer")
                peers[key] = current["allowed_ips"]
            current = {"public_key": None, "allowed_ips": []}
        elif row.startswith("["):
            if current is not None and current["public_key"]:
                key = current["public_key"]
                if key in peers:
                    raise CrossPathCheckError("Duplicate persisted peer")
                peers[key] = current["allowed_ips"]
            current = None
        elif current is not None and "=" in row:
            k, value = [x.strip() for x in row.split("=", 1)]
            if k == "PublicKey":
                if current["public_key"] is not None or not KEY.fullmatch(value):
                    raise CrossPathCheckError("Ambiguous persisted peer key")
                current["public_key"] = value
            elif k == "AllowedIPs":
                try:
                    current["allowed_ips"] += [
                        str(ip_network(item.strip(), strict=True))
                        for item in value.split(",")]
                except ValueError as exc:
                    raise CrossPathCheckError("Invalid persisted AllowedIPs") from exc
    if current is not None and current["public_key"]:
        if current["public_key"] in peers:
            raise CrossPathCheckError("Duplicate persisted peer")
        peers[current["public_key"]] = current["allowed_ips"]
    return peers


class LinuxCrossPathProbe:
    def __init__(self, node_name, management_addresses, *, runner=None,
                 config="/etc/wireguard/wg0.conf"):
        self.node_name = node_name
        self.protected = tuple(a for a in management_addresses if a)
        self.runner = runner or subprocess.run
        self.config = Path(config)

    def _read(self, argv):
        completed = self.runner(
            argv, capture_output=True, text=True, timeout=10, check=False)
        if completed.returncode:
            raise CrossPathCheckError("Kernel observation failed: " + argv[0])
        return completed.stdout

    def _persisted(self):
        if self.config.is_symlink() or not self.config.is_file():
            raise CrossPathCheckError("Persistent WireGuard config missing")
        st = self.config.stat()
        if (st.st_uid != os.geteuid() or not stat.S_ISREG(st.st_mode)
                or st.st_mode & 0o077):
            raise CrossPathCheckError("Persistent WireGuard config must be root 0600")
        return parse_persisted_peers(self.config.read_text())

    def check(self, raw):
        plan = validate(raw, self.node_name, self.protected)
        kernel = parse_peer_dump(self._read(["wg", "show", "wg0", "dump"]))
        disk = self._persisted()
        peer_key = plan["peer_public_key"]
        required = plan["required_peer_allowed_ip"]
        problems = []
        if peer_key not in kernel:
            problems.append("Remote Magos peer is absent from running WireGuard")
        if peer_key not in disk:
            problems.append("Remote Magos peer is absent from persisted WireGuard")
        for label, source in (("kernel", kernel), ("disk", disk)):
            if peer_key in source and required not in source[peer_key]:
                problems.append("Required " + required + " missing from " + label + " peer AllowedIPs")
        if plan["role"] == "source":
            client = plan["client_public_key"]
            if client not in kernel or plan["client_cidr"] not in kernel[client]:
                problems.append("Cognitor /32 not installed at source Magos")
            if client not in disk or plan["client_cidr"] not in disk[client]:
                problems.append("Cognitor /32 not persisted at source Magos")
        # Ownership is checked across ALL peers, not only the named peer.
        for label, source in (("kernel", kernel), ("disk", disk)):
            for key, allowed in source.items():
                if key == peer_key:
                    continue
                for cidr in allowed:
                    if ip_network(required).overlaps(ip_network(cidr)):
                        problems.append(label + " peer AllowedIPs conflict with " + required)
                        break
        if self._read(["sysctl", "-n", "net.ipv4.ip_forward"]).strip() != "1":
            problems.append("IPv4 forwarding disabled")
        if self._read(["sysctl", "-n", "net.ipv4.conf.wg0.rp_filter"]).strip() == "1":
            problems.append("Strict reverse path filter on wg0")
        # ip route get with iif/from better approximates FORWARD than a
        # locally generated packet; the kernel may still drop another way.
        dest = (ip_network(required).network_address
                + (1 if ip_network(required).prefixlen < 32 else 0))
        argv = ["ip", "-j", "-4", "route", "get", str(dest)]
        if plan["role"] == "source":
            argv += ["from", str(ip_network(plan["client_cidr"]).network_address),
                     "iif", "wg0"]
        # A missing route before the route-extension transaction is normal.
        # Represent it as a blocking diagnostic, NOT a root RPC exception/503.
        # Never treat missing/invalid kernel output as evidence of a safe path.
        def check_route(argv, expected, label):
            try:
                response = self.runner(
                    argv, capture_output=True, text=True, timeout=10, check=False)
                if response.returncode:
                    raise CrossPathCheckError("Route lookup failed")
                rows = json.loads(response.stdout)
                if not isinstance(rows, list) or len(rows) != 1:
                    raise CrossPathCheckError("Route lookup returned no unique path")
                row = rows[0]
                if not isinstance(row, dict) or not isinstance(row.get("dev"), str):
                    raise CrossPathCheckError("Route lookup has no outgoing device")
                if row.get("type") in ("unreachable", "blackhole", "prohibit"):
                    raise CrossPathCheckError("Kernel rejects packets to destination")
                if row["dev"] in expected:
                    return True
            except (ValueError, TypeError, OSError, subprocess.SubprocessError):
                pass
            problems.append(label)
            return False

        check_route(
            argv, ("wg0",),
            "Required route to " + required + " via wg0 is missing or unverifiable")
        if plan["role"] == "destination":
            resource = ip_network(plan["resource_cidr"])
            address = resource.network_address + (1 if resource.prefixlen < 32 else 0)
            # Destination resource must leave on the local LAN, not the VPN.
            try:
                response = self.runner(
                    ["ip", "-j", "-4", "route", "get", str(address)],
                    capture_output=True, text=True, timeout=10, check=False)
                lan = json.loads(response.stdout) if response.returncode == 0 else None
                if (not isinstance(lan, list) or len(lan) != 1
                        or not isinstance(lan[0], dict)
                        or lan[0].get("dev") in (None, "wg0", "lo")):
                    problems.append("Destination Magos lacks local route to protected resource")
            except (ValueError, TypeError, OSError, subprocess.SubprocessError):
                problems.append("Destination Magos LAN route cannot be verified")
        # Management must continue to use underlay; inability to verify blocks.
        for addr in self.protected:
            try:
                response = self.runner(
                    ["ip", "-j", "-4", "route", "get", addr],
                    capture_output=True, text=True, timeout=10, check=False)
                management = json.loads(response.stdout) if response.returncode == 0 else None
                if (not isinstance(management, list) or len(management) != 1
                        or not isinstance(management[0], dict)
                        or management[0].get("dev") in ("wg0", None)):
                    problems.append("Management/underlay routing unsafe for " + addr)
            except (ValueError, TypeError, OSError, subprocess.SubprocessError):
                problems.append("Management/underlay route cannot be verified for " + addr)
        return {
            "node_name": self.node_name, "role": plan["role"],
            "peer_name": plan["peer_name"], "required_allowed_ip": required,
            "required_route": required, "gateway_checks_passed": not problems,
            "blockers": sorted(set(problems)),
            "protected_host_return_verified": False,
            "cognitor_route_verified": False,
            "writes_performed": False,
        }
