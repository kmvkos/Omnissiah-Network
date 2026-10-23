"""Restricted nftables policy engine for managed Cognitor forwarding.

Never modifies wg0, the system firewall chains, or routes.  The *only* kernel
object this module may own is inet/omnissiah_acl_v2.  Applies are explicitly
opt-in and guarded by validated desired revision + UUID + root lock.
"""
import fcntl
import hashlib
from ipaddress import ip_address, ip_interface, ip_network
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

TABLE = "omnissiah_acl_v2"
STATE = Path("/var/lib/omnissiah-network/vpn")
PUBLIC_KEYS = re.compile(r"^[A-Za-z0-9+/]{43}=$")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,49}$")


class PolicyRejected(ValueError):
    pass


def _network(value, *, host=False):
    try:
        n = ip_interface(value) if host else ip_network(value, strict=True)
    except (TypeError, ValueError) as exc:
        raise PolicyRejected("Invalid network in policy plan") from exc
    if n.version != 4 or (host and n.network.prefixlen != 32):
        raise PolicyRejected("Only IPv4 and /32 client addresses supported")
    if n.ip.is_multicast or n.ip.is_loopback or n.ip.is_unspecified if host else (
            n.is_multicast or n.is_loopback or n.is_link_local or n.prefixlen == 0
            or n.is_reserved):
        raise PolicyRejected("Unsafe address in policy plan")
    return n


def normalize(plan, expected_node, management_addresses=()):
    """Strictly accept only the documented manifest with bounded resources."""
    if not isinstance(plan, dict) or set(plan) != {"node_name", "address", "clients"}:
        raise PolicyRejected("Unexpected ACL plan fields")
    if not isinstance(plan["node_name"], str) or not NAME.fullmatch(plan["node_name"]):
        raise PolicyRejected("Invalid Magos identity")
    if plan["node_name"] != expected_node:
        raise PolicyRejected("ACL plan belongs to another Magos")
    own = _network(plan["address"], host=True)
    raw = plan["clients"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
        raise PolicyRejected("ACL plan must contain 1-32 managed Cognitors")
    management = []
    for addr in management_addresses:
        try:
            ip = ip_address(addr)
        except (ValueError, TypeError) as exc:
            raise PolicyRejected("Invalid trusted management IP") from exc
        if ip.version != 4:
            raise PolicyRejected("Only IPv4 management addresses supported")
        management.append(ip)
    used_sources, used_keys, normalized, entries = set(), set(), [], 0
    for client in raw:
        if not isinstance(client, dict) or set(client) != {"name", "address", "public_key", "targets"}:
            raise PolicyRejected("Invalid Cognitor manifest")
        name = client["name"]
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise PolicyRejected("Invalid Cognitor name")
        source = _network(client["address"], host=True)
        ip = str(source.ip)
        key = client["public_key"]
        if (ip == str(own.ip) or ip in used_sources or not isinstance(key, str)
                or not PUBLIC_KEYS.fullmatch(key) or key in used_keys):
            raise PolicyRejected("Invalid/duplicate Cognitor identity")
        used_sources.add(ip)
        used_keys.add(key)
        targets = client["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= 32:
            raise PolicyRejected("Cognitor must have 1-32 target resources")
        seen_targets, out_targets = set(), []
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"network", "via_magos", "rules"}:
                raise PolicyRejected("Invalid target resource")
            dst = _network(target["network"])
            cidr = str(dst)
            if (cidr in seen_targets or source.ip in dst or own.ip in dst
                    or any(ip in dst for ip in management)):
                raise PolicyRejected("Overlapping/management resource refused")
            if type(target["via_magos"]) is not bool:
                raise PolicyRejected("Target location must be explicit")
            for existing in seen_targets:
                if dst.overlaps(ip_network(existing)):
                    raise PolicyRejected("Overlapping targets within one Cognitor")
            seen_targets.add(cidr)
            rules = target["rules"]
            if not isinstance(rules, list) or not 1 <= len(rules) <= 64:
                raise PolicyRejected("Each target needs explicit policy rules")
            seen_match, out_rules = set(), []
            for rule in rules:
                if not isinstance(rule, dict) or set(rule) != {"protocol", "port", "decision"}:
                    raise PolicyRejected("Unexpected policy rule fields")
                proto, port, decision = rule["protocol"], rule["port"], rule["decision"]
                if proto not in ("tcp", "udp", "icmp") or decision not in ("allow", "deny"):
                    raise PolicyRejected("Invalid protocol or action")
                if type(port) is not int or (port != 0 if proto == "icmp" else not 1 <= port <= 65535):
                    raise PolicyRejected("Invalid destination port")
                match = (proto, port)
                if match in seen_match:
                    raise PolicyRejected("Duplicate or conflicting policy rules")
                seen_match.add(match)
                out_rules.append({"protocol": proto, "port": port, "decision": decision})
                entries += 1
            out_targets.append({"network": cidr, "via_magos": target["via_magos"],
                                "rules": sorted(out_rules, key=lambda r: (r["protocol"], r["port"]))})
        normalized.append({"name": name, "address": str(source), "public_key": key,
                           "targets": sorted(out_targets, key=lambda t: t["network"])})
    if entries > 256:
        raise PolicyRejected("Too many policy rules")
    return {"node_name": expected_node, "address": str(own),
            "clients": sorted(normalized, key=lambda c: c["address"])}


def digest(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def nft_batch(plan, *, replace=False):
    """Generate nft-only commands. No shell, raw expressions or arbitrary tables."""
    lines = []
    if replace:
        lines.append(f"delete table inet {TABLE}")
    lines.append(f"add table inet {TABLE}")
    lines.append(
        f"add chain inet {TABLE} forward {{ type filter hook forward priority -30; policy accept; }}")
    for client in plan["clients"]:
        source = str(ip_interface(client["address"]).ip)
        for target in client["targets"]:
            match = (f'add rule inet {TABLE} forward iifname "wg0" '
                     f'ip saddr {source} ip daddr {target["network"]}')
            # Explicit allow/deny first; fall-through denies remaining forwarded
            # traffic to the *registered target only*, not unrelated networks.
            for rule in target["rules"]:
                proto = rule["protocol"]
                qualifier = "ip protocol icmp" if proto == "icmp" else f"{proto} dport {rule['port']}"
                action = "accept" if rule["decision"] == "allow" else "drop"
                lines.append(f"{match} {qualifier} {action}")
            lines.append(f"{match} drop")
    return "\n".join(lines) + "\n"


class LinuxACL:
    """Privileged but narrowly-scoped ACL transaction with root-only journal."""
    def __init__(self, *, node_name, protected_ips=(), state=STATE, runner=None):
        self.node_name = node_name
        self.protected_ips = tuple(a for a in protected_ips if a)
        self.state = Path(state)
        self.runner = runner or subprocess.run

    def _run(self, argv, *, input=None, fail=True):
        res = self.runner(argv, input=input, text=True, capture_output=True, timeout=15)
        if fail and res.returncode:
            raise PolicyRejected("Read-only preflight or nft operation failed")
        return res

    def _table_present(self):
        result = self._run(["nft", "-j", "list", "table", "inet", TABLE], fail=False)
        return result.returncode == 0

    def _active(self):
        file = self.state / "acl-active.json"
        if file.is_symlink():
            raise PolicyRejected("Symlink ACL state refused")
        if not file.exists():
            return None
        try:
            data = json.loads(file.read_text())
        except (ValueError, OSError) as exc:
            raise PolicyRejected("Corrupt ACL state") from exc
        if not isinstance(data, dict) or set(data) != {"plan", "digest"} or digest(data["plan"]) != data["digest"]:
            raise PolicyRejected("Untrusted ACL state")
        return data

    def _verify(self, plan):
        # Fail closed on drift; never change an existing unmanaged nft table.
        previous = self._active()
        present = self._table_present()
        if bool(previous) != present:
            raise PolicyRejected("Existing nft ACL/table state mismatch; manual reconciliation required")
        dump = self._run(["wg", "show", "wg0", "dump"]).stdout
        peers = {}
        for row in dump.splitlines()[1:]:
            cells = row.split("\t")
            if len(cells) >= 4:
                peers[cells[0]] = set(cells[3].split(","))
        for client in plan["clients"]:
            if client["address"] not in peers.get(client["public_key"], set()):
                raise PolicyRejected("Cognitor peer is not installed with expected /32 route")
            for target in client["targets"]:
                dst = ip_network(target["network"])
                address = dst.network_address
                if dst.prefixlen < 32:
                    address += 1
                route = self._run(["ip", "-j", "route", "get", str(address)]).stdout
                try:
                    data = json.loads(route)
                    iface = data[0]["dev"]
                except (ValueError, IndexError, KeyError, TypeError) as exc:
                    raise PolicyRejected("Unknown protected-resource route") from exc
                if target["via_magos"] and iface != "wg0":
                    raise PolicyRejected("Remote resource must route via wg0")
                if not target["via_magos"] and iface in ("wg0", "lo"):
                    raise PolicyRejected("Local resource must use a local transit interface")
        # Syntax validation is read-only even if current table exists.
        self._run(["nft", "-c", "-f", "-"], input=nft_batch(plan, replace=present))
        return previous, present

    def preview(self, raw):
        plan = normalize(raw, self.node_name, self.protected_ips)
        _, present = self._verify(plan)
        return {"revision": digest(plan), "client_count": len(plan["clients"]),
                "rule_count": sum(len(t["rules"]) for c in plan["clients"] for t in c["targets"]),
                "target_count": sum(len(c["targets"]) for c in plan["clients"]),
                "previous_policy_present": present, "route_preflight_ok": True,
                "writes_performed": False, "apply_available": True}

    def _atomic(self, path, data):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise PolicyRejected("Symlink ACL state refused")
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".acl-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def apply(self, raw, *, revision, operation_id):
        if os.environ.get("OMNISSIAH_ENABLE_POLICY_APPLY") != "YES":
            raise PolicyRejected("ACL apply disabled by host installation policy")
        try:
            uid = uuid.UUID(operation_id)
            if uid.version != 4 or str(uid) != operation_id:
                raise ValueError
        except (TypeError, ValueError, AttributeError) as exc:
            raise PolicyRejected("Canonical UUIDv4 required") from exc
        if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{64}", revision):
            raise PolicyRejected("Expected policy revision required")
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.state / "acl.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            plan = normalize(raw, self.node_name, self.protected_ips)
            if digest(plan) != revision:
                raise PolicyRejected("Plan changed since policy preview")
            previous, present = self._verify(plan)
            marker = self.state / "acl-previous.json"
            # Prewrite recovery data before changing the in-kernel table.
            if marker.exists():
                raise PolicyRejected("Unresolved previous ACL transaction; recovery required")
            self._atomic(marker, json.dumps({"operation_id": operation_id, "previous": previous}))
            try:
                self._run(["nft", "-f", "-"], input=nft_batch(plan, replace=present))
                self._atomic(self.state / "acl-active.json",
                             json.dumps({"plan": plan, "digest": digest(plan)}, sort_keys=True))
                marker.unlink()
                return {"state": "committed", "revision": digest(plan), "operation_id": operation_id}
            except Exception as exc:
                # Replace with last known managed policy, or delete only OUR table.
                try:
                    if previous is None:
                        self._run(["nft", "-f", "-"], input=f"delete table inet {TABLE}\n")
                        (self.state / "acl-active.json").unlink(missing_ok=True)
                    else:
                        self._run(["nft", "-f", "-"],
                                  input=nft_batch(previous["plan"], replace=True))
                    marker.unlink()
                except Exception as rollback_error:
                    raise PolicyRejected("ACL rollback failed; manual recovery required") from rollback_error
                raise PolicyRejected("ACL apply failed; previous managed policy restored") from exc
