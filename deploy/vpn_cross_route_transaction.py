"""Root-owned, narrowly scoped one-hop route extension transaction for Magos.

Only adds ONE already-approved IPv4 CIDR to ONE existing Magos peer on wg0,
then installs exactly that kernel route. Preserves Cognitor and Mesh peers.
No SSH, iptables, arbitrary paths, ports, or route replacement.

An interrupted operation leaves a durable fence. Recovery is explicit.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

from vpn_cross_path_probe import (
    CrossPathCheckError, LinuxCrossPathProbe, parse_peer_dump,
    parse_persisted_peers, validate
)
from vpn_linux_backend import _atomic_bytes
from vpn_route_executor_sim import _durable_write

STATE = Path("/var/lib/omnissiah-network/vpn")
WG_CONF = Path("/etc/wireguard/wg0.conf")
MARKER = "cross-route-operation.json"
LOCK = "mesh-transaction.lock"


class CrossRouteError(ValueError):
    pass


def _uuid(value):
    try:
        parsed = uuid.UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError
    except (TypeError, ValueError, AttributeError) as exc:
        raise CrossRouteError("Canonical UUIDv4 required") from exc


def _digest(data):
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def extend_peer_config(original, public_key, cidr):
    """One-peer-only AllowedIPs append, preserving every unrelated byte of config."""
    if not original.startswith("# Managed by Omnissiah VPN v2\n"):
        raise CrossRouteError("Only Omnissiah-owned wg0.conf can be extended")
    lines = original.splitlines(keepends=True)
    sections, active = [], None
    for line_no, line in enumerate(lines):
        stripped = line.split("#", 1)[0].strip()
        if stripped == "[Peer]":
            active = {"start": line_no, "key": None, "allowed_lines": []}
            sections.append(active)
        elif stripped.startswith("["):
            active = None
        elif active is not None and "=" in stripped:
            key, value = (v.strip() for v in stripped.split("=", 1))
            if key == "PublicKey":
                if active["key"] is not None:
                    raise CrossRouteError("Duplicate PublicKey entries")
                active["key"] = value
            if key == "AllowedIPs":
                active["allowed_lines"].append((line_no, value))
    matching = [sec for sec in sections if sec["key"] == public_key]
    if len(matching) != 1 or len(matching[0]["allowed_lines"]) != 1:
        raise CrossRouteError("Exactly one owned Magos peer and AllowedIPs line required")
    section = matching[0]
    row, current = section["allowed_lines"][0]
    routes = [x.strip() for x in current.split(",") if x.strip()]
    if cidr in routes:
        raise CrossRouteError("This CIDR is already persisted")
    # Strict prior parsing and route-conflict checks happen in prepare().
    from ipaddress import ip_network
    try:
        normalized = [str(ip_network(value, strict=True)) for value in routes]
    except ValueError as exc:
        raise CrossRouteError("Invalid persisted peer AllowedIPs") from exc
    if len(set(normalized)) != len(normalized):
        raise CrossRouteError("Duplicate persisted AllowedIPs")
    new_line = "AllowedIPs = " + ", ".join(normalized + [cidr]) + "\n"
    lines[row] = new_line
    return "".join(lines), normalized


class CrossRouteExtension:
    def __init__(self, node_name, trusted_addresses, *, runner=None,
                 state=STATE, config=WG_CONF):
        self.node_name = node_name
        self.trusted = tuple(a for a in trusted_addresses if a)
        self.runner = runner or subprocess.run
        self.state = Path(state)
        self.config = Path(config)

    def _read(self, argv, *, input=None):
        response = self.runner(argv, input=input, text=True, capture_output=True,
                               timeout=15, check=False)
        if response.returncode:
            raise CrossRouteError("Kernel command rejected: " + argv[0])
        return response.stdout

    def _safe_paths(self):
        if os.geteuid() != 0:
            raise CrossRouteError("Root permissions required")
        if (self.state.is_symlink() or not self.state.is_dir()
                or self.state.stat().st_uid != 0 or self.state.stat().st_mode & 0o077):
            raise CrossRouteError("Root-owned private state directory required")
        if (self.config.is_symlink() or not self.config.is_file()
                or self.config.stat().st_uid != 0 or self.config.stat().st_mode & 0o077
                or not stat.S_ISREG(self.config.stat().st_mode)):
            raise CrossRouteError("Root-owned 0600 wg0.conf required")

    def _journal(self):
        path = self.state / MARKER
        if path.is_symlink():
            raise CrossRouteError("Unsafe route journal symlink")
        if not path.exists():
            return None
        try:
            result = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise CrossRouteError("Corrupt route journal; manual recovery required") from exc
        if not isinstance(result, dict) or "state" not in result:
            raise CrossRouteError("Invalid route journal")
        return result

    def _capture(self, plan, *, require_absent):
        self._safe_paths()
        manifest = validate(plan, self.node_name, self.trusted)
        # Runtime and persisted config are separately verified; none of this
        # changes WireGuard. A missing destination is expected pre-commit.
        wg_output = self._read(["wg", "show", "wg0", "dump"])
        kernel = parse_peer_dump(wg_output)
        old_conf = self.config.read_text()
        saved = parse_persisted_peers(old_conf)
        key = manifest["peer_public_key"]
        cidr = manifest["required_peer_allowed_ip"]
        if key not in kernel or key not in saved:
            raise CrossRouteError("Existing Magos peer must be present in kernel and wg0.conf")
        if set(kernel[key]) != set(saved[key]):
            raise CrossRouteError("Persisted and running peer AllowedIPs differ")
        if require_absent and (cidr in kernel[key] or cidr in saved[key]):
            raise CrossRouteError("Required route already exists; refuse duplicate change")
        if len(kernel[key]) > 32:
            raise CrossRouteError("Peer AllowedIPs limit exceeded")
        for other, routes in kernel.items():
            if other == key:
                continue
            from ipaddress import ip_network
            if any(ip_network(cidr).overlaps(ip_network(value)) for value in routes):
                raise CrossRouteError("Destination overlaps other WireGuard peer")
        for other, routes in saved.items():
            if other == key:
                continue
            from ipaddress import ip_network
            if any(ip_network(cidr).overlaps(ip_network(value)) for value in routes):
                raise CrossRouteError("Destination overlaps persisted WireGuard peer")
        # Management IPv4 + explicit endpoint routing must remain on underlay.
        if not self.trusted:
            raise CrossRouteError("Management IP allowlist unavailable")
        for address in self.trusted:
            observed = json.loads(self._read(["ip", "-j", "-4", "route", "get", address]))
            if len(observed) != 1 or observed[0].get("dev") in ("wg0", None):
                raise CrossRouteError("Management route traverses VPN")
        routes = json.loads(self._read(["ip", "-j", "-4", "route", "show", "table", "main"]))
        if not isinstance(routes, list) or not all(isinstance(row, dict) for row in routes):
            raise CrossRouteError("Untrusted kernel route snapshot")
        from ipaddress import ip_network
        target = ip_network(cidr, strict=True)
        if require_absent:
            for row in routes:
                name = row.get("dst", "default")
                if name == "default":
                    continue
                try:
                    route = ip_network(name, strict=False)
                except (ValueError, TypeError) as exc:
                    raise CrossRouteError("Invalid kernel route in snapshot") from exc
                if route.version == 4 and route.overlaps(target):
                    raise CrossRouteError("Existing route overlaps destination; manual review required")
        expected_config, old_allowed = extend_peer_config(old_conf, key, cidr)
        plan_snapshot = {
            "manifest": manifest, "old_wg_peer": sorted(kernel[key]),
            "old_config_sha": hashlib.sha256(old_conf.encode()).hexdigest(),
            "routes_sha": _digest(routes),
        }
        return manifest, old_conf, expected_config, old_allowed, plan_snapshot

    def prepare(self, raw, operation_id):
        _uuid(operation_id)
        if os.environ.get("OMNISSIAH_ENABLE_CROSS_ROUTE_APPLY") != "YES":
            raise CrossRouteError("Cross-Magos route mutations disabled by host policy")
        self._safe_paths()
        with (self.state / LOCK).open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous = self._journal()
            if previous and previous.get("state") not in ("finished", "reverted"):
                raise CrossRouteError("Unresolved route transaction; recover first")
            manifest, old_conf, new_conf, old_allowed, snapshot = self._capture(
                raw, require_absent=True)
            revision = _digest(snapshot)
            journal = {
                "operation_id": operation_id, "revision": revision,
                "state": "prepared", "plan": manifest, "snapshot": snapshot,
                "old_config": old_conf, "new_config": new_conf,
                "old_allowed_ips": old_allowed,
            }
            _durable_write(self.state, MARKER, journal)
            return {"state": "prepared", "revision": revision,
                    "operation_id": operation_id, "writes_performed": False}

    def commit(self, operation_id, revision):
        _uuid(operation_id)
        if os.environ.get("OMNISSIAH_ENABLE_CROSS_ROUTE_APPLY") != "YES":
            raise CrossRouteError("Cross-Magos route mutations disabled by host policy")
        self._safe_paths()
        with (self.state / LOCK).open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            saved = self._journal()
            if (not saved or saved["state"] != "prepared"
                    or saved["operation_id"] != operation_id
                    or saved["revision"] != revision):
                raise CrossRouteError("No matching prepared operation")
            manifest, old_conf, updated, old_allowed, observation = self._capture(
                saved["plan"], require_absent=True)
            if (_digest(observation) != revision or
                    old_conf != saved["old_config"] or updated != saved["new_config"]):
                raise CrossRouteError("Kernel/configuration changed since Prepare")
            key = manifest["peer_public_key"]
            cidr = manifest["required_peer_allowed_ip"]
            # A write-ahead recovery record persists *before* the first kernel change.
            saved["state"] = "committing"
            _durable_write(self.state, MARKER, saved)
            try:
                self._read(["wg", "set", "wg0", "peer", key,
                            "allowed-ips", ",".join(old_allowed + [cidr])])
                self._read(["ip", "-4", "route", "add", cidr, "dev", "wg0"])
                _atomic_bytes(self.config, updated.encode())
                self._verify_installed(saved)
                saved["state"] = "committed"
                _durable_write(self.state, MARKER, saved)
                return {"state": "committed", "operation_id": operation_id,
                        "revision": revision}
            except Exception as exc:
                # A failing command may have modified kernel state. Treat as
                # UNKNOWN; never automatically retry another distributed half.
                saved["state"] = "recovery_required"
                _durable_write(self.state, MARKER, saved)
                raise CrossRouteError("Commit outcome uncertain; rollback required") from exc

    def _verify_installed(self, journal):
        manifest = journal["plan"]
        key, cidr = manifest["peer_public_key"], manifest["required_route"]
        wg = parse_peer_dump(self._read(["wg", "show", "wg0", "dump"]))
        expected = sorted(journal["old_allowed_ips"] + [cidr])
        if sorted(wg.get(key, [])) != expected:
            raise CrossRouteError("Live WireGuard peer does not match committed AllowedIPs")
        if self.config.read_text() != journal["new_config"]:
            raise CrossRouteError("Persisted WireGuard configuration mismatch")
        effective = json.loads(self._read(
            ["ip", "-j", "-4", "route", "get", str(
                __import__("ipaddress").ip_network(cidr).network_address)]))
        if len(effective) != 1 or effective[0].get("dev") != "wg0":
            raise CrossRouteError("Missing effective wg0 route")

    def revert(self, operation_id, revision):
        _uuid(operation_id)
        if os.environ.get("OMNISSIAH_ENABLE_CROSS_ROUTE_APPLY") != "YES":
            raise CrossRouteError("Cross-Magos route mutations disabled by host policy")
        self._safe_paths()
        with (self.state / LOCK).open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            j = self._journal()
            if (not j or j["operation_id"] != operation_id
                    or j["revision"] != revision or j["state"] not in
                    ("committed", "committing", "recovery_required", "prepared")):
                raise CrossRouteError("No matching operation to revert")
            if j["state"] == "prepared":
                j["state"] = "reverted"
                _durable_write(self.state, MARKER, j)
                return {"state": "reverted", "operation_id": operation_id,
                        "revision": revision}
            j["state"] = "reverting"
            _durable_write(self.state, MARKER, j)
            key, cidr = j["plan"]["peer_public_key"], j["plan"]["required_route"]
            try:
                peer_now = parse_peer_dump(self._read(["wg", "show", "wg0", "dump"]))
                current = peer_now.get(key)
                previous = j["old_allowed_ips"]
                new = previous + [cidr]
                if current is None or sorted(current) not in (sorted(previous), sorted(new)):
                    raise CrossRouteError("Peer changed during transaction; manual restore required")
                if sorted(current) == sorted(new):
                    self._read(["wg", "set", "wg0", "peer", key,
                                "allowed-ips", ",".join(previous)])
                routes = json.loads(self._read(
                    ["ip", "-j", "-4", "route", "show", "table", "main"]))
                owned = [route for route in routes if route.get("dst") == cidr]
                if len(owned) > 1 or (owned and owned[0].get("dev") != "wg0"):
                    raise CrossRouteError("Route ownership changed; manual recovery required")
                if owned:
                    self._read(["ip", "-4", "route", "del", cidr, "dev", "wg0"])
                disk = self.config.read_text()
                if disk == j["new_config"]:
                    _atomic_bytes(self.config, j["old_config"].encode())
                elif disk != j["old_config"]:
                    raise CrossRouteError("Persistent configuration changed since Prepare")
                j["state"] = "reverted"
                _durable_write(self.state, MARKER, j)
                return {"state": "reverted", "operation_id": operation_id,
                        "revision": revision}
            except Exception as exc:
                j["state"] = "recovery_required"
                _durable_write(self.state, MARKER, j)
                raise CrossRouteError("Rollback not confirmed; manual recovery required") from exc

    def finalize(self, operation_id, revision):
        _uuid(operation_id)
        self._safe_paths()
        with (self.state / LOCK).open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            j = self._journal()
            if (not j or j["operation_id"] != operation_id
                    or j["revision"] != revision or j["state"] != "committed"):
                raise CrossRouteError("No matching committed operation")
            self._verify_installed(j)
            j["state"] = "finished"
            # Keep secrets in root-only journal, not in controller DB/logs.
            _durable_write(self.state, MARKER, j)
            return {"state": "finished", "revision": revision,
                    "operation_id": operation_id}
