"""Opt-in add-only Cognitor transaction using the shared VPN journal and UUID lock.

No existing peer is changed on successful admission. Interrupted operations
fail closed through the ordinary mesh transaction journal and ledger.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from vpn_cognitor_preview import preview_add, validate_plan
from vpn_linux_backend import _atomic_bytes, _digest
from vpn_linux_preflight import LinuxReadOnlyPreflight, _strict_route_operation
from vpn_mesh_transaction import run_offline_mesh_transaction
from vpn_operation_fence import validate_operation_id
from vpn_reconcile import parse_wg_dump
from vpn_route_executor_sim import _durable_write, _load_journal, TransactionBlocked
from vpn_route_journal import prepare_transaction, snapshot_digest
from vpn_route_tx import reject_protected_host_routes, normalize_route


class CognitorTransactionBlocked(TransactionBlocked):
    pass


class AddOnlyBackend:
    """Restricted backend, operated only by root RPC and the shared coordinator."""

    def __init__(self, plan, expected_revision, protected_addresses, *, runner=subprocess.run,
                 state="/var/lib/omnissiah-network/vpn", config="/etc/wireguard/wg0.conf"):
        self.plan = plan
        self.expected_revision = expected_revision
        self.protected = tuple(protected_addresses)
        self.runner = runner
        self.state = Path(state)
        self.config = Path(config)
        self.target = plan["client_address"]
        self.key = plan["public_key"]
        self.backup = self.state / "mesh-backup.json"
        self.before = None
        self.preview = None
        self._protection = None

    def _command(self, args, *, input=None):
        result = self.runner(args, input=input, capture_output=True, text=True,
                             timeout=20, check=False)
        if result.returncode:
            raise CognitorTransactionBlocked("Kernel command failed: " + args[0])
        return result.stdout

    def snapshot(self):
        return LinuxReadOnlyPreflight(self.runner).snapshot()

    def _file(self):
        import stat
        if (self.config.is_symlink() or not self.config.is_file()
                or self.config.stat().st_uid != os.geteuid()
                or not stat.S_ISREG(self.config.stat().st_mode)
                or self.config.stat().st_mode & 0o077):
            raise CognitorTransactionBlocked("Unsafe managed WireGuard config")
        return self.config.read_text()

    def _effective_routes(self):
        observed = {}
        for ip in self.protected:
            rows = json.loads(self._command(["ip", "-j", "-4", "route", "get", ip]))
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                raise CognitorTransactionBlocked("Management route unavailable")
            route = rows[0]
            if not route.get("dev") or route.get("dev") == "wg0":
                raise CognitorTransactionBlocked("Protected route is not in underlay")
            observed[ip] = (route.get("dev"), route.get("gateway"),
                            route.get("prefsrc") or route.get("src"), route.get("table"))
        return observed

    def _check_owner(self):
        if (os.geteuid() != 0 or self.state.is_symlink() or not self.state.is_dir()
                or self.state.stat().st_uid != 0 or self.state.stat().st_mode & 0o077):
            raise CognitorTransactionBlocked("Root-owned state directory required")

    def stage_backup(self):
        self._check_owner()
        previous_config = self._file()
        peers, routes = self.snapshot()
        checked = preview_add(self.plan, expected_name=self.plan["node_name"],
                              current_peers=peers, routes=routes, persisted_config=previous_config,
                              protected_addresses=self.protected)
        if checked["revision"] != self.expected_revision:
            raise CognitorTransactionBlocked("Stale Cognitor preview; run again")
        desired = peers + [{"public_key": self.key, "allowed_ips": [self.target],
                            "keepalive": 0, "endpoint": ""}]
        reject_protected_host_routes(desired, peers, self.protected)
        expected = prepare_transaction(desired, peers, routes)
        if expected != self.preview or expected["delta"]["add"] != [self.target] or expected["delta"]["remove"]:
            raise CognitorTransactionBlocked("Unexpected route delta")
        self._protection = self._effective_routes()
        old_kernel = self._command(["wg", "showconf", "wg0"])
        if self.backup.is_symlink():
            raise CognitorTransactionBlocked("Unsafe backup symlink")
        if self.backup.exists():
            # The previous mesh transaction must be terminal and authenticated.
            previous = _load_journal(self.state / "mesh-transaction.json")
            if not isinstance(previous, dict) or previous.get("state") not in ("committed", "rolled_back"):
                raise CognitorTransactionBlocked("Unresolved previous backup")
            import stat
            st = self.backup.stat()
            if st.st_uid != os.geteuid() or not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
                raise CognitorTransactionBlocked("Unsafe previous backup")
            envelope = json.loads(self.backup.read_text())
            if (envelope.get("sha256") != _digest(envelope.get("data"))
                    or envelope["data"].get("snapshot_sha256") != previous.get("snapshot_sha256")):
                raise CognitorTransactionBlocked("Previous backup mismatches transaction")
            import uuid
            archive = self.state / ("mesh-backup-" + uuid.uuid4().hex + ".json")
            os.link(self.backup, archive, follow_symlinks=False)
            self.backup.unlink()
            dirfd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        data = {"wg_conf": old_kernel, "config": previous_config,
                "routes": routes, "peers": peers,
                "snapshot_sha256": self.preview["snapshot_sha256"]}
        _durable_write(self.state, "mesh-backup.json",
                       {"data": data, "sha256": _digest(data)})
        self.before = data

    def sync_wireguard(self, desired):
        if self.before is None:
            raise CognitorTransactionBlocked("Durable backup not staged")
        old = self.before["peers"]
        if len(desired) != len(old) + 1 or desired[:-1] != old:
            raise CognitorTransactionBlocked("Not a pure add-only peer change")
        self._command(["wg", "set", "wg0", "peer", self.key,
                       "allowed-ips", self.target])

    def route_step(self, step):
        if step != {"op": "add", "dst": self.target, "dev": "wg0"}:
            raise CognitorTransactionBlocked("Non-additive route step denied")
        self._command(_strict_route_operation(step))

    def verify(self, desired, preview):
        if preview != self.preview or desired[-1]["public_key"] != self.key:
            raise CognitorTransactionBlocked("Unexpected desired peer set")
        peers, routes = self.snapshot()
        expected = {p["public_key"]: (p["allowed_ips"], int(p["keepalive"])) for p in desired}
        actual = {p["public_key"]: (p["allowed_ips"], int(p["keepalive"])) for p in peers}
        if len(peers) != len(expected) or expected != actual:
            raise CognitorTransactionBlocked("Peer identity/settings changed")
        matches = [r for r in routes if normalize_route(r) is not None
                   and normalize_route(r)["dst"] == self.target]
        if len(matches) != 1 or matches[0].get("dev") != "wg0" or matches[0].get("gateway"):
            raise CognitorTransactionBlocked("Cognitor host route missing")
        if self._effective_routes() != self._protection:
            raise CognitorTransactionBlocked("Management routing changed")

    def persist_config(self, desired):
        if self.before is None:
            raise CognitorTransactionBlocked("Missing backup")
        if self._file() != self.before["config"]:
            raise CognitorTransactionBlocked("Persisted VPN file changed during apply")
        text = self.before["config"].rstrip("\n") + (
            "\n\n# Cognitor: " + self.plan["client_name"] +
            "\n[Peer]\nPublicKey = " + self.key +
            "\nAllowedIPs = " + self.target + "\n")
        _atomic_bytes(self.config, text.encode())
        from vpn_cognitor_preview import persisted_inventory
        _, pairs = persisted_inventory(self._file())
        if pairs.get(self.key) != [self.target]:
            raise CognitorTransactionBlocked("Persisted client peer not verified")

    def restore_wireguard(self):
        if self.before is None:
            raise CognitorTransactionBlocked("No backed-up kernel state")
        peers, _ = self.snapshot()
        match = [p for p in peers if p["public_key"] == self.key]
        if match:
            if (len(match) != 1 or match[0]["allowed_ips"] != [self.target]):
                raise CognitorTransactionBlocked("Client peer changed; manual recovery")
            self._command(["wg", "set", "wg0", "peer", self.key, "remove"])

    def restore_routes(self):
        if self.before is None:
            raise CognitorTransactionBlocked("No backed-up routes")
        _, routes = self.snapshot()
        matches = [normalize_route(r) for r in routes
                   if normalize_route(r) is not None
                   and normalize_route(r)["dst"] == self.target]
        if matches:
            if (len(matches) != 1 or matches[0]["dev"] != "wg0"
                    or matches[0]["gateway"] or matches[0]["metric"] not in (None, 0)):
                raise CognitorTransactionBlocked("Foreign route; manual recovery")
            self._command(["ip", "-4", "route", "delete",
                           self.target, "dev", "wg0", "table", "main"])

    def restore_config(self):
        if self.before is None:
            raise CognitorTransactionBlocked("Missing persisted backup")
        current = self._file()
        if current == self.before["config"]:
            return
        expected = self.before["config"].rstrip("\\n") + (
            "\\n\\n# Cognitor: " + self.plan["client_name"] +
            "\\n[Peer]\\nPublicKey = " + self.key +
            "\\nAllowedIPs = " + self.target + "\\n")
        if current != expected:
            raise CognitorTransactionBlocked("Unexpected persisted change; manual recovery")
        _atomic_bytes(self.config, self.before["config"].encode())

    def verify_restored(self):
        peers, routes = self.snapshot()
        if (snapshot_digest(peers, routes) != self.before["snapshot_sha256"]
                or self._file() != self.before["config"]
                or self._effective_routes() != self._protection):
            raise CognitorTransactionBlocked("Rollback incomplete; manual recovery")


def add_cognitor(plan, *, operation_id, expected_revision, protected_addresses,
                 runner=subprocess.run, state="/var/lib/omnissiah-network/vpn",
                 config="/etc/wireguard/wg0.conf"):
    """Compute one added peer and route, reuse durable coordinator lock+UUID."""
    validate_operation_id(operation_id)
    data = validate_plan(plan, plan.get("node_name") if isinstance(plan, dict) else None)
    if not isinstance(expected_revision, str) or len(expected_revision) != 64 or any(
            letter not in "0123456789abcdef" for letter in expected_revision):
        raise CognitorTransactionBlocked("Missing canonical preview revision")
    if not protected_addresses:
        raise CognitorTransactionBlocked("Protected control IP list required")
    backend = AddOnlyBackend(data, expected_revision, protected_addresses,
                             runner=runner, state=state, config=config)
    # No writes before the coordinator's exclusive lock.
    peers, routes = backend.snapshot()
    checked = preview_add(data, expected_name=data["node_name"],
                          current_peers=peers, routes=routes,
                          persisted_config=backend._file(),
                          protected_addresses=protected_addresses)
    if checked["revision"] != expected_revision:
        raise CognitorTransactionBlocked("Preview expired")
    desired = peers + [{"public_key": data["public_key"],
                        "allowed_ips": [data["client_address"]],
                        "endpoint": "", "keepalive": 0}]
    reject_protected_host_routes(desired, peers, protected_addresses)
    transaction = prepare_transaction(desired, peers, routes)
    if transaction["delta"]["add"] != [data["client_address"]] or transaction["delta"]["remove"]:
        raise CognitorTransactionBlocked("Non-additive plan")
    backend.preview = transaction
    result = run_offline_mesh_transaction(
        transaction, desired, backend, state, operation_id=operation_id)
    return {"state": result["state"], "client_address": data["client_address"],
            "existing_peers": len(peers), "operation_id": operation_id}
