"""Isolated Linux backend for the offline mesh coordinator.

NOT installed by Ansible, imported by privileged RPC, or exposed to HTTP.
Explicit mutation opt-in is required. Deploy ONLY after integration tests in
network namespaces and recovery/security review. Secrets stay in mode 0600
root-only files, never in the coordinator's public transaction journal.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from vpn_helper import render, validate_plan
from vpn_linux_preflight import LinuxReadOnlyPreflight, _strict_route_operation
from vpn_reconcile import parse_wg_dump
from vpn_route_tx import normalize_route, RouteConflict
from vpn_route_executor_sim import _durable_write, TransactionBlocked

MANAGED = "# Managed by Omnissiah VPN v2\n"


def _atomic_bytes(path, data):
    path = Path(path)
    if path.is_symlink():
        raise TransactionBlocked("Symlink destination refused")
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".wg-txn-", delete=False) as out:
            temp = Path(out.name)
            os.fchmod(out.fileno(), 0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        temp = None
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def _digest(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class IsolatedLinuxMeshBackend:
    """Concrete command backend, deliberately opt-in and unreachable from RPC.

    Pass a validated node plan containing node_name, address, listen_port, peers,
    and a canonical read-only route preview. The controller never supplies paths.
    """

    def __init__(self, node_plan, preview, *, state_dir="/var/lib/omnissiah-network/vpn",
                 config_path="/etc/wireguard/wg0.conf", runner=subprocess.run,
                 allow_mutations=False):
        self._name = node_plan.get("node_name")
        self._plan = validate_plan(node_plan, self._name)
        self._preview = preview
        self._state = Path(state_dir)
        self._config = Path(config_path)
        self._runner = runner
        self._enabled = allow_mutations
        self._backup = self._state / "mesh-backup.json"
        self._original = None
        if preview.get("iface") != "wg0" or preview.get("executable") is not False:
            raise TransactionBlocked("Only inert wg0 preview supported")

    def _require_enabled(self):
        if not self._enabled or os.geteuid() != 0:
            raise TransactionBlocked("Linux backend writes disabled")
        for path in (self._state, self._config.parent):
            if path.is_symlink() or not path.is_dir():
                raise TransactionBlocked("Unsafe state/config directory")
        if self._state.stat().st_uid != 0 or self._state.stat().st_mode & 0o077:
            raise TransactionBlocked("State directory must be root-owned 0700")

    def _command(self, argv, *, input=None):
        result = self._runner(argv, capture_output=True, text=True, timeout=20,
                              check=False, input=input)
        if result.returncode:
            # Never include command stdout/stderr: wg showconf can contain keys.
            raise TransactionBlocked("Kernel command failed: " + argv[0])
        return result.stdout

    def snapshot(self):
        # Use one runner to keep all observations mockable.
        return LinuxReadOnlyPreflight(self._runner).snapshot()

    def _config_bytes(self):
        if self._config.is_symlink() or not self._config.is_file():
            raise TransactionBlocked("Managed wg0.conf missing or unsafe")
        if self._config.stat().st_uid != 0 or not stat.S_ISREG(self._config.stat().st_mode):
            raise TransactionBlocked("wg0.conf must be root owned")
        data = self._config.read_bytes()
        if not data.startswith(MANAGED.encode()):
            raise TransactionBlocked("Refusing foreign WireGuard configuration")
        return data

    def _load_backup(self):
        if self._backup.is_symlink() or not self._backup.is_file():
            raise TransactionBlocked("Missing or unsafe WireGuard backup")
        st = self._backup.stat()
        if st.st_uid != 0 or st.st_mode & 0o077:
            raise TransactionBlocked("Backup must be root-owned 0600")
        record = json.loads(self._backup.read_text())
        body = record.get("data")
        if record.get("sha256") != _digest(body):
            raise TransactionBlocked("WireGuard backup integrity check failed")
        if body.get("snapshot_sha256") != self._preview["snapshot_sha256"]:
            raise TransactionBlocked("Backup does not match preview")
        return body

    def stage_backup(self):
        self._require_enabled()
        if self._backup.is_symlink():
            raise TransactionBlocked("Symlink backup refused")
        if self._backup.exists():
            # A prior completed transaction must not block the next planned
            # change. Keep its secret-containing backup, but never rotate an
            # unresolved transaction or a malformed/tampered backup.
            from vpn_route_executor_sim import _load_journal
            journal = _load_journal(self._state / "mesh-transaction.json")
            if not isinstance(journal, dict) or journal.get("state") not in ("committed", "rolled_back"):
                raise TransactionBlocked("Unresolved backup already present; manual recovery required")
            if self._backup.stat().st_uid != os.geteuid() or self._backup.stat().st_mode & 0o077:
                raise TransactionBlocked("Unsafe previous backup permissions")
            try:
                previous = json.loads(self._backup.read_text())
                if not isinstance(previous, dict) or previous.get("sha256") != _digest(previous.get("data")):
                    raise ValueError("Invalid backup digest")
                if previous["data"]["snapshot_sha256"] != journal.get("snapshot_sha256"):
                    raise ValueError("Backup and journal do not match")
            except (KeyError, TypeError, ValueError) as exc:
                raise TransactionBlocked("Previous backup is invalid; manual recovery required") from exc
            # Preserve history with restrictive permissions, using O_EXCL to
            # avoid collisions and symlink targets. No backup bytes in logs.
            import uuid
            archive = self._state / ("mesh-backup-" + uuid.uuid4().hex + ".json")
            os.link(self._backup, archive, follow_symlinks=False)
            self._backup.unlink()
            directory_fd = os.open(self._state, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        old_file = self._config_bytes().decode()
        previous_wg = self._command(["wg", "showconf", "wg0"])
        peers, routes = self.snapshot()
        from vpn_route_journal import assert_snapshot_unchanged
        assert_snapshot_unchanged(self._preview, peers, routes)
        data = {"wg_conf": previous_wg, "config": old_file,
                "routes": routes, "peers": peers,
                "snapshot_sha256": self._preview["snapshot_sha256"]}
        _durable_write(self._state, self._backup.name,
                       {"data": data, "sha256": _digest(data)})
        self._original = data

    def _prepared_config(self, desired):
        if desired != self._plan["peers"]:
            raise TransactionBlocked("Desired peers differ from validated node plan")
        secret = self._state / "private.key"
        if secret.is_symlink() or not secret.is_file():
            raise TransactionBlocked("Private key missing")
        st = secret.stat()
        if st.st_uid != 0 or st.st_mode & 0o077:
            raise TransactionBlocked("Private key has unsafe permissions")
        return render(self._plan, secret.read_text().strip())

    def sync_wireguard(self, desired):
        self._require_enabled()
        full = self._prepared_config(desired)
        # wg-quick requires the basename to be a valid interface, i.e. wg0.conf.
        # Keep the fixed filename in a private temporary directory so that we
        # never overwrite the host's persisted WireGuard configuration.
        with tempfile.TemporaryDirectory(dir=self._state, prefix="wg-stage-") as directory:
            staged = Path(directory) / "wg0.conf"
            fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as out:
                out.write(full)
                out.flush()
                os.fsync(out.fileno())
            stripped = self._command(["wg-quick", "strip", str(staged)])
        self._command(["wg", "syncconf", "wg0", "/dev/stdin"], input=stripped)

    def route_step(self, step):
        self._require_enabled()
        if step not in self._preview["steps"]:
            raise TransactionBlocked("Route operation absent from approved preview")
        argv = _strict_route_operation(step)
        self._command(argv)

    def verify(self, desired, preview):
        if preview != self._preview or desired != self._plan["peers"]:
            raise TransactionBlocked("Unexpected verification target")
        peers, routes = self.snapshot()
        actual = {p["public_key"]: p for p in peers}
        expected = {p["public_key"]: p for p in desired}
        if len(actual) != len(peers) or len(expected) != len(desired) or set(actual) != set(expected):
            raise TransactionBlocked("WireGuard peer identities differ")
        for key, want in expected.items():
            got = actual[key]
            if sorted(got["allowed_ips"]) != sorted(want["allowed_ips"]) or int(got["keepalive"]) != int(want["keepalive"]):
                raise TransactionBlocked("WireGuard peer settings differ")
        records = [normalize_route(r) for r in routes]
        destinations = set(self._preview["delta"]["add"] + self._preview["delta"]["remove"] + self._preview["delta"]["unchanged"])
        wanted = {entry for p in desired for entry in p["allowed_ips"]}
        for dst in destinations:
            matches = [r for r in records if r is not None and r["dst"] == dst]
            if dst in wanted:
                if len(matches) != 1 or matches[0]["dev"] != "wg0" or matches[0]["gateway"]:
                    raise TransactionBlocked("Expected wg0 route missing or changed")
            elif matches:
                raise TransactionBlocked("Removed route is still installed")

    def persist_config(self, desired):
        self._require_enabled()
        self._load_backup()
        _atomic_bytes(self._config, self._prepared_config(desired).encode())

    def restore_wireguard(self):
        self._require_enabled()
        record = self._load_backup()
        self._command(["wg", "syncconf", "wg0", "/dev/stdin"], input=record["wg_conf"])

    def restore_routes(self):
        self._require_enabled()
        old = self._load_backup()
        changed = set(self._preview["delta"]["add"] + self._preview["delta"]["remove"])
        initial = {r["dst"]: r for r in (normalize_route(item) for item in old["routes"])
                   if r is not None and r["dst"] in changed}
        _, current = self.snapshot()
        records = [r for r in (normalize_route(item) for item in current)
                   if r is not None and r["dst"] in changed]
        present = {}
        for route in records:
            if route["dst"] in present or route["dev"] != "wg0" or route["gateway"] or route["metric"] not in (None, 0):
                raise TransactionBlocked("Foreign/ambiguous route during rollback")
            present[route["dst"]] = route
        for dst in sorted(changed):
            if dst in initial and dst not in present:
                self._command(_strict_route_operation({"op": "add", "dst": dst, "dev": "wg0"}))
            elif dst not in initial and dst in present:
                self._command(_strict_route_operation({"op": "delete", "dst": dst, "dev": "wg0"}))

    def restore_config(self):
        self._require_enabled()
        old = self._load_backup()
        _atomic_bytes(self._config, old["config"].encode())

    def verify_restored(self):
        old = self._load_backup()
        from vpn_route_journal import assert_snapshot_unchanged
        peers, routes = self.snapshot()
        assert_snapshot_unchanged(self._preview, peers, routes)
        if self._config_bytes() != old["config"].encode():
            raise TransactionBlocked("Persisted WireGuard configuration not restored")
