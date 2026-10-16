"""Privileged integration tests for a REAL wg0 isolated inside a Linux netns.

Run only in a disposable GitHub Actions runner as root. Nothing in this test is
installed by Ansible and no host wg0, routes, or VPN config are touched.

This suite deliberately does not simulate host reboot recovery: an interrupted
journal blocks further operations pending explicit manual recovery.
"""
import copy
import json
from ipaddress import ip_network
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy"))

from vpn_helper import render
from vpn_linux_backend import IsolatedLinuxMeshBackend
from vpn_mesh_transaction import MeshTransactionBlocked, run_offline_mesh_transaction

WG0_ADDRESS = "10.77.0.2/32"
OLD_ROUTE = "10.77.0.3/32"
NEW_ROUTE = "10.77.0.4/32"


def command(*argv, input=None):
    return subprocess.run(list(argv), capture_output=True, text=True,
                          check=True, timeout=20, input=input)


def keypair():
    private = command("wg", "genkey").stdout.strip()
    public = command("wg", "pubkey", input=private + "\n").stdout.strip()
    return private, public


class IsolatedWireGuardIntegration(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.fail("Requires root in a disposable Linux CI runner")
        self.root = tempfile.TemporaryDirectory(prefix="omni-netns-")
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)
        # Keep interface names and namespaces unambiguous and disposable.
        self.netns = "omni-it-" + uuid.uuid4().hex[:8]
        command("ip", "netns", "add", self.netns)
        self.addCleanup(self._delete_namespace)
        command("ip", "-n", self.netns, "link", "add", "wg0", "type", "wireguard")
        command("ip", "-n", self.netns, "address", "add", WG0_ADDRESS, "dev", "wg0")
        command("ip", "-n", self.netns, "link", "set", "wg0", "up")
        private, _ = keypair()
        _, old_public = keypair()
        _, new_public = keypair()
        self.old_public, self.new_public = old_public, new_public
        self.node = {
            "node_name": "magos01",
            "address": WG0_ADDRESS,
            "listen_port": 51820,
            "peers": [{
                "public_key": old_public,
                "endpoint": "192.0.2.3:51820",
                "allowed_ips": [OLD_ROUTE],
                "keepalive": 25,
            }]
        }
        self.desired = copy.deepcopy(self.node)
        self.desired["peers"].append({
            "public_key": new_public,
            "endpoint": "192.0.2.4:51820",
            "allowed_ips": [NEW_ROUTE],
            "keepalive": 25,
        })
        self.state = self.path / "state"
        self.state.mkdir(mode=0o700)
        (self.state / "private.key").write_text(private + "\n")
        (self.state / "private.key").chmod(0o600)
        self.config_dir = self.path / "etc"
        self.config_dir.mkdir()
        self.config = self.config_dir / "wg0.conf"
        self.config.write_text(render(self.node, private))
        self.config.chmod(0o600)
        command("ip", "netns", "exec", self.netns, "wg", "set", "wg0",
                "private-key", str(self.state / "private.key"),
                "listen-port", "51820", "peer", old_public,
                "endpoint", "192.0.2.3:51820",
                "allowed-ips", OLD_ROUTE, "persistent-keepalive", "25")
        command("ip", "-n", self.netns, "-4", "route", "add", OLD_ROUTE,
                "dev", "wg0", "table", "main")
        self.backend = IsolatedLinuxMeshBackend(
            self.desired, {"iface": "wg0", "executable": False},
            state_dir=self.state, config_path=self.config,
            runner=self._runner, allow_mutations=True)
        # Snapshot and plan use the live network namespace, never fake results.
        from vpn_route_journal import prepare_transaction
        peers, routes = self.backend.snapshot()
        self.plan = prepare_transaction(self.desired["peers"], peers, routes)
        self.backend._preview = self.plan
        self.before_wg = self._runner(["wg", "showconf", "wg0"],
                                      capture_output=True, text=True,
                                      timeout=20, check=False).stdout
        self.before_config = self.config.read_bytes()

    def _runner(self, argv, **kwargs):
        return subprocess.run(["ip", "netns", "exec", self.netns] + list(argv), **kwargs)

    def _delete_namespace(self):
        subprocess.run(["ip", "netns", "del", self.netns],
                       capture_output=True, text=True, timeout=20, check=False)

    def _route_set(self):
        _, routes = self.backend.snapshot()
        return {str(ip_network(r["dst"], strict=False)) for r in routes if r.get("dev") == "wg0"}

    def _wg_keys(self):
        peers, _ = self.backend.snapshot()
        return {p["public_key"] for p in peers}

    def test_success_persists_real_kernel_and_disk_state(self):
        result = run_offline_mesh_transaction(
            self.plan, self.desired["peers"], self.backend, self.state)
        self.assertEqual(result["state"], "committed")
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertIn(self.new_public, self.config.read_text())
        backup = self.state / "mesh-backup.json"
        self.assertEqual(backup.stat().st_mode & 0o077, 0)
        journal = json.loads((self.state / "mesh-transaction.json").read_text())
        self.assertEqual(journal["state"], "committed")
        self.assertNotIn("PRIVATE", str(journal))
        self.assertNotIn("wg_conf", journal)

    def test_route_failure_after_real_kernel_mutation_restores_everything(self):
        original_route_step = self.backend.route_step

        def failing_step(step):
            original_route_step(step)
            raise RuntimeError("Injected error after ip route add")

        self.backend.route_step = failing_step
        with self.assertRaisesRegex(RuntimeError, "Injected"):
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state)
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)
        self.assertEqual(self._runner(["wg", "showconf", "wg0"],
                        capture_output=True, text=True, timeout=20,
                        check=False).stdout, self.before_wg)
        journal = json.loads((self.state / "mesh-transaction.json").read_text())
        self.assertEqual(journal["state"], "rolled_back")

    def test_interrupted_journal_blocks_real_route_changes(self):
        (self.state / "mesh-transaction.json").write_text(
            json.dumps({"schema_version": 1, "state": "applying", "phase": "route"}))
        with self.assertRaisesRegex(MeshTransactionBlocked, "Unresolved"):
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state)
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertFalse((self.state / "mesh-backup.json").exists())


    def test_crashed_prepared_journal_recovers_without_changing_live_wg(self):
        """Recovery after a durable backup but before first kernel write."""
        from vpn_route_executor_sim import _durable_write
        from vpn_prepared_recovery import reconcile_prepared
        # The coordinator creates the exclusive lock before staging a backup.
        lock_path = self.state / "mesh-transaction.lock"
        lock_path.touch(mode=0o600)
        lock_path.chmod(0o600)
        self.backend.stage_backup()
        _durable_write(self.state, "mesh-transaction.json", {
            "schema_version": 1, "state": "prepared", "phase": "none",
            "snapshot_sha256": self.plan["snapshot_sha256"], "route_ops": 0})
        result = reconcile_prepared(self.state, self.backend)
        self.assertEqual(result, {"state": "rolled_back", "changed": True})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)
        self.assertEqual(self._runner(
            ["wg", "showconf", "wg0"], capture_output=True, text=True,
            timeout=20, check=False).stdout, self.before_wg)

    def test_prepared_journal_does_not_recover_after_foreign_wireguard_change(self):
        """Refuse if a journal claims prepared but kernel peers have drifted."""
        from vpn_route_executor_sim import _durable_write
        from vpn_prepared_recovery import reconcile_prepared, PreparedRecoveryBlocked
        lock_path = self.state / "mesh-transaction.lock"
        lock_path.touch(mode=0o600)
        lock_path.chmod(0o600)
        self.backend.stage_backup()
        _durable_write(self.state, "mesh-transaction.json", {
            "schema_version": 1, "state": "prepared", "phase": "none",
            "snapshot_sha256": self.plan["snapshot_sha256"], "route_ops": 0})
        # Simulate a foreign process modifying the running interface.
        self.backend.sync_wireguard(self.desired["peers"])
        with self.assertRaisesRegex(PreparedRecoveryBlocked, "Original state changed"):
            reconcile_prepared(self.state, self.backend)
        self.assertEqual(json.loads(
            (self.state / "mesh-transaction.json").read_text())["state"], "prepared")
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})

    def test_sequential_real_peer_additions_preserve_existing_mesh(self):
        """Apply a third peer, then a fourth without disrupting previous routes."""
        first = run_offline_mesh_transaction(
            self.plan, self.desired["peers"], self.backend, self.state)
        self.assertEqual(first["state"], "committed")
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        _, third_key = keypair()
        extra = {
            "public_key": third_key,
            "endpoint": "192.0.2.5:51820",
            "allowed_ips": ["10.77.0.5/32"],
            "keepalive": 25,
        }
        next_desired = copy.deepcopy(self.desired)
        next_desired["peers"].append(extra)
        from vpn_route_journal import prepare_transaction
        previous_peers, previous_routes = self.backend.snapshot()
        next_plan = prepare_transaction(next_desired["peers"], previous_peers, previous_routes)
        second_backend = IsolatedLinuxMeshBackend(
            next_desired, next_plan,
            state_dir=self.state, config_path=self.config,
            runner=self._runner, allow_mutations=True)
        second = run_offline_mesh_transaction(
            next_plan, next_desired["peers"], second_backend, self.state)
        self.assertEqual(second["state"], "committed")
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE, "10.77.0.5/32"})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public, third_key})
        self.assertEqual(len(list(self.state.glob("mesh-backup-*.json"))), 1)

    def test_second_route_failure_rolls_back_only_second_change(self):
        """An error during a later expansion must keep all earlier committed peers."""
        run_offline_mesh_transaction(self.plan, self.desired["peers"],
                                     self.backend, self.state)
        before_second = self._runner(
            ["wg", "showconf", "wg0"], capture_output=True, text=True,
            timeout=20, check=False).stdout
        before_file = self.config.read_bytes()
        _, third_key = keypair()
        next_desired = copy.deepcopy(self.desired)
        next_desired["peers"].append({
            "public_key": third_key,
            "endpoint": "192.0.2.5:51820",
            "allowed_ips": ["10.77.0.5/32"],
            "keepalive": 25,
        })
        from vpn_route_journal import prepare_transaction
        peers, routes = self.backend.snapshot()
        next_plan = prepare_transaction(next_desired["peers"], peers, routes)
        second_backend = IsolatedLinuxMeshBackend(
            next_desired, next_plan, state_dir=self.state,
            config_path=self.config, runner=self._runner,
            allow_mutations=True)
        real_step = second_backend.route_step

        def fail_after_route(step):
            real_step(step)
            raise RuntimeError("Injected second-stage route failure")

        second_backend.route_step = fail_after_route
        with self.assertRaisesRegex(RuntimeError, "Injected second-stage"):
            run_offline_mesh_transaction(
                next_plan, next_desired["peers"], second_backend, self.state)
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertEqual(self.config.read_bytes(), before_file)
        self.assertEqual(self._runner(
            ["wg", "showconf", "wg0"], capture_output=True, text=True,
            timeout=20, check=False).stdout, before_second)
        self.assertEqual(json.loads(
            (self.state / "mesh-transaction.json").read_text())["state"], "rolled_back")


if __name__ == "__main__":
    unittest.main(verbosity=2)
