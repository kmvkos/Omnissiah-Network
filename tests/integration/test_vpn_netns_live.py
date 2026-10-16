"""Privileged integration tests for a REAL wg0 isolated inside a Linux netns.

Run only in a disposable GitHub Actions runner as root. Nothing in this test is
installed by Ansible and no host wg0, routes, or VPN config are touched.

Includes real SIGKILL of a forked transaction/recovery process at selected
journaling boundaries, not a simulated exception or a full VM power loss.
"""
import copy
import json
from ipaddress import ip_network
import os
import signal
import time
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
from vpn_route_executor_sim import TransactionBlocked

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
        # Explicit underlay path for management/peer endpoint safety checks.
        command("ip", "-n", self.netns, "link", "set", "lo", "up")
        command("ip", "-n", self.netns, "-4", "route", "add",
                "192.0.2.0/24", "dev", "lo")
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

    def _crash_route_stage(self, *, route_present):
        """Reproduce real on-disk state before a write-ahead route step."""
        from vpn_route_executor_sim import _durable_write
        lock = self.state / "mesh-transaction.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        self.backend.stage_backup()
        self.backend.sync_wireguard(self.desired["peers"])
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        step = self.plan["steps"][0]
        _durable_write(self.state, "mesh-transaction.json", {
            "schema_version": 1, "state": "applying", "phase": "route",
            "snapshot_sha256": self.plan["snapshot_sha256"],
            "route_ops": 0,
            "pending_route": step,
            "recovery": {"desired_peers": self.desired["peers"]},
        })
        if route_present:
            self.backend.route_step(step)

    def test_partial_add_recovery_after_wg_sync_before_route_write(self):
        """Remove only the new peer; keep original peer and route."""
        from vpn_add_only_recovery import reconcile_add_only
        self._crash_route_stage(route_present=False)
        result = reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(result, {"state": "rolled_back", "changed": True})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)
        self.assertEqual(json.loads(
            (self.state / "mesh-transaction.json").read_text())["state"], "rolled_back")

    def test_partial_add_recovery_after_route_written_but_before_journal_update(self):
        """Delete only the new /32 and peer after validating both."""
        from vpn_add_only_recovery import reconcile_add_only
        self._crash_route_stage(route_present=True)
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        result = reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(result["state"], "rolled_back")
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_partial_add_recovery_rejects_foreign_peer_before_any_write(self):
        """A different peer attached after crash must never be removed."""
        from vpn_add_only_recovery import reconcile_add_only, AddOnlyRecoveryBlocked
        self._crash_route_stage(route_present=True)
        _, foreign = keypair()
        command("ip", "netns", "exec", self.netns, "wg", "set", "wg0",
                "peer", foreign, "allowed-ips", "10.77.0.99/32")
        with self.assertRaises(AddOnlyRecoveryBlocked):
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertIn(foreign, self._wg_keys())
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})

    def test_partial_add_recovery_rejects_foreign_route(self):
        """Never roll back a route with a foreign interface or metadata."""
        from vpn_add_only_recovery import reconcile_add_only, AddOnlyRecoveryBlocked
        self._crash_route_stage(route_present=False)
        command("ip", "-n", self.netns, "-4", "route", "add", NEW_ROUTE, "dev", "lo")
        with self.assertRaisesRegex(AddOnlyRecoveryBlocked, "Foreign route"):
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})

    def test_partial_add_recovery_resume_after_terminated_route_cleanup(self):
        """A second invocation finishes when route was deleted before crash."""
        from vpn_route_executor_sim import _durable_write
        from vpn_add_only_recovery import reconcile_add_only
        self._crash_route_stage(route_present=True)
        self._runner(["ip", "-4", "route", "delete",
                      NEW_ROUTE, "dev", "wg0", "table", "main"],
                     capture_output=True, text=True, timeout=20, check=True)
        record = json.loads((self.state / "mesh-transaction.json").read_text())
        record.update(state="rolling_back", phase="add_only_recovery")
        _durable_write(self.state, "mesh-transaction.json", record)
        self.assertEqual(reconcile_add_only(
            self.state, self.backend, ["10.77.0.2"])["state"], "rolled_back")
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})

    def test_partial_add_recovery_rejects_modified_original_peer(self):
        """Never overwrite or remove a peer that existed before the failure."""
        from vpn_add_only_recovery import reconcile_add_only, AddOnlyRecoveryBlocked
        self._crash_route_stage(route_present=True)
        command("ip", "netns", "exec", self.netns, "wg", "set", "wg0",
                "peer", self.old_public, "persistent-keepalive", "0")
        with self.assertRaises(AddOnlyRecoveryBlocked):
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})

    def test_partial_add_recovery_rejects_legacy_journal_without_descriptor(self):
        """Previously committed journal format is deliberately not recoverable."""
        from vpn_add_only_recovery import reconcile_add_only, AddOnlyRecoveryBlocked
        self._crash_route_stage(route_present=True)
        from vpn_route_executor_sim import _durable_write
        record = json.loads((self.state / "mesh-transaction.json").read_text())
        record.pop("recovery")
        _durable_write(self.state, "mesh-transaction.json", record)
        with self.assertRaisesRegex(AddOnlyRecoveryBlocked, "descriptor"):
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})

    def _kill_forked_worker(self, action):
        """Kill only a disposable forked worker, never the CI test runner."""
        pid = os.fork()
        if pid == 0:
            try:
                action()
            except BaseException:
                os._exit(84)
            os._exit(85)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed:
                self.assertTrue(os.WIFSIGNALED(status),
                                "Worker exited without injected SIGKILL: " + str(status))
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                return
            time.sleep(0.02)
        # A stuck process must not hang or poison the CI runner.
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        self.fail("Worker timed out instead of hitting the injected kill point")

    def _run_transaction_with_sigkill(self, boundary, *, operation_id=None):
        """Real coordinator + real commands; kill after a precise journaled step."""
        lockfile = self.state / "mesh-transaction.lock"
        lockfile.touch(mode=0o600)
        lockfile.chmod(0o600)

        def work():
            if boundary == "after_wg_sync":
                original = self.backend.sync_wireguard

                def kill_after_sync(desired):
                    original(desired)
                    os.kill(os.getpid(), signal.SIGKILL)
                self.backend.sync_wireguard = kill_after_sync
            else:
                original = self.backend.route_step

                def kill_route_step(step):
                    if boundary == "before_route_write":
                        os.kill(os.getpid(), signal.SIGKILL)
                    original(step)
                    if boundary == "after_route_write":
                        os.kill(os.getpid(), signal.SIGKILL)
                self.backend.route_step = kill_route_step
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state,
                operation_id=operation_id)

        self._kill_forked_worker(work)
        return json.loads((self.state / "mesh-transaction.json").read_text())

    def test_sigkill_after_backup_before_journal_detects_orphan_and_blocks(self):
        """A durable backup with no journal is not an idle VPN."""
        from vpn_transaction_health import inspect_transaction
        from vpn_route_executor_sim import TransactionBlocked
        lock = self.state / "mesh-transaction.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)

        def work():
            original = self.backend.stage_backup

            def kill_after_backup():
                original()
                os.kill(os.getpid(), signal.SIGKILL)
            self.backend.stage_backup = kill_after_backup
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state)

        self._kill_forked_worker(work)
        self.assertTrue((self.state / "mesh-backup.json").exists())
        self.assertFalse((self.state / "mesh-transaction.json").exists())
        state = inspect_transaction(self.state)
        self.assertEqual((state["state"], state["reason"]),
                         ("recovery_required", "orphan_backup"))
        self.assertTrue(state["needs_attention"])
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        with self.assertRaisesRegex(TransactionBlocked, "Unresolved backup"):
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state)

    def test_sigkill_after_prepared_journal_recovers_without_network_changes(self):
        """Actual process is killed after durable prepared journal, before WG sync."""
        import vpn_mesh_transaction
        from vpn_prepared_recovery import reconcile_prepared
        from vpn_operation_fence import status
        operation_id = str(uuid.uuid4())
        lock = self.state / "mesh-transaction.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)

        def work():
            original = vpn_mesh_transaction._journal

            def kill_after_prepared(folder, record):
                original(folder, record)
                if record.get("state") == "prepared":
                    os.kill(os.getpid(), signal.SIGKILL)
            vpn_mesh_transaction._journal = kill_after_prepared
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state,
                operation_id=operation_id)

        self._kill_forked_worker(work)
        saved = json.loads((self.state / "mesh-transaction.json").read_text())
        self.assertEqual((saved["state"], saved["phase"]), ("prepared", "none"))
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(status(self.state, operation_id)["state"], "reserved")
        self.assertEqual(reconcile_prepared(
            self.state, self.backend), {"state": "rolled_back", "changed": True})
        self.assertEqual(status(self.state, operation_id)["state"], "rolled_back")
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_sigkill_and_add_only_rollback_closes_operation_uuid(self):
        """Recovery resolves durable admission only after original state verified."""
        from vpn_add_only_recovery import reconcile_add_only
        from vpn_operation_fence import status
        operation_id = str(uuid.uuid4())
        record = self._run_transaction_with_sigkill(
            "after_route_write", operation_id=operation_id)
        self.assertEqual(record["operation_id"], operation_id)
        self.assertEqual(status(self.state, operation_id)["state"], "reserved")
        self.assertEqual(reconcile_add_only(
            self.state, self.backend, ["10.77.0.2"])["state"], "rolled_back")
        self.assertEqual(status(self.state, operation_id)["state"], "rolled_back")
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_sigkill_after_wg_sync_fails_closed_at_nonrecoverable_phase(self):
        """Real kernel new peer exists, but old route/peer must remain untouched."""
        from vpn_add_only_recovery import reconcile_add_only, AddOnlyRecoveryBlocked
        record = self._run_transaction_with_sigkill("after_wg_sync")
        self.assertEqual((record["state"], record["phase"]), ("applying", "wg_sync"))
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        with self.assertRaisesRegex(AddOnlyRecoveryBlocked, "not recoverable"):
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_sigkill_before_first_route_write_then_recover(self):
        """A fresh process validates and removes the new peer after SIGKILL."""
        from vpn_add_only_recovery import reconcile_add_only
        record = self._run_transaction_with_sigkill("before_route_write")
        self.assertEqual((record["state"], record["phase"]), ("applying", "route"))
        self.assertEqual(record["route_ops"], 0)
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        result = reconcile_add_only(self.state, self.backend, ["10.77.0.2"])
        self.assertEqual(result, {"state": "rolled_back", "changed": True})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_sigkill_after_route_written_before_journal_ack_then_recover(self):
        """A route command can succeed immediately before the worker dies."""
        from vpn_add_only_recovery import reconcile_add_only
        record = self._run_transaction_with_sigkill("after_route_write")
        self.assertEqual((record["state"], record["phase"]), ("applying", "route"))
        self.assertEqual(record["route_ops"], 0)
        self.assertEqual(record["pending_route"], self.plan["steps"][0])
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        self.assertEqual(reconcile_add_only(
            self.state, self.backend, ["10.77.0.2"])["state"], "rolled_back")
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_sigkill_during_recovery_then_resume_without_old_peer_damage(self):
        """Kill cleanup after actual route delete, recover again under same lock."""
        from vpn_add_only_recovery import reconcile_add_only
        self._run_transaction_with_sigkill("after_route_write")

        def work():
            original = self.backend._command

            def kill_after_delete(argv, **kwargs):
                result = original(argv, **kwargs)
                if argv[:4] == ["ip", "-4", "route", "delete"]:
                    os.kill(os.getpid(), signal.SIGKILL)
                return result
            self.backend._command = kill_after_delete
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])

        self._kill_forked_worker(work)
        record = json.loads((self.state / "mesh-transaction.json").read_text())
        self.assertEqual((record["state"], record["phase"]),
                         ("rolling_back", "add_only_recovery"))
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})
        self.assertEqual(reconcile_add_only(
            self.state, self.backend, ["10.77.0.2"])["state"], "rolled_back")
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_sigkill_after_final_peer_delete_recovery_is_idempotent(self):
        """Recovery can finish if process dies after network is already restored."""
        from vpn_add_only_recovery import reconcile_add_only
        self._run_transaction_with_sigkill("after_route_write")

        def work():
            original = self.backend._command

            def kill_after_peer_delete(argv, **kwargs):
                result = original(argv, **kwargs)
                if argv[:4] == ["wg", "set", "wg0", "peer"] and argv[-1] == "remove":
                    os.kill(os.getpid(), signal.SIGKILL)
                return result
            self.backend._command = kill_after_peer_delete
            reconcile_add_only(self.state, self.backend, ["10.77.0.2"])

        self._kill_forked_worker(work)
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(reconcile_add_only(
            self.state, self.backend, ["10.77.0.2"])["state"], "rolled_back")
        self.assertEqual(self._wg_keys(), {self.old_public})
        self.assertEqual(self.config.read_bytes(), self.before_config)

    def test_durable_uuid_blocks_reuse_for_a_new_topology_after_first_commit(self):
        """At-most-once fence survives a successful real WireGuard update."""
        from vpn_operation_fence import status
        first_id, next_id = str(uuid.uuid4()), str(uuid.uuid4())
        result = run_offline_mesh_transaction(
            self.plan, self.desired["peers"], self.backend, self.state,
            operation_id=first_id)
        self.assertEqual(result["state"], "committed")
        self.assertEqual(status(self.state, first_id)["state"], "committed")

        _, another_key = keypair()
        extended = copy.deepcopy(self.desired)
        extended["peers"].append({
            "public_key": another_key,
            "endpoint": "192.0.2.5:51820",
            "allowed_ips": ["10.77.0.5/32"],
            "keepalive": 25,
        })
        from vpn_route_journal import prepare_transaction
        peers, routes = self.backend.snapshot()
        delta = prepare_transaction(extended["peers"], peers, routes)
        next_backend = IsolatedLinuxMeshBackend(
            extended, delta, state_dir=self.state,
            config_path=self.config, runner=self._runner,
            allow_mutations=True)
        with self.assertRaisesRegex(TransactionBlocked, "already used"):
            run_offline_mesh_transaction(
                delta, extended["peers"], next_backend, self.state,
                operation_id=first_id)
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public})

        updated = run_offline_mesh_transaction(
            delta, extended["peers"], next_backend, self.state,
            operation_id=next_id)
        self.assertEqual(updated["state"], "committed")
        self.assertEqual(status(self.state, next_id)["state"], "committed")
        self.assertEqual(self._route_set(), {OLD_ROUTE, NEW_ROUTE, "10.77.0.5/32"})
        self.assertEqual(self._wg_keys(), {self.old_public, self.new_public, another_key})

    def test_sigkill_after_operation_reservation_prevents_any_new_apply(self):
        """Even before backup/journal, an unknown accepted request blocks a retry."""
        from vpn_operation_fence import status
        from vpn_transaction_health import inspect_transaction
        op_id, next_id = str(uuid.uuid4()), str(uuid.uuid4())
        lock = self.state / "mesh-transaction.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)

        def work():
            real_backup = self.backend.stage_backup

            def kill_after_backup():
                real_backup()
                os.kill(os.getpid(), signal.SIGKILL)
            self.backend.stage_backup = kill_after_backup
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state,
                operation_id=op_id)

        self._kill_forked_worker(work)
        self.assertEqual(status(self.state, op_id)["state"], "reserved")
        self.assertEqual(inspect_transaction(self.state)["reason"], "orphan_operation")
        self.assertEqual(self._route_set(), {OLD_ROUTE})
        self.assertEqual(self._wg_keys(), {self.old_public})
        with self.assertRaisesRegex(TransactionBlocked, "outcome unknown"):
            run_offline_mesh_transaction(
                self.plan, self.desired["peers"], self.backend, self.state,
                operation_id=next_id)
        self.assertEqual(status(self.state, next_id)["state"], "unknown")

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
