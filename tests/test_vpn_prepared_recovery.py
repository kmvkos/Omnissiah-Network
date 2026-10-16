"""Conservative recovery tests: no WireGuard writes and no secret disclosures."""
import fcntl
import importlib.util
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from vpn_route_journal import snapshot_digest

spec = importlib.util.spec_from_file_location(
    "vpn_prepared_recovery", ROOT / "deploy/vpn_prepared_recovery.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

PEERS = [{
    "public_key": "fake-key",
    "allowed_ips": ["10.77.0.3/32"],
    "keepalive": 25,
}]
ROUTES = [{"dst": "10.77.0.3", "dev": "wg0", "scope": "link"}]
ORIGINAL = "# Managed by Omnissiah VPN v2\nprivate-test-secret\n"


class Backend:
    def __init__(self):
        self.peers = list(PEERS)
        self.routes = list(ROUTES)
        self.config = ORIGINAL.encode()
        self.writes = 0

    def snapshot(self):
        return self.peers, self.routes

    def _config_bytes(self):
        return self.config


def setup_journal(tmp_path, state="prepared", phase="none"):
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    folder.chmod(0o700)
    lock = folder / "mesh-transaction.lock"
    lock.touch(mode=0o600)
    lock.chmod(0o600)
    snapshot = snapshot_digest(PEERS, ROUTES)
    saved = {
        "wg_conf": "private-test-secret",
        "config": ORIGINAL,
        "peers": PEERS,
        "routes": ROUTES,
        "snapshot_sha256": snapshot,
    }
    packed = {
        "data": saved,
        "sha256": hashlib.sha256(json.dumps(saved, sort_keys=True,
             separators=(",", ":")).encode()).hexdigest(),
    }
    backup = folder / "mesh-backup.json"
    backup.write_text(json.dumps(packed))
    backup.chmod(0o600)
    journal = folder / "mesh-transaction.json"
    journal.write_text(json.dumps({
        "schema_version": 1, "state": state, "phase": phase,
        "snapshot_sha256": snapshot, "route_ops": 0
    }))
    journal.chmod(0o600)
    return folder


def test_prepared_unmodified_is_marked_rolled_back_without_touching_network(tmp_path):
    folder = setup_journal(tmp_path)
    backend = Backend()
    before = (folder / "mesh-backup.json").read_bytes()
    result = mod.reconcile_prepared(folder, backend)
    assert result == {"state": "rolled_back", "changed": True}
    assert json.loads((folder / "mesh-transaction.json").read_text())["state"] == "rolled_back"
    assert (folder / "mesh-backup.json").read_bytes() == before
    assert backend.writes == 0
    assert "private" not in json.dumps(result)
    assert mod.reconcile_prepared(folder, backend) == {"state": "rolled_back", "changed": False}


@pytest.mark.parametrize("state,phase", [
    ("applying", "wg_sync"), ("rolling_back", "restore"),
    ("recovery_required", "manual"), ("prepared", "route"),
])
def test_recovery_refuses_possible_mutations(tmp_path, state, phase):
    folder = setup_journal(tmp_path, state, phase)
    before = (folder / "mesh-transaction.json").read_bytes()
    with pytest.raises(mod.PreparedRecoveryBlocked, match="operator review"):
        mod.reconcile_prepared(folder, Backend())
    assert (folder / "mesh-transaction.json").read_bytes() == before


def test_modified_kernel_peers_are_refused(tmp_path):
    folder = setup_journal(tmp_path)
    backend = Backend()
    backend.peers = []
    with pytest.raises(mod.PreparedRecoveryBlocked, match="Original state changed"):
        mod.reconcile_prepared(folder, backend)


def test_modified_disk_config_is_refused(tmp_path):
    folder = setup_journal(tmp_path)
    backend = Backend()
    backend.config = b"foreign change"
    with pytest.raises(mod.PreparedRecoveryBlocked, match="Original state changed"):
        mod.reconcile_prepared(folder, backend)


def test_tampered_backup_digest_is_refused(tmp_path):
    folder = setup_journal(tmp_path)
    p = folder / "mesh-backup.json"
    data = json.loads(p.read_text())
    data["data"]["wg_conf"] = "TAMPERED"
    p.write_text(json.dumps(data))
    with pytest.raises(mod.PreparedRecoveryBlocked, match="Invalid transaction backup"):
        mod.reconcile_prepared(folder, Backend())


def test_symlink_backup_is_refused(tmp_path):
    folder = setup_journal(tmp_path)
    backup = folder / "mesh-backup.json"
    alternate = tmp_path / "alternate"
    alternate.write_bytes(backup.read_bytes())
    backup.unlink()
    backup.symlink_to(alternate)
    with pytest.raises(mod.PreparedRecoveryBlocked, match="Unsafe transaction"):
        mod.reconcile_prepared(folder, Backend())


def test_missing_lockfile_is_refused_without_creating_it(tmp_path):
    folder = setup_journal(tmp_path)
    (folder / "mesh-transaction.lock").unlink()
    with pytest.raises(mod.PreparedRecoveryBlocked, match="Unsafe transaction"):
        mod.reconcile_prepared(folder, Backend())
    assert not (folder / "mesh-transaction.lock").exists()


def test_active_writer_cannot_be_raced(tmp_path):
    folder = setup_journal(tmp_path)
    with (folder / "mesh-transaction.lock").open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(mod.PreparedRecoveryBlocked, match="still in progress"):
            mod.reconcile_prepared(folder, Backend())
    assert json.loads((folder / "mesh-transaction.json").read_text())["state"] == "prepared"


def test_invalid_backup_generation_is_refused(tmp_path):
    folder = setup_journal(tmp_path)
    p = folder / "mesh-transaction.json"
    state = json.loads(p.read_text())
    state["snapshot_sha256"] = "f" * 64
    p.write_text(json.dumps(state))
    with pytest.raises(mod.PreparedRecoveryBlocked, match="Invalid transaction backup"):
        mod.reconcile_prepared(folder, Backend())


def test_boot_unit_is_installed_disabled_and_never_starts_wireguard():
    tasks = (ROOT / "ansible/roles/services/tasks/main.yml").read_text()
    unit = (ROOT / "ansible/roles/services/templates/vpn-prepared-recovery.service.j2").read_text()
    cli = (ROOT / "deploy/vpn_prepared_recover_cli.py").read_text()
    assert "vpn_prepared_recovery.py" in tasks
    assert "omnissiah-vpn-prepared-recover" in tasks
    assert "omnissiah-vpn-prepared-recovery.service" in tasks
    assert "omnissiah_vpn_prepared_recovery_boot_enabled | default(false)" in tasks
    assert "ExecStart=/usr/bin/python3 /usr/local/libexec/omnissiah-vpn-prepared-recover" in unit
    assert "After=local-fs.target wg-quick@wg0.service" in unit
    assert "Wants=wg-quick@wg0.service" not in unit
    assert "Requires=wg-quick@wg0.service" not in unit
    assert "wg-quick up" not in cli and "ip route add" not in cli


def test_root_cli_blocks_applying_journal_without_mutating(tmp_path, monkeypatch):
    source = ROOT / "deploy/vpn_prepared_recover_cli.py"
    module_spec = importlib.util.spec_from_file_location("vpn_prepared_recover_cli", source)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    folder = setup_journal(tmp_path, state="applying", phase="route")
    monkeypatch.setattr(module, "STATE", folder)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    before = (folder / "mesh-transaction.json").read_bytes()
    with pytest.raises(mod.PreparedRecoveryBlocked, match="operator review"):
        module.run()
    assert (folder / "mesh-transaction.json").read_bytes() == before


def test_root_cli_skips_clean_or_missing_journal_without_writes(tmp_path, monkeypatch):
    source = ROOT / "deploy/vpn_prepared_recover_cli.py"
    module_spec = importlib.util.spec_from_file_location("vpn_prepared_recover_cli_clean", source)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    folder = tmp_path / "vpn"
    monkeypatch.setattr(module, "STATE", folder)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    assert module.run() == {"state": "not_initialized", "changed": False}
    assert not folder.exists()
    folder.mkdir()
    assert module.run() == {"state": "idle", "changed": False}
    assert list(folder.iterdir()) == []
