"""Fault-injection test of actual kernel command sequence and recovery journal."""
import importlib.util
from pathlib import Path
import json
import uuid
from types import SimpleNamespace as Obj

import pytest


spec = importlib.util.spec_from_file_location(
    "vpn_cross_route_transaction",
    Path(__file__).resolve().parents[1] / "deploy" / "vpn_cross_route_transaction.py")
# Keep the existing deploy modules discoverable without installing network packages.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SOURCE_PUB = "B"*43+"="
DEST_PUB = "A"*43+"="
COGNITOR_PUB = "C"*43+"="

PLAN = {
    "node_name": "magos03", "address": "10.77.0.4/32", "role": "source",
    "own_vpn_cidr": "10.77.0.4/32", "peer_name": "magos01",
    "peer_public_key": DEST_PUB, "peer_vpn_cidr": "10.77.0.2/32",
    "client_cidr": "10.77.0.5/32", "client_public_key": COGNITOR_PUB,
    "resource_cidr": "192.165.42.2/32",
    "required_peer_allowed_ip": "192.165.42.2/32",
    "required_route": "192.165.42.2/32",
}


def config():
    return (
        "# Managed by Omnissiah VPN v2\n"
        "[Interface]\nAddress = 10.77.0.4/32\nPrivateKey = secret-hidden\n"
        f"[Peer]\nPublicKey = {DEST_PUB}\nAllowedIPs = 10.77.0.2/32\n"
        f"[Peer]\nPublicKey = {COGNITOR_PUB}\nAllowedIPs = 10.77.0.5/32\n"
    )


class Fake:
    def __init__(self):
        self.allowed = ["10.77.0.2/32"]
        self.added = False
        self.fail_route_add = False
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append(tuple(command))
        if command[:3] == ["wg", "show", "wg0"]:
            rows = [
                "private\tpublic\t51820\t0",
                f"{DEST_PUB}\t(none)\t192.168.32.168:51820\t{','.join(self.allowed)}\t0\t0\t0\t25",
                f"{COGNITOR_PUB}\t(none)\t(none)\t10.77.0.5/32\t0\t0\t0\t25",
            ]
            return Obj(returncode=0, stdout="\n".join(rows)+"\n", stderr="")
        if command[:4] == ["ip", "-j", "-4", "route"]:
            if command[4] == "show":
                routes = [
                    {"dst": "10.77.0.2/32", "dev": "wg0"},
                    {"dst": "10.77.0.5/32", "dev": "wg0"},
                    {"dst": "192.168.32.0/24", "dev": "eth0"},
                ]
                if self.added:
                    routes.append({"dst": "192.165.42.2/32", "dev": "wg0"})
                return Obj(returncode=0, stdout=json.dumps(routes), stderr="")
            return Obj(returncode=0, stdout=json.dumps([{
                "dev": "wg0" if self.added and command[5] == "192.165.42.2" else "eth0"
            }]), stderr="")
        if command[:4] == ["wg", "set", "wg0", "peer"]:
            self.allowed = command[-1].split(",")
            return Obj(returncode=0, stdout="", stderr="")
        if command[:4] == ["ip", "-4", "route", "add"]:
            if self.fail_route_add:
                return Obj(returncode=1, stdout="", stderr="route error")
            self.added = True
            return Obj(returncode=0, stdout="", stderr="")
        if command[:4] == ["ip", "-4", "route", "del"]:
            self.added = False
            return Obj(returncode=0, stdout="", stderr="")
        raise AssertionError(f"Unexpected command: {command}")


def worker(tmp_path, fake, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    file = tmp_path / "wg0.conf"
    file.write_text(config())
    file.chmod(0o600)
    tx = module.CrossRouteExtension(
        "magos03", ["192.168.32.167", "192.168.32.172"],
        runner=fake, state=root, config=file)
    # Unprivileged CI can test all network decisions with an injected runner.
    # Root-owned file access is independently enforced in the real helper.
    monkeypatch.setattr(tx, "_safe_paths", lambda: None)
    monkeypatch.setenv("OMNISSIAH_ENABLE_CROSS_ROUTE_APPLY", "YES")
    return tx, file, root


def test_prepare_commit_and_revert_preserve_original_mesh_and_cognitor(tmp_path, monkeypatch):
    fake = Fake()
    tx, file, root = worker(tmp_path, fake, monkeypatch)
    opid = str(uuid.uuid4())
    first = tx.prepare(PLAN, opid)
    assert first["state"] == "prepared"
    assert file.read_text() == config()
    assert fake.added is False
    committed = tx.commit(opid, first["revision"])
    assert committed["state"] == "committed"
    assert "192.165.42.2/32" in fake.allowed
    assert fake.added is True
    assert "192.165.42.2/32" in file.read_text()
    assert COGNITOR_PUB in file.read_text()
    rolled = tx.revert(opid, first["revision"])
    assert rolled["state"] == "reverted"
    assert fake.added is False
    assert fake.allowed == ["10.77.0.2/32"]
    assert file.read_text() == config()
    assert all("iptables" not in str(cmd) for cmd in fake.calls)


def test_interrupted_add_creates_recovery_fence_before_rollback(tmp_path, monkeypatch):
    fake = Fake()
    fake.fail_route_add = True
    tx, file, root = worker(tmp_path, fake, monkeypatch)
    opid = str(uuid.uuid4())
    revision = tx.prepare(PLAN, opid)["revision"]
    with pytest.raises(module.CrossRouteError, match="uncertain"):
        tx.commit(opid, revision)
    assert json.loads((root / module.MARKER).read_text())["state"] == "recovery_required"
    with pytest.raises(module.CrossRouteError, match="Unresolved"):
        tx.prepare(PLAN, str(uuid.uuid4()))
    restored = tx.revert(opid, revision)
    assert restored["state"] == "reverted"
    assert file.read_text() == config()
    assert fake.allowed == ["10.77.0.2/32"]


def test_route_extension_rejects_ambiguous_or_unowned_file():
    forged = config().replace("# Managed by Omnissiah VPN v2\n", "")
    with pytest.raises(module.CrossRouteError):
        module.extend_peer_config(forged, DEST_PUB, "192.165.42.2/32")
    with pytest.raises(module.CrossRouteError):
        module.extend_peer_config(config(), "Z"*43+"=", "192.165.42.2/32")


def test_mutation_requires_separate_root_opt_in(tmp_path, monkeypatch):
    fake = Fake()
    tx, file, root = worker(tmp_path, fake, monkeypatch)
    monkeypatch.delenv("OMNISSIAH_ENABLE_CROSS_ROUTE_APPLY")
    with pytest.raises(module.CrossRouteError, match="disabled"):
        tx.prepare(PLAN, str(uuid.uuid4()))
    assert fake.calls == []
