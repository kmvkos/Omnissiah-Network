"""Contract tests for isolated Linux backend, without touching real interfaces."""
import base64
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for name in ("vpn_route_tx", "vpn_route_journal", "vpn_route_executor_sim",
             "vpn_reconcile", "vpn_linux_preflight", "vpn_helper", "vpn_linux_backend"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

from vpn_linux_backend import IsolatedLinuxMeshBackend, _atomic_bytes, _digest
from vpn_route_journal import prepare_transaction
from vpn_route_executor_sim import TransactionBlocked

KEY = base64.b64encode(b"a" * 32).decode()
SECRET = base64.b64encode(b"b" * 32).decode()
BASE = {"node_name": "magos01", "address": "10.77.0.2/32",
        "listen_port": 51820,
        "peers": [{"public_key": KEY, "endpoint": "192.168.32.169:51820",
                   "allowed_ips": ["10.77.0.3/32"], "keepalive": 25}]}
ADDED = {"public_key": base64.b64encode(b"c" * 32).decode(),
         "endpoint": "192.168.32.172:51820",
         "allowed_ips": ["10.77.0.4/32"], "keepalive": 25}
WG_OLD = "SECRET\tPUBLIC\t51820\toff\n" + KEY + "\t(none)\t192.168.32.169:51820\t10.77.0.3/32\t100\t1\t2\t25\n"
ROUTES = [{"dst": "10.77.0.3/32", "dev": "wg0"}]


def make_backend(tmp_path):
    from vpn_helper import render
    config_dir = tmp_path / "etc"
    config_dir.mkdir()
    conf = config_dir / "wg0.conf"
    conf.write_text(render(BASE, SECRET))
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    (state_dir / "private.key").write_text(SECRET)
    plan = prepare_transaction(BASE["peers"] + [ADDED], BASE["peers"], ROUTES)
    node = dict(BASE, peers=BASE["peers"] + [ADDED])
    backend = IsolatedLinuxMeshBackend(node, plan, state_dir=state_dir,
                                        config_path=conf, allow_mutations=False)
    return backend, conf, state_dir, plan


def test_default_is_not_authorized_to_mutate(tmp_path):
    backend, _, _, _ = make_backend(tmp_path)
    with pytest.raises(TransactionBlocked, match="disabled"):
        backend.stage_backup()
    with pytest.raises(TransactionBlocked, match="disabled"):
        backend.restore_routes()


def test_atomic_configuration_write_and_symlink_refusal(tmp_path):
    target = tmp_path / "wg0.conf"
    _atomic_bytes(target, b"original")
    assert target.read_bytes() == b"original"
    assert target.stat().st_mode & 0o077 == 0
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(TransactionBlocked, match="Symlink"):
        _atomic_bytes(link, b"evil")
    assert target.read_bytes() == b"original"


def test_snapshot_and_route_step_use_only_fixed_commands(tmp_path, monkeypatch):
    backend, _, _, plan = make_backend(tmp_path)
    called = []
    monkeypatch.setattr(backend, "_require_enabled", lambda: None)
    monkeypatch.setattr(backend, "_command",
                        lambda argv, **kwargs: called.append(argv) or "")
    backend.route_step(plan["steps"][0])
    assert called == [["ip", "-4", "route", "add", "10.77.0.4/32",
                       "dev", "wg0", "table", "main"]]
    with pytest.raises(TransactionBlocked, match="approved preview"):
        backend.route_step({"op": "delete", "dst": "10.77.0.3/32", "dev": "wg0"})
    assert len(called) == 1


def test_backup_created_before_mutation_and_mode_0600(tmp_path, monkeypatch):
    backend, _, state, plan = make_backend(tmp_path)
    monkeypatch.setattr(backend, "_require_enabled", lambda: None)
    monkeypatch.setattr(backend, "_config_bytes",
                        lambda: b"# Managed by Omnissiah VPN v2\nold-config")
    monkeypatch.setattr(backend, "_command",
                        lambda argv, **kwargs: "PRIVATE-OLD\n")
    monkeypatch.setattr(backend, "snapshot",
                        lambda: (list(BASE["peers"]), list(ROUTES)))
    backend.stage_backup()
    record = json.loads((state / "mesh-backup.json").read_text())
    assert record["sha256"] == _digest(record["data"])
    assert record["data"]["snapshot_sha256"] == plan["snapshot_sha256"]
    assert record["data"]["wg_conf"] == "PRIVATE-OLD\n"
    assert (state / "mesh-backup.json").stat().st_mode & 0o077 == 0
    with pytest.raises(TransactionBlocked, match="Unresolved backup"):
        backend.stage_backup()


def test_restore_routes_only_touches_delta_and_refuses_foreign(tmp_path, monkeypatch):
    backend, _, _, plan = make_backend(tmp_path)
    monkeypatch.setattr(backend, "_require_enabled", lambda: None)
    monkeypatch.setattr(backend, "_load_backup", lambda: {"routes": ROUTES})
    monkeypatch.setattr(backend, "snapshot",
                        lambda: (list(BASE["peers"]), ROUTES +
                                 [{"dst": "10.77.0.4/32", "dev": "wg0"}]))
    issued = []
    monkeypatch.setattr(backend, "_command",
                        lambda argv, **kwargs: issued.append(argv) or "")
    backend.restore_routes()
    assert issued == [["ip", "-4", "route", "delete", "10.77.0.4/32",
                       "dev", "wg0", "table", "main"]]

    monkeypatch.setattr(backend, "snapshot",
                        lambda: (list(BASE["peers"]), ROUTES +
                                 [{"dst": "10.77.0.4/32", "dev": "eth0"}]))
    with pytest.raises(TransactionBlocked, match="Foreign"):
        backend.restore_routes()
    assert len(issued) == 1


def test_verify_rejects_stale_peer_state(tmp_path, monkeypatch):
    backend, _, _, plan = make_backend(tmp_path)
    monkeypatch.setattr(backend, "snapshot",
                        lambda: (list(BASE["peers"]), ROUTES))
    with pytest.raises(TransactionBlocked, match="peer identities"):
        backend.verify(BASE["peers"] + [ADDED], plan)


def test_no_runtime_api_integration():
    for name in ("vpn_rpc.py", "vpn_helper.py"):
        content = (ROOT / "deploy" / name).read_text()
        assert "vpn_linux_backend" not in content
