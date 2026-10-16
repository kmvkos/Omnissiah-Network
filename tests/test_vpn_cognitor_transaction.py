"""Offline add-only backend checks: no WireGuard or network namespace needed."""
import base64
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
from vpn_cognitor_transaction import AddOnlyBackend, CognitorTransactionBlocked

A = base64.b64encode(b"a" * 32).decode()
B = base64.b64encode(b"b" * 32).decode()
C = base64.b64encode(b"c" * 32).decode()
PLAN = {"node_name": "magos03", "address": "10.77.0.4/32",
        "client_name": "cognitor01", "client_address": "10.77.0.5/32",
        "public_key": C}
BEFORE = [
    {"public_key": A, "allowed_ips": ["10.77.0.2/32"], "keepalive": 25, "endpoint": "192.168.32.168:51820"},
    {"public_key": B, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25, "endpoint": "192.168.32.169:51820"},
]
NEW = {"public_key": C, "allowed_ips": ["10.77.0.5/32"], "keepalive": 0, "endpoint": ""}


def make_backend(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    raw = ("# Managed by Omnissiah VPN v2\n[Interface]\n"
           "PrivateKey = dummy-private\nAddress = 10.77.0.4/32\n"
           "ListenPort = 51820\n")
    for i, p in enumerate(BEFORE):
        raw += ("\n[Peer]\nPublicKey = " + p["public_key"] + "\nAllowedIPs = "
                + p["allowed_ips"][0] + "\nEndpoint = " + p["endpoint"]
                + "\nPersistentKeepalive = 25\n")
    conf.write_text(raw)
    conf.chmod(0o600)
    backend = AddOnlyBackend(PLAN, "a" * 64, ["192.168.32.167"],
                             state=tmp_path, config=conf)
    backend.before = {"peers": BEFORE, "config": raw, "snapshot_sha256": "x"}
    backend.preview = {"delta": {"add": ["10.77.0.5/32"], "remove": []},
                       "steps": [{"op": "add", "dst": "10.77.0.5/32", "dev": "wg0"}]}
    monkeypatch.setattr(backend, "_file", conf.read_text)
    return backend, conf, raw


def test_root_mutation_touch_only_new_peer_and_route(tmp_path, monkeypatch):
    backend, _, _ = make_backend(tmp_path, monkeypatch)
    commands = []
    monkeypatch.setattr(backend, "_command", lambda argv, **kwargs: commands.append(argv) or "")
    backend.sync_wireguard(BEFORE + [NEW])
    backend.route_step({"op": "add", "dst": "10.77.0.5/32", "dev": "wg0"})
    assert commands == [
        ["wg", "set", "wg0", "peer", C, "allowed-ips", "10.77.0.5/32"],
        ["ip", "-4", "route", "add", "10.77.0.5/32", "dev", "wg0", "table", "main"]]


def test_changing_or_deleting_existing_mesh_peer_is_rejected(tmp_path, monkeypatch):
    backend, _, _ = make_backend(tmp_path, monkeypatch)
    with pytest.raises(CognitorTransactionBlocked):
        backend.sync_wireguard([BEFORE[0], NEW])
    with pytest.raises(CognitorTransactionBlocked):
        backend.sync_wireguard([dict(BEFORE[0], allowed_ips=["10.77.0.8/32"]),
                                BEFORE[1], NEW])
    with pytest.raises(CognitorTransactionBlocked):
        backend.route_step({"op": "delete", "dst": "10.77.0.2/32", "dev": "wg0"})


def test_handshake_and_byte_counters_do_not_change_peer_identity(tmp_path, monkeypatch):
    backend, _, _ = make_backend(tmp_path, monkeypatch)
    commands = []
    monkeypatch.setattr(backend, "_command", lambda argv, **kwargs: commands.append(argv) or "")
    dynamic = [dict(p, rx_bytes=12345, tx_bytes=67890,
                    latest_handshake=9999) for p in BEFORE]
    backend.sync_wireguard(dynamic + [NEW])
    assert commands[0][:4] == ["wg", "set", "wg0", "peer"]


def test_persist_appends_single_client_without_touching_mesh(tmp_path, monkeypatch):
    backend, conf, original = make_backend(tmp_path, monkeypatch)
    backend.persist_config(BEFORE + [NEW])
    new = conf.read_text()
    assert new.startswith(original.rstrip("\n"))
    assert new.count("[Peer]") == 3
    assert new.count(A) == new.count(B) == new.count(C) == 1
    assert "Endpoint = " + PLAN["client_address"] not in new
    assert "# Cognitor: cognitor01" in new
    assert conf.stat().st_mode & 0o077 == 0
    backend.restore_config()
    assert conf.read_text() == original


def test_restore_refuses_foreign_config_change(tmp_path, monkeypatch):
    backend, conf, _ = make_backend(tmp_path, monkeypatch)
    conf.write_text("UNEXPECTED CONFIG")
    with pytest.raises(CognitorTransactionBlocked, match="Unexpected persisted"):
        backend.restore_config()


def test_restore_peer_refuses_foreign_client_mutation(tmp_path, monkeypatch):
    backend, _, _ = make_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "snapshot",
                        lambda: ([*BEFORE, dict(NEW, allowed_ips=["10.77.0.99/32"])], []))
    commands = []
    monkeypatch.setattr(backend, "_command", lambda argv, **kwargs: commands.append(argv) or "")
    with pytest.raises(CognitorTransactionBlocked, match="Client peer changed"):
        backend.restore_wireguard()
    assert commands == []


def test_restore_route_refuses_foreign_device(tmp_path, monkeypatch):
    backend, _, _ = make_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(backend, "snapshot",
                        lambda: (BEFORE, [{"dst": "10.77.0.5/32", "dev": "eth1"}]))
    commands = []
    monkeypatch.setattr(backend, "_command", lambda argv, **kwargs: commands.append(argv) or "")
    with pytest.raises(CognitorTransactionBlocked, match="Foreign route"):
        backend.restore_routes()
    assert commands == []
