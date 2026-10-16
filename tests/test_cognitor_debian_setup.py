"""Rootless tests for client config generator; no WireGuard/network calls."""
import base64
import importlib.util
from pathlib import Path
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cognitor_debian_setup.py"
spec = importlib.util.spec_from_file_location("cognitor_debian_setup", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
A = base64.b64encode(b"A" * 32).decode()
B = base64.b64encode(b"B" * 32).decode()


def data():
    return dict(secret=A, address="10.77.0.5/32", parent_ip="10.77.0.4/32",
                parent_public_key=B, endpoint="192.168.32.172:51820")


def test_only_magos_host_route_not_full_tunnel():
    conf = mod.config(**data())
    assert "AllowedIPs = 10.77.0.4/32" in conf
    assert "Address = 10.77.0.5/32" in conf
    assert "Endpoint = 192.168.32.172:51820" in conf
    assert "PersistentKeepalive = 25" in conf
    assert "0.0.0.0/0" not in conf
    assert conf.count("[Peer]") == 1


@pytest.mark.parametrize("field,bad", [
    ("address", "10.77.0.5/24"),
    ("address", "10.77.0.4/32"),
    ("parent_ip", "10.77.0.0/24"),
    ("parent_ip", "::1/128"),
    ("parent_public_key", "invalid"),
    ("secret", "invalid"),
    ("endpoint", "192.168.32.172:0"),
    ("endpoint", "192.168.32.172:65536"),
    ("endpoint", "evil.example:51820"),
])
def test_invalid_client_config_rejected(field, bad):
    params = data()
    params[field] = bad
    with pytest.raises(ValueError):
        mod.config(**params)


def test_client_config_is_owner_only_and_not_overwritten(tmp_path):
    source = tmp_path / "cognitor.key"
    source.write_text(A + "\n")
    source.chmod(0o600)
    path = tmp_path / "private" / "wg0.conf"
    args = data()
    args.pop("secret")
    assert mod.write_config(source, path, **args) == str(path)
    assert path.stat().st_mode & 0o077 == 0
    assert A in path.read_text()
    with pytest.raises(FileExistsError):
        mod.write_config(source, path, **args)


def test_private_key_permissions_are_enforced(tmp_path):
    source = tmp_path / "client.key"
    source.write_text(A)
    source.chmod(0o644)
    args = data()
    args.pop("secret")
    with pytest.raises(ValueError, match="0600"):
        mod.write_config(source, tmp_path / "wg0.conf", **args)


def test_reject_symlink_input(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text(A)
    secret.chmod(0o600)
    ref = tmp_path / "link"
    ref.symlink_to(secret)
    args = data()
    args.pop("secret")
    with pytest.raises(ValueError):
        mod.write_config(ref, tmp_path / "wg0.conf", **args)
