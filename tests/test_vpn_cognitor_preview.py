"""Pure, offline Cognitor add-only read-only preview regression suite."""
import base64
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
from vpn_cognitor_preview import (preview_add, validate_plan, persisted_inventory,
                                  CognitorPreflightError)

A = base64.b64encode(b"a" * 32).decode()
B = base64.b64encode(b"b" * 32).decode()
C = base64.b64encode(b"c" * 32).decode()

PLAN = {"node_name": "magos03", "address": "10.77.0.4/32",
        "client_name": "cognitor01", "client_address": "10.77.0.5/32",
        "public_key": C}
CONF = ("# Managed by Omnissiah VPN v2\n[Interface]\n"
        "PrivateKey = NEVER-DISCLOSE-THIS-VALUE\nAddress = 10.77.0.4/32\n"
        "ListenPort = 51820\n\n[Peer]\nPublicKey = " + A +
        "\nAllowedIPs = 10.77.0.2/32\nEndpoint = 192.168.32.168:51820\n\n"
        "[Peer]\nPublicKey = " + B +
        "\nAllowedIPs = 10.77.0.3/32\nEndpoint = 192.168.32.169:51820\n")
PEERS = [{"public_key": A, "allowed_ips": ["10.77.0.2/32"]},
         {"public_key": B, "allowed_ips": ["10.77.0.3/32"]}]
ROUTES = [{"dst": "default", "gateway": "192.168.32.1", "dev": "ens33"},
          {"dst": "10.77.0.2", "dev": "wg0"},
          {"dst": "10.77.0.3", "dev": "wg0"},
          {"dst": "192.168.32.0/24", "dev": "ens33"}]


def preview(**kwargs):
    args = {"current_peers": PEERS, "routes": ROUTES,
            "persisted_config": CONF, "protected_addresses": ["192.168.32.167"]}
    args.update(kwargs)
    return preview_add(dict(PLAN), **args)


def test_ready_has_no_secret_or_write():
    output = preview()
    assert output["safe_to_plan"] is True
    assert output["writes_performed"] is False
    assert output["existing_peers"] == 2
    assert output["client_address"] == "10.77.0.5/32"
    assert len(output["revision"]) == 64
    assert "NEVER-DISCLOSE-THIS-VALUE" not in str(output)


def test_exact_disk_and_kernel_peers_must_agree():
    with pytest.raises(CognitorPreflightError, match="inventories differ"):
        preview(current_peers=PEERS[:1])
    with pytest.raises(CognitorPreflightError, match="inventories differ"):
        preview(persisted_config=CONF.replace("10.77.0.3/32", "10.77.0.8/32"))


def test_refuse_client_identity_or_address_collision():
    with pytest.raises(CognitorPreflightError, match="key already installed"):
        preview_add(dict(PLAN, public_key=A), current_peers=PEERS,
                    routes=ROUTES, persisted_config=CONF)
    with pytest.raises(CognitorPreflightError, match="already belongs"):
        preview_add(dict(PLAN, client_address="10.77.0.3/32"),
                    current_peers=PEERS, routes=ROUTES, persisted_config=CONF)


def test_refuse_foreign_or_existing_kernel_host_route():
    with pytest.raises(CognitorPreflightError, match="already exists"):
        preview(routes=ROUTES + [{"dst": "10.77.0.5/32", "dev": "eth1"}])


def test_refuse_protected_address():
    with pytest.raises(CognitorPreflightError, match="protected management"):
        preview(protected_addresses=["10.77.0.5"])


def test_refuse_broad_or_foreign_source():
    for bad in (dict(PLAN, client_address="10.77.0.5/24"),
                dict(PLAN, node_name="magos01"),
                dict(PLAN, address="10.77.0.5/32"),
                dict(PLAN, public_key="not-a-key"),
                dict(PLAN, unknown="field")):
        with pytest.raises(CognitorPreflightError):
            preview_add(bad, current_peers=PEERS, routes=ROUTES,
                        persisted_config=CONF)


def test_unmanaged_or_malformed_disk_blocks():
    with pytest.raises(CognitorPreflightError):
        preview(persisted_config=CONF.replace("# Managed by Omnissiah VPN v2", "# Foreign"))
    with pytest.raises(CognitorPreflightError):
        preview(persisted_config=CONF.replace("AllowedIPs = 10.77.0.2/32",
                                              "AllowedIPs = 10.77.0.0/24"))


def test_revision_changes_with_plan_and_live_snapshot():
    base = preview()["revision"]
    assert base != preview(routes=ROUTES + [{"dst": "172.16.0.0/16", "dev": "eth0"}])["revision"]
    assert base != preview_add(dict(PLAN, client_name="other"),
                current_peers=PEERS, routes=ROUTES, persisted_config=CONF)["revision"]
