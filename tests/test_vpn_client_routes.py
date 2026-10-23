"""Policy paths on Cognitor must be explicitly included in peer AllowedIPs."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_client_route_expectations import expected_client_allowed_ips


def test_client_route_plan_contains_magos_and_only_approved_destination():
    node = SimpleNamespace(name="magos03", ip_pool="10.77.0.4/32")
    client = SimpleNamespace(id=7, parent_magos=node)
    obj = SimpleNamespace(network="192.165.42.2/32")
    rules = [
        SimpleNamespace(source_cognitor_id=7, target_object=obj, status="draft"),
        SimpleNamespace(source_cognitor_id=7, target_object=obj, status="applied"),
        SimpleNamespace(source_cognitor_id=3, target_object=obj, status="applied"),
    ]
    assert set(expected_client_allowed_ips(client, rules)) == {
        "10.77.0.4/32", "192.165.42.2/32"
    }


def test_removed_rule_not_in_cognitor_route_manifest():
    node = SimpleNamespace(name="magos03", ip_pool="10.77.0.4/32")
    client = SimpleNamespace(id=7, parent_magos=node)
    rules = [SimpleNamespace(source_cognitor_id=7,
             target_object=SimpleNamespace(network="172.16.40.10/32"),
             status="pending_delete")]
    assert expected_client_allowed_ips(client, rules) == ["10.77.0.4/32"]


def test_global_default_route_is_never_accepted():
    node = SimpleNamespace(name="magos03", ip_pool="10.77.0.4/32")
    client = SimpleNamespace(id=7, parent_magos=node)
    rules = [SimpleNamespace(source_cognitor_id=7,
             target_object=SimpleNamespace(network="0.0.0.0/0"),
             status="draft")]
    with pytest.raises(ValueError):
        expected_client_allowed_ips(client, rules)
