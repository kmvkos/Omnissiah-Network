"""Verify deployment passes every management IP to the isolated VPN root service.

The Ansible inventory is already validated as IPv4/unique by validate_manifest.
This test renders only the systemd template and never starts a service.
"""
from pathlib import Path
import ipaddress

from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "ansible/roles/services/templates/vpn-rpc.service.j2"


def render_service():
    env = Environment()
    # Ansible provides the 'extract' filter. Implement its equivalent for
    # standalone template tests, without importing/initializing Ansible.
    env.filters["extract"] = lambda key, mapping, field: mapping[key][field]
    hosts = {
        "omni01": {"ansible_host": "192.168.32.167"},
        "magos01": {"ansible_host": "192.168.32.168"},
        "magos02": {"ansible_host": "192.168.32.169"},
        "magos03": {"ansible_host": "192.168.32.170"},
    }
    return env.from_string(TEMPLATE.read_text()).render(
        inventory_hostname="magos03", hostvars=hosts,
        groups={"omnissiah": ["omni01"], "magos": ["magos01", "magos02", "magos03"]})


def test_root_service_receives_entire_trusted_management_inventory():
    service = render_service()
    prefix = 'Environment="OMNISSIAH_PROTECTED_MANAGEMENT_IPV4='
    lines = [line for line in service.splitlines() if line.startswith(prefix)]
    assert len(lines) == 1
    values = lines[0][len(prefix):].removesuffix('"').split(",")
    assert values == [
        "192.168.32.167", "192.168.32.168",
        "192.168.32.169", "192.168.32.170"]
    assert all(ipaddress.ip_address(value).version == 4 for value in values)


def test_transaction_execution_stays_disabled_on_fresh_install():
    service = render_service()
    assert 'Environment="OMNISSIAH_ENABLE_ROUTE_TRANSACTIONS=' not in service
    assert 'Environment="OMNISSIAH_NODE_NAME=magos03"' in service
