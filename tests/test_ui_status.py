"""Read-only UI contract checks for Omnissiah control-plane and Magos status."""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_all_ui_templates_parse():
    from jinja2 import Environment
    env = Environment()
    for path in (ROOT / "templates").glob("*.html"):
        env.parse(path.read_text())


def test_controller_has_no_wireguard_toggle():
    source = (ROOT / "templates/main_node.html").read_text()
    assert 'onclick="toggleVPN' not in source
    assert "WireGuard не требуется" in source
    assert "VPN выполняется на Magos" in source


def test_dashboard_renders_control_plane_and_independent_mtls():
    source = (ROOT / "templates/dashboard.html").read_text()
    assert "Control Plane · mTLS" in source
    assert "magos.mtls_status" in source
    assert "magos.vpn_status" in source


def test_heartbeat_reads_wg0_not_hostname_interface():
    source = (ROOT / "agents/app/heartbeat.py").read_text()
    assert '["ip", "-j", "-d", "link", "show", "dev", "wg0"]' in source
    assert 'request_helper("status"' in source
    assert 'vpn_last_handshake' in source


def test_controller_reads_magos_observations_not_its_own_wg_dump():
    source = (ROOT / "src/app.py").read_text()
    section = source.split("def dashboard():", 1)[1].split("def get_interfaces_with_ips(", 1)[0]
    assert "peer_status(magos)" in section
    assert '["wg", "show", "all", "dump"]' not in section
