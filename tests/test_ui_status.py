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

def test_vpn_reconcile_script_is_emitted_in_script_block_not_title():
    """A JS function inside the title block renders as inert title text."""
    source = (ROOT / "templates/vpn_overview.html").read_text()
    title = source.split("{% block title %}", 1)[1].split("{% endblock %}", 1)[0]
    script = source.split("{% block scripts %}", 1)[1].split("{% endblock %}", 1)[0]
    assert "<script" not in title
    assert "checkVpnDrift" not in title
    assert "async function checkVpnDrift()" in script
    assert "url_for(\"reconcile_vpn_mesh\")" in script

def test_reconcile_uses_request_context_not_contextless_threads():
    source = (ROOT / "src/app.py").read_text()
    section = source.split("def reconcile_vpn_mesh():", 1)[1].split("@app.route(", 1)[0]
    assert "ThreadPoolExecutor" not in section
    assert "map(poll, plans)" in section
    assert "RuntimeError" in section


def test_reconcile_ui_checks_response_content_type():
    source = (ROOT / "templates/vpn_overview.html").read_text()
    script = source.split("{% block scripts %}", 1)[1]
    assert "content-type" in script
    assert "Сервер вернул HTTP" in script
