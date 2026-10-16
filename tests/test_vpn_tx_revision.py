"""Verify per-node preview revision fencing and UI opt-in contract."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vpn_tx_revision import plan_revision


def test_preview_revision_is_stable_and_changes_with_desired_topology():
    initial = {
        "node_name": "magos01", "address": "10.77.0.2/32",
        "listen_port": 51820,
        "peers": [{"public_key": "first", "endpoint": "192.168.32.169:51820",
                   "allowed_ips": ["10.77.0.3/32"], "keepalive": 25}],
    }
    same = {
        "peers": list(initial["peers"]), "listen_port": 51820,
        "address": "10.77.0.2/32", "node_name": "magos01",
    }
    assert plan_revision(initial) == plan_revision(same)
    modified = dict(initial, peers=initial["peers"] + [{
        "public_key": "second", "endpoint": "192.168.32.170:51820",
        "allowed_ips": ["10.77.0.4/32"], "keepalive": 25,
    }])
    assert plan_revision(initial) != plan_revision(modified)
    assert len(plan_revision(initial)) == 64


def test_ui_only_offers_transaction_with_preview_revision_and_explicit_confirmation():
    page = (ROOT / "templates/vpn_overview.html").read_text()
    controller = (ROOT / "src/app.py").read_text()
    action = controller.split("def vpn_mesh_operation():", 1)[1].split("@app.route(", 1)[0]
    preview = controller.split("def vpn_mesh_change_preview():", 1)[1].split("@app.route(", 1)[0]
    assert "item.transaction_available === true" in page
    assert "item.preview_revision" in page
    assert "expected_revision: previewRevision" in page
    assert "prompt('Для подтверждения введите имя узла:" in page
    assert 'body["expected_revision"] != plan_revision(plan)' in action
    assert '_vpn_v2_send(node, "route-preview", plan)' in action
    assert 'if plan_revision(fresh_plan) != body["expected_revision"]:' in action
    assert 'result["preview_revision"] = plan_revision(strict_plan)' in preview
    assert "VPN_ROUTE_TRANSACTIONS_ENABLED" in controller
