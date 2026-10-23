"""Isolated Flask/SQLite tests for Cognitor draft admission.

No import of giant legacy src/app.py, no subprocesses and no WireGuard.
"""
import base64
from pathlib import Path
import re
import sys

import pytest
from flask import Flask
from flask_login import LoginManager
from jinja2 import DictLoader

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
from nmc_models import BaseUser, General, db
from nmc_api.cognitors import cognitors_bp
from vpn_cognitor_models import CognitorDraft


KEY = base64.b64encode(bytes(range(32))).decode()
KEY2 = base64.b64encode(bytes(range(32, 64))).decode()


@pytest.fixture
def web(tmp_path):
    app = Flask("cognitor-test")
    app.config.update(
        SECRET_KEY="only-for-unit-testing",
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "test.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_ENABLED=True,
        TESTING=True,
    )
    app.jinja_loader = DictLoader({"vpn_cognitors.html":
        "<form>{{ form.hidden_tag() }}{% for e in form.errors %}{{e}}{% endfor %}</form>"
        "{% for d in drafts %}<span>{{d.name}}</span>{% endfor %}"})
    db.init_app(app)
    login_manager = LoginManager(app)

    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(BaseUser, int(uid))

    app.register_blueprint(cognitors_bp)
    with app.app_context():
        db.create_all()
        root = BaseUser(email="admin", password_hash="x", role="admin")
        guest = BaseUser(email="reader", password_hash="x", role="user")
        omni = General(name="omni01", ip_pool="10.77.0.0/24",
                       listen_port=51820, private_key="", public_key="",
                       role="Omnissiah", endpoint="192.168.32.167")
        magos = General(name="magos01", ip_pool="10.77.0.2/32",
                        listen_port=51820, private_key="", public_key=KEY2,
                        role="Magos", endpoint="192.168.32.168")
        db.session.add_all([root, guest, omni, magos])
        db.session.commit()
        admin_id, user_id, magos_id = root.id, guest.id, magos.id
    return app, app.test_client(), admin_id, user_id, magos_id


def login(client, uid):
    with client.session_transaction() as session:
        session["_user_id"] = str(uid)
        session["_fresh"] = True


def csrf(client):
    html = client.get("/vpn/cognitors").get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, html[:500]
    return match.group(1)


def test_unauthenticated_and_non_admin_cannot_view_or_register(web):
    app, client, admin, guest, magos_id = web
    response = client.get("/vpn/cognitors")
    assert response.status_code in (302, 401)
    login(client, guest)
    assert client.get("/vpn/cognitors").status_code == 403
    assert client.post("/vpn/cognitors", data={
        "name":"clientA", "vpn_address":"10.77.0.5/32",
        "public_key":KEY, "parent_magos_id":str(magos_id)}).status_code == 403
    with app.app_context():
        assert CognitorDraft.query.count() == 0


def test_admin_can_create_pending_draft_with_client_public_key(web):
    app, client, admin, _, magos_id = web
    login(client, admin)
    token = csrf(client)
    resp = client.post("/vpn/cognitors", data={
        "name": "clientA", "vpn_address": "10.77.0.5/32",
        "public_key": KEY, "parent_magos_id": str(magos_id),
        "csrf_token": token,
    })
    assert resp.status_code == 302
    assert "/vpn/cognitors" in resp.headers["Location"]
    with app.app_context():
        rows = CognitorDraft.query.all()
        assert len(rows) == 1
        draft = rows[0]
        assert (draft.name, draft.vpn_address, draft.public_key, draft.parent_magos_id, draft.status) == (
            "clientA", "10.77.0.5/32", KEY, magos_id, "draft")
        assert not hasattr(draft, "private_key")
        assert General.query.filter_by(role="Cognitor").count() == 0
    assert "clientA" in client.get("/vpn/cognitors").get_data(as_text=True)


def test_forged_or_missing_csrf_never_commits(web):
    app, client, admin, _, magos_id = web
    login(client, admin)
    for value in ("", "invalid"):
        result = client.post("/vpn/cognitors", data={
            "name":"clientB", "vpn_address":"10.77.0.6/32",
            "public_key":KEY, "parent_magos_id":str(magos_id),
            "csrf_token":value})
        assert result.status_code == 200
    with app.app_context():
        assert CognitorDraft.query.count() == 0


def test_duplicate_ip_and_invalid_parent_do_not_create_client(web):
    app, client, admin, _, magos_id = web
    login(client, admin)
    for addr, parent in (("10.77.0.2/32", magos_id),
                         ("10.77.1.5/32", magos_id),
                         ("10.77.0.5/32", 100000)):
        result = client.post("/vpn/cognitors", data={
            "name": "clientC", "vpn_address": addr,
            "public_key": KEY, "parent_magos_id":str(parent),
            "csrf_token":csrf(client),
        })
        assert result.status_code == 200
    with app.app_context():
        assert CognitorDraft.query.count() == 0


def test_duplicate_draft_does_not_override_previous_entry(web):
    app, client, admin, _, magos_id = web
    login(client, admin)
    def submit(name, key, address):
        return client.post("/vpn/cognitors", data={
            "name":name, "vpn_address":address, "public_key":key,
            "parent_magos_id":str(magos_id), "csrf_token":csrf(client)})
    assert submit("clientA", KEY, "10.77.0.5/32").status_code == 302
    assert submit("clientA", KEY2, "10.77.0.6/32").status_code == 200
    assert submit("clientB", KEY, "10.77.0.6/32").status_code == 200
    assert submit("clientB", KEY2, "10.77.0.5/32").status_code == 200
    with app.app_context():
        assert CognitorDraft.query.count() == 1

def test_admin_apply_requires_csrf_and_exact_confirmation(web, monkeypatch):
    app, client, admin, _, magos_id = web
    login(client, admin)
    with app.app_context():
        row = CognitorDraft(name="clientApply", vpn_address="10.77.0.5/32",
                            public_key=KEY, parent_magos_id=magos_id, status="draft")
        db.session.add(row)
        db.session.commit()
        draft_id = row.id
    import sys
    from types import SimpleNamespace
    called = []
    monkeypatch.setitem(sys.modules, "app", SimpleNamespace(
        _vpn_v2_send=lambda *args, **kwargs: called.append((args, kwargs)) or
        {"state": "committed", "client_address": "10.77.0.5/32",
         "operation_id": kwargs.get("operation_id")}))
    for data in [
        {"confirm_name":"clientApply", "expected_revision":"a" * 64},
        {"csrf_token":"broken", "confirm_name":"clientApply", "expected_revision":"a" * 64},
        {"csrf_token":csrf(client), "confirm_name":"WrongName", "expected_revision":"a" * 64},
    ]:
        result = client.post("/vpn/cognitors/" + str(draft_id) + "/apply", data=data)
        assert result.status_code in (302, 400)
    assert called == []
    with app.app_context():
        assert db.session.get(CognitorDraft, draft_id).status == "draft"
    result = client.post("/vpn/cognitors/" + str(draft_id) + "/apply", data={
        "csrf_token":csrf(client), "confirm_name":"clientApply",
        "expected_revision":"a" * 64,
    })
    assert result.status_code == 302
    assert len(called) == 1
    assert called[0][0][1] == "cognitor-add"
    assert called[0][0][2]["client_address"] == "10.77.0.5/32"
    assert called[0][0][2]["expected_revision"] == "a" * 64
    assert len(called[0][1]["operation_id"]) == 36
    with app.app_context():
        assert db.session.get(CognitorDraft, draft_id).status == "applied"


def test_unknown_remote_apply_outcome_must_not_mark_applied(web, monkeypatch):
    app, client, admin, _, magos_id = web
    login(client, admin)
    with app.app_context():
        row = CognitorDraft(name="clientUnknown", vpn_address="10.77.0.7/32",
                            public_key=KEY, parent_magos_id=magos_id, status="draft")
        db.session.add(row)
        db.session.commit()
        draft_id = row.id
    import sys
    from types import SimpleNamespace
    monkeypatch.setitem(sys.modules, "app", SimpleNamespace(
        _vpn_v2_send=lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("no reply"))))
    response = client.post("/vpn/cognitors/" + str(draft_id) + "/apply", data={
        "csrf_token":csrf(client), "confirm_name":"clientUnknown",
        "expected_revision":"a" * 64,
    })
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(CognitorDraft, draft_id).status == "draft"


def test_handshake_status_must_ignore_other_peers(web, monkeypatch):
    app, client, admin, _, magos_id = web
    login(client, admin)
    with app.app_context():
        row = CognitorDraft(name="clientStatus", vpn_address="10.77.0.7/32",
                            public_key=KEY, parent_magos_id=magos_id, status="applied")
        db.session.add(row)
        db.session.commit()
        draft_id = row.id
    import sys, time
    from types import SimpleNamespace
    app.jinja_loader.mapping["vpn_cognitor_status.html"] = (
        "{% if seen %}{{ seen.installed }}|{{ seen.connected }}|{{ seen.rx_bytes }}{% else %}NONE{% endif %}")
    now = int(time.time())
    peers = [{"public_key": KEY2, "allowed_ips": ["10.77.0.9/32"],
              "latest_handshake": now, "rx_bytes": 1111, "tx_bytes": 2222},
             {"public_key": KEY, "allowed_ips": ["10.77.0.7/32"],
              "latest_handshake": now, "rx_bytes": 92, "tx_bytes": 180}]
    monkeypatch.setitem(sys.modules, "app", SimpleNamespace(
        _vpn_v2_send=lambda *args, **kwargs: {"active": True, "peers": peers}))
    response = client.get("/vpn/cognitors/" + str(draft_id) + "/status")
    assert response.status_code == 200
    assert "True|True|92" in response.get_data(as_text=True)
    assert "1111" not in response.get_data(as_text=True)



def test_full_mesh_plus_applied_cognitor_endpoints_and_legacy_write_gate(web, monkeypatch):
    """A registered client is not a foreign peer, and legacy Mesh Apply is denied."""
    app, client, admin, guest, first_id = web
    login(client, admin)
    from nmc_models import NodeConnection
    from types import SimpleNamespace
    import sys
    mesh_a = base64.b64encode(b"c" * 32).decode()
    mesh_b = base64.b64encode(b"d" * 32).decode()
    client_key = base64.b64encode(b"e" * 32).decode()
    with app.app_context():
        magos02 = General(name="magos02", ip_pool="10.77.0.3/32",
                          role="Magos", endpoint="192.168.32.169",
                          listen_port=51820, public_key=mesh_a, private_key="")
        magos03 = General(name="magos03", ip_pool="10.77.0.4/32",
                          role="Magos", endpoint="192.168.32.172",
                          listen_port=51820, public_key=mesh_b, private_key="")
        db.session.add_all([magos02, magos03])
        db.session.flush()
        magos2_id, magos3_id = magos02.id, magos03.id
        db.session.add_all([
            NodeConnection(node1_id=first_id, node2_id=magos2_id),
            NodeConnection(node1_id=first_id, node2_id=magos3_id),
            NodeConnection(node1_id=magos2_id, node2_id=magos3_id),
            CognitorDraft(name="cognitor01", public_key=client_key,
                         vpn_address="10.77.0.5/32", parent_magos_id=magos3_id,
                         status="applied"),
        ])
        db.session.commit()

    known = {
        "magos01": [{"public_key": mesh_a, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25},
                    {"public_key": mesh_b, "allowed_ips": ["10.77.0.4/32"], "keepalive": 25}],
        "magos02": [{"public_key": KEY2, "allowed_ips": ["10.77.0.2/32"], "keepalive": 25},
                    {"public_key": mesh_b, "allowed_ips": ["10.77.0.4/32"], "keepalive": 25}],
        "magos03": [{"public_key": KEY2, "allowed_ips": ["10.77.0.2/32"], "keepalive": 25},
                    {"public_key": mesh_a, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25},
                    {"public_key": client_key, "allowed_ips": ["10.77.0.5/32"], "keepalive": 0}],
    }
    calls = []
    def mock_send(node, action, plan=None, operation_id=None):
        calls.append((node.name, action))
        assert action == "status"   # healthy client: no route-preview or mutations
        return {"active": True, "peers": list(known[node.name])}
    monkeypatch.setitem(sys.modules, "app", SimpleNamespace(_vpn_v2_send=mock_send))

    compared = client.get("/vpn/cognitors/mesh/reconcile")
    assert compared.status_code == 200
    values = {entry["node_name"]: entry for entry in compared.get_json()["results"]}
    assert all(entry["state"] == "in_sync" for entry in values.values())
    assert values["magos03"]["desired_peers"] == 3
    assert values["magos03"]["desired_mesh_peers"] == 2
    assert values["magos03"]["desired_cognitor_peers"] == 1
    assert values["magos03"]["unregistered_peers"] == 0
    checked = client.get("/vpn/cognitors/mesh/change-preview")
    assert checked.status_code == 200
    preview = {entry["node_name"]: entry for entry in checked.get_json()["results"]}
    assert preview["magos03"]["decision"] == "no_change"
    assert preview["magos03"]["remove"] == 0
    assert preview["magos03"]["transaction_available"] is False
    assert all(action == "status" for _, action in calls)

    legacy = client.post("/api/v2/vpn/mesh/operation",
        headers={"X-VPN-Explicit-Apply": "ENABLE_TEST_MESH"},
        json={"action": "route-transaction", "node_id": magos3_id,
              "expected_revision": "a" * 64, "operation_id": "00000000-0000-4000-8000-000000000001"})
    assert legacy.status_code == 409
    assert "Cognitor" in legacy.get_json()["error"]
    assert all(action == "status" for _, action in calls)
    # Even after access via URL/API, no write call is made.


def test_unknown_peer_with_applied_cognitor_does_not_offer_mesh_apply(web, monkeypatch):
    app, client, admin, _, magos_id = web
    login(client, admin)
    with app.app_context():
        db.session.add(CognitorDraft(
            name="client01", public_key=KEY, vpn_address="10.77.0.5/32",
            status="applied", parent_magos_id=magos_id))
        db.session.commit()
    from types import SimpleNamespace
    import sys
    unknown = base64.b64encode(b"x" * 32).decode()
    monkeypatch.setitem(sys.modules, "app", SimpleNamespace(
        _vpn_v2_send=lambda *args, **kwargs: {
            "active": True, "peers": [
                {"public_key": KEY, "allowed_ips": ["10.77.0.5/32"], "keepalive": 0},
                {"public_key": unknown, "allowed_ips": ["10.77.0.99/32"], "keepalive": 0}
            ]}))
    preview = client.get("/vpn/cognitors/mesh/change-preview")
    assert preview.status_code == 200
    row = preview.get_json()["results"][0]
    assert row["decision"] == "blocked"
    assert row["remove"] == 1
    assert row["transaction_available"] is False
    assert row["reason"] == "cognitor_managed_drift_requires_review"
