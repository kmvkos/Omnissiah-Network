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
