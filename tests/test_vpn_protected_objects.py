"""Protected-object inventory tests; never require WireGuard or a root helper."""
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask
from flask_login import LoginManager
from jinja2 import DictLoader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nmc_models import BaseUser, General, db
from nmc_api.protected_objects import protected_objects_bp
from vpn_protected_models import ProtectedNetworkDraft
from vpn_protected_validation import ProtectedResourceError, validate_protected_object


OWNER = SimpleNamespace(id=3, role="Magos")


def valid(**changes):
    kwargs = dict(name="database", network="172.16.40.10/32",
                  description="Production DB", parent=OWNER,
                  registered_networks=[], vpn_pool="10.77.0.0/24",
                  management_ips=["192.168.32.167", "192.168.32.172"])
    kwargs.update(changes)
    return validate_protected_object(**kwargs)


def test_valid_host_and_subnet_inventory():
    assert valid()["network"] == "172.16.40.10/32"
    assert valid(network="172.16.50.0/24")["network"] == "172.16.50.0/24"


@pytest.mark.parametrize("overrides", [
    dict(network="0.0.0.0/0"),
    dict(network="10.77.0.5/32"),
    dict(network="192.168.32.0/24"),
    dict(network="172.16.40.0/24", registered_networks=["172.16.40.10/32"]),
    dict(network="172.16.40.10/24"),
    dict(network="127.0.0.1/32"),
    dict(network="224.0.0.1/32"),
    dict(network="169.254.1.1/32"),
    dict(name="../../malicious"),
    dict(parent=SimpleNamespace(id=5, role="Omnissiah")),
])
def test_network_and_ownership_rejections(overrides):
    with pytest.raises(ProtectedResourceError):
        valid(**overrides)


@pytest.fixture
def web(tmp_path):
    app = Flask("protected-object-test")
    app.config.update(
        SECRET_KEY="tests-not-production",
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "objects.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_ENABLED=True,
        TESTING=True,
    )
    app.jinja_loader = DictLoader({
        "vpn_protected_objects.html":
            "<form>{{ form.hidden_tag() }}{{ form.name() }}"
            "{{ form.network() }}{{ form.description() }}"
            "{{ form.parent_magos_id() }}</form>"
            "{% for obj in objects %}{{ obj.name }}|{{ obj.network }}{% endfor %}",
    })
    db.init_app(app)
    logins = LoginManager(app)

    @logins.user_loader
    def load_user(uid):
        return db.session.get(BaseUser, int(uid))

    app.register_blueprint(protected_objects_bp)
    with app.app_context():
        db.create_all()
        root = BaseUser(email="admin", password_hash="x", role="admin")
        guest = BaseUser(email="reader", password_hash="x", role="user")
        omni = General(name="omni01", ip_pool="10.77.0.0/24", role="Omnissiah",
                       endpoint="192.168.32.167", listen_port=51820,
                       public_key="", private_key="")
        magos = General(name="magos03", ip_pool="10.77.0.4/32", role="Magos",
                        endpoint="192.168.32.172", listen_port=51820,
                        public_key="", private_key="")
        db.session.add_all([root, guest, omni, magos])
        db.session.commit()
        root_id, guest_id, magos_id = root.id, guest.id, magos.id
    return app, app.test_client(), root_id, guest_id, magos_id


def login(client, user_id):
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def csrf(client):
    html = client.get("/vpn/protected-objects").get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, html[:300]
    return match.group(1)


def test_auth_and_csrf_fail_closed(web):
    app, client, admin, reader, magos = web
    assert client.get("/vpn/protected-objects").status_code in (302, 401)
    login(client, reader)
    assert client.get("/vpn/protected-objects").status_code == 403
    assert client.post("/vpn/protected-objects", data={}).status_code == 403
    login(client, admin)
    for forged_token in ("", "bad"):
        response = client.post("/vpn/protected-objects", data={
            "name": "db01", "network": "172.16.40.10/32",
            "parent_magos_id": str(magos), "csrf_token": forged_token,
        })
        assert response.status_code == 200
    with app.app_context():
        assert ProtectedNetworkDraft.query.count() == 0


def test_registration_does_not_mutate_network(web, monkeypatch):
    app, client, admin, _, magos = web
    login(client, admin)
    import subprocess

    def must_never_execute(*args, **kwargs):
        raise AssertionError("Inventory cannot start root/network subprocesses")

    monkeypatch.setattr(subprocess, "run", must_never_execute)
    response = client.post("/vpn/protected-objects", data={
        "name": "db01", "network": "172.16.40.10/32",
        "description": "database",
        "parent_magos_id": str(magos), "csrf_token": csrf(client),
    })
    assert response.status_code == 302
    with app.app_context():
        rows = ProtectedNetworkDraft.query.all()
        assert len(rows) == 1
        assert rows[0].status == "inventory_only"
        assert rows[0].parent_magos_id == magos
        assert rows[0].network == "172.16.40.10/32"
    assert "db01|172.16.40.10/32" in client.get(
        "/vpn/protected-objects").get_data(as_text=True)


def test_overlap_fails_without_second_object(web):
    app, client, admin, _, magos = web
    login(client, admin)
    def submit(name, network):
        return client.post("/vpn/protected-objects", data={
            "name": name, "network": network,
            "parent_magos_id": str(magos), "csrf_token": csrf(client),
        })
    assert submit("db01", "172.16.40.10/32").status_code == 302
    assert submit("db02", "172.16.40.0/24").status_code == 200
    assert submit("db03", "0.0.0.0/0").status_code == 200
    with app.app_context():
        assert ProtectedNetworkDraft.query.count() == 1
