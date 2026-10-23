"""Controller policy path: source ownership, mTLS live preview, opt-in and status."""
import importlib.util
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest
from flask import Flask
from flask_login import LoginManager
from jinja2 import DictLoader

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
from nmc_models import db, General, BaseUser
from nmc_api.policy_apply import policy_apply_bp, build_magos_policy_plan, PolicyPlanError
from nmc_api.access_policies import access_policies_bp
from vpn_cognitor_models import CognitorDraft
from vpn_protected_models import ProtectedNetworkDraft
from vpn_access_policy_models import AccessPolicyDraft


@pytest.fixture
def site(tmp_path, monkeypatch):
    app = Flask("controller-policy-tests")
    app.config.update(
        SECRET_KEY="test-secret",
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "db.sqlite"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_ENABLED=True,
        TESTING=True,
    )
    app.jinja_loader = DictLoader({
        "access_policy_apply_preview.html":
            "<form>{{ confirmation.hidden_tag() }}</form>"
            "{% if result %}{{ result.revision }}|{{ result.rule_count }}{% endif %}"
            "{% if problem %}{{problem}}{% endif %}"
            "{% if actual %}{{actual.active_revision}}{% endif %}",
    })
    db.init_app(app)
    login = LoginManager(app)

    @login.user_loader
    def user_loader(uid):
        return db.session.get(BaseUser, int(uid))

    app.register_blueprint(policy_apply_bp)
    app.register_blueprint(access_policies_bp)
    with app.app_context():
        db.create_all()
        admin = BaseUser(email="admin", password_hash="test", role="admin")
        reader = BaseUser(email="viewer", password_hash="test", role="user")
        omni = General(name="omni01", ip_pool="10.77.0.0/24",
                       role="Omnissiah", endpoint="192.168.32.167",
                       listen_port=51820, private_key="", public_key="")
        magos01 = General(name="magos01", ip_pool="10.77.0.2/32",
                          role="Magos", endpoint="192.168.32.168",
                          listen_port=51820, private_key="", public_key="")
        magos03 = General(name="magos03", ip_pool="10.77.0.4/32",
                          role="Magos", endpoint="192.168.32.172",
                          listen_port=51820, private_key="", public_key="")
        db.session.add_all([admin, reader, omni, magos01, magos03])
        db.session.flush()
        client = CognitorDraft(
            name="cognitor01", vpn_address="10.77.0.5/32",
            public_key="A" * 43 + "=", parent_magos_id=magos03.id,
            status="applied")
        resource = ProtectedNetworkDraft(
            name="app-db", network="172.16.40.10/32",
            parent_magos_id=magos01.id, status="inventory_only",
            description="Lab DB")
        db.session.add_all([client, resource])
        db.session.flush()
        rule = AccessPolicyDraft(
            name="allow-db-ssh", source_cognitor_id=client.id,
            target_object_id=resource.id, protocol="tcp",
            destination_port=22, decision="allow", status="draft")
        db.session.add(rule)
        db.session.commit()
        identifiers = (admin.id, reader.id, magos03.id, client.id, rule.id)
    module = SimpleNamespace()
    calls = []

    def send(node, action, plan=None, operation_id=None):
        calls.append((node.name, action, plan, operation_id))
        if action == "policy-status":
            return {"active_revision": None, "writes_performed": False}
        if action == "policy-preview":
            return {"revision": "a" * 64, "rule_count": 1,
                    "client_count": 1, "target_count": 1,
                    "route_preflight_ok": True, "writes_performed": False}
        if action == "policy-apply":
            return {"state": "committed", "revision": plan["expected_revision"],
                    "operation_id": operation_id}
        raise AssertionError("Unexpected mTLS command")

    module._vpn_v2_send = send
    monkeypatch.setitem(sys.modules, "app", module)
    return app, app.test_client(), identifiers, calls


def login(client, uid):
    with client.session_transaction() as session:
        session["_user_id"] = str(uid)
        session["_fresh"] = True


def token(client, mid):
    html = client.get(f"/access-policy/apply/{mid}/preview").get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_policy_plan_uses_managed_cognitor_and_destination_owner(site):
    app, client, (_, _, magos_id, _, _), calls = site
    with app.app_context():
        node, plan = build_magos_policy_plan(magos_id)
        assert node.name == "magos03"
        assert plan["clients"][0]["name"] == "cognitor01"
        assert plan["clients"][0]["targets"][0]["via_magos"] is True
        assert plan["clients"][0]["targets"][0]["network"] == "172.16.40.10/32"
    assert calls == []


def test_controller_live_preview_read_only_and_auth(site):
    app, client, (admin, reader, mid, _, _), calls = site
    assert client.get(f"/access-policy/apply/{mid}/preview").status_code in (302, 401)
    login(client, reader)
    assert client.get(f"/access-policy/apply/{mid}/preview").status_code == 403
    login(client, admin)
    response = client.get(f"/access-policy/apply/{mid}/preview")
    assert response.status_code == 200
    assert "a" * 64 in response.get_data(as_text=True)
    assert [c[1] for c in calls[-2:]] == ["policy-status", "policy-preview"]
    assert all(c[1] not in ("policy-apply", "policy-rollback") for c in calls)


def test_disabled_apply_rejects_without_mtls_write(site, monkeypatch):
    app, client, (admin, _, mid, _, _), calls = site
    login(client, admin)
    monkeypatch.delenv("VPN_POLICY_APPLY_ENABLED", raising=False)
    cs = token(client, mid)
    before = len(calls)
    result = client.post(f"/access-policy/apply/{mid}", data={
        "csrf_token": cs, "confirm_name": "magos03", "expected_revision": "a" * 64,
    })
    assert result.status_code == 403
    assert len(calls) == before


def test_confirmed_apply_requires_name_and_revision(site, monkeypatch):
    app, client, (admin, _, mid, _, rid), calls = site
    login(client, admin)
    monkeypatch.setenv("VPN_POLICY_APPLY_ENABLED", "YES")
    cs = token(client, mid)
    bad = client.post(f"/access-policy/apply/{mid}", data={
        "csrf_token": cs, "confirm_name": "magos01",
        "expected_revision": "a" * 64,
    })
    assert bad.status_code == 302
    assert "policy-apply" not in [c[1] for c in calls]
    okay = client.post(f"/access-policy/apply/{mid}", data={
        "csrf_token": cs, "confirm_name": "magos03",
        "expected_revision": "a" * 64,
    })
    assert okay.status_code == 302
    assert [c[1] for c in calls if c[1] == "policy-apply"] == ["policy-apply"]
    with app.app_context():
        assert db.session.get(AccessPolicyDraft, rid).status == "applied"


def test_pending_client_blocks_snapshot(site):
    app, client, (_, _, mid, cid, _), calls = site
    with app.app_context():
        db.session.get(CognitorDraft, cid).status = "draft"
        db.session.commit()
        with pytest.raises(PolicyPlanError):
            build_magos_policy_plan(mid)
    assert calls == []


def test_legacy_record_does_not_enter_policy_plan(site):
    app, client, (_, _, mid, _, _), calls = site
    with app.app_context():
        node = General.query.filter_by(name="magos03").one()
        legacy = General(name="legacy01", role="Cognitor", parent_id=node.id,
                         ip_pool="10.77.0.12/32", endpoint="192.168.32.190",
                         listen_port=51820, private_key="", public_key="")
        db.session.add(legacy)
        db.session.commit()
        _, plan = build_magos_policy_plan(mid)
        assert len(plan["clients"]) == 1
        assert plan["clients"][0]["name"] == "cognitor01"
