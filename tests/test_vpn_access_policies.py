"""VPN v2 policy draft safety: validation, CSRF, SQLite and no network writes."""
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest
from flask import Flask
from flask_login import LoginManager
from jinja2 import DictLoader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nmc_models import BaseUser, General, db
from nmc_api.access_policies import access_policies_bp
from vpn_cognitor_models import CognitorDraft
from vpn_protected_models import ProtectedNetworkDraft
from vpn_access_policy_models import AccessPolicyDraft
from vpn_access_policy_validation import AccessPolicyError, preview_policy, validate_policy


SOURCE = SimpleNamespace(
    id=17, name="cognitor01", vpn_address="10.77.0.5/32",
    status="applied", parent_magos_id=3)
TARGET = SimpleNamespace(
    id=22, name="db", network="172.16.40.10/32",
    status="inventory_only", parent_magos_id=2)


def build(**overrides):
    fields = dict(
        name="cognitor-db-ssh", source=SOURCE, target=TARGET, protocol="tcp",
        port="22", decision="allow", existing_rules=(),
    )
    fields.update(overrides)
    return validate_policy(**fields)


def test_valid_tcp_udp_and_icmp():
    result = build()
    assert result == {
        "name": "cognitor-db-ssh", "source_cognitor_id": 17,
        "target_object_id": 22, "protocol": "tcp",
        "destination_port": 22, "decision": "allow",
    }
    assert build(protocol="udp", port="0053", decision="deny")["destination_port"] == 53
    assert build(protocol="icmp", port="", decision="deny")["destination_port"] == 0


@pytest.mark.parametrize("override", [
    {"name": "../danger"},
    {"source": None},
    {"source": SimpleNamespace(**{**SOURCE.__dict__, "status": "revoked"})},
    {"source": SimpleNamespace(**{**SOURCE.__dict__, "status": "unknown"})},
    {"target": None},
    {"target": SimpleNamespace(**{**TARGET.__dict__, "status": "changed"})},
    {"protocol": "any"},
    {"protocol": "icmp", "port": "22"},
    {"protocol": "tcp", "port": ""},
    {"protocol": "udp", "port": "0"},
    {"protocol": "tcp", "port": "65536"},
    {"protocol": "tcp", "port": "22-24"},
    {"protocol": "tcp", "port": "-1"},
    {"decision": "permit"},
    {"source": SimpleNamespace(**{**SOURCE.__dict__, "parent_magos_id": None})},
    {"target": SimpleNamespace(**{**TARGET.__dict__, "network": "10.77.0.5/32"})},
    {"existing_rules": [SimpleNamespace(
        source_cognitor_id=17, target_object_id=22,
        protocol="tcp", destination_port=22, decision="deny")]},
])
def test_reject_unsafe_or_ambiguous_policy(override):
    with pytest.raises(AccessPolicyError):
        build(**override)


def test_draft_client_may_be_selected_for_draft_policy_but_never_for_apply():
    pending = SimpleNamespace(**{**SOURCE.__dict__, "status": "draft"})
    assert build(source=pending)["source_cognitor_id"] == pending.id
    rule = SimpleNamespace(
        name="pending-ssh", source_cognitor=pending, target_object=TARGET,
        protocol="tcp", destination_port=22, decision="allow", status="draft")
    preview = preview_policy(rule)
    assert preview["source_registration_status"] == "draft"
    assert preview["source_prepared"] is False
    assert preview["apply_available"] is False
    assert preview["writes_performed"] is False


def test_preview_never_claims_effective_enforcement():
    rule = SimpleNamespace(
        id=1, name="allow-ssh", source_cognitor=SOURCE, target_object=TARGET,
        protocol="tcp", destination_port=22, decision="allow", status="draft")
    result = preview_policy(rule)
    assert result["cross_magos"] is True
    assert result["result"] == "inventory_only"
    assert result["routing_verified"] is False
    assert result["firewall_installed"] is False
    assert result["traffic_filtered"] is False
    assert result["writes_performed"] is False
    assert result["apply_available"] is False
    rule.destination_port = 0
    with pytest.raises(AccessPolicyError):
        preview_policy(rule)


@pytest.fixture
def web(tmp_path):
    app = Flask("policy-test")
    app.config.update(
        SECRET_KEY="only-for-tests",
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "policies.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_ENABLED=True, TESTING=True,
    )
    app.jinja_loader = DictLoader({
        "vpn_access_policies.html":
            "<form>{{ form.hidden_tag() }}{{ form.name() }}"
            "{{ form.source_cognitor_id() }}{{ form.target_object_id() }}"
            "{{ form.protocol() }}{{ form.destination_port() }}"
            "{{ form.decision() }}</form>"
            "{% for rule in rules %}{{ rule.name }}|{{ rule.status }}{% endfor %}"
            "{% for item in legacy_clients %}{{ item.name }}{% endfor %}"
            "{% for item in unresolved_clients %}{{ item.status }}{% endfor %}",
        "vpn_access_policy_preview.html":
            "{% if result %}{{ result.result }}|{{ result.cross_magos }}"
            "|{{ result.apply_available }}|{{ result.writes_performed }}"
            "{% else %}{{ problem }}{% endif %}",
    })
    db.init_app(app)
    logins = LoginManager(app)

    @logins.user_loader
    def load_user(uid):
        return db.session.get(BaseUser, int(uid))

    app.register_blueprint(access_policies_bp)
    with app.app_context():
        db.create_all()
        admin = BaseUser(email="admin", password_hash="x", role="admin")
        viewer = BaseUser(email="viewer", password_hash="x", role="user")
        omni = General(name="omni01", ip_pool="10.77.0.0/24", role="Omnissiah",
                       endpoint="192.168.32.167", listen_port=51820,
                       private_key="", public_key="")
        magos02 = General(name="magos02", ip_pool="10.77.0.3/32", role="Magos",
                          endpoint="192.168.32.169", listen_port=51820,
                          private_key="", public_key="")
        magos03 = General(name="magos03", ip_pool="10.77.0.4/32", role="Magos",
                          endpoint="192.168.32.172", listen_port=51820,
                          private_key="", public_key="")
        db.session.add_all([admin, viewer, omni, magos02, magos03])
        db.session.flush()
        client = CognitorDraft(
            name="cognitor01", vpn_address="10.77.0.5/32",
            public_key="A" * 43 + "=", parent_magos_id=magos03.id, status="applied")
        resource = ProtectedNetworkDraft(
            name="database", network="172.16.40.10/32",
            parent_magos_id=magos02.id, description="", status="inventory_only")
        db.session.add_all([client, resource])
        db.session.commit()
        ids = (admin.id, viewer.id, client.id, resource.id)
    return app, app.test_client(), ids


def login(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = str(user)
        session["_fresh"] = True


def csrf(client):
    html = client.get("/vpn/access-policies").get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, html[:300]
    return match.group(1)


def submit(client, ids, **overrides):
    _, _, client_id, target_id = ids
    data = {
        "name": "ssh-policy",
        "source_cognitor_id": str(client_id),
        "target_object_id": str(target_id),
        "protocol": "tcp", "destination_port": "22", "decision": "allow",
        "csrf_token": csrf(client),
    }
    data.update(overrides)
    return client.post("/vpn/access-policies", data=data)


def test_read_write_access_and_csrf(web):
    app, client, (admin, viewer, src, dst) = web
    assert client.get("/vpn/access-policies").status_code in (302, 401)
    assert client.get("/vpn/access-policies/1/preview").status_code in (302, 401)
    login(client, viewer)
    assert client.get("/vpn/access-policies").status_code == 403
    assert client.post("/vpn/access-policies", data={}).status_code == 403
    login(client, admin)
    for invalid in ("", "fake"):
        assert client.post("/vpn/access-policies", data={
            "name": "bad", "source_cognitor_id": str(src),
            "target_object_id": str(dst), "protocol": "tcp",
            "destination_port": "22", "decision": "allow",
            "csrf_token": invalid,
        }).status_code == 200
    with app.app_context():
        assert AccessPolicyDraft.query.count() == 0


def test_create_and_preview_only_no_commands(web, monkeypatch):
    import subprocess
    app, client, ids = web
    login(client, ids[0])

    def forbidden(*args, **kwargs):
        raise AssertionError("Policy drafts must not call a network subprocess")

    monkeypatch.setattr(subprocess, "run", forbidden)
    response = submit(client, ids)
    assert response.status_code == 302
    with app.app_context():
        saved = AccessPolicyDraft.query.one()
        assert saved.status == "draft"
        assert saved.decision == "allow"
        assert saved.destination_port == 22
        saved_id = saved.id
    page = client.get("/vpn/access-policies")
    assert "ssh-policy|draft" in page.get_data(as_text=True)
    preview = client.get(f"/vpn/access-policies/{saved_id}/preview")
    assert preview.status_code == 200
    assert "inventory_only|True|False|False" in preview.get_data(as_text=True)


def test_conflicting_and_repeated_rule_rejected(web):
    app, client, ids = web
    login(client, ids[0])
    assert submit(client, ids).status_code == 302
    assert submit(client, ids, name="deny-same", decision="deny").status_code == 200
    assert submit(client, ids, name="duplicate-other-name").status_code == 200
    assert submit(client, ids, name="ssh-policy", destination_port="443").status_code == 200
    with app.app_context():
        assert AccessPolicyDraft.query.count() == 1


def test_forged_source_or_unsafe_port_rejected(web):
    app, client, ids = web
    login(client, ids[0])
    assert submit(client, ids, source_cognitor_id="99999").status_code == 200
    assert submit(client, ids, destination_port="65536").status_code == 200
    assert submit(client, ids, protocol="icmp", destination_port="22").status_code == 200
    with app.app_context():
        assert AccessPolicyDraft.query.count() == 0


def test_pending_cognitor_visible_and_policy_is_draft_only(web):
    app, client, ids = web
    login(client, ids[0])
    with app.app_context():
        registered = db.session.get(CognitorDraft, ids[2])
        registered.status = "draft"
        db.session.commit()
    listing = client.get("/vpn/access-policies").get_data(as_text=True)
    assert "черновик, пока не применён" in listing
    assert submit(client, ids).status_code == 302
    with app.app_context():
        saved = AccessPolicyDraft.query.one()
        assert saved.status == "draft"
        preview_id = saved.id
    response = client.get(f"/vpn/access-policies/{preview_id}/preview")
    assert response.status_code == 200
    assert "inventory_only|True|False|False" in response.get_data(as_text=True)


def test_legacy_cognitor_is_visible_diagnostic_but_never_persisted_as_policy(web):
    app, client, ids = web
    login(client, ids[0])
    with app.app_context():
        magos = General.query.filter_by(name="magos03").one()
        legacy = General(
            name="legacy-cognitor", role="Cognitor",
            parent_id=magos.id, ip_pool="10.77.0.10/32",
            endpoint="192.168.32.190", listen_port=51820,
            private_key="", public_key="")
        db.session.add(legacy)
        db.session.commit()
        legacy_id = legacy.id
    page = client.get("/vpn/access-policies").get_data(as_text=True)
    # Template fixture below exposes diagnostic legacy entries, never as a select option.
    assert "legacy-cognitor" in page
    assert f'value="{legacy_id}"' not in page.split("</select>")[0]
    assert submit(client, ids, source_cognitor_id=str(legacy_id)).status_code == 200
    with app.app_context():
        assert AccessPolicyDraft.query.count() == 0


def test_unknown_cognitor_state_displayed_but_not_selectable(web):
    app, client, ids = web
    login(client, ids[0])
    with app.app_context():
        registered = db.session.get(CognitorDraft, ids[2])
        registered.status = "recovery_required"
        db.session.commit()
    page = client.get("/vpn/access-policies").get_data(as_text=True)
    assert "recovery_required" in page
    assert submit(client, ids).status_code == 200
    with app.app_context():
        assert AccessPolicyDraft.query.count() == 0
