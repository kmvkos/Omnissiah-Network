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
from nmc_models import db, General, BaseUser, NodeConnection
from nmc_api.policy_apply import policy_apply_bp, build_magos_policy_plan, PolicyPlanError, inspect_cross_magos_paths
from nmc_api.access_policies import access_policies_bp
from nmc_api.cross_routes import cross_route_bp
from vpn_cross_route_models import CrossRouteOperation
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
    app.register_blueprint(cross_route_bp)
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
            parent_magos_id=magos03.id, status="inventory_only",
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
        assert plan["clients"][0]["targets"][0]["via_magos"] is False
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


def test_cross_magos_preview_has_explicit_blocker_and_no_apply(site):
    app, client, (admin, _, mid, _, _), calls = site
    with app.app_context():
        owner = General.query.filter_by(name="magos01").one()
        target = ProtectedNetworkDraft.query.one()
        target.parent_magos_id = owner.id
        db.session.commit()
    login(client, admin)
    response = client.get(f"/access-policy/apply/{mid}/preview")
    text = response.get_data(as_text=True)
    # The API never claims it can enforce an unverified mesh route.
    assert "WG AllowedIPs" in text or "другим Magos" in text
    assert not any(action == "policy-apply" for _, action, _, _ in calls)


def test_cross_magos_preview_queries_both_gated_root_sides_but_never_applies(site):
    app, client, (_, _, mid, _, _), _ = site
    with app.app_context():
        source = General.query.filter_by(name="magos03").one()
        destination = General.query.filter_by(name="magos01").one()
        source.public_key = "B" * 43 + "="
        destination.public_key = "C" * 43 + "="
        ProtectedNetworkDraft.query.one().parent_magos_id = destination.id
        db.session.add(NodeConnection(node1_id=source.id, node2_id=destination.id))
        db.session.commit()
        selected, plan = build_magos_policy_plan(mid)
        sent = []
        def probe(node, action, manifest):
            sent.append((node.name, action, manifest))
            return {
                "node_name": node.name, "role": manifest["role"],
                "required_allowed_ip": manifest["required_peer_allowed_ip"],
                "required_route": manifest["required_route"],
                "gateway_checks_passed": True, "blockers": [],
                "protected_host_return_verified": False,
                "cognitor_route_verified": False,
                "writes_performed": False,
            }
        checks = inspect_cross_magos_paths(selected, plan, probe)
        assert len(checks) == 1
        assert checks[0]["gateway_checks_passed"] is True
        assert [value[0] for value in sent] == ["magos03", "magos01"]
        assert all(value[1] == "policy-path-preview" for value in sent)
        assert sent[0][2]["required_peer_allowed_ip"] == "172.16.40.10/32"
        assert sent[1][2]["required_peer_allowed_ip"] == "10.77.0.5/32"


def test_cross_magos_fail_closed_when_direct_edge_is_missing(site):
    app, client, (_, _, mid, _, _), _ = site
    with app.app_context():
        source = General.query.filter_by(name="magos03").one()
        destination = General.query.filter_by(name="magos01").one()
        source.public_key = "B" * 43 + "="
        destination.public_key = "C" * 43 + "="
        ProtectedNetworkDraft.query.one().parent_magos_id = destination.id
        db.session.commit()
        selected, plan = build_magos_policy_plan(mid)
        calls = []
        def forbidden(*args):
            calls.append(args)
            raise AssertionError("Must not query without a direct edge")
        result = inspect_cross_magos_paths(selected, plan, forbidden)
        assert result[0]["gateway_checks_passed"] is False
        assert "direct mesh" in result[0]["error"]
        assert calls == []


def test_distributed_route_action_denied_by_default_and_without_confirmation(site, monkeypatch):
    app, client, (admin, _, mid, cid, _), calls = site
    login(client, admin)
    csrf = token(client, mid)
    with app.app_context():
        source = General.query.filter_by(name="magos03").one()
        destination = General.query.filter_by(name="magos01").one()
        source.public_key = "B"*43+"="
        destination.public_key = "C"*43+"="
        target = ProtectedNetworkDraft.query.one()
        target.parent_magos_id = destination.id
        obj_id = target.id
        db.session.add(NodeConnection(node1_id=source.id, node2_id=destination.id))
        db.session.commit()
    monkeypatch.delenv("VPN_CROSS_ROUTE_APPLY_ENABLED", raising=False)
    route = f"/access-policy/cross-route/{cid}/{obj_id}/apply"
    assert client.post(route, data={"csrf_token": csrf,
                       "confirm_path": "magos03->magos01"}).status_code == 403
    monkeypatch.setenv("VPN_CROSS_ROUTE_APPLY_ENABLED", "YES")
    response = client.post(route, data={"csrf_token": csrf,
                                      "confirm_path": "magos01->magos03"})
    assert response.status_code == 302
    with app.app_context():
        assert CrossRouteOperation.query.count() == 0
    assert not any(a[1].startswith("route-ext-") for a in calls)


def test_distributed_route_apply_journaled_before_writes(site, monkeypatch):
    app, client, (admin, _, mid, cid, _), calls = site
    login(client, admin)
    csrf = token(client, mid)
    with app.app_context():
        source = General.query.filter_by(name="magos03").one()
        destination = General.query.filter_by(name="magos01").one()
        source.public_key = "B"*43+"="
        destination.public_key = "C"*43+"="
        target = ProtectedNetworkDraft.query.one()
        target.parent_magos_id = destination.id
        obj_id = target.id
        db.session.add(NodeConnection(node1_id=source.id, node2_id=destination.id))
        db.session.commit()
    monkeypatch.setenv("VPN_CROSS_ROUTE_APPLY_ENABLED", "YES")
    calls.clear()
    def send(node, action, plan, operation_id=None):
        calls.append((node.name, action))
        if action == "route-ext-prepare":
            with app.app_context():
                # Persist an operation fence before the very first RPC.
                assert CrossRouteOperation.query.filter_by(
                    operation_id=operation_id, state="preparing").count() == 1
            return {"state": "prepared", "revision": "a"*64, "operation_id": operation_id}
        if action == "route-ext-commit":
            return {"state": "committed", "revision": plan["revision"],
                    "operation_id": operation_id}
        if action == "policy-path-preview":
            return {"gateway_checks_passed": True, "writes_performed": False}
        if action == "route-ext-finalize":
            return {"state": "finished", "operation_id": operation_id}
        raise AssertionError("Unexpected RPC " + action)
    monkeypatch.setattr(sys.modules["app"], "_vpn_v2_send", send)
    route = f"/access-policy/cross-route/{cid}/{obj_id}/apply"
    response = client.post(route, data={"csrf_token": csrf,
                                      "confirm_path": "magos03->magos01"})
    assert response.status_code == 302
    assert calls[:4] == [("magos03", "route-ext-prepare"),
                         ("magos01", "route-ext-prepare"),
                         ("magos01", "route-ext-commit"),
                         ("magos03", "route-ext-commit")]
    with app.app_context():
        operation = CrossRouteOperation.query.one()
        assert operation.state == "committed"
        assert operation.source_revision == "a"*64
        assert operation.destination_revision == "a"*64
