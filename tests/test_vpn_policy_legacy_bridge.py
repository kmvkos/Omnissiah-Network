"""Legacy policy editor is retired without deleting live iptables or DB rules."""
from pathlib import Path
import sys

import pytest
from flask import Flask
from flask_login import LoginManager
from jinja2 import DictLoader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nmc_models import db, BaseUser, AccessPolicyRule
from nmc_api.legacy_policy_bridge import legacy_policy_bridge_bp
from nmc_api.access_policies import access_policies_bp


@pytest.fixture
def web(tmp_path):
    app = Flask("vpn-policy-unified-test")
    app.config.update(
        SECRET_KEY="only-for-tests",
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(tmp_path / "legacy-policy.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        TESTING=True,
    )
    app.jinja_loader = DictLoader({
        "vpn_legacy_policy_archive.html":
            "Legacy rules: {{ rules|length }} "
            "{% for rule in rules %}{{rule.id}}|{{rule.get_source_display()}}"
            "|{{rule.get_destination_display()}}|{{rule.status}}{% endfor %}",
    })
    db.init_app(app)
    manager = LoginManager(app)

    @manager.user_loader
    def load_user(uid):
        return db.session.get(BaseUser, int(uid))

    # Register the real endpoint so the redirect verifies blueprint wiring.
    app.register_blueprint(access_policies_bp)

    effects = []

    @app.route("/access_policy")
    @app.route("/access_policy/node/<int:node_id>")
    @app.route("/access_policy/view/<int:rule_id>")
    def old_editor(node_id=None, rule_id=None):
        effects.append("old-editor")
        return "INSECURE OLD EDITOR"

    @app.route("/api/access_policy/rules", methods=["POST"])
    @app.route("/api/access_policy/apply_all", methods=["POST"])
    @app.route("/api/access_policy/reapply_all", methods=["POST"])
    @app.route("/api/access_policy/cleanup_orphaned", methods=["POST"])
    @app.route("/api/access_policy/rules/5/save", methods=["POST"])
    @app.route("/api/access_policy/rules/5/apply", methods=["POST"])
    @app.route("/api/access_policy/rules/5", methods=["DELETE"])
    @app.route("/api/access_policy/rules/list", methods=["GET"])
    def old_api():
        effects.append("old-network-mutation")
        return "SHOULD NEVER BE EXECUTED"

    app.register_blueprint(legacy_policy_bridge_bp)
    with app.app_context():
        db.create_all()
        admin = BaseUser(email="admin", password_hash="x", role="admin")
        user = BaseUser(email="viewer", password_hash="x", role="user")
        db.session.add_all([admin, user])
        db.session.flush()
        db.session.add(AccessPolicyRule(
            source_type="network", source_network="10.77.0.5/32",
            destination_type="network", destination_network="172.16.40.10/32",
            protocol="tcp", ports="22", action="ACCEPT",
            status="applied", configuration_snapshot="NEVER SHOW SECRET STATE",
        ))
        db.session.commit()
        users = (admin.id, user.id)
    return app, app.test_client(), users, effects


def login(client, uid):
    with client.session_transaction() as session:
        session["_user_id"] = str(uid)
        session["_fresh"] = True


@pytest.mark.parametrize("old_url", (
    "/access_policy",
    "/access_policy/node/3",
    "/access_policy/view/1",
))
def test_old_editor_redirects_to_single_v2_ui(web, old_url):
    app, client, (admin, _), effects = web
    login(client, admin)
    response = client.get(old_url)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/access-policy")
    assert effects == []


@pytest.mark.parametrize("method,path", (
    ("POST", "/api/access_policy/rules"),
    ("POST", "/api/access_policy/apply_all"),
    ("POST", "/api/access_policy/reapply_all"),
    ("POST", "/api/access_policy/cleanup_orphaned"),
    ("POST", "/api/access_policy/rules/5/save"),
    ("POST", "/api/access_policy/rules/5/apply"),
    ("DELETE", "/api/access_policy/rules/5"),
    ("GET", "/api/access_policy/rules/list"),
))
def test_old_policy_rest_api_is_retired_before_it_can_execute(web, method, path):
    app, client, (admin, _), effects = web
    login(client, admin)
    response = client.open(path, method=method)
    assert response.status_code == 410
    assert "Legacy Policy API" in response.get_json()["error"]
    assert effects == []
    with app.app_context():
        rule = AccessPolicyRule.query.one()
        assert rule.status == "applied"
        assert rule.configuration_snapshot == "NEVER SHOW SECRET STATE"


def test_legacy_archive_read_only_without_secrets(web):
    app, client, (admin, _), effects = web
    login(client, admin)
    response = client.get("/vpn/access-policies/legacy")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "10.77.0.5/32" in text
    assert "172.16.40.10/32" in text
    assert "applied" in text
    assert "NEVER SHOW SECRET STATE" not in text
    assert effects == []


@pytest.mark.parametrize("path", (
    "/access_policy", "/api/access_policy/apply_all",
    "/vpn/access-policies/legacy",
))
def test_legacy_access_denied_to_non_admin(web, path):
    app, client, (admin, user), effects = web
    method = "POST" if path.endswith("apply_all") else "GET"
    assert client.open(path, method=method).status_code in (401, 302)
    login(client, user)
    assert client.open(path, method=method).status_code == 403
    assert effects == []


def test_sidebar_points_to_v2_and_labels_old_as_archive():
    template = (Path(__file__).resolve().parents[1] / "templates/layout.html").read_text()
    assert "url_for('access_policies.vpn_access_policies')" in template
    assert "url_for('legacy_policy_bridge.vpn_legacy_policy_archive')" in template
    assert "url_for('access_policy')" not in template
