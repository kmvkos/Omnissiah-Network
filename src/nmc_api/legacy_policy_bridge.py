"""Disable the legacy policy editor / REST mutations in managed VPN v2.

The old editor uses General/ProtectedObject and may send iptables/SSH commands.
Never replay, delete or migrate its live rules implicitly. This bridge changes
navigation and API availability only, not any existing network configuration.
"""
from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from nmc_models import AccessPolicyRule


legacy_policy_bridge_bp = Blueprint("legacy_policy_bridge", __name__)


@legacy_policy_bridge_bp.before_app_request
def retire_legacy_policy_entrypoints():
    path = request.path
    is_editor = (path == "/access_policy"
                 or path.startswith("/access_policy/node/")
                 or path.startswith("/access_policy/view/"))
    is_api = path == "/api/access_policy" or path.startswith("/api/access_policy/")
    if not (is_editor or is_api):
        return None
    # Guard before executing the old endpoint (including its side effects).
    # Return no record counts or other policy inventory to unauthorized users.
    if not current_user.is_authenticated:
        abort(401)
    if current_user.role != "admin":
        abort(403)
    if is_editor and request.method == "GET":
        return redirect(url_for("access_policies.vpn_access_policies"), code=302)
    if is_api:
        # Fail closed for both old write and read endpoints. The new read-only
        # archive below replaces the legacy SSH/iptables diagnostic APIs.
        return {
            "success": False,
            "error": ("Legacy Policy API отключён: он может изменять маршруты "
                      "и iptables через SSH. Используйте VPN v2 и журнал старых правил."),
        }, 410
    abort(405)


@legacy_policy_bridge_bp.route("/vpn/access-policies/legacy", methods=["GET"])
@login_required
def vpn_legacy_policy_archive():
    if current_user.role != "admin":
        abort(403)
    rules = AccessPolicyRule.query.order_by(AccessPolicyRule.id.desc()).all()
    return render_template("vpn_legacy_policy_archive.html", rules=rules)
