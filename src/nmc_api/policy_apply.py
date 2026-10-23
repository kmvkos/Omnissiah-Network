"""Controlled per-Magos policy preview and explicitly confirmed nftables Apply.

Only VPN v2 CognitorDraft(status=applied) and ProtectedNetworkDraft objects.
No legacy iptables, SSH, route or WireGuard mutation. Full desired snapshot
is sent via the existing authenticated mTLS Magos control channel.
"""
import logging
import os
from collections import defaultdict
from uuid import uuid4

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm

from nmc_models import General, db
from vpn_cognitor_models import CognitorDraft
from vpn_protected_models import ProtectedNetworkDraft
from vpn_access_policy_models import AccessPolicyDraft

policy_apply_bp = Blueprint("policy_apply", __name__)
LOG = logging.getLogger(__name__)


class PolicyPlanError(ValueError):
    pass


def build_magos_policy_plan(magos_id):
    node = db.session.get(General, magos_id)
    if node is None or node.role != "Magos":
        raise PolicyPlanError("Неизвестный Magos")
    clients = CognitorDraft.query.filter_by(parent_magos_id=magos_id).all()
    all_rules = AccessPolicyDraft.query.order_by(AccessPolicyDraft.id).all()
    registered = {c.id: c for c in clients}
    source_ids = {r.source_cognitor_id for r in all_rules if r.source_cognitor_id in registered}
    if not source_ids:
        raise PolicyPlanError("Нет правил для клиентов этого Magos")
    resources = {obj.id: obj for obj in ProtectedNetworkDraft.query.all()}
    entries = defaultdict(lambda: defaultdict(list))
    for rule in all_rules:
        if rule.source_cognitor_id not in source_ids:
            continue
        client = registered[rule.source_cognitor_id]
        if client.status != "applied":
            raise PolicyPlanError("У Cognitor есть правило, но применение его WireGuard-пира не подтверждено")
        if rule.status not in ("draft", "applied"):
            raise PolicyPlanError("Обнаружено неизвестное состояние политики")
        obj = resources.get(rule.target_object_id)
        if obj is None or obj.status != "inventory_only":
            raise PolicyPlanError("Защищаемый объект отсутствует или требует проверки")
        if rule.protocol not in ("tcp", "udp", "icmp") or rule.decision not in ("allow", "deny", "reject"):
            raise PolicyPlanError("Неверный протокол/действие в сохранённой политике")
        if type(rule.destination_port) is not int:
            raise PolicyPlanError("Неверный порт в сохранённом правиле")
        entries[client.id][obj.id].append({
            "protocol": rule.protocol, "port": rule.destination_port,
            "decision": rule.decision,
        })
    plan_clients = []
    for client_id, grouped in entries.items():
        client = registered[client_id]
        targets = []
        for resource_id, rules in grouped.items():
            obj = resources[resource_id]
            targets.append({
                "network": obj.network,
                "via_magos": obj.parent_magos_id != node.id,
                "rules": rules,
            })
        plan_clients.append({
            "name": client.name, "address": client.vpn_address,
            "public_key": client.public_key, "targets": targets,
        })
    return node, {
        "node_name": node.name, "address": node.ip_pool,
        "clients": plan_clients,
    }


@policy_apply_bp.route("/access-policy/apply/<int:magos_id>/preview", methods=["GET"])
@login_required
def access_policy_apply_preview(magos_id):
    if current_user.role != "admin":
        abort(403)
    result, problem, node, count, actual = None, None, None, 0, None
    node = db.session.get(General, magos_id)
    if node is None or node.role != "Magos":
        abort(404)
    try:
        from app import _vpn_v2_send
        actual = _vpn_v2_send(node, "policy-status")
        if not isinstance(actual, dict) or actual.get("writes_performed") is not False:
            actual = None
        node, plan = build_magos_policy_plan(magos_id)
        count = sum(len(t["rules"]) for c in plan["clients"] for t in c["targets"])
        from app import _vpn_v2_send
        result = _vpn_v2_send(node, "policy-preview", plan)
        if (not isinstance(result, dict)
                or result.get("writes_performed") is not False
                or result.get("route_preflight_ok") is not True
                or not isinstance(result.get("revision"), str)
                or len(result["revision"]) != 64):
            result = None
            problem = "Magos вернул непроверенный результат"
    except Exception:
        LOG.warning("VPN ACL preview rejected for magos_id=%s", magos_id, exc_info=True)
        problem = "Проверка на Magos не пройдена: проверьте WireGuard, маршруты и nftables"
    return render_template(
        "access_policy_apply_preview.html",
        magos=node, magos_id=magos_id, rule_count=count, result=result,
        problem=problem, actual=actual, confirmation=FlaskForm(),
        enabled=os.environ.get("VPN_POLICY_APPLY_ENABLED") == "YES",
    )


@policy_apply_bp.route("/access-policy/apply/<int:magos_id>", methods=["POST"])
@login_required
def access_policy_apply(magos_id):
    if current_user.role != "admin":
        abort(403)
    if not FlaskForm().validate_on_submit():
        abort(400)
    if os.environ.get("VPN_POLICY_APPLY_ENABLED") != "YES":
        abort(403)
    revision = request.form.get("expected_revision", "")
    if len(revision) != 64 or any(c not in "0123456789abcdef" for c in revision):
        abort(400)
    node, plan = build_magos_policy_plan(magos_id)
    if request.form.get("confirm_name") != node.name:
        flash("Имя Magos не совпадает; применение отменено", "danger")
        return redirect(url_for("policy_apply.access_policy_apply_preview", magos_id=magos_id))
    operation_id = str(uuid4())
    try:
        # Never implicitly retry an unknown result. Root checks revision,
        # peer identities, actual routes, nft ownership and applies atomically.
        from app import _vpn_v2_send
        result = _vpn_v2_send(
            node, "policy-apply", {**plan, "expected_revision": revision},
            operation_id=operation_id)
        if (not isinstance(result, dict)
                or result.get("state") != "committed"
                or result.get("revision") != revision
                or result.get("operation_id") != operation_id):
            raise ValueError("Commit not acknowledged")
    except Exception:
        LOG.error("VPN ACL apply outcome UNKNOWN magos=%s UUID=%s; DO NOT REPEAT",
                  node.name, operation_id, exc_info=True)
        flash("Результат применения не подтверждён. Не повторяйте Apply. "
              "Проверьте журнал Magos. UUID: " + operation_id, "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    rules = AccessPolicyDraft.query.all()
    client_ids = {c.id for c in CognitorDraft.query.filter_by(parent_magos_id=magos_id).all()}
    for rule in rules:
        if rule.source_cognitor_id in client_ids:
            rule.status = "applied"
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        LOG.critical("ACL committed on Magos but DB state not confirmed. UUID=%s", operation_id)
        flash("Magos применил ACL, но запись в БД не подтверждена. Не повторяйте операцию.", "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    flash("ACL на " + node.name + " применён. Проверьте фактический доступ с Cognitor.", "success")
    return redirect(url_for("access_policies.vpn_access_policies"))


@policy_apply_bp.route("/access-policy/apply/<int:magos_id>/rollback", methods=["POST"])
@login_required
def access_policy_rollback(magos_id):
    if current_user.role != "admin":
        abort(403)
    if not FlaskForm().validate_on_submit():
        abort(400)
    if os.environ.get("VPN_POLICY_APPLY_ENABLED") != "YES":
        abort(403)
    node = db.session.get(General, magos_id)
    if node is None or node.role != "Magos":
        abort(404)
    if request.form.get("confirm_name") != node.name:
        flash("Неправильное имя Magos; откат отменён", "danger")
        return redirect(url_for("policy_apply.access_policy_apply_preview", magos_id=magos_id))
    revision = request.form.get("expected_revision", "")
    if len(revision) != 64 or any(c not in "0123456789abcdef" for c in revision):
        abort(400)
    operation_id = str(uuid4())
    try:
        from app import _vpn_v2_send
        result = _vpn_v2_send(
            node, "policy-rollback",
            {"node_name": node.name, "address": node.ip_pool,
             "expected_revision": revision},
            operation_id=operation_id)
        if (not isinstance(result, dict)
                or result.get("state") != "rolled_back"
                or result.get("operation_id") != operation_id):
            raise ValueError("Rollback not acknowledged")
    except Exception:
        LOG.error("ACL rollback UNKNOWN magos=%s UUID=%s", node.name,
                  operation_id, exc_info=True)
        flash("Итог отката не подтверждён. Не повторяйте без проверки Magos. UUID: "
              + operation_id, "danger")
        return redirect(url_for("policy_apply.access_policy_apply_preview", magos_id=magos_id))
    # A rollback can restore another revision: do not claim per-rule statuses
    # until a desired-vs-actual reconciliation exists.
    flash("На Magos восстановлена предыдущая ACL. Статусы отдельных правил "
          "в БД требуют сверки с фактической ревизией.", "warning")
    return redirect(url_for("policy_apply.access_policy_apply_preview", magos_id=magos_id))
