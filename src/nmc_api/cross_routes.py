"""Explicit, admin-only cross-Magos routing apply. Never runs during rule Save.

Client must confirm source/destination names. The DB operation UUID is stored
BEFORE root RPC. Unknown network outcomes block subsequent operations.
"""
import logging
import os
from uuid import uuid4

from flask import Blueprint, abort, flash, redirect, request, url_for
from flask_login import login_required, current_user
from flask_wtf import FlaskForm

from nmc_models import General, NodeConnection, db
from vpn_access_policy_models import AccessPolicyDraft
from vpn_cognitor_models import CognitorDraft
from vpn_protected_models import ProtectedNetworkDraft
from vpn_cross_route_models import CrossRouteOperation, CrossRouteLease
from sqlalchemy.exc import IntegrityError
from vpn_cross_magos_plan import plan_cross_magos, CrossPathRejected
from vpn_cross_route_coordinator import (
    CrossRouteCoordinationError, run_direct_route_transaction
)

cross_route_bp = Blueprint("cross_route", __name__)
LOG = logging.getLogger(__name__)
INFLIGHT = ("preparing", "prepared", "committing", "verifying",
            "finalizing", "reverting", "recovery_required")


@cross_route_bp.route("/access-policy/cross-route/<int:client_id>/<int:object_id>/apply",
                      methods=["POST"])
@login_required
def apply_cross_route(client_id, object_id):
    if current_user.role != "admin":
        abort(403)
    if not FlaskForm().validate_on_submit():
        abort(400)
    if os.environ.get("VPN_CROSS_ROUTE_APPLY_ENABLED") != "YES":
        abort(403)
    cognitor = db.session.get(CognitorDraft, client_id)
    resource = db.session.get(ProtectedNetworkDraft, object_id)
    if cognitor is None or resource is None:
        abort(404)
    if resource.status != "inventory_only" or cognitor.status != "applied":
        flash("Клиент или защищаемый объект не подтверждены", "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    rules = AccessPolicyDraft.query.filter_by(
        source_cognitor_id=client_id, target_object_id=object_id).all()
    if not any(r.status in ("draft", "applied") for r in rules):
        flash("Нет активного желаемого правила для этого пути", "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    try:
        nodes = {n.id: n for n in General.query.filter_by(role="Magos").all()}
        edges = NodeConnection.query.all()
        source, dest, src_plan, dest_plan = plan_cross_magos(
            cognitor, resource, nodes, edges)
    except CrossPathRejected as exc:
        flash(str(exc), "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    if request.form.get("confirm_path", "") != source.name + "->" + dest.name:
        flash("Подтверждение Magos не совпадает; изменения отменены", "danger")
        return redirect(url_for("policy_apply.access_policy_apply_preview",
                                magos_id=source.id))
    # Any previous unknown or in-flight operation on EITHER gateway blocks
    # new transactions. Never infer a successful commit from an HTTP timeout.
    locked = CrossRouteOperation.query.filter(
        CrossRouteOperation.state.in_(INFLIGHT)).all()
    if any(n.source_magos_id in (source.id, dest.id)
           or n.destination_magos_id in (source.id, dest.id) for n in locked):
        flash("На одном из Magos есть незавершённая маршрутная операция. "
              "Требуется восстановление по журналу.", "danger")
        return redirect(url_for("policy_apply.access_policy_apply_preview",
                                magos_id=source.id))
    opid = str(uuid4())
    record = CrossRouteOperation(
        operation_id=opid, source_magos_id=source.id,
        destination_magos_id=dest.id, cognitor_id=client_id,
        object_id=object_id, state="preparing")
    db.session.add(record)
    db.session.add_all([
        CrossRouteLease(node_id=source.id, operation_id=opid),
        CrossRouteLease(node_id=dest.id, operation_id=opid),
    ])
    try:
        db.session.commit()  # Atomic unique ownership of both Magos.
    except IntegrityError:
        db.session.rollback()
        flash("Один из Magos занят другой маршрутной транзакцией. "
              "Операция не запускалась.", "danger")
        return redirect(url_for("policy_apply.access_policy_apply_preview",
                                magos_id=source.id))

    def state(value, source_revision, dest_revision):
        record.state = value
        record.source_revision = source_revision
        record.destination_revision = dest_revision
        db.session.commit()

    try:
        from app import _vpn_v2_send
        outcome = run_direct_route_transaction(
            source, dest, src_plan, dest_plan, _vpn_v2_send, opid, state)
        CrossRouteLease.query.filter_by(operation_id=opid).delete()
        db.session.commit()
        flash(
            "Маршруты на двух Magos подтверждены. Далее проверьте обратный "
            "маршрут на сервере и AllowedIPs Cognitor перед применением ACL.",
            "success")
    except CrossRouteCoordinationError:
        if record.state == "reverted":
            CrossRouteLease.query.filter_by(operation_id=opid).delete()
            db.session.commit()
        # All unknown results deliberately retain the unique node leases.
        LOG.error("Cross-Magos routing transaction %s needs operator attention. "
                  "Controller state: %s", opid, record.state, exc_info=True)
        flash("Маршрутная транзакция не завершена. Проверьте состояние "
              "обоих Magos; UUID: " + opid + ". Не повторяйте Apply.", "danger")
    return redirect(url_for("policy_apply.access_policy_apply_preview",
                            magos_id=source.id))
