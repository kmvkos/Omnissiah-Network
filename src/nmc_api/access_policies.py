"""Admin-only VPN v2 policy drafts with no network write paths."""
from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

from nmc_models import db, General, AccessPolicyRule
from vpn_access_policy_models import AccessPolicyDraft
from vpn_access_policy_validation import AccessPolicyError, preview_policy, validate_policy
from vpn_cognitor_models import CognitorDraft
from vpn_protected_models import ProtectedNetworkDraft


access_policies_bp = Blueprint("access_policies", __name__)


class AccessPolicyForm(FlaskForm):
    name = StringField("Название правила", validators=[DataRequired(), Length(max=50)])
    source_cognitor_id = SelectField("Источник — Cognitor", coerce=int,
                                     validators=[DataRequired()])
    target_object_id = SelectField("Назначение — защищаемый объект", coerce=int,
                                   validators=[DataRequired()])
    protocol = SelectField("Протокол", choices=[
        ("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP")
    ], validators=[DataRequired()])
    destination_port = StringField("Порт назначения (только TCP/UDP)")
    decision = SelectField("Решение", choices=[
        ("allow", "Разрешить"), ("deny", "Запретить")
    ], validators=[DataRequired()])
    submit = SubmitField("Сохранить черновик правила")


@access_policies_bp.route("/vpn/access-policies", methods=["GET", "POST"])
@login_required
def vpn_access_policies():
    if current_user.role != "admin":
        abort(403)
    # Policy drafts describe intent and may be written before the client Apply.
    # Never hide pending clients: an unknown add-only result may leave a live
    # peer on Magos while the controller still labels the record 'draft'.
    all_clients = CognitorDraft.query.order_by(CognitorDraft.name).all()
    clients = [c for c in all_clients if c.status in ("draft", "applied")]
    unresolved_clients = [c for c in all_clients if c.status not in ("draft", "applied")]
    # Legacy General(Cognitor) is not the managed CognitorDraft registry.
    # Expose it read-only for diagnosis, NEVER cast IDs into policy FK fields.
    legacy_clients = General.query.filter_by(role="Cognitor").order_by(
        General.name).all()
    resources = ProtectedNetworkDraft.query.filter_by(
        status="inventory_only").order_by(ProtectedNetworkDraft.name).all()
    by_client = {item.id: item for item in clients}
    by_object = {item.id: item for item in resources}
    form = AccessPolicyForm()
    form.source_cognitor_id.choices = [
        (item.id, item.name + (" — применён на Magos" if item.status == "applied"
                               else " — черновик, применение не подтверждено в БД"))
        for item in clients
    ]
    form.target_object_id.choices = [
        (item.id, item.name + " — " + item.network) for item in resources]
    if form.validate_on_submit():
        try:
            rule = validate_policy(
                name=form.name.data,
                source=by_client.get(form.source_cognitor_id.data),
                target=by_object.get(form.target_object_id.data),
                protocol=form.protocol.data,
                port=form.destination_port.data or "",
                decision=form.decision.data,
                existing_rules=AccessPolicyDraft.query.all(),
            )
            db.session.add(AccessPolicyDraft(**rule, status="draft"))
            db.session.commit()
            flash("Правило сохранено как черновик. На Magos ничего не применялось.", "success")
            return redirect(url_for("access_policies.vpn_access_policies"))
        except (AccessPolicyError, IntegrityError) as exc:
            db.session.rollback()
            flash(str(exc) if isinstance(exc, AccessPolicyError)
                  else "Название или условие правила уже существуют", "danger")
    rules = AccessPolicyDraft.query.order_by(AccessPolicyDraft.created_at.desc()).all()
    return render_template("vpn_access_policies.html", form=form, rules=rules,
                           clients=clients, resources=resources,
                           unresolved_clients=unresolved_clients,
                           legacy_clients=legacy_clients,
                           legacy_policy_count=AccessPolicyRule.query.count())


@access_policies_bp.route("/vpn/access-policies/<int:rule_id>/preview",
                          methods=["GET"])
@login_required
def vpn_access_policy_preview(rule_id):
    if current_user.role != "admin":
        abort(403)
    rule = db.session.get(AccessPolicyDraft, rule_id)
    if rule is None:
        abort(404)
    result, problem = None, None
    try:
        result = preview_policy(rule)
    except AccessPolicyError:
        problem = "Не удалось подтвердить корректность сохранённого правила"
    return render_template("vpn_access_policy_preview.html", rule=rule,
                           result=result, problem=problem)
