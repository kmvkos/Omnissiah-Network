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
@access_policies_bp.route("/access-policy", methods=["GET", "POST"])
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
                           legacy_policy_count=AccessPolicyRule.query.count(),
                           magos_nodes=General.query.filter_by(role="Magos").order_by(General.name).all())


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


@access_policies_bp.route("/access-policy/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete_policy_draft(rule_id):
    """Do not remove live ACL via DB deletion; applied rules need a transaction."""
    if current_user.role != "admin":
        abort(403)
    if not FlaskForm().validate_on_submit():
        abort(400)
    rule = db.session.get(AccessPolicyDraft, rule_id)
    if rule is None:
        abort(404)
    if rule.status != "draft":
        flash("Применённое правило нельзя удалить без транзакционного отката", "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    db.session.delete(rule)
    db.session.commit()
    flash("Черновик правила удалён. Firewall не изменялся.", "success")
    return redirect(url_for("access_policies.vpn_access_policies"))


@access_policies_bp.route("/access-policy/rules/<int:rule_id>/edit", methods=["POST"])
@login_required
def edit_policy_draft(rule_id):
    if current_user.role != "admin":
        abort(403)
    if not FlaskForm().validate_on_submit():
        abort(400)
    rule = db.session.get(AccessPolicyDraft, rule_id)
    if rule is None:
        abort(404)
    if rule.status != "draft":
        flash("Сначала выполните безопасный откат применённой политики", "danger")
        return redirect(url_for("access_policies.vpn_access_policies"))
    from flask import request
    try:
        fields = validate_policy(
            name=request.form.get("name", ""),
            source=db.session.get(CognitorDraft, int(request.form.get("source_cognitor_id", "0"))),
            target=db.session.get(ProtectedNetworkDraft, int(request.form.get("target_object_id", "0"))),
            protocol=request.form.get("protocol", ""),
            port=request.form.get("destination_port", ""),
            decision=request.form.get("decision", ""),
            existing_rules=AccessPolicyDraft.query.filter(AccessPolicyDraft.id != rule_id).all(),
        )
        for key, value in fields.items():
            setattr(rule, key, value)
        db.session.commit()
        flash("Черновик обновлён. Применение на Magos не выполнялось.", "success")
    except (AccessPolicyError, IntegrityError, TypeError, ValueError):
        db.session.rollback()
        flash("Изменения отклонены: проверьте объекты, порт и конфликты правил", "danger")
    return redirect(url_for("access_policies.vpn_access_policies"))
