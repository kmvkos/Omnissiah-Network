"""Admin-only inventory for protected IPv4 resources (no agent/network writes)."""
from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from wtforms import SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length

from nmc_models import General, db
from vpn_protected_models import ProtectedNetworkDraft
from vpn_protected_validation import ProtectedResourceError, validate_protected_object


protected_objects_bp = Blueprint("protected_objects", __name__)


class ProtectedObjectForm(FlaskForm):
    name = StringField("Название объекта", validators=[DataRequired(), Length(max=50)])
    network = StringField("IPv4-адрес или подсеть (CIDR)", validators=[DataRequired()])
    parent_magos_id = SelectField("Magos — владелец сети", coerce=int,
                                  validators=[DataRequired()])
    description = TextAreaField("Описание", validators=[Length(max=255)])
    submit = SubmitField("Зарегистрировать объект")


@protected_objects_bp.route("/vpn/protected-objects", methods=["GET", "POST"])
@login_required
def vpn_protected_objects():
    if current_user.role != "admin":
        abort(403)
    magos = General.query.filter_by(role="Magos").order_by(General.name).all()
    by_id = {n.id: n for n in magos}
    form = ProtectedObjectForm()
    form.parent_magos_id.choices = [(n.id, n.name) for n in magos]
    if form.validate_on_submit():
        try:
            nodes = General.query.all()
            controller = next((n for n in nodes if n.role == "Omnissiah"), None)
            if controller is None:
                raise ProtectedResourceError("Отсутствует VPN-пул Omnissiah")
            fields = validate_protected_object(
                name=form.name.data,
                network=form.network.data,
                description=form.description.data or "",
                parent=by_id.get(form.parent_magos_id.data),
                registered_networks=[obj.network for obj in ProtectedNetworkDraft.query.all()],
                vpn_pool=controller.ip_pool,
                management_ips=[
                    address for node in nodes for address in
                    (node.ssh_ip, node.endpoint) if address
                ],
            )
            db.session.add(ProtectedNetworkDraft(**fields, status="inventory_only"))
            db.session.commit()
            flash("Защищаемый объект сохранён в реестре. Маршруты, WireGuard и firewall НЕ изменялись.", "success")
            return redirect(url_for("protected_objects.vpn_protected_objects"))
        except (ProtectedResourceError, IntegrityError) as exc:
            db.session.rollback()
            flash(str(exc) if isinstance(exc, ProtectedResourceError)
                  else "Название или сеть уже зарегистрированы", "danger")
    objects = ProtectedNetworkDraft.query.order_by(ProtectedNetworkDraft.created_at.desc()).all()
    return render_template("vpn_protected_objects.html", form=form, objects=objects, magos=magos)
