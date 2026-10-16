"""Admin-only, pending Cognitor registration. No network writes.

This blueprint deliberately keeps staged Cognitors separate from legacy
General(Cognitor), whose old routes can mutate WireGuard directly.
"""
from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.exc import IntegrityError
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Regexp

from nmc_models import General, db
from vpn_cognitor_models import CognitorDraft
from vpn_cognitor_validation import CognitorValidationError, validate_draft


cognitors_bp = Blueprint("cognitors", __name__)


class CognitorDraftForm(FlaskForm):
    name = StringField("Имя клиента", validators=[
        DataRequired(),
        Regexp(r"^[A-Za-z][A-Za-z0-9_-]{0,49}$",
               message="Используйте латиницу, цифры, _ или -; первый символ — буква"),
    ])
    vpn_address = StringField("VPN-адрес клиента", validators=[DataRequired()])
    public_key = StringField("Публичный ключ WireGuard", validators=[DataRequired()])
    parent_magos_id = SelectField("Родительский Magos", coerce=int,
                                  validators=[DataRequired()])
    submit = SubmitField("Создать черновик")


@cognitors_bp.route("/vpn/cognitors", methods=["GET", "POST"])
@login_required
def vpn_cognitors():
    """The only POST effect here is one database row with status='draft'."""
    if current_user.role != "admin":
        abort(403)
    magos = General.query.filter_by(role="Magos").order_by(General.name).all()
    by_id = {node.id: node for node in magos}
    form = CognitorDraftForm()
    form.parent_magos_id.choices = [(node.id, node.name) for node in magos]

    if form.validate_on_submit():
        try:
            existing = General.query.all()
            registry = CognitorDraft.query.all()
            controller = next((node for node in existing if node.role == "Omnissiah"), None)
            if controller is None:
                raise CognitorValidationError("VPN-пул Omnissiah не настроен")
            fields = validate_draft(
                name=form.name.data,
                address=form.vpn_address.data,
                public_key=form.public_key.data,
                parent=by_id.get(form.parent_magos_id.data),
                pool=controller.ip_pool,
                occupied_names=[n.name for n in existing] + [n.name for n in registry],
                occupied_ips=[n.ip_pool for n in existing if n.ip_pool] +
                             [n.vpn_address for n in registry],
                occupied_keys=[n.public_key for n in existing if n.public_key] +
                              [n.public_key for n in registry],
            )
            db.session.add(CognitorDraft(
                name=fields["name"],
                vpn_address=fields["address"],
                public_key=fields["public_key"],
                parent_magos_id=fields["parent_id"],
                status="draft",
            ))
            db.session.commit()
            flash("Черновик Cognitor сохранён. VPN, маршруты и политики не изменялись.", "success")
            return redirect(url_for("cognitors.vpn_cognitors"))
        except CognitorValidationError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        except IntegrityError:
            db.session.rollback()
            flash("Имя, VPN-адрес или публичный ключ уже зарегистрированы", "danger")

    drafts = CognitorDraft.query.order_by(CognitorDraft.created_at.desc()).all()
    return render_template("vpn_cognitors.html", form=form, drafts=drafts, magos=magos)


@cognitors_bp.route("/vpn/cognitors/<int:draft_id>/preview", methods=["GET"])
@login_required
def vpn_cognitor_preview(draft_id):
    """Read-only remote preflight over controller-authenticated mTLS.

    This does NOT install the peer, claim a route or change draft status.
    """
    if current_user.role != "admin":
        abort(403)
    draft = db.session.get(CognitorDraft, draft_id)
    if draft is None:
        abort(404)
    magos = db.session.get(General, draft.parent_magos_id)
    if magos is None or magos.role != "Magos":
        abort(409)
    plan = {
        "node_name": magos.name,
        "address": magos.ip_pool,
        "client_name": draft.name,
        "client_address": draft.vpn_address,
        "public_key": draft.public_key,
    }
    result = None
    problem = None
    try:
        # Delayed import prevents circular startup dependency.
        from app import _vpn_v2_send
        result = _vpn_v2_send(magos, "cognitor-preview", plan)
        if (not isinstance(result, dict)
                or result.get("writes_performed") is not False
                or result.get("safe_to_plan") is not True
                or result.get("action") != "add_only"
                or result.get("parent_node") != magos.name
                or result.get("client_address") != draft.vpn_address
                or result.get("client_name") != draft.name
                or not isinstance(result.get("revision"), str)
                or len(result["revision"]) != 64):
            result = None
            problem = "Magos вернул неподтверждённый результат проверки"
    except Exception:
        # No low-level exception, private key or unmanaged peer metadata in UI.
        import logging
        logging.getLogger(__name__).warning(
            "Read-only Cognitor admission rejected for draft id %d at %s",
            draft.id, magos.name, exc_info=True)
        problem = ("Не удалось выполнить проверку на Magos. "
                   "Проверьте mTLS, службу локального RPC, WireGuard и системный журнал.")
    return render_template("vpn_cognitor_preview.html", draft=draft,
                           magos=magos, result=result, problem=problem,
                           apply_form=FlaskForm())


@cognitors_bp.route("/vpn/cognitors/<int:draft_id>/apply", methods=["POST"])
@login_required
def vpn_cognitor_apply(draft_id):
    """A single explicitly confirmed add-only request; never auto-retry."""
    if current_user.role != "admin":
        abort(403)
    # Flask-WTF verifies CSRF on the same authenticated session.
    form = FlaskForm()
    if not form.validate_on_submit():
        abort(400)
    draft = db.session.get(CognitorDraft, draft_id)
    if draft is None:
        abort(404)
    if draft.status != "draft":
        flash("Клиент уже обрабатывался. Перед повторным действием проверьте Magos.", "warning")
        return redirect(url_for("cognitors.vpn_cognitors"))
    from flask import request
    revision = request.form.get("expected_revision")
    if not isinstance(revision, str) or len(revision) != 64 or any(
            ch not in "0123456789abcdef" for ch in revision):
        abort(400)
    if request.form.get("confirm_name") != draft.name:
        flash("Имя Cognitor не совпало: применение отменено.", "danger")
        return redirect(url_for("cognitors.vpn_cognitor_preview", draft_id=draft.id))
    magos = db.session.get(General, draft.parent_magos_id)
    if magos is None or magos.role != "Magos":
        abort(409)
    plan = {"node_name": magos.name, "address": magos.ip_pool,
            "client_name": draft.name, "client_address": draft.vpn_address,
            "public_key": draft.public_key, "expected_revision": revision}
    from uuid import uuid4
    operation_id = str(uuid4())
    try:
        # Writes are allowed only after root RPC rechecks the live/disk state,
        # durable backup and UUID lock. A timeout leaves the outcome unknown.
        from app import _vpn_v2_send
        result = _vpn_v2_send(magos, "cognitor-add", plan,
                              operation_id=operation_id)
        if (not isinstance(result, dict) or result.get("state") != "committed"
                or result.get("client_address") != draft.vpn_address
                or result.get("operation_id") != operation_id):
            raise ValueError("Unconfirmed VPN transaction result")
    except Exception:
        import logging
        logging.getLogger(__name__).error(
            "Cognitor add outcome unknown: draft %s, operation UUID %s, Magos %s. DO NOT RETRY.",
            draft.id, operation_id, magos.name, exc_info=True)
        flash("Результат применения не подтверждён. Не повторяйте операцию. "
              "Проверьте журнал VPN-транзакций на Magos. "
              "Идентификатор операции: " + operation_id, "danger")
        return redirect(url_for("cognitors.vpn_cognitors"))
    # Record committed ONLY after root confirms both live state and persistence.
    draft.status = "applied"
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        logging = __import__("logging")
        logging.getLogger(__name__).critical(
            "Cognitor root transaction committed but DB status update failed! "
            "Draft id=%s UUID=%s; manual reconciliation required", draft.id, operation_id)
        flash("Magos подтвердил применение, но БД Omnissiah не обновилась. "
              "НЕ повторяйте операцию, обратитесь к журналу и проверьте состояние.", "danger")
        return redirect(url_for("cognitors.vpn_cognitors"))
    flash("Cognitor добавлен на " + magos.name +
          ". Теперь установите WireGuard на клиенте и проверьте handshake.", "success")
    return redirect(url_for("cognitors.vpn_cognitors"))


@cognitors_bp.route("/vpn/cognitors/<int:draft_id>/status", methods=["GET"])
@login_required
def vpn_cognitor_status(draft_id):
    """Observe only the named client's public WireGuard peer over mTLS."""
    if current_user.role != "admin":
        abort(403)
    draft = db.session.get(CognitorDraft, draft_id)
    if draft is None:
        abort(404)
    magos = db.session.get(General, draft.parent_magos_id)
    if magos is None or magos.role != "Magos":
        abort(409)
    seen = None
    failure = None
    try:
        from app import _vpn_v2_send
        from datetime import datetime, timezone
        data = _vpn_v2_send(magos, "status")
        if not isinstance(data, dict) or data.get("active") is not True:
            raise ValueError("WireGuard inactive")
        peers = data.get("peers")
        if not isinstance(peers, list):
            raise ValueError("Invalid peer list")
        matches = [p for p in peers if isinstance(p, dict)
                   and p.get("public_key") == draft.public_key]
        if len(matches) > 1:
            raise ValueError("Duplicate client public key")
        if matches:
            p = matches[0]
            if p.get("allowed_ips") != [draft.vpn_address]:
                raise ValueError("Cognitor AllowedIPs differ from registry")
            last = p.get("latest_handshake", 0)
            rx, tx = p.get("rx_bytes"), p.get("tx_bytes")
            if (type(last) is not int or last < 0 or type(rx) is not int
                    or type(tx) is not int or rx < 0 or tx < 0):
                raise ValueError("Malformed WireGuard counters")
            age = max(0, int(datetime.now(timezone.utc).timestamp()) - last) if last > 0 else None
            seen = {"installed": True, "connected": age is not None and age <= 180,
                    "handshake_age": age, "rx_bytes": rx, "tx_bytes": tx}
        else:
            seen = {"installed": False, "connected": False,
                    "handshake_age": None, "rx_bytes": 0, "tx_bytes": 0}
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "Cognitor status unavailable: draft id=%s, Magos=%s",
            draft.id, magos.name, exc_info=True)
        failure = ("Не удалось получить достоверный статус с Magos. "
                   "Проверьте mTLS, WireGuard и журналы.")
    return render_template("vpn_cognitor_status.html", draft=draft,
                           magos=magos, seen=seen, failure=failure)
