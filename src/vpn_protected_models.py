"""VPN v2 protected resource inventory only; no enforcement side effects."""
from datetime import datetime, timezone
from nmc_models import db


class ProtectedNetworkDraft(db.Model):
    __tablename__ = "vpn_v2_protected_objects"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    network = db.Column(db.String(18), nullable=False, unique=True)
    parent_magos_id = db.Column(db.Integer, db.ForeignKey("general.id"), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    status = db.Column(db.String(24), nullable=False, default="inventory_only")
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    parent_magos = db.relationship("General", foreign_keys=[parent_magos_id])
