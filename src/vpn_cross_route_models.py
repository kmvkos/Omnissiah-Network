"""Durable controller-side ledger for a distributed two-gateway route operation."""
from datetime import datetime, timezone
from nmc_models import db


class CrossRouteOperation(db.Model):
    __tablename__ = "vpn_v2_cross_route_operations"

    id = db.Column(db.Integer, primary_key=True)
    operation_id = db.Column(db.String(36), nullable=False, unique=True)
    source_magos_id = db.Column(db.Integer, db.ForeignKey("general.id"), nullable=False)
    destination_magos_id = db.Column(db.Integer, db.ForeignKey("general.id"), nullable=False)
    cognitor_id = db.Column(db.Integer, db.ForeignKey("vpn_cognitor_drafts.id"), nullable=False)
    object_id = db.Column(db.Integer, db.ForeignKey("vpn_v2_protected_objects.id"), nullable=False)
    source_revision = db.Column(db.String(64), nullable=True)
    destination_revision = db.Column(db.String(64), nullable=True)
    state = db.Column(db.String(32), nullable=False, default="preparing")
    message = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))


class CrossRouteLease(db.Model):
    """Unique per-node controller fence, enforced by the database itself."""
    __tablename__ = "vpn_v2_cross_route_leases"

    node_id = db.Column(db.Integer, db.ForeignKey("general.id"), primary_key=True)
    operation_id = db.Column(db.String(36), nullable=False)
