"""Pending-only client-owned Cognitor admission records.

Kept separate from legacy General(Cognitor) entries so old background
resend/add_peer code cannot accidentally apply these drafts to WireGuard.
Creating a draft MUST NOT generate keys, change wg0, routes or firewall.
"""
from datetime import datetime, timezone
from nmc_models import db


class CognitorDraft(db.Model):
    __tablename__ = "vpn_cognitor_drafts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    vpn_address = db.Column(db.String(18), unique=True, nullable=False)
    public_key = db.Column(db.String(44), unique=True, nullable=False)
    parent_magos_id = db.Column(db.Integer, db.ForeignKey("general.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="draft")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           nullable=False)
    parent_magos = db.relationship("General", foreign_keys=[parent_magos_id])
