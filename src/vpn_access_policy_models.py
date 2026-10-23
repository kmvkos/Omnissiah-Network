"""VPN v2 policy intentions: no firewall, route or agent-side effects."""
from datetime import datetime, timezone

from nmc_models import db


class AccessPolicyDraft(db.Model):
    __tablename__ = "vpn_v2_access_policy_drafts"
    __table_args__ = (
        db.UniqueConstraint(
            "source_cognitor_id", "target_object_id", "protocol",
            "destination_port", name="uq_vpn_v2_policy_match"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    source_cognitor_id = db.Column(
        db.Integer, db.ForeignKey("vpn_cognitor_drafts.id"), nullable=False)
    target_object_id = db.Column(
        db.Integer, db.ForeignKey("vpn_v2_protected_objects.id"), nullable=False)
    protocol = db.Column(db.String(8), nullable=False)
    # ICMP uses zero (never NULL) so the database can reject duplicate rules.
    destination_port = db.Column(db.Integer, nullable=False)
    decision = db.Column(db.String(8), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="draft")
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=lambda: datetime.now(timezone.utc))

    source_cognitor = db.relationship("CognitorDraft", foreign_keys=[source_cognitor_id])
    target_object = db.relationship("ProtectedNetworkDraft", foreign_keys=[target_object_id])
