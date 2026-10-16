"""Stable digest for the exact VPN plan shown in preview."""
import hashlib
import json


def plan_revision(plan):
    if not isinstance(plan, dict):
        raise ValueError("Invalid plan")
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
