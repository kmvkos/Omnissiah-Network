"""Read-only kernel WireGuard peer observation and desired-state comparison.

Never reads or returns private keys. Does not change routes, links or files.
"""
from ipaddress import ip_address, ip_network


def parse_wg_dump(output):
    """Parse 'wg show wg0 dump', omitting interface private key and preshared keys."""
    rows = [line.split("\t") for line in output.splitlines() if line.strip()]
    peers = []
    for row in rows[1:]:
        if len(row) < 8:
            raise ValueError("Invalid WireGuard peer dump")
        key, _psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = row[:8]
        if not key:
            raise ValueError("Empty peer key")
        routes = sorted(
            str(ip_network(route.strip(), strict=True))
            for route in allowed_ips.split(",") if route.strip() and route.strip() != "(none)"
        )
        peers.append({"public_key": key,
                      "endpoint": endpoint if endpoint != "(none)" else "",
                      "allowed_ips": routes,
                      "latest_handshake": int(handshake),
                      "rx_bytes": int(rx), "tx_bytes": int(tx),
                      "keepalive": int(keepalive) if keepalive != "off" else 0})
    return peers


def compare(desired, observed):
    """Compare peer identities/routes without overclaiming session health.

    Returns unknown when observations cannot be obtained; an empty list is
    a valid observation and means the interface has no peers.
    """
    if observed is None:
        return {"state": "unknown", "reason": "no_observation"}
    wanted = {p["public_key"]: p for p in desired}
    actual = {p["public_key"]: p for p in observed}
    if len(wanted) != len(desired) or len(actual) != len(observed):
        return {"state": "drift", "reason": "duplicate_peer_key"}
    missing = sorted(set(wanted) - set(actual))
    extra = sorted(set(actual) - set(wanted))
    mismatch = []
    for key in sorted(set(wanted) & set(actual)):
        wp = wanted[key]
        ap = actual[key]
        expected_routes = sorted(str(ip_network(r, strict=True)) for r in wp["allowed_ips"])
        actual_routes = sorted(str(ip_network(r, strict=True)) for r in ap["allowed_ips"])
        if expected_routes != actual_routes or int(wp["keepalive"]) != int(ap["keepalive"]):
            mismatch.append(key)
    # Endpoint may change through WireGuard roaming, so endpoint differences
    # are diagnostic and do not by themselves prove configuration drift.
    return {"state": "in_sync" if not (missing or extra or mismatch) else "drift",
            "missing_peer_keys": missing,
            "unexpected_peer_keys": extra,
            "different_peers": mismatch}
