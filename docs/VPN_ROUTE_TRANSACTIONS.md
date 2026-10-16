# Magos03 route changes — phase 1 (read-only)

Stacked on the existing VPN PRs. Do not promote this experimental branch to production.

## Implemented

- A pure IPv4 /32 route ownership planner: deploy/vpn_route_tx.py.
- Refusal of duplicate routes, foreign interfaces, gateways, route metrics, overlapping foreign networks, missing existing peer routes, broad AllowedIPs and unowned targets.
- A new root-owned Magos route-preview helper/RPC verb over existing controller mTLS. It reads WireGuard peers and Linux main-table routes, validates and returns add/remove/unchanged with writes_performed=false.
- Omnissiah includes route deltas in Preview Changes when a route-set change is requested, but still marks actual application blocked.
- Automated regression tests in GitHub Actions.

## Still required for Magos03 VPN links

1. Root-only durable journal with encrypted/protected pre-change configuration and owned routes.
2. Per-node lock and narrow /32 add/delete executor with safe ordering around wg syncconf.
3. Postflight verification and restoration of both routes and WireGuard state.
4. Crash/boot recovery, revisions and multi-Magos partial-failure accounting.
5. VM snapshots and explicit destructive-failure tests.

Keep running magos01 ↔ magos02 unchanged until the route executor and rollback are validated.
