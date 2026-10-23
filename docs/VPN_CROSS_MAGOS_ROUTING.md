# VPN v2 — Direct Cross-Magos routing, lab P8/P9

## Implementation

One-hop supported route intent for a managed Cognitor attached to source
Magos and a resource behind destination Magos:
`Cognitor01 → Magos03 → wg0 → Magos01 → resource`.

The controller derives both directions only when the database contains
exactly one direct `NodeConnection` for those Magos. It never invents a
path through a third Magos. No default routes are accepted.

- Magos03: append `resource CIDR` to Magos01's existing WireGuard peer
  `AllowedIPs` and add one exact `ip route ... dev wg0`.
- Magos01: append `Cognitor /32` to Magos03's existing WireGuard peer
  `AllowedIPs` and add one exact return route via wg0.
- Existing peer keys, endpoints, keepalive, unrelated AllowedIPs, Cognitor
  peers and interface addresses are preserved.

The root service permits **only** the fixed `wg set wg0 peer` and
`ip -4 route add/del ... dev wg0` forms after strict validation and
a root-owned, durable per-node journal/back-up. No shell, SSH,
arbitrary route-replace or iptables writes.

## State machine

1. Controller creates an operation UUID and atomically acquires unique
   database leases for both Magos before the first network RPC.
2. Both root helpers **prepare** the change, snapshot current kernel
   and persisted `/etc/wireguard/wg0.conf`, and durably journal it.
3. Target Magos commits the **return** path first.
4. Source Magos commits the **outbound** path.
5. Controller probes BOTH gateways (kernel and on-disk WG peer, route,
   management/underlay and IPv4 forwarding).
6. Both nodes finalize; controller commits the operation ledger and
   releases DB leases.

On any failure, compensation is attempted on every known prepared/committed
Magos in reverse order. A missing Prepare acknowledgement, unknown Commit,
or failed rollback leaves `recovery_required` in the controller DB and
the root journal. **Do not retry unknown operations automatically**.

## Feature gates (all disabled by default)

- Controller web environment:
  `VPN_CROSS_ROUTE_APPLY_ENABLED=YES`
- Agent inventory:
  `omnissiah_cross_route_apply_agent_enabled: true`
- Root-RPC inventory:
  `omnissiah_cross_route_apply_root_enabled: true`
- Existing VPN route-transaction agent gate:
  `vpn_route_transactions_enabled: true`

For lab-only testing, use VM snapshots and a backup of Omnissiah DB and
the root-owned WireGuard config on **both** Magos. None of these gates
may be enabled solely because mock CI is green.

## Explicit limitations / acceptance criteria

- **One direct Magos-Magos edge**: no M1→M2→M3 forwarding.
- The Cognitor WireGuard client is not centrally managed by an agent.
  Its own `AllowedIPs` must include the protected destination CIDR.
- The protected resource or its gateway must have a route back to
  Cognitor via the destination Magos.
- Firewall and routing are separate: applying route extensions DOES NOT
  install a source ACL or guarantee access. Cross-Magos ACL Apply
  intentionally remains disabled pending independently verified
  bidirectional reachability and policy consistency.
- The route transaction currently adds new CIDRs and can roll back the
  last matching operation. It does **not** yet garbage-collect obsolete
  routes after policy deletion; removing them automatically could cut
  off another active policy.
- Boot persistence assumes wg-quick restores routes from the managed
  AllowedIPs config. `Table=off` is rejected. Confirm real reboot and
  recovery on the isolated test lab before live use.
- Successful root checks validate gateway state, NOT a host-level return
  path. End-to-end TCP/ICMP tests and existing firewall chain checks
  must be completed before calling the route functional for users.

This is a **draft branch**. No actual network configuration is changed
by GitHub commits or GitHub Actions. Real live verification remains.
