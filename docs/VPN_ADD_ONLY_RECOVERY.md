# Interrupted add-only transaction rollback (development)

**Branch:** `feature/vpn-add-only-recovery` (draft stacked PR #19).
**Deployment:** none; no Magos service, Unix RPC verb or HTTP action runs
`vpn_add_only_recovery.reconcile_add_only`. This is a guarded recovery
engine for isolated root-owned tests, **not** enabled for production or the
three-Magos lab.

## Recovery eligibility

Only a transaction which **added** previously absent WireGuard peers with
one IPv4 /32 AllowedIPs each and associated owned `wg0` routes.

A journal must be durable before any writes, containing the original kernel
snapshot generation and a restricted `recovery.desired_peers` (public
identifiers, endpoint, /32 AllowedIPs, keepalive; never private keys).
Old journals which do not have the descriptor must not be upgraded
automatically.

Only these interrupted states may be recovered:

- `applying / route`: WireGuard sync completed and route work may have
  applied, including a pending route command with ambiguous completion.
- `rolling_back / add_only_recovery`: this same recovery previously
  completed some cleanup and crashed before marking terminal state.

All other states are rejected. The earlier prepared-only no-network
recovery remains separate.

## Before the first rollback write

1. Lock exactly the root-owned journal under the same exclusive `flock`
   as the transaction runner. Validate root-only files and backup SHA256.
2. Reconstruct the route delta from the backup and desired peer descriptor,
   rejecting deletes, existing peer edits, duplicate routes and mismatched
   generation.
3. Require original kernel peers to be intact; only recorded new peers may
   have appeared. Validate peer endpoint, keepalive and host AllowedIPs.
4. Compare every unrelated main-table route, **including default routes**,
   against the original backup. New destination routes must be unambiguous
   unicast `wg0` /32 entries without a gateway/metric.
5. Confirm `wg showconf` interface identity is unchanged and persisted
   managed `wg0.conf` still matches the original backup.
6. Check effective IPv4 paths to the trusted management IPs and every
   recorded transport endpoint. The paths must not use `wg0`.

For eligible transactions, write durable
`rolling_back / add_only_recovery` state, then remove **only** recorded new
routes and new peers. Reinspect unrelated routes, old peers and protected
paths before each write. If interrupted, recovery can resume only after the
same checks. On exact original state verification, mark `rolled_back`.

## Limitations and next gate

- Peer endpoint roaming can cause a conservative false refusal. **Refusal
  is preferable to modifying live peer state ambiguously.**
- A crash during removal of an existing peer, a changed endpoint, wide
  AllowedIPs, partial config persistence, an unavailable `wg0`, a foreign
  route or altered management routing is not recoverable automatically.
- This rollback is not yet called by a boot unit or exposed as an operator
  API. Do not deploy to the current three-Magos network.
- Before enabling, exercise exact process-kill points, full VM power loss,
  original-peer heartbeat preservation, netns failure injection, reboot and
  management connectivity with out-of-band console and snapshots.
- Next work: unique durable operation IDs, explicit retry fencing, nuanced
  peer modification/removal recovery, and operator-controlled recovery
  workflow with reliable alerting.
