# Live VPN apply safety — current restricted implementation

This branch extends PR #7 (stacked on PR #5, #4 and #3).
It is suitable for **lab review and tests**, not a production rollout.

## Implemented

1. Omnissiah reads live Magos peer state via mTLS.
2. Pure preflight compares active AllowedIPs against desired routes. It
   refuses offline nodes, missing observations, duplicate keys and any
   route-set changes.
3. Existing explicit `apply` operation (still gated by the
   `X-VPN-Explicit-Apply` confirmation header) rechecks preflight
   immediately before sending the plan to the root-owned agent helper.
4. Privileged helper verifies the live kernel routes match its saved config,
   performs `wg syncconf`, verifies the live key/AllowedIPs/keepalive set,
   and **only then** atomically replaces `wg0.conf`.
5. If applying or persisting fails, the helper attempts to restore the
   previous live kernel configuration and reports failure.
6. Omnissiah checks live peer state again after return.

## Important limits

- **No changing host routes or adding/removing a /32 with a changed route
  set**. The explicit route-set guard remains in place.
- No distributed atomic commit or rollback across Magos nodes.
- An unexpected process crash, power loss, or external concurrent
  modification during apply can defeat local rollback; this is not an
  ACID transaction.
- Actual config is compared on both ends of the request, but a later
  concurrent update can still occur. Locking and revision fencing are
  needed before multi-node automatic apply.
- Peer handshake freshness is a separate indicator; matching peer
  configuration does not guarantee packets are flowing.
- The UI continues to expose read-only preflight. The existing per-Magos
  apply operation is not advertised as safe for route changes.

## Next gate before a third Magos

Implement persistent transaction journal, strict per-node revision fencing,
route-aware add/remove with explicit preflight conflict checks, local
rollback that restores both routes and peer config, then a multi-node
orchestrator with partial-failure reporting. Test on VM snapshots.
