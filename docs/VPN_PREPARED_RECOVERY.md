# Prepared-phase VPN transaction recovery (lab milestone)

**Scope:** recover only an unchanged `prepared` journal, where no WireGuard
or route mutation has yet occurred. All other interrupted phases remain
blocked. This is **not** full power-loss crash recovery.

## Why this restriction exists

The coordinator makes a durable backup and writes `prepared` before writing
`applying` and before the first `wg syncconf` call. If a process crashes
inside this narrow window, recovery can verify the original state and mark the
transaction `rolled_back` without sending *any* command to alter Linux routes
or WireGuard. An `applying` or `rolling_back` journal could indicate a
partially updated peer, route or persisted file; blindly restoring it may
disconnect management or overwrite another administrator's changes.

## Safety properties

- Root-owned state directory, lock, journal and backup must pass file-type,
  ownership, mode and symlink checks.
- An exclusive, nonblocking flock prevents racing a still-running operation.
  Missing lock files and corrupted backups fail closed.
- Backup digest must match the journal's generation and its saved kernel
  snapshot. Running peers and routes must still match the saved snapshot,
  and the persisted `wg0.conf` must match its original bytes.
- On exact match, only `mesh-transaction.json` changes to
  `state=rolled_back, phase=done`. Backups remain intact.
- No WireGuard, route, firewall, interface, sysctl, or VPN private key
  mutation; no backup contents or private key material in stdout.
- The recovery CLI is **not exposed to the HTTP or Unix socket RPC**.
- All other states (including `applying`, `rolling_back`, corrupted backup,
  foreign route drift and inaccessible wg0) require operator review.

## Rollout and operations

The `omnissiah-vpn-prepared-recovery.service` one-shot unit is staged on
Magos through Ansible and is **disabled by default**. It does **not** require or
start `wg-quick@wg0` automatically. The inventory opt-in is
`omnissiah_vpn_prepared_recovery_boot_enabled`, which defaults to false.

Do not enable the boot unit on the current working three-Magos mesh until
supervised disposable-VM reboot testing and outage simulation pass.

The read-only Omnissiah VPN transaction status view in PR #17 is the first
diagnostic. If it shows `recovery_required` or `prepared`, capture system
logs and confirm out-of-band access; do not delete or edit journals, modify
root backups, rerun Apply, or restore a snapshot blindly. A cleanly completed
transaction shows `committed` or `rolled_back`.

## Next hardening tasks

1. Introduce an operation ID and durable desired-plan descriptor sufficient
   to distinguish pre-write, partially applied and fully committed states.
2. Recovery planning for `applying`/`rolling_back` must detect foreign changes
   and only restore original state when route ownership can be proven.
3. Tests for abrupt process termination during each journal phase, reboot
   persistence, timeout and idempotent retry.
4. Authorize the limited boot recovery on a disposable Debian VM before any
   feature flag is enabled on live Magos.
