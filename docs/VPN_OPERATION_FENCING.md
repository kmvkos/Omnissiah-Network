# VPN route-transaction operation UUID and at-most-once admission

**Development only.** Draft PR stacked on the reboot-probe PR. Do not
merge or deploy to the working three-Magos Full Mesh before disposable VM
tests with snapshots and out-of-band console access.

## Why

A route mutation can succeed while the controller/agent HTTP request times out.
Resending Apply might otherwise run a second privileged write even when the
original outcome is unknown.

This change uses a **canonical UUIDv4 per operator click**. The same UUID is
validated through the web controller → authenticated Magos mTLS control API →
local Unix RPC → privileged root helper → transaction coordinator.

The coordinator takes its exclusive `mesh-transaction.lock`, validates
the current snapshot and desired plan, then **durably reserves the UUID**
in `mesh-operation-ledger.json` before staging a backup, touching WireGuard,
or writing a route. Entries contain only the UUID, SHA256 revision and
`reserved | committed | rolled_back`. No keys, config bodies, public keys
or routes are stored there. The ledger is mode 0600.

### Guarantees

- Reusing **any earlier UUID**, including one committed many operations
  ago, is rejected before a privileged network write.
- While **any** earlier operation remains `reserved`, new UUIDs are also
  rejected. A timeout, SIGKILL or partial rollback thus cannot silently
  allow another Apply before operator review.
- On a success, the coordinator durably journals `committed` **before**
  marking the ledger entry `committed`. A ledger write failure leaves a
  reserved ID and fails closed, without attempting a dangerous rollback
  of a successfully committed transaction.
- A safely rolled-back transaction is recorded as terminal in both journal
  and ledger. A crash between them leaves `reserved` requiring explicit
  reconciliation.
- VPN transaction health exposes the sanitized last operation UUID and
  shows `orphan_operation`, `unsettled_operation_ledger`, or
  `missing_operation_reservation` instead of incorrectly claiming idle.
- Operator web UI shows the exact UUID on both success and failure;
  it does **not** automatically retry a failed or timed-out Apply.

### Deliberate limitations

- This is **at-most-once admission**, not distributed exactly-once
  execution or automatic retry. The caller may still receive a timeout,
  and recovery must check the journal, ledger and actual network state.
- A new UUID cannot bypass a `reserved` entry; it can proceed only after
  a supervised recovery that resolves the earlier attempt.
- No operator button to override or reset the ledger exists. Do **not**
  delete, rename or manually rewrite the root-owned journal/ledger files
  while peers are active.
- Every accepted UUID is stored permanently until a separately designed
  archival/retention mechanism exists. The default limit is 4096 completed
  entries per Magos; hitting capacity blocks further transactions.
- No controller-level distributed fencing across nodes, no network VM
  power-off test, no recovery from all in-flight route mutations yet.

## Validation

Unit tests cover canonical UUID enforcement, secure durable ledger writes,
duplicate reuse after later operations, pending operations blocking different
IDs, tampering, symlink refusal, root RPC forwarding and read-only reporting.

Real WireGuard namespace tests cover successful additions followed by a
second operation, an attempted duplicate UUID, and SIGKILL after reservation
but before the first transaction journal: the new Apply must be refused
and the existing mesh must stay unchanged.

**No running Magos VM has been updated.** Do not assume CI passing means
a real VM power cut is safe; follow
`docs/VPN_VM_REBOOT_ACCEPTANCE.md` for an isolated, supervised VM gate.
