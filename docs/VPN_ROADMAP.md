# VPN Roadmap — Omnissiah Network

Status: **lab full mesh verified; production hardening in progress**.
Scope: controller **Omnissiah**, managed Linux **Magos**, WireGuard, web UX, routing and security.
Source-of-truth for planned work; historical README / STATUS / architecture drafts may lag
behind the running three-node lab. This document does not authorize route mutations.

## Current verified baseline (2026-10-16)

- 3 Magos are enrolled via HTTPS/mTLS; Omnissiah is control-plane only.
- All 3 WireGuard interfaces have been activated through the management web UI.
- Direct links exist between each Magos pair; operator reports successful ICMP
  across peers, including the new third Magos.
- Existing active peers were expanded through per-node route transactions using
  Preview/Apply without manually editing wg0.conf or configuring routes via SSH.
- Desired/Actual reconciliation, route dry-run, peer check after apply and
  root helper with separate Unix RPC are implemented.
- A Python-import deployment blocker was found on Magos01 and fixed by
  installing vpn_helper.py next to the root executable; CI and live test passed.
- **Not verified yet:** reboot survival on all three nodes, failure recovery
  after power loss, safe node removal, protected subnet routing, ACLs, sustained
  cross-network performance, key rotation, high availability or upgrade rollback.
- Working branch: `feature/vpn-sequential-transactions`; PR #16 is experimental.
  Do not merge to main merely on successful ICMP or netns tests.

## Release definition

**VPN v1.0 (stable)** means a Linux Magos operator can add, update, disable and
remove nodes and private /32 peer links using only Omnissiah web UI; operations
are authenticated, auditable, idempotent, safe under retries/timeouts and
recoverable after interruptions; management connectivity survives; WireGuard
state persists after reboot and upgrades. A **Cognitor client** can be provisioned
under a selected Magos through the web UI, receive its own WireGuard configuration,
connect, be revoked, and reach only explicitly approved destinations. A basic
routed protected-LAN scenario behind Magos is tested with explicit policies.
The three-node end-to-end test and failure injection must pass on disposable Debian 13 VMs.

**Beyond v1.0**: complex multi-LAN policy routing, NAT traversal/orchestration,
dynamic endpoint discovery, HA controller/relays, native Cognitor apps,
large multi-tenant deployments and sophisticated ACL templates.

## P0 — Reliability and recovery (next)

1. Model transaction lifecycle: pending, preparing, applying, verifying,
   committed, rolling_back, recovery_required. Use unique operation IDs, safe
   journal durability and record baseline/config revisions with no private keys
   in controller history.
2. Provide on-boot local transaction recovery: detect interrupted journal,
   distinguish complete/partial steps, validate original backup integrity and
   restore/reconcile safely. Never blindly overwrite foreign routes or corrupt
   configs. Unrecoverable state must stay fail-closed with a documented console
   recovery path.
3. Timeouts & retries: align browser, HTTP, RPC and subprocess timeout budgets.
   Prevent unknown late completion after a reported timeout; support status
   lookup by operation ID and idempotent retries, never repeated blind applies.
4. One in-flight transaction per Magos (local lock plus controller operation
   fencing); compare exact desired revision and current kernel snapshot at write.
5. Preserve effective routes to controller and every peer transport endpoint;
   prove health of already working peers before/after apply; freeze further
   changes on management-path failure.
6. Failure-injection tests in root-owned netns and disposable Debian VMs:
   process kill, power loss, interrupted route addition, lost management TLS,
   stale preview, rerun identical operation. Run with console/snapshots.

**Exit criteria:** successful two-phase lab mutation, deterministic recovery
or explicit safe recovery_required, unchanged old-peer traffic after failure,
no silent success, and no unauthorized route change.

## P1 — Full node and peer lifecycle

- Initialize key / prepare / enable / disable / restart / resync through
  restricted RPC, with explicit permissions and acknowledgements.
- Remove a link or decommission Magos safely, including peers and **owned**
  /32 routes on both ends, PKI revocation and correct DB state.
- Change endpoint, keepalive, listen port, addresses and peer AllowedIPs with
  preflight. Do not auto-change the default route.
- Support scheduled key rotation (staged identity, handshake cutover, rollback)
  without transmitting private keys.
- Reconcile state after a Magos reconnects, lost heartbeat or stale node plan.
- Separate desired network edits from applying them and expose partial
  completion clearly.

**Exit criteria:** add / remove / update a 4th Magos without manual editing;
 old peers stay connected; rollback restores the previous topology.

## P1 — Cognitor client lifecycle (core feature)

The original architecture defines Cognitor as an individual WireGuard client
attached to a selected Magos, not another Magos node. This is distinct from
ordinary LAN hosts behind a Magos, which do **not** need WireGuard themselves.

- Admin selects a parent Magos and assigns a unique client VPN address.
- Create client key material securely: private key should be generated on the
  client when possible; otherwise issue a one-time encrypted configuration and
  never display or log the private key again. Define key ownership explicitly.
- Provision the Cognitor peer to **only its parent Magos**, using mTLS control,
  restricted root RPC, preflight, journaled transaction and rollback.
- Web UI shows Cognitor pending/active/revoked, last handshake, traffic counters,
  and whether the parent Magos has acknowledged the intended peer config.
- Deliver a client configuration for supported WireGuard platforms with explicit
  AllowedIPs, endpoint, DNS and keepalive; never assume a default 0.0.0.0/0
  route. Client-to-client and client-to-LAN access is policy controlled.
- Disable/revoke/delete Cognitor safely and clean parent routes + peers.
- Test two Cognitors behind different Magos, with permitted and denied traffic;
  confirm a revoked Cognitor cannot reconnect.

**Exit criteria:** two Cognitors managed entirely in the web UI can establish
WireGuard handshakes via their respective Magos and exchange only allowed
traffic, even while the three-Magos mesh remains healthy.

## P1 — Routing real protected subnets

- Extend /32-only model to explicit IPv4 CIDRs after validating
  overlaps, ownership, gateways, Linux policy routing and return paths.
- Configure opt-in IPv4 forwarding and optional NAT only on selected
  gateway Magos; no implicit 0.0.0.0/0 or management hijack.
- Explicit route owners and cleanup, packet-forwarding verification,
  interface/firewall consistency and subnet reachability preview.
- Demonstrate Magos-A LAN to Magos-B LAN access with no ambiguous
  / asymmetric paths.

**Exit criteria:** end-to-end TCP/UDP across two separate protected LANs,
with explicit route/ACL ownership, failure rollback and reboot persistence.

## P1 — Access control and security

- Inventory management and VPN data-plane independently; mTLS stays
  mandatory for control APIs. Reject legacy privileged mutation endpoints.
- RBAC for read-only, operator and admin; CSRF protection and audit of
  mutating web actions.
- Restrict helper verbs, filesystem paths, Unix socket credentials, subprocess
  argv and input; apply rate limits and concurrency safeguards.
- Explicit inter-Magos and protected subnet ACL policies; consistent
  nftables/iptables backend, preview, safe rollback and no silent permissive
  defaults.
- Certificate renewal and revocation, WireGuard key rotation and sensitive
  data redaction; check public Git metadata for accidental disclosures.

**Exit criteria:** allow/deny tests across the mesh, unauthorized API tests,
 no secrets in logs/API, and revoked node cannot administer or rejoin.

## P1 — VPN observability

- Per-peer actual status: public identity fingerprint, handshake freshness,
  RX/TX, route state, control-plane health and explicit unknown vs offline.
- Endpoint reachability / ICMP and bandwidth measurements on demand
  (not misleading always-on assumptions).
- Route/peer drift alerting, recovery_required alarms, controller/Magos
  operation history and detailed errors with sanitized diagnostics.
- JSON audit events for log aggregation and optional Prometheus/SIEM.

**Exit criteria:** a deliberately broken peer yields an actionable UI
 message and detection/recovery without requiring SSH for routine issues.

## P1 — Web management UX

- Show topology graph/list with desired and observed edges and statuses.
- Keep Save Desired → Preview → Apply → Verify, with per-node and
  multi-node progress, explicit confirmations and stable revision tokens.
- Idempotent operation IDs/status polling, safe browser refresh,
  rollback/retry paths and explainable errors.
- Disable impossible actions (e.g. route transaction on an inactive interface);
  expose Enable VPN lifecycle separately for a newly prepared Magos.
- Retire obsolete SSH-driven VPN toggles from the managed UI.

**Exit criteria:** operator manages three to four Magos completely in
 browser, with accurate progress and a rollback report.

## P1 — Persistence, upgrade and release verification

- Prove wg-quick@wg0, peers and routes survive reboot one Magos at a time.
- Controller reboot/outage must not drop already established Magos-to-Magos
  data-plane traffic.
- Ansible update must preserve VPN state and recover if one node upgrade
  fails; revision pinning, health checks and documented rollback.
- Test 3, 5 and 10 Magos with topology growth and shrink, simultaneous
  operator actions, stale controller versions and partial outages.
- Update README.md, docs/STATUS.md and operational recovery runbooks from
  verified evidence; tag stable release only after all acceptance checks.

**Exit criteria:** repeatable full VM acceptance suite and documented
 update/restore from a clean install and an existing mesh.

## Later (v1.1+ / optional)

- Alternative topologies: hub-and-spoke, partial mesh, relay, controller
  policy templates and scale planning beyond N*(N-1)/2 full-mesh links.
- Sophisticated policy routing/multiple interfaces, site-to-site public
  endpoints and NAT traversal.
- Dedicated native Cognitor applications and large-scale client provisioning (basic WireGuard Cognitor provisioning is mandatory for v1.0).
- HA control plane, distributed mesh rollout policy and fleet-scale queues.
- IPv6 and dual-stack after separate routing/security model validation.

## Execution discipline

- Development on feature branches with PR/CI; no automatic change to a running
  lab from a Git commit.
- Disposable netns tests → simulated failure tests → VM snapshot/console
  lab → supervised web apply to one Magos → verify old peer & mTLS → next node.
- Each completed phase must add tests, a diagnostic runbook and documentation.
- Never copy private.key, wg0.conf, backup data or credentials into tickets,
  chat messages or public Git.
