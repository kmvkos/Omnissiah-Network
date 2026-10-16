# Adding Magos03 to an existing Magos01–Magos02 WireGuard mesh

**LAB ONLY — not a production runbook.** The first two Magos already have
a working WireGuard link. Do not reinitialise their keys, prepare their
running wg0 as a fresh interface, or replace their configuration by hand.

This document records the read-only gates and the intended lab test sequence.
The VPN overview now displays a per-node transactional apply button after a
valid preview, but **only when the controller explicitly enables this feature**.
New installations keep all three execution gates disabled by default. It is not
permission to enable transactions without completing the remaining live tests.

## Trusted environment and expected design

* Omni01: controller only, no wg0 required. Its management IP comes from the
  validated Ansible inventory; do not assume it is always 192.168.32.167.
* Magos01 and Magos02: working direct WireGuard link with /32 peer routes.
* Magos03: managed via mTLS, not yet a working member of the VPN mesh.
* The new root RPC service receives all management IPs from the deployment
  inventory via OMNISSIAH_PROTECTED_MANAGEMENT_IPV4. HTTP plans cannot change
  these addresses. No transaction feature flag is enabled at install.
* Controller opt-in: `omnissiah_vpn_route_transactions_controller_enabled: true`
  on Omni01 in the Ansible inventory. The controller bootstrap persists
  `VPN_ROUTE_TRANSACTIONS_ENABLED=YES` to its private environment file.
  Disabled by default; leave false unless approving this lab stage.
* Agent opt-in: boolean inventory variable
  `omnissiah_vpn_route_transactions_agent_enabled: true` for the Magos.
  Disabled by default.
* Privileged helper opt-in: boolean inventory variable
  `omnissiah_vpn_route_transactions_root_enabled: true` for the Magos.
  Disabled by default. Root service obtains this through systemd; do not edit
  its unit on a Magos by hand.
* The helper checks effective route-to-management and peer endpoint paths
  before and after writes (including policy routing); a changed path rejects
  the transaction and triggers local rollback.
* Standard `apply` still refuses route-set changes. Do not use it to add Magos03.

## First: verify baseline without writes

Create VM snapshots of all three Magos and Omni01 *before deploying this draft
branch*, and confirm out-of-band console access. Capture baselines separately
on each Magos. Do not copy any private keys or /etc/wireguard/wg0.conf contents
into a chat, ticket or CI log.

```bash
sudo systemctl is-active omnissiah-network
sudo systemctl is-active omnissiah-vpn-rpc.socket
sudo wg show interfaces
sudo wg show wg0 latest-handshakes       # only where wg0 exists
ip -4 route get <OMNI01_MANAGEMENT_IP>
ip -4 route show table main
curl -fsS http://127.0.0.1:5001/health
```

Use the *actual inventory* to obtain IPs for Omni01 and each Magos. Readiness
is acceptable only if Omni01 remains reachable by a physical management
interface (not wg0), HTTPS/mTLS heartbeats continue and the existing
Magos01↔Magos02 tunnel still passes traffic both ways.

## Deployment gate: disabled code only

After reviewed CI, take additional VM snapshots, and on control:

```bash
git status --short
git fetch origin
git switch --track origin/feature/vpn-sequential-transactions
# If already present: git switch feature/vpn-sequential-transactions
git pull --ff-only
# Only for an approved, disposable lab snapshot:
bash control-install.sh --update
```

Never run `control-update.sh` for this experimental branch: it targets main.
Install must not modify existing wg0, keys, routes, firewall or VPN state.
After install compare the same baseline observations and verify the trusted
systemd Environment on each Magos:

```bash
sudo systemctl show omnissiah-vpn-rpc.service -p Environment
```

Confirm `OMNISSIAH_PROTECTED_MANAGEMENT_IPV4` lists *all* management IPs.
The output must **not** include `OMNISSIAH_ENABLE_ROUTE_TRANSACTIONS=YES`.

## Later supervised, explicit live test (requires separate approval)

The existing UI under **VPN-сеть → Preview Changes** supports the new
`Применить маршруты` action on a node only when all preliminary checks
succeed and the controller has enabled the feature. It requires confirmation,
node-name entry and the exact desired-plan revision returned by Preview.
The root helper also independently rechecks the live kernel state under lock.

Before enabling the three independent gates, review remaining risks below.
The intended sequence is:

1. Read-only preview for all nodes. Initialise *Magos03's* key if absent; do not
   rotate Magos01 or Magos02 keys.
2. Set desired Magos01–Magos03 and Magos02–Magos03 direct edges; save desired
   topology without activating it.
3. Review each node's preview. Expected changes: Magos01 gets one new /32 to
   Magos03; Magos02 gets one new /32 to Magos03; Magos03 gets two peers.
4. One explicitly approved node at a time: transactional apply on Magos01,
   confirm existing Magos01↔Magos02 traffic and management route unchanged;
   then apply on Magos02 and repeat verification.
5. Prepare/start Magos03 only after verifying the plans and the two existing
   nodes. Its private key remains local; do not export it.
6. Verify Magos03 handshakes and ICMP bidirectionally with both peers, then
   verify Magos01↔Magos02 still works. Check heartbeat, HTTPS/mTLS and all
   management routes after every change.
7. Reboot exactly one disposable Magos at a time; verify wireguard persistence,
   routes, peers and management connectivity. Only then test the next node.

A failed or interrupted transaction can leave an unresolved journal that blocks
further writes; do **not** manually delete transaction files. Inspect the
root-owned backup/journal on-console and restore from reviewed VM snapshots
under a documented recovery process.

## Mandatory remaining work

* Crash/power-loss recovery is not automatic. A journal can remain unresolved
  after sudden process termination or VM power failure; restore only with
  on-console review and a known-good snapshot.
* The current helper timeout and service restart behavior require a reviewed
  failure-injection test on real lab VMs.
* Desired plan revision and kernel state are rechecked, but controller-wide
  distributed locking across all Magos is not implemented.
* Verify all three Debian 13 VMs in both normal and failure scenarios.
  Per-node transactions are not atomic across the full mesh.
* Per-operation persistent audit records and central progress tracking are
  not yet implemented; the web UI reports each individual result.

## Controlled feature enablement — prepared Magos03 lab only

The current lab has already prepared Magos03 with two peers, but its WireGuard
interface is still **inactive**. Magos01 and Magos02 remain directly linked.
The desired links to Magos03 are saved and Preview validates one new route
on each existing Magos.

When the operator has reviewed remaining failure risks and approves the lab
transaction, set only these host-level inventory switches:

```yaml
omnissiah:
  hosts:
    omni01:
      omnissiah_vpn_route_transactions_controller_enabled: true

magos:
  hosts:
    magos01:
      omnissiah_vpn_route_transactions_agent_enabled: true
      omnissiah_vpn_route_transactions_root_enabled: true
    magos02:
      omnissiah_vpn_route_transactions_agent_enabled: true
      omnissiah_vpn_route_transactions_root_enabled: true
    magos03:
      # Both default false; never route-transact while wg0 is inactive.
```

Merge the booleans into the existing `ansible/inventory.yml`; do not replace
existing ansible_host, VPN addresses, SSH settings, or credentials.
`control-install.sh --update` propagates the switches. Check the installed
application and root service are healthy; do not click Apply until the
preflight reports only one expected new /32 route per active Magos.

Apply **one Magos at a time** from the VPN Overview preview; inspect result
and old peer handshake before proceeding to the next node.
Do not run route transactions on Magos03: with its inactive interface, the
existing Prepare / Enable VPN lifecycle is the correct separate path.

The route transaction feature is not covered by automatic crash recovery or
atomic multi-node activation; use only with VM snapshots and console recovery.
