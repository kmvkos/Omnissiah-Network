# Adding Magos03 to an existing Magos01–Magos02 WireGuard mesh

**LAB ONLY — not a production runbook.** The first two Magos already have
a working WireGuard link. Do not reinitialise their keys, prepare their
running wg0 as a fresh interface, or replace their configuration by hand.

This document records the required read-only gates and the **intended** test
sequence; it is not permission to enable the experimental route transactions.
The UI does not yet expose this new operation, and its three execution flags
remain disabled by default.

## Trusted environment and expected design

* Omni01: controller only, no wg0 required. Its management IP comes from the
  validated Ansible inventory; do not assume it is always 192.168.32.167.
* Magos01 and Magos02: working direct WireGuard link with /32 peer routes.
* Magos03: managed via mTLS, not yet a working member of the VPN mesh.
* The new root RPC service receives all management IPs from the deployment
  inventory via OMNISSIAH_PROTECTED_MANAGEMENT_IPV4. HTTP plans cannot change
  these addresses. No transaction feature flag is enabled at install.
* Controller, Magos and privileged helper each require independent opt-in
  before the route-transaction verb can run.
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

## Later supervised, explicit live test (NOT YET AUTHORIZED)

Once rollback, revision fencing and management-path verification are accepted,
the intended sequence is:

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

* Management-path pre/post verification and explicit route fencing against
  policy routing, not just the current main-table comparison.
* Crash/power-loss recovery and bounded helper timeouts.
* Revision fencing against updates to desired state between preview and apply.
* Verify all three nodes from actual Debian 13 VMs and both success/failure
  scenarios. Local transactions are not atomic across the three Magos.
* A reviewed UI workflow with explicit per-node confirmations and audit entries.
