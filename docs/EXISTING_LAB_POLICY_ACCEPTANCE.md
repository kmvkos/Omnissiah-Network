# Existing lab: end-to-end Policy Center acceptance

No new VMs. Targets: omni01 / magos01 / magos03 / cognitor01 / an
existing protected resource registered in Omnissiah.

## Before any live route / firewall writes

1. Snapshot omni01, magos01, magos03, cognitor01, and the protected
   resource; back up the controller DB and both `/etc/wireguard/wg0.conf`.
2. Ensure the intended mesh links work on wg0 and management HTTPS
   via mTLS remains available. No extra interface or WireGuard re-key.
3. Update the installed branch with:
   ```bash
   cd ~/Omnissiah-Network
   git status --short
   git fetch origin feature/policy-end-to-end-apply
   git switch feature/policy-end-to-end-apply || git switch --track origin/feature/policy-end-to-end-apply
   git pull --ff-only origin feature/policy-end-to-end-apply
   bash control-install.sh --update --skip-system-packages
   ```
   **Stop if git status is nonempty** or Ansible errors. No implicit live
   apply gates are enabled by this update.
4. Check `nft --version`, `wg --version` and `ip -V` on both Magos;
   `ip -4 route`, `wg show wg0` and `sysctl net.ipv4.ip_forward`.
   If nft is absent, install nftables on the Magos first, using the
   OS-supported package manager and the authorized maintenance process.

## Control plane: Policy Center → one test rule

- Check Cognitor01 is `applied` and belongs to Magos03 in the **new**
  client inventory, not the legacy model.
- Check the protected resource is owned by Magos01, with its *actual*
  IP/CIDR. Do not assume sample addresses are correct.
- Create `allow-ssh` Cognitor01 → resource TCP/22 ACCEPT.
- Review the bilateral read-only route preview. It must report a direct
  Magos03 ↔ Magos01 connection and show **exact** expected AllowedIPs:
  outbound destination CIDR at Magos03; return Cognitor /32 at Magos01.
- No traffic change should happen on Save or Preview.

## Live route step (explicit lab opt-ins only)

Controller: `VPN_CROSS_ROUTE_APPLY_ENABLED=YES` in *web service*
environment. On both Magos inventory:
`omnissiah_cross_route_apply_agent_enabled: true` and
`omnissiah_cross_route_apply_root_enabled: true`.
The existing Magos `vpn_route_transactions_enabled` gate must also
permit explicit routed transactions.

Re-run the Ansible service deployment after reviewing these settings.
Confirm Magos03 and Magos01 names in Policy Center before the
cross-route operation. This performs durable bilateral Prepare, then
destination Commit, source Commit, verify, Finalize.

If RPC returns unknown or timed out, **do not repeat**. Inspect
controller `vpn_v2_cross_route_operations` and root-only
`/var/lib/omnissiah-network/vpn/cross-route-operation.json` on BOTH
Magos. Backup + rollback should be performed as an explicit recovery
procedure, never by indiscriminate rerun of Apply.

## Cognitor and protected-server return path

There is **no remotely controlled Cognitor agent** by design.

- Cognitor's WG peer for Magos03 must include the protected resource
  CIDR in `AllowedIPs`. Policy Center displays the exact expected list.
  Save it in client WireGuard configuration and confirm
  `ip route get <resource_IP>` selects wg0. A live handshake alone
  does not prove this route.
- The destination server or its default gateway must route the
  Cognitor /32 back through Magos01. If the server directly uses Magos01
  as default gateway this may already be true. Verify from the server;
  do not invent or automatically alter its default route.
- Both Magos need IPv4 forwarding. Verify path with ICMP where allowed.
  Existing firewall hooks may still override an ACCEPT in the dedicated
  nftables table.

## Live ACL step (separate explicit lab opt-ins)

- Controller web environment: `VPN_POLICY_APPLY_ENABLED=YES`.
- Source Magos inventory:
  `omnissiah_policy_apply_agent_enabled: true`,
  `omnissiah_policy_apply_root_enabled: true`,
  `omnissiah_policy_restore_boot_enabled: true`.
- The source Magos must be able to restore committed ACL before a
  systemd-managed wg0 starts on reboot. Confirm the service topology
  before enabling. No automatic wg0 restart is performed by installer.

Back in Policy Center, open the Preview for Magos03. It now allows
remote-resource ACL only if the controller DB has a committed bilateral
route transaction, with no pending leases, AND the root helpers on
both Magos independently confirm the exact WireGuard peers/routes.
Type the Magos name and Apply the desired revision.

## Acceptance tests

From Cognitor01:
- `ip route get <resource_IP>` → wg0.
- `ping -c 3 <resource_IP>` → succeeds if ICMP is allowed in policy
  and on the host; ping alone is not a test of TCP/22.
- `nc -zvw3 <resource_IP> 22` → succeeds **if SSH listens**.
- Add a **DROP TCP/3389** rule and apply the new ACL revision; a test
  TCP connect must fail even if a service listens on that port.
- Check `sudo nft -a list table inet omnissiah_acl_v2` on Magos03,
  and confirm the expected revision in the Policy Center Preview.
- Edit TCP/22 from ACCEPT to DROP; apply and confirm connection fails.
  Restore ACCEPT; apply and confirm connection succeeds.
- Delete test rule and confirm the old ACL remains until the
  deletion transaction is acknowledged by the Magos.
- Test rollback of the last committed ACL revision, then reboot Magos03
  in a maintenance window and check ACL persistence and Mesh health.

**Restrictions:** route removal after deleting the final ACL rule still
needs reference-aware cleanup. Do not remove a shared route while any
other Cognitor policy requires it. No multi-hop through magos02 is
implemented. These remain explicit limitations rather than hidden
side effects.
