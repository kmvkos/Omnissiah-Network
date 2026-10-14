# Experimental direct Magos mesh (NOT production-ready)

This separate Ansible playbook is **not imported by site.yml** and is never
executed by control-update.sh. The normal deployment does not start a VPN.

Current status: stage/activate lifecycle exists for a two-or-more Magos
experiment. It uses existing Ansible SSH/sudo authority, not the web API.
There is no automatic convergence controller yet. Only IPv4 /32 peer addresses
are supported; no default routes, forwarded subnets, NAT or firewall changes.

## Requirements
- Reviewed and installed PR changes on the isolated test VMs (not main).
- The privileged helper must be staged root-owned on each Magos by Ansible.
- Magos management IPs in inventory must reach each other on UDP 51820.
- No existing wg0 should be used by other software.
- Back up VM snapshots before experimental activation.

## Phase 1: prepare only (never starts the interface)

From the control's project checkout, after setting up the normal control
Ansible environment and Vault / become credentials:

```bash
cd ansible
ansible-playbook -i inventory.yml vpn-mesh.yml --ask-become-pass
```

If using the encrypted credentials Vault, use the established Vault wrapper
instead of adding --ask-become-pass; the playbook is a low-level developer
entrypoint and does not automatically unlock the project's Vault.

This generates the private key on each Magos in a 0700 root state directory,
exchanges ONLY public keys using Ansible hostvars, validates the full mesh,
and stages `/etc/wireguard/wg0.conf`. Does not create interface/routes.
It does not touch Omni's WireGuard state.

## Phase 2: explicit experimental activation

```bash
ansible-playbook -i inventory.yml vpn-mesh.yml \
  -e omnissiah_vpn_activate=true \
  -e omnissiah_vpn_explicit_ack=ENABLE_TEST_MESH \
  --ask-become-pass
```

Phase 2 rejects an existing wg0 rather than overwriting it. Since it
executes once for every Magos, failures can leave a partially started mesh
requiring manual inspection. It does not yet enable a systemd boot service.
For manual, limited lab recovery, review state with `wg show`,
`ip route`, and `ip -br addr`, then explicitly bring down wg0 on affected
lab machines if necessary.

DO NOT run this on hosts carrying actual user traffic.

## Pending for full architecture
- Local root-helper RPC protocol with no broad sudo grant and authenticated
  configuration delivery via mTLS.
- Registration of public keys and authoritative desired/actual state at Omni.
- Atomic multi-node coordination, rollback, reboot persistence, strict
  management-route protection, and validated protected-network policies.
- Remove/disable legacy unsafe VPN configuration paths before production use.
- UI node settings / gear integration after the above validation.

Do not merge this PR into main or run control-update.sh for the branch until
the experimental lifecycle has been reviewed and tested on dedicated VMs.
