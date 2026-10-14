# VPN control plane: agreed target architecture (draft)

This document defines the intended behavior. The staged validator in
`agents/app/vpn_plan.py` is NOT wired to deployment or runtime yet.

* Omnissiah is the control plane, not a mandatory traffic gateway.
* Magos may peer directly with another Magos.
* HTTPS/mTLS management runs on existing management IPs independent of VPN.
* VPN nodes have a distinct /32 interface address, separate from the VPN pool.
* WireGuard private keys must originate and remain on the node. Only public keys
  and desired peer routes should return to the controller.
* AllowedIPs is explicit; no implicit 0.0.0.0/0, gateway or default-route mutation.
* The first-stage planner permits only IPv4 /32 routes. Protected networks are
  deferred until policy validation and routing safeguards are implemented.
* Save desired state separately from apply. Apply must validate, produce a
  preview/diff, stage a rollback snapshot, and require an authenticated
  privileged helper with a narrow interface. Never grant blanket sudo.
* The applying helper must preserve management connectivity, persist state,
  return verified actual state and error on partial application.
* Changes must survive reboot. Source updates must never turn VPN on.
* A direct Magos link is an independent edge, distinct from parent-child
  ownership/enrollment in the controller.
* UI navigation to link management belongs inside the node's gear/settings.
  UI and network operations will be changed after the runtime lifecycle works.

Current limitations blocking activation:
1. Service user has no noninteractive sudo rights (confirmed on magos01).
2. Existing key fields are empty on all three nodes.
3. Legacy generator puts 0.0.0.0/0 on Magos parent peers.
4. Legacy Magos parser overwrites repeated [Peer] sections, assumes wg0,
   and may report success despite partial wg set failure.
5. Legacy link-save commits DB changes before checking distribution.
6. Encryption/key provisioning and authenticated config delivery need a new
   independently verified protocol (not an exemption from mTLS).

Safety: do not enable VPN, change sudoers, modify running firewall/routes or
merge to main based on these pure-function tests alone.
