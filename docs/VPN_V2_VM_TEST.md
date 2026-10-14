# Omnissiah VPN v2: first real Debian 13 VM test

**LAB ONLY.** This branch has automated unit/syntax checks but is not
proven on the real three-node environment. Use dedicated snapshots. Do not
merge to main until the complete test has passed.

Existing VMs:
- omni01 management: 192.168.32.167, VPN network pool: 10.77.0.0/24.
  Omnissiah is control-plane only, with **no WireGuard interface required**.
- magos01 management: 192.168.32.168, VPN 10.77.0.2/32.
- magos02 management: 192.168.32.169, VPN 10.77.0.3/32.

## A. Take VM snapshots before deployment

Check clean Git checkout on **control**, retain existing ignored inventory
and credential Vault. Switch explicitly to the test branch and update using
the existing installation mechanism:

```bash
git status --short
git fetch origin
git switch --track origin/feature/vpn-control-plane-safety
bash control-install.sh --update
```

If the local feature branch already exists, use
`git switch feature/vpn-control-plane-safety` and `git pull --ff-only`.
Use the same SSH/Vault options required by your installation.

**Do not use control-update.sh on this branch.** It was designed to update
the main release branch. Do not use this branch on production hosts.

## B. Read-only readiness before creating VPN

On each Magos:

```bash
sudo systemctl status omnissiah-network --no-pager
sudo systemctl status omnissiah-vpn-rpc.socket --no-pager
sudo stat /run/omnissiah-vpn/control.sock
sudo wg show
ip route get 192.168.32.167
```

There must be no unintended WireGuard interfaces at this stage. The socket
unit should be active/listening. The RPC service itself may be inactive
until the first request because it uses systemd socket activation.

## C. Prepare direct peer link using the UI

1. Open Omnissiah HTTPS dashboard, navigate to magos01's gear/settings.
2. Click **Initialize key**. Repeat on magos02.
3. On magos01 gear/settings open **Manage links**, select magos02, Save.
   This only changes the desired link in DB; it does NOT activate VPN.
4. On Omnissiah, `GET /api/v2/vpn/mesh/preview` as an authenticated
   admin should show exactly one peer per Magos (not Omnissiah).
5. On magos01 and magos02, click **Prepare VPN**. Verify
   root-owned `/etc/wireguard/wg0.conf` exists, but do not display its
   contents (it contains a private key). A prepared plan creates no route.
6. Check management routes again; they should be unchanged.

## D. Explicit activation on two test Magos

Click **Enable VPN** for magos01, then magos02.
This operation requires an explicit browser confirmation and sends
`X-VPN-Explicit-Apply: ENABLE_TEST_MESH` from the UI.

On magos01:
```bash
sudo wg show wg0
ip route get 10.77.0.3
ip route get 192.168.32.167
ping -c 3 -W 2 10.77.0.3
```

On magos02:
```bash
sudo wg show wg0
ip route get 10.77.0.2
ip route get 192.168.32.167
ping -c 3 -W 2 10.77.0.2
```

Success means handshake times become nonzero and packets pass, while
management HTTPS/heartbeats continue.

## E. Persistence

After successful bidirectional traffic, verify
`systemctl is-enabled wg-quick@wg0` on each Magos. Only when lab traffic
works, reboot ONE test Magos and verify the tunnel returns and the
management route/heartbeat remains available. Repeat on the other.

## Known limits

- Root RPC/HTTP path is new and has not been tested on the user's VMs.
- Changes to AllowedIPs after activation are explicitly rejected because
  wg syncconf does not reconcile Linux routing tables.
- Multi-node configuration apply is not atomic. There is no distributed
  two-phase commit; node activation is explicitly sequential.
- A failed live peer sync attempts a local rollback but cannot guarantee
  cross-node rollback or recover from power loss.
- There is no web-driven stop, rotation, PSK management, protected-subnet
  routing or sophisticated policy reconciliation yet.
- The legacy SSH UI functions and many old API routes still need separate
  audit. The old /api/magos/update_config endpoint is disabled in
  managed-mTLS mode but the whole legacy surface has not been audited.
- Never paste private.key or wg0.conf content into logs or chat.

If RPC calls fail, inspect these on the failing Magos:
```bash
sudo journalctl -u omnissiah-vpn-rpc.service -u omnissiah-network -n 100 --no-pager
sudo systemctl status omnissiah-vpn-rpc.socket omnissiah-vpn-rpc.service --no-pager
```
