# VPN reboot and power-loss acceptance: disposable Debian 13 VMs only

**STATUS:** the read-only acceptance probe and offline unit tests are implemented.
**A real VM reboot or power cut has NOT been run in GitHub CI or on the user's
three working Magos.** These remain separate supervised acceptance steps.

Do not test this by rebooting or powering off `magos01`, `magos02` or
`magos03`. Use disposable clones or new VMs with **isolated test VPN
addresses and transport networks**, out-of-band hypervisor console and
snapshots. Never connect a clone with duplicate live identity/keys/IPs to the
working network.

## Scope / pass criteria

- The controller remains reachable through the original management NIC,
  not through `wg0`. Distinguish mTLS management plane from VPN dataplane.
- `wg-quick@wg0.service` is enabled before reboot. It may be
  `inactive` **before reboot** when Omnissiah has started `wg0` manually
  via `wg-quick up` and only enabled systemd. After reboot it must be
  **active**. Do not attempt `systemctl start` on an already-running wg0
  just to satisfy the preflight.
- Root-owned `/etc/wireguard/wg0.conf` must be managed by Omnissiah and
  describe exactly the same peer keys and /32 AllowedIPs as the running
  interface. This protects against rebooting with an older saved topology.
- Every expected WireGuard peer has the same (hashed) identity, exact /32
  AllowedIPs and corresponding main-table `wg0` host route.
- Every peer has a fresh WireGuard handshake within 180 seconds at the end
  of the post-boot wait. Keepalives must have a reachable peer.
- The original effective controller management route (device, gateway,
  source and table) remains the same.
- `transaction-status` shows a terminal journal or a clearly identified
  recovery_required state; unknown states never authorize an Apply.

The probe never executes `wg set`, `wg-quick up/down`, `ip route add/del`,
`systemctl start/stop`, or any other mutation. The baseline is mode 0600
and stores SHA256 peer fingerprints instead of raw peer keys.

## Phase A: clean reboot, supervised (still pending execution)

1. Create disposable Debian 13 VMs, fresh node identities and a test
   mesh, isolated from the real `10.77.0.0/24` mesh and management networks.
   Preserve out-of-band console access; snapshot all test machines.
2. On the disposable Magos VM, place the repository script locally, and
   run it **as root** before reboot (do not put private keys in the report):

   ```bash
   sudo python3 scripts/vpn_vm_reboot_probe.py baseline \
       --controller-ip TEST_CONTROLLER_IP --out /root/vpn-before.json
   ```

   Replace `TEST_CONTROLLER_IP` with the **test** Omnissiah management
   IPv4 address. If this command fails, do not reboot to continue testing:
   fix the baseline state first. Ensure traffic is active and handshakes fresh.

3. From the **hypervisor console**, reboot only this disposable Magos VM
   normally. Do not touch running production Magos nodes.
4. After it comes back, on the test VM run:

   ```bash
   sudo python3 scripts/vpn_vm_reboot_probe.py verify \
       --controller-ip TEST_CONTROLLER_IP \
       --baseline /root/vpn-before.json --wait 120
   ```

   Expected: `{"result":"pass","problems":[],"writes_performed":false}`.
   Then separately check the Magos mTLS heartbeat on the test controller
   and end-to-end ICMP/TCP/UDP between test VPN peers.

5. Repeat one test VM at a time and record which node, OS, installed Git
   revision, systemd state, interface/route state and operator timestamp
   were tested. Do not include any secret or private key in reports.

## Phase B: abrupt power off (NOT READY)

Power loss while an add-only transaction is in flight needs a separate
**test-only orchestrator** and timing fault hooks. Existing SIGKILL CI
tests demonstrate process death at seven durable journal points, but do
not model filesystem power-off or recovery ordering after `wg-quick`
re-creates an interface from the persisted configuration.

Do not power-cut a VM holding real Magos identities. Before enabling an
unattended recovery service, create isolated VMs and prove all of:

- abrupt power cut after backup but before journal; result must be
  `recovery_required/orphan_backup`, never idle;
- abrupt power cut at prepared, wg_sync, before/after route write,
  during rollback, after persisted config before commit;
- protected controller management path and existing peer connectivity
  survive every safely recoverable case;
- on an impossible/foreign state, the boot routine must fail closed without
  touching routes or peers;
- after reboot or controller timeout, duplicate Apply attempts do not
  start a second privileged write (operation IDs/retry fencing);
- no secrets appear in journal, diagnostic UI or CI artifacts.

**Phase B is explicitly blocked pending an operation-ID/idempotency feature,
a safe VM-only fault runner and supervised VM power-cycle access.**

## Developer / CI check

```bash
python3 -m pytest -q tests/test_vpn_vm_reboot_probe.py
python3 -m compileall -q scripts/vpn_vm_reboot_probe.py
```

Neither command requires WireGuard or root; observations are mocked.
Actual Phase A/B can only be claimed after running the steps against VMs.


## Existing three-Magos lab — operator-controlled exception

The operator elected to test the existing four VMs, without a disposable
clone. Risk is higher: an unexpected reboot failure can interrupt current
Full Mesh. Do NOT automatically reboot nodes or initiate power-loss testing
from this script. Work only one Magos at a time, ensure hypervisor console
and fresh VM snapshots are available, and explicitly validate the surviving
Magos01 ↔ Magos02 link while Magos03 is down.

Magos03 observed before reboot: `wg0` exists, `wg-quick@wg0.service`
is enabled but inactive, consistent with the helper's manual `wg-quick up`
followed by `systemctl enable`. Updated baseline accepts that state *only*
if live peer/route/handshake checks and the on-disk config parity all pass.
Post-boot `verify` requires the systemd unit to be active and both peer
handshakes to become fresh.

The baseline file should be stored as `/root/vpn-before.json` (not a
truncated `.jso`). Existing old probes must be replaced by the newly
tested revision before any reboot is authorized.
