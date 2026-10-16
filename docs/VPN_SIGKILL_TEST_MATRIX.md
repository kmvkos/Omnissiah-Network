# VPN v2: SIGKILL failure-injection matrix

These tests run in **disposable Linux network namespaces on GitHub Actions**
against real kernel WireGuard state, `wg syncconf`, `ip -4 route`, fsynced
journals and root-owned backups.

They use `fork()` and `SIGKILL` on the **child only**. The parent waits with a
10-second watchdog, then reads persisted state from a fresh post-kill execution
path. Nothing touches the CI runner's host `wg0` or any real Magos VM.

| Crash boundary | Durable state | Expected outcome |
| --- | --- | --- |
| Backup written, journal absent | Orphan backup | Block new writes; show `recovery_required / orphan_backup` |
| `prepared` journal durable, before WG update | Original kernel state | Read-only verification and mark `rolled_back` |
| After `wg syncconf`, journal `wg_sync` | New peer, no route | Fail closed, no unreviewed mutation |
| Before first `ip route add` | `applying/route`, pending step | Remove recorded new peer, preserve old peer/route |
| After `ip route add`, before journal acknowledgement | `applying/route`, stale counter | Remove recorded new route and peer, preserve old state |
| During rollback, after route deleted | `rolling_back/add_only_recovery` | Resume, revalidate and remove new peer |
| During rollback, after peer removed | `rolling_back/add_only_recovery` | Revalidate original state and finalize journal |

All recovery tests check the surviving original peer set, IPv4 route set and
original `wg0.conf` bytes. Existing peer handshake *continuity* is not yet
proven by these tests: the isolated mock peer keys do not represent an active
remote transport session.

## Known unresolved scenarios

- True **VM power loss** / filesystem recovery / post-boot `wg-quick` ordering.
- `SIGKILL` during a kernel subprocess rather than just after command completion.
- `SIGKILL` after configuration persistence but before committed journal.
- Unknown completion of a timeout along the controller → mTLS → Unix RPC chain.
- Changes to existing peers, endpoint reconfiguration, subnet routes and deletion.
- Simultaneous out-of-band administrators modifying the same kernel state.

Any unknown or foreign state must fail closed. Do not enable an automatic boot
restore for add-only recovery until these cases are addressed and supervised
VM snapshot/console tests pass.

## Repeat CI tests

GitHub Actions: `Isolated WireGuard network namespace integration` workflow,
`tests/integration/test_vpn_netns_live.py`.

No deployment or inventory changes are required for this test milestone.
