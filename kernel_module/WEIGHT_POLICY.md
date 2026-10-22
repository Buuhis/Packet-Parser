# Weight policy and load-balancing modes

The existing BE profile field `sdwan_profiles.weight_enable` controls whether
the module selects data tunnels. It is independent of the runtime
`per-flow` / `per-packet` mode selected with `sd-wan -m`.

| Weight policy | Data egress |
| --- | --- |
| Disabled | Preserve the device chosen by Linux routing. No module load balancing or BFD-driven tunnel substitution. L2-PQC still encrypts/decrypts; unencrypted data follows the normal IPv4 output path. |
| Enabled, per-flow | Existing load-aware weighted flow admission, sticky paths and BFD failover. Existing flows retain the existing weight-update/stickiness behavior. |
| Enabled, per-packet | Weighted round-robin across eligible UP, nonzero-weight tunnels in the existing NONE/L2-PQC datapaths. |

Both modes consume the same configured weights and BFD path publication.
Per-packet selection uses exact weights rather than rounding to LUT slots.
80:20 reduces to a five-selection cycle (four on A, one on B), with a
flow-hash-derived starting offset. DOWN/zero-weight tunnels are excluded and
the remaining weights are renormalized. An empty eligible set drops data.
Counts refer to original packets before GSO segmentation or IPv4 fragmentation,
not bytes or measured wire throughput. The existing per-protocol window
parameters multiply each selection; their default is one.

BFD sessions and peer discovery remain active in both policies. BE continues
using `-gs/--get-status` for BFD status and `-gpi/--get-peer-ip` for discovered
peer IP. The latter is a peer-discovery query, not a BFD status query.

Full configuration and in-place weight updates carry an explicit
`MWAN_ATTR_WEIGHT_ENABLED`. The DB loader emits zero runtime weights when
disabled; the flag, not those numbers, determines routing policy. Re-enabling
reloads the configured percentages from the DB. Flag-only edits are sent to
the kernel even if the numeric weights are unchanged, without restarting BFD
or PQC just for that edit.

## Upgrade and verification

Deploy daemon and module from this revision together (Generic Netlink protocol
version 9). The module rejects configuration/weight updates missing the
explicit policy flag. A weight-only edit does not select/reset the runtime
load-balancing mode. The existing mode-switch requirement remains: stop
application traffic before switching modes. Seamless transitions with queued
application traffic are not validated by these host tests.

Run `make -C tests check`, `make -C failover/test check`, `make -C kernel W=1`
and build the daemon with the project's libscrypt dependency available.
Host tests cover weighted ratios, eligibility changes, configuration flag-only
updates, routing-only dispatch and the RX NULL-flow regression; routing/RX
tests execute source-extracted branches with stub kernel dependencies.

Before production use, verify on a test device with both modes: disabled
weight follows route changes while encryption and BE queries work; enabled
weight distributes data across eligible tunnels and reacts to BFD DOWN/recovery.
Do not infer successful on-device crypto, failover timing or freedom from
kernel crashes solely from host tests/builds.
