# Step 4 — Platform: NS-3

## Decision

NS-3 (3.40 or later), not an extension of the Paper 1 codebase.

## Reasoning

The feature inventory in Step 3 requires simultaneous access to node mobility and
true positions, AODV internals, per-packet transmit/receive/drop events, routing
tables, physical-layer RSSI, per-hop delay, throughput, PDR, routing overhead and
energy. NS-3 exposes all of these through documented trace sources in one process.

Reusing the Paper 1 code would mean retrofitting a physical layer to it. RSSI is not
an optional extra here — without it there is no localization-consistency evidence and
Objective 3 collapses to a behaviour-only trust model, which the literature already
covers. The physical layer is the load-bearing requirement, and it is the thing NS-3
provides that a higher-level detection codebase does not.

Paper 1 is not discarded; it is the *source of candidates*. Its output is replayed
into this simulator as a candidate list (`--candidates=`), so the two papers stay
coupled at the interface rather than at the code level.

## Which trace sources carry which feature

| Feature | Source |
|---|---|
| RSSI | `WifiPhy` `MonitorSnifferRx` → `signalNoise.signal` |
| True position | `MobilityModel::GetPosition()` |
| Claimed position | beacon application payload |
| Forwarded / received | `Ipv4L3Protocol` `Tx` / `Rx` traces |
| Deliberate drops | counter inside the malicious routing wrapper |
| PDR, throughput, delay | `FlowMonitor` |
| Routing overhead | AODV control bytes vs. total bytes |
| Energy | `BasicEnergySource` + `WifiRadioEnergyModel` |

## Grey-hole implementation approach

NS-3 has no built-in malicious node. Rather than fork the AODV module — which makes
the diff hard to defend and hard to rebase — the simulator installs a small
`Ipv4RoutingProtocol` wrapper at higher priority than AODV in `Ipv4ListRouting`:

- `RouteOutput` always returns null, so locally originated traffic is untouched and
  the attacker's own flows behave normally.
- `RouteInput` intercepts packets that are *transiting* the node. With probability
  `p` it consumes and discards them; otherwise it declines and AODV forwards as usual.

Consequence: AODV control plane is untouched, so the attacker still wins routes and
still answers RREQs. That is exactly the grey-hole behaviour we want, and the
attacker stays on paths instead of being routed around for the wrong reason.

## Environment

```bash
./scripts/setup_ns3.sh          # clone + configure + build NS-3
./scripts/run_baseline.sh       # Step 5 clean baseline
./scripts/run_attacks.sh        # Steps 6-7 attack scenarios
```

`setup_ns3.sh` expects `NS3_DIR` (default `$HOME/ns-3-dev`). The simulator source is
symlinked into `scratch/`, so no NS-3 file is ever modified. That property is worth
protecting — it is what makes the work reproducible by a reviewer with a stock NS-3.

## Build status

**Not yet compiled.** The sources target the 3.40+ API and are unverified against a
live tree. Expect to spend the first session on build errors rather than results;
the API surface for `MonitorSnifferRx` and the energy model has shifted across
releases. Fix them before trusting any number this produces.
