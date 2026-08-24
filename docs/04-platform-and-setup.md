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

**Compiles to an object file against NS-3 3.42** (`g++ -c -std=c++20 -I build/include`).
Full link and execution are still outstanding — see the caveat at the end.

Four defects were found and fixed by compiling. They are recorded because three of
them are not guessable from documentation:

1. **`struct Config` collided with `ns3::Config`**, the attribute/trace namespace.
   Renamed to `SimConfig`.
2. **Energy classes are split across two namespaces in 3.42.** The models
   (`EnergySourceContainer`, `DeviceEnergyModelContainer`, `BasicEnergySource`)
   moved into `ns3::energy`; the helpers (`BasicEnergySourceHelper`,
   `WifiRadioEnergyModelHelper`) stayed in plain `ns3`. Half-qualifying either way
   fails.
3. **`InternetStackHelper` does not wrap the routing helper in `Ipv4ListRouting`.**
   Passing `AodvHelper` directly makes `GetRoutingProtocol()` return a bare
   `aodv::RoutingProtocol`, so the `DynamicCast<Ipv4ListRouting>` returns null and
   the run aborts. The compiler cannot see this; it is a runtime failure. The list
   is now built explicitly with AODV at priority 10.
4. **`Ipv4ListRouting` sorts by descending priority** (verified in
   `Ipv4ListRouting::Compare`), so `TransitControlRouting` at 100 is consulted
   before AODV. The design depended on this and it had been assumed, not checked.

Two signatures were verified against the NS-3 source rather than assumed:

- `MonitorSnifferRx` fires
  `(Ptr<const Packet>, uint16_t, WifiTxVector, MpduInfo, SignalNoiseDbm, uint16_t)`.
  Trace callbacks are type-checked at *runtime*, so a mismatch here would have
  aborted mid-simulation with no compile-time warning.
- `Ipv4L3Protocol::UnicastForward` uses `SentTracedCallback`, and `Drop` uses
  `DropTracedCallback`. Both match.

### What compiling still does not prove

An object file is not a working simulation. Still unverified: linking, TypeId
registration at runtime, whether `BlacklistQueueDisc` installs correctly through
`TrafficControlHelper`, whether beacon receptions actually find a matching RSSI
sample, and every number the thing produces. Run it before believing any of it.
