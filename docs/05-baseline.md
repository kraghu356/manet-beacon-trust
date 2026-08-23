# Steps 5–7 — Baseline, first attack, behavioural evidence

## Step 5 — The clean baseline

No malicious nodes. Run this first and do not proceed until it looks sane.

```bash
./scripts/run_baseline.sh
```

### Parameters

| Parameter | Value |
|---|---|
| Nodes | 20 (ids 0–2 are beacons) |
| Area | 1000 × 1000 m |
| Mobility | Random Waypoint, 1–5 m/s, 2 s pause |
| MAC/PHY | IEEE 802.11b, 11 Mbps DSSS, log-distance path loss (n = 3) |
| Routing | AODV |
| Traffic | 4 UDP CBR flows, 512 B, 4 pkt/s, starting at t = 10 s |
| Beacons | 1 Hz position broadcast |
| Duration | 200 s |
| Seeds | 5 |

### Result table to fill in

| Metric | Normal MANET |
|---|---|
| PDR | |
| Throughput (kbps) | |
| End-to-end delay (ms) | |
| Routing overhead | |
| Energy consumption (J) | |

Report mean ± 95 % CI over the five seeds. A single run is not a baseline.

### Sanity conditions before moving on

If any of these fail, the fault is in the baseline, not in the attack — fix it here.

- **PDR above roughly 0.85.** Much lower on a clean 20-node network means the
  topology is partitioning. Reduce the area or raise transmit power.
- **`malicious_drop = 0` in `summary.csv`.** Non-zero on a clean run means the
  routing wrapper is misconfigured.
- **`beacon_rx.csv` residuals small and roughly symmetric about zero.** These come
  from honest beacons, so the residual is pure RSSI estimation noise. Record its
  standard deviation: **this number sets the detection floor for A1** and every
  localization threshold in Step 8 is expressed as a multiple of it. It is the
  single most important quantity produced by the baseline.
- **Every node appears in `behaviour.csv`.** Nodes with `transit_rx = 0`
  throughout are never on a route and contribute nothing; if most nodes look like
  that, the flows are too few or too clustered.

## Step 6 — One malicious beacon (A1)

```bash
./scripts/run_attacks.sh   # or a single --attack=A1 run
```

The attacker (node 2, a beacon) advertises a position displaced by 300 m from
t = 30 s, and forwards packets honestly throughout.

Expected: network metrics essentially unchanged from baseline, because nothing is
being dropped. **If PDR falls under A1, something is wrong** — A1 has no routing
component. The signal appears only in `beacon_rx.csv`, as a step change in
`residual_m` for `beacon_id = 2` at t = 30 s.

Plot residual against time per observer. That plot is the existence proof for the
localization-evidence branch, and it belongs in the paper.

## Step 7 — Behavioural evidence (A2, A3)

A2 makes the same beacon drop 60 % of transit traffic while reporting position
honestly. A3 halves both intensities.

The counters in `behaviour.csv` give, per 10 s window:

- `fwd_ratio` = forwarded / offered-for-forwarding
- `drop_ratio` = (offered − forwarded) / offered
- `mean_relay_delay_s`
- `malicious_drop` (ground truth, for validation only — never a model input)

A value of `-1` means the node carried no transit traffic in that window. Treat it
as missing, not as zero — a node with nothing to forward is not a node that failed
to forward, and conflating the two manufactures false positives on idle nodes.

### The cross-check that matters

Take the two single-evidence views and confirm they are blind where the attack
model says they should be:

| Scenario | Localization residual | Forwarding ratio |
|---|---|---|
| A1 | elevated | normal |
| A2 | normal | depressed |
| A3 | mildly elevated | mildly depressed |

If A2 shows an elevated residual, the two evidence classes are not independent and
the fusion argument in `docs/01-objectives.md` weakens. Investigate before Step 8 —
the likely cause is that dropped data traffic is changing channel contention enough
to perturb RSSI, which would be worth reporting either way.

## Known implementation caveats

1. **RSSI attribution** keys on the transmitter MAC from the sniffed frame rather
   than packet UID, which survives fragmentation and aggregation. It stores only
   the most recent sample per pair, so a beacon reception is matched to the last
   frame heard from that node — near-simultaneous in practice, but it is an
   approximation and should be stated as one.
2. **Relay delay** is measured from `RouteInput` acceptance to `UnicastForward`,
   so it captures queueing and MAC contention but not propagation.
3. **Energy module namespace** changed in NS-3 3.41. See the note in the source.
4. **Beacon broadcasts are single-hop** by design, since a position claim is only
   verifiable by nodes in direct radio range. Multi-hop beacon propagation would
   need a separate consistency argument.
