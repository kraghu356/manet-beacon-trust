# Step 2 — Attack model

Three attacks. Not five, not six. Each one exists to stress a *different* part of the
verification mechanism, and together they cover the cases where a single-evidence
detector must fail.

## Threat assumptions

- The attacker is an **internal** node: it holds valid credentials and participates
  normally in AODV. Cryptography does not stop it.
- The attacker is a **beacon** node, i.e. one of the nodes the localization service
  treats as a position reference. It is therefore trusted by construction, which is
  what makes it worth attacking.
- The attacker controls its own transmissions only. It cannot forge another node's
  identity (no Sybil), cannot jam, and does not collude. Collusion is deferred; see
  the note at the end.
- The attacker's radio behaves physically. It can lie about *where it says it is*,
  but it cannot lie about *where its signal comes from*. This asymmetry is the entire
  basis of the localization-consistency evidence class.

## A1 — False-location beacon

The beacon advertises a position that is not its own.

| Parameter | Value |
|---|---|
| Offset model | fixed displacement vector, configurable magnitude |
| Default offset | 300 m (e.g. true `(100, 200)` → claimed `(400, 500)`) |
| Routing behaviour | fully honest — forwards every packet |
| Beacon period | identical to honest beacons |

**Why it is in the set.** It is invisible to behavioural evidence. Forwarding ratio,
drop ratio and delay are all nominal. Any detector built only on routing behaviour
scores this node as perfectly trustworthy. Localization consistency must catch it
alone, which makes A1 the ablation case that justifies the beacon-evidence branch.

**Sweep.** Offset magnitude is the primary sensitivity parameter, from ~20 m (inside
RSSI estimation noise, should be undetectable and *should not* be flagged) up to
500 m (trivially detectable). The detection floor found here is a reportable result.

## A2 — Malicious forwarding beacon

The beacon reports its position honestly but drops or selectively forwards packets
it is asked to relay.

| Parameter | Value |
|---|---|
| Drop probability | configurable, default 0.6 (grey-hole) |
| Special cases | `p = 1.0` is black-hole; `p ∈ (0,1)` is grey-hole |
| Selectivity | uniform random by default; per-flow selectivity is a later variant |
| Position reporting | fully honest |
| Control traffic | AODV RREQ/RREP forwarded normally, so it stays on routes |

**Why it is in the set.** The mirror image of A1. Localization consistency sees a
model citizen. Only behavioural evidence catches it. It also generates the hard
false-positive case, because congestion, buffer overflow and mobility-induced link
breakage produce packet loss that looks like this at low `p`.

**Sweep.** Drop probability from 0.1 to 1.0. The low end is where the mechanism must
prove it separates malice from ordinary loss — that is the false-positive-rate result.

## A3 — Hybrid malicious beacon

Both behaviours, at reduced intensity.

| Parameter | Value |
|---|---|
| Location offset | 150 m (half of A1) |
| Drop probability | 0.3 (half of A2) |
| Rationale | each signal individually sits near or below its single-evidence threshold |

**Why it is in the set.** This is the case the whole thesis rests on. Neither
evidence class alone should reliably confirm A3 at these intensities, but their
*agreement* should. If the fused detector does not beat both single-evidence
detectors on A3, the contribution claimed in `docs/01-objectives.md` is not
supported and the design needs to change before any paper is written.

## Ground truth

Every simulation writes `ground_truth.csv`:

```
node_id, is_beacon, attack_type, attack_start_s, attack_stop_s, param_offset_m, param_drop_prob
```

`attack_type ∈ {none, A1, A2, A3}`. No labelling is inferred at analysis time.

## Timing

Attacks activate at `t = 30 s`, after AODV routes have converged, and run to the end
of the simulation. A quiet warm-up matters: trust histories built during route
convergence are noisy and would contaminate the historical-trust term in Step 8.

An intermittent (on-off) attacker is a natural later addition — it directly attacks
the historical-trust term — but it is **not** in the first implementation.

## Deferred

Recorded so the scope decision is explicit and defensible at review:

- **Colluding beacons** mutually endorsing false positions. Breaks the
  neighbour-agreement feature. The strongest single extension.
- **Sybil / identity forgery.** Different problem class; needs an identity mechanism.
- **Wormhole.** Distorts distance estimation, but the countermeasure is orthogonal.
- **Adaptive attacker** that observes its own trust score and throttles to stay
  under threshold. The natural attack on any threshold-based scheme, and the right
  subject for future work rather than this paper.
