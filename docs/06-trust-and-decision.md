# Steps 8–9 — Trust model and three-way decision

Implemented in `analysis/`. Runnable now against synthetic evidence; the interfaces
match the CSV schema `ns3/mbtr-sim.cc` emits, so no rewiring is needed when real
runs arrive.

## The model

```
T_ij = (w_d · D_ij + w_r · R_ij + w_h · H_ij) / (w_d + w_r + w_h)

D_ij = fusion of behavioural and localization evidence, observer j on target i
R_ij = bounded trimmed consensus of D_ik for k ≠ j
H_ij = asymmetric EWMA of past T_ij
```

Nothing is hand-tuned. Every threshold is a multiple of a dispersion estimated from
the attack-free baseline by `analysis/calibrate.py`, using MAD rather than standard
deviation so a transient partition in the baseline cannot silently destroy
sensitivity.

## Three design decisions worth defending

### 1. Weights are availability-gated and confidence-scaled

If a target carried no transit traffic in a window, the behavioural branch has no
measurement, and its weight goes to zero rather than contributing a default. A
branch backed by three samples counts less than one backed by forty. Fixed weights
over missing data is the standard way trust schemes manufacture false positives on
idle nodes, and it is avoidable.

### 2. Behavioural evidence is scored peer-relative, not against a fixed baseline

Congestion depresses every node's forwarding ratio at once; a grey-hole depresses
one. A static threshold cannot tell these apart. The behavioural z-statistic is
therefore computed against the median and MAD of the contemporaneous node
population, falling back to static calibration when there are too few peers.

**This was measured, not assumed.** Before peer-relative scoring, a benign
congestion scenario (network-wide forwarding ratio dropped to 0.68, no attacker)
produced 3 false confirmations in both fused and behaviour-only modes. After, zero
in all modes. Reproduce with `python3 tests/test_pipeline.py`.

Note honestly where the credit lies: the congestion robustness comes from
peer-relative normalisation, **not** from fusion. Do not attribute it to fusion in
the paper.

### 3. Evidence is combined by Stouffer's method, not by averaging scores

This is the load-bearing decision, and the first two attempts were wrong.

**Arithmetic mean fails outright.** A beacon lying about its position by 300 m
while forwarding perfectly scores about 0.5 and escapes any sensible threshold.
Honest forwarding is not counter-evidence to a false position claim — the two are
independent by construction — so averaging them is the wrong model of the evidence.

**Geometric mean fails structurally.** The geometric mean of two scores always
lies at or above the lower one. So anything the fused detector confirms, the
more-alarmed single branch confirms too, usually sooner. Under this rule fusion
**cannot** beat the best single-evidence detector, ever. That is a property of the
algebra, not of the data, and no parameter tuning escapes it. Since the entire
contribution in `docs/01-objectives.md` is that fusion beats single-evidence
detection, this rule would have made the thesis unprovable — while still producing
plausible-looking results tables.

**Stouffer's method sums standardised deviations instead of averaging scores**, so
two independently mild anomalies compose into one strong one: z = 1.3 on each
branch gives a combined 1.84, stronger than either input. That super-additivity is
what makes fusion capable of detecting the hybrid attack A3 when neither branch
alone can.

The combination rule is exposed as `--combine {stouffer,geometric,arithmetic}`,
because the comparison above is itself a reportable result and a reviewer will ask.

**Validity condition.** Stouffer's `√(Σw²)` denominator assumes the branches are
independent. If they are correlated, the combined statistic is over-confident and
the false-positive rate is understated. The A1/A2 blindness cross-check in
`docs/05-baseline.md` is therefore not a nicety — it is the precondition for this
rule being correct. Verify it on real data before reporting any fused result.

## Step 9 — The three-way verdict

Promotion to `confirmed` requires four conditions simultaneously:

| Condition | Guards against |
|---|---|
| trust < `theta_low` | — |
| ≥ `min_observers` independent observers | a single badly placed observer convicting a node |
| observer agreement ≥ `min_agreement` | localised radio anomalies |
| sustained `persistence` consecutive windows | transient congestion and link breakage |

plus, in fused mode, either both branches available or one branch flagging
extremely. Leaving `confirmed` requires `clear_persistence` clean windows, which is
deliberately longer than entering it, so a node cannot oscillate back into routing.

`suspicious` is a real state, not a rounding error: it extends observation and
de-prioritises the node in route selection without isolating it. The count of
windows spent in `suspicious` is a metric in its own right — it is the cost of
caution, and it is what makes the false-positive claim honest.

## Findings so far, from synthetic data only

**These are not results.** The generator draws from the distributions the detector
assumes, so it cannot falsify the detector. It can only show the code runs and the
logic branches as designed. No number from this section goes in the paper.

Structural checks that pass (`tests/test_pipeline.py`):

- Zero confirmations on a clean run, in all three modes.
- Fused confirms A1, A2 and A3.
- Behaviour-only misses A1; localization-only misses A2. The designed blindness
  holds, so the two branches really are independent under these assumptions.
- Zero false confirmations under benign congestion, in all modes.

**The finding that matters most, and it is a warning.** `tests/test_superadditivity.py`
sweeps hybrid-attack intensity looking for a region where fusion confirms and
*neither* single branch does. Such a region exists — but in exactly **1 of 42 cells**
tested. The fusion advantage is real and extremely narrow.

Implication for the research plan: the viability of Objective 3's contribution
depends entirely on whether real NS-3 attackers land in that narrow band. This is
the first thing to check once the baseline runs, and it should be checked **before**
committing to the full Step 12 comparison. If the band turns out to be empty on real
data, better options than forcing it include reframing the contribution around
false-positive reduction under adversarial conditions, or adding a third evidence
class to widen the band.

## Open items

- Behavioural counters from the current simulator are node-global, modelling an
  idealised watchdog with perfect promiscuous observation. A true per-observer
  watchdog is a refinement; until it exists, the behavioural branch must not be
  described as distributed.
- The recommendation term is bounded by trimming and an influence cap, but has not
  been tested against a deliberate bad-mouthing attacker. That test belongs with the
  collusion scenario deferred in `docs/02-attack-model.md`.
- `theta_low = 0.40` corresponds to roughly z = 1.35, which is a loose bar. Re-derive
  both thresholds from the real baseline's false-positive curve rather than keeping
  these defaults.
