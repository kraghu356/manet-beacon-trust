# Step 14 — Dataset strategy

Three tiers, doing three different jobs. Do not blur them in the paper.

## Tier 1 (primary) — NS-3 generated, with ground truth

This is the only tier that can support the detection claims, because it is the
only one with ground truth for true position, claimed position, RSSI, forwarding
behaviour and attack state simultaneously. No public dataset has that combination,
which is the actual justification for generating it — not convenience.

Assembled by `analysis/dataset.py` from per-run evidence tables.

### Splitting rule, and why it is not negotiable

Rows are **not independent samples**. Rows from one run share topology, mobility
and the same attacker; rows from one (target, run) are a time series. A row-level
train/test split places windows from the same run on both sides and produces
accuracy figures that mean nothing.

Every split is therefore **by seed**. `check_leakage()` refuses to return a split
that violates this, and also refuses when a calibration seed appears in the test
set — thresholds are fitted on calibration data, so a test set that helped set them
is not a test set.

Suggested allocation over 15 seeds per scenario:

| Purpose | Seeds |
|---|---|
| Calibration (attack-free only) | 1–3 |
| Development / tuning | 4–10 |
| Held-out evaluation, touched once | 11–15 |

Report the held-out numbers. If you tune after looking at seeds 11–15, they stop
being held out and you must say so.

### Report class balance, never bare accuracy

With one attacker among three beacons, a detector that flags nothing scores about
67 % accuracy on beacon rows and far higher across all nodes. `class_balance()`
prints the majority-class accuracy alongside every table so that number is visible.
Precision, recall and FPR are the honest metrics here; accuracy is close to
meaningless and reviewers know it.

## Tier 2 (validation) — realistic mobility traces

Random Waypoint is known to be unrealistic: speed decay, non-uniform node density,
no obstacles, no social structure. If the method only works under RWP, that is a
finding about RWP.

Feed real traces through `--mobilityTrace=<ns-2 movement file>`, which switches the
simulator to `Ns2MobilityHelper` and leaves everything else identical. Node count
must match the trace; a mismatch is checked and aborts rather than silently leaving
surplus nodes at the origin, which would corrupt every localization residual.

**Sourcing note, checked August 2026.** CRAWDAD is no longer a standalone archive.
The collection migrated to IEEE DataPort and has been hosted there since 2022, so
crawdad.org download links found in older papers are dead and a free IEEE DataPort
account is needed. Cite the IEEE DataPort location.

Candidate tracesets: `ncsu/mobilitymodels` (GPS pedestrian traces with plain
time/x/y records, closest to drop-in), `rice/ad_hoc_city` (bus mobility, already in
metres-like coordinates), `epfl/mobility` (San Francisco taxis, needs projection
from lat/long to a metric plane).

Most need conversion into ns-2 movement format. Budget real time for this — trace
coordinates are typically in the wrong units, the wrong span for a 1000 × 1000 m
field, and at the wrong sampling rate.

**What Tier 2 can and cannot claim.** It validates that detection survives
realistic mobility. It cannot validate the attack model, because the traces contain
no attackers — the attack is still injected synthetically. Say this plainly.

## Tier 3 (behavioural cross-check) — public intrusion datasets

The plan calls for a public MANET dataset to validate the behavioural component.
Be careful here: there is no widely used public dataset with labelled malicious
**beacon** behaviour in a MANET. Substitutes usually offered (KDD'99, NSL-KDD,
CICIDS variants, WSN-DS) are wired or WSN intrusion datasets whose features do not
correspond to the ones defined in `docs/03-architecture.md`.

Two honest options:

1. **Drop Tier 3** and state that no public dataset provides the required feature
   combination. This is defensible and easy to support.
2. **Use one narrowly**, e.g. WSN-DS for grey-hole-like behaviour, to show the
   *behavioural branch alone* transfers. Do not present it as validating the fused
   method, because the localization branch has no counterpart in it.

Forcing a mismatched public dataset in to look thorough is a bigger review risk
than not having one. Option 1 with a clear sentence beats a strained Option 2.

## Release

Publish the generated dataset with the paper: evidence CSVs, ground truth,
calibration JSON, seed allocation and simulator commit hash. Reproducibility is
cheap here and it is the strongest answer to "did you tune on the test set".
