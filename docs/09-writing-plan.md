# Step 15 — Writing plan

**Do not start writing yet.** Nothing in this repository has been compiled or run.
Every number that would go into a manuscript today would be invented.

The order below exists to prevent the standard failure: writing the paper first and
then reverse-engineering experiments that support it.

## Order

| # | Section | Precondition |
|---|---|---|
| 1 | Research gap | literature file added to `docs/lit/`, EMBN-MANET cited by full reference |
| 2 | System model | — |
| 3 | Attack model | `docs/02-attack-model.md` |
| 4 | Dataset generation | Tier 1 runs complete, seed allocation fixed |
| 5 | Proposed trust model | baseline calibration measured, thresholds re-derived from real data |
| 6 | Verification algorithm | fusion-only region confirmed non-empty on real data |
| 7 | Isolation + recovery algorithm | arms C/D/E run |
| 8 | Experiments | full matrix, ≥5 seeds |
| 9 | Results | — |
| 10 | Comparison | — |
| 11 | Discussion | — |
| 12 | Introduction and literature review | everything above settled |
| 13 | Conclusion | — |

Introduction last. It is a summary of findings, and findings do not exist yet.

## Claims-to-evidence map

Every claim the paper makes must name the file that supports it. Fill the right
column in as runs complete; anything still blank at submission time is a claim to
delete, not a claim to soften.

| Claim | Supporting evidence | Status |
|---|---|---|
| Baseline network is healthy | `results/A/*-summary.csv`, PDR ≥ 0.85 over 5 seeds | |
| A1 is invisible to behavioural evidence | `behaviour.csv`, attacker `fwd_ratio` within peer band | |
| A2 is invisible to localization evidence | `beacon_rx.csv`, attacker residual within honest band | |
| The two branches are independent | A1/A2 cross-check, `docs/05-baseline.md` | |
| Fusion beats both single-evidence detectors | ablation over `--mode`, fusion-only region non-empty | **highest risk** |
| Stouffer beats mean-based fusion | ablation over `--combine` | |
| Peer-relative scoring cuts false positives | congestion scenario, fused FPR before/after | |
| Three-way verdict reduces false isolation | arm D vs arm E false-isolation count | |
| Isolation restores network performance | `recovery.csv`, recovery ratio arm E vs arm B | |
| Recovery minimizes impact | throughput debt, arm E vs arm D | |
| Method survives realistic mobility | Tier 2 runs with `--mobilityTrace` | |

## Claims that must NOT be made

Recording these now, while it is easy to be honest about them:

- **"We propose a novel route recovery algorithm."** Recovery is AODV's native
  rediscovery under an exclusion constraint. The contribution is the constraint and
  the measurement.
- **"The malicious node is fully isolated."** Ingress is not filtered; the node can
  still be heard. Next-hop exclusion is what is implemented.
- **"Behavioural monitoring is distributed."** The current counters are node-global,
  modelling an idealised watchdog with perfect promiscuous observation.
- **Any number from `analysis/synth.py`.** It is a code test, not a result.
- **Accuracy as a headline metric.** The classes are heavily imbalanced; report
  precision, recall and FPR.

## Two things to settle before writing a word

1. **The fusion-only region.** On synthetic data it covered 1 of 42 intensity cells.
   If it is empty on NS-3 output, the Objective 3 claim as currently framed does not
   hold. Better responses than forcing it: reframe the contribution around
   false-positive reduction under adversarial conditions, or add a third evidence
   class to widen the band. Decide this before Step 12 consumes simulation time.
2. **The EMBN-MANET delta.** The literature file is still not in this repository, so
   the closest prior work is currently cited from memory of a conversation. Add it,
   read the paper again, and write one paragraph stating precisely what MBTR does
   that EMBN does not. If that paragraph is hard to write, the problem is the
   contribution, not the prose.

## Venue note

Q1/Q2 targets will expect: ≥5 seeds with confidence intervals, a non-strawmanned
prior-work baseline, an ablation isolating the claimed contribution, and released
code and data. The repository is arranged to make all four easy — the ablations are
CLI flags, arm D's advantage is asserted by a test, and the dataset ships with the
paper.
