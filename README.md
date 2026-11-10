# MBTR-MANET

**Multi-evidence Beacon Trust and Recovery for MANETs**

Verification, isolation and secure-route recovery for malicious beacon nodes in
mobile ad hoc networks, using combined *behavioural* and *localization-consistency*
evidence.

This repository is the implementation arm of Paper 2, which consumes the candidate
malicious beacon nodes produced by Paper 1 and answers the question Paper 1 leaves
open: *is this candidate actually malicious, and what does the network do about it?*

## Research objectives

3. Develop a multi-evidence trust mechanism for verifying malicious beacon nodes
   using behavioural and localization consistency.
4. Isolate confirmed malicious beacon nodes and dynamically recover secure routes
   while minimizing the impact on network performance.

Full framing in [`docs/01-objectives.md`](docs/01-objectives.md).

## Repository layout

| Path | Contents |
|---|---|
| `docs/` | Design documents, one per planning step |
| `ns3/` | NS-3 simulation source (C++) |
| `scripts/` | Build and run helpers |
| `analysis/` | Evidence extraction, trust model, decision rule |
| `tests/` | Executable checks on synthetic evidence |
| `results/` | Simulation output (git-ignored except `.gitkeep`) |

## Running the analysis

```bash
pip install -r requirements.txt
python3 tests/test_pipeline.py          # structural checks, ~10 s
python3 tests/test_metrics.py           # metric suite, ~2 s
python3 tests/test_superadditivity.py   # fusion-advantage sweep, ~10 min
```

Both run on synthetic evidence and are code tests, not results. See the warning at
the top of `analysis/synth.py`.

## What is blocking everything

Nothing here has been compiled or run against a live NS-3 tree. All 15 planning
steps have an implementation, but every number they could produce is currently
hypothetical. The next action is `./scripts/setup_ns3.sh`, then the baseline.

Two open risks are recorded in full in `docs/09-writing-plan.md`: the fusion-only
detection region (narrow on synthetic data, unverified on real data) and the
missing literature file behind the EMBN-MANET comparison.

## Phase 2 (review, Nov 2026)

Runs requested by the internal review of the Paper 2 draft. One stage at a time:

| Stage | ns-3? | What it answers |
|---|---|---|
| `STAGE=phi ./scripts/phase2.sh` | no | Is Policy D a warm-up strawman? Adds arms Dw (warm-up guard) and D1 (one window of malicious evidence) and computes Phi on clean **and** attacked runs, with paired bootstrap CIs |
| `STAGE=low` | 30 runs | Locates the behavioural 50% crossing below 15 m / 3% drop |
| `STAGE=pair2` | 80 runs | Shows how the sensitivity ratio depends on the delta-p pairing (p = 0.3 f) |
| `STAGE=seeds` | 105 runs | 30 seeds, sigma = 0: coverage, latency, Phi with paired CIs |
| `STAGE=shadow` | 170 runs | sigma = 4 and 8 dB: does the localisation branch survive? |
| `STAGE=eval` | no | Scores all of the above into `results/tables/` |

`python3 -m analysis.fusion_region` prints the corrected fusion-region bound
(r < 1 + sqrt(2) for equal weights; the draft's sqrt(2) was the region's width, not
the condition) and the Table 6 crossings. `tests/test_fusion_region.py` checks it.

## Build status

The NS-3 sources in `ns3/` have **not** been compiled against a live NS-3 tree yet.
They target the NS-3 3.40+ API. Treat the first successful build as a milestone in
its own right — see `docs/04-platform-and-setup.md`.

## Progress against the plan

- [x] Step 1 — Freeze objectives
- [x] Step 2 — Define the malicious-beacon attack model
- [x] Step 3 — Architecture
- [x] Step 4 — Platform selection (NS-3)
- [x] Step 5 — Baseline MANET
- [x] Step 6 — Single false-location beacon
- [x] Step 7 — Behavioural evidence
- [x] Step 8 — Trust model
- [x] Step 9 — Three-way decision
- [x] Step 10 — Isolation
- [x] Step 11 — Route recovery
- [x] Step 12 — Comparative evaluation (harness; needs runs)
- [x] Step 13 — Metric suite
- [x] Step 14 — Dataset strategy
- [ ] Step 15 — Manuscript (plan written; blocked on real runs)

### Figures

`python3 scripts/make_figures.py --results results --out figures` regenerates
every data figure of the paper (coverage, throughput, intensity sweeps, first
isolation, recovery ratio, cumulative false isolation, aggregation ablation,
shadowing) from the result tables. Each figure is skipped, with a message, if
its inputs are absent. Raw traces for all 485 runs are archived on Zenodo
(see the paper's data availability statement).
