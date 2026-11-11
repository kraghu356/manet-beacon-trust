"""Evaluate a multi-seed campaign end to end, without re-running ns-3.

For a directory of simulator outputs named <ATK>-seed<N>-run1-{beacon_rx,behaviour}.csv
(ATK in none, A1, A2, A3) this:

  1. calibrates on separate clean runs (--calib-glob), never on the test seeds;
  2. decides each run in behaviour / localization / fused mode -> coverage table;
  3. writes fused verdicts and the C, D, Dw, D1, E schedules for every run;
  4. computes Phi per arm for clean AND attacked runs (analysis.phi).

    python -m analysis.campaign_eval --runs results/seeds30 \
        --calib-glob "results/calib/none-seed10*-run1-beacon_rx.csv" \
        --out results/tables/seeds30
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import numpy as np
import pandas as pd

from .calibrate import calibrate
from .decide import DecisionParams, confirmation_summary, decide
from .features import run_finished, WindowSpec, build_evidence, load_beacon_rx, load_behaviour
from .make_schedules import _write, build_schedules
from .phi import bootstrap_ci, paired_diff_ci, phi_for_run
from .trust import TrustParams, compute_trust

SPEC = WindowSpec(10.0, 5.0)


def _evidence(brx: str) -> pd.DataFrame:
    """Evidence for every beacon present in the trace (3 in the base topology,
    more in the scaled ones)."""
    beh = brx.replace("-beacon_rx.csv", "-behaviour.csv")
    rx = load_beacon_rx(brx)
    beacons = sorted(int(b) for b in rx["beacon_id"].unique())
    return build_evidence(rx, load_behaviour(beh), SPEC, beacon_ids=beacons)


def calibrate_many(paths: list[str]):
    if not paths:
        raise SystemExit("no calibration runs matched --calib-glob")
    ev = pd.concat([_evidence(p) for p in paths], ignore_index=True)
    return calibrate(ev)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.campaign_eval")
    ap.add_argument("--runs", required=True, help="dir with <ATK>-seed<N>-run1-*.csv")
    ap.add_argument("--calib-glob", required=True)
    ap.add_argument("--attack-start", type=float, default=30.0)
    ap.add_argument("--sim-time", type=float, default=400.0)
    ap.add_argument("--warmup-windows", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    cal = calibrate_many(sorted(glob.glob(args.calib_glob)))
    cal.to_json(os.path.join(args.out, "calibration.json"))
    print(cal.summary())

    pat = re.compile(r"(?P<atk>none|A1|A2|A3)-seed(?P<seed>\d+)-run1-beacon_rx\.csv$")
    cov, phi_rows = [], []
    for brx in sorted(glob.glob(os.path.join(args.runs, "**", "*-run1-beacon_rx.csv"),
                            recursive=True)):
        m = pat.search(os.path.basename(brx))
        if not m or not run_finished(brx):
            continue
        atk, seed = m["atk"], int(m["seed"])
        ev = _evidence(brx)
        row = {"attack": atk, "seed": seed}
        for mode in ("behaviour", "localization", "fused"):
            trust = compute_trust(ev, cal, TrustParams(mode=mode))
            v = decide(trust, DecisionParams(), mode=mode)
            s = confirmation_summary(v, args.attack_start)
            a, h = s[s["is_attacker"] == 1], s[s["is_attacker"] == 0]
            # With several attackers, *_tp is 1 only if every attacker was confirmed;
            # *_tp_frac records the fraction confirmed.
            row[f"{mode}_tp"] = int(a["ever_confirmed"].min()) if len(a) else np.nan
            row[f"{mode}_tp_frac"] = float(a["ever_confirmed"].mean()) if len(a) else np.nan
            row[f"{mode}_fp"] = int(h["ever_confirmed"].sum())
            if mode == "fused":
                # Single attacker: its latency. Several: the mean over attackers detected.
                row["latency_s"] = float(a["detection_latency_s"].mean()) if len(a) else np.nan
                vdir = os.path.join(args.out, "verdicts")
                os.makedirs(vdir, exist_ok=True)
                v.to_csv(os.path.join(vdir, f"{atk}-seed{seed}-verdicts.csv"), index=False)
                sdir = os.path.join(args.out, "sched", f"sched-{atk}-seed{seed}")
                for arm, rows in build_schedules(v, args.warmup_windows).items():
                    _write(os.path.join(sdir, f"{arm}.csv"), rows)
                for r in phi_for_run(s, sdir, args.sim_time):
                    phi_rows.append({"attack": atk, "seed": seed, **r})
        cov.append(row)

    cov = pd.DataFrame(cov)
    cov.to_csv(os.path.join(args.out, "coverage_per_run.csv"), index=False)
    agg = cov.groupby("attack").agg(
        seeds=("seed", "size"),
        behaviour_tp=("behaviour_tp", "sum"), localization_tp=("localization_tp", "sum"),
        fused_tp=("fused_tp", "sum"), fused_fp=("fused_fp", "sum"),
        latency_mean=("latency_s", "mean"), latency_sd=("latency_s", "std"))
    agg.to_csv(os.path.join(args.out, "coverage.csv"))
    print("\n=== coverage (attacker confirmed, of seeds) ===\n" + agg.to_string())

    phi = pd.DataFrame(phi_rows)
    phi.to_csv(os.path.join(args.out, "phi_per_run.csv"), index=False)
    lines = []
    for (atk, arm), g in phi.groupby(["attack", "arm"]):
        lo, hi = bootstrap_ci(g["phi_node_s"].to_numpy())
        lines.append({"attack": atk, "arm": arm, "seeds": len(g),
                      "honest_isolated": f"{g['honest_isolated'].sum()}/{g['n_honest'].sum()}",
                      "phi_mean": round(g["phi_node_s"].mean(), 1),
                      "boot95": f"[{lo:.0f}, {hi:.0f}]",
                      "phi_bar": round(g["phi_bar"].mean(), 3)})
    pa = pd.DataFrame(lines)
    pa.to_csv(os.path.join(args.out, "phi.csv"), index=False)
    print("\n=== Phi by attack and arm ===\n" + pa.to_string(index=False))

    print("\n=== paired Phi difference vs E (node-seconds, bootstrap 95% CI) ===")
    for atk, g in phi.groupby("attack"):
        w = g.pivot(index="seed", columns="arm", values="phi_node_s")
        for arm in ("D", "Dw", "D1"):
            if arm in w and "E" in w:
                x = w[[arm, "E"]].dropna()
                mu, lo, hi = paired_diff_ci(x[arm].to_numpy(), x["E"].to_numpy())
                print(f"  {atk:5s} {arm:3s}-E {mu:8.1f} [{lo:8.1f}, {hi:8.1f}] n={len(x)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
