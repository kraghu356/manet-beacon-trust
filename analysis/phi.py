"""Cumulative false isolation, Phi (node-seconds), computed from schedules alone.

Phi needs only *when* each honest beacon was isolated and released, so it can be
computed for every arm, clean and attacked, without re-running ns-3:

    Phi    = sum over honest targets of time spent isolated in [0, T]
    Phi_bar = Phi / (|H| * T)                       (fraction of honest service withdrawn)

Honest targets come from the verdict summary (is_attacker == 0), never from the
schedule, so an arm cannot make a node honest by not isolating it.

    python -m analysis.phi \
        --runs "results/arms/*-seed*-verdicts-summary.csv" \
        --sched-root results/arms --sim-time 400 --out results/tables/phi.csv
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import numpy as np
import pandas as pd

ARMS = ("D", "Dw", "D1", "E")


def isolated_seconds(schedule: pd.DataFrame, target: int, sim_time: float) -> float:
    """Total time `target` spends isolated, from isolate/release events."""
    ev = schedule[pd.to_numeric(schedule["target"], errors="coerce") == target]
    ev = ev.sort_values("time_s")
    total, since = 0.0, None
    for _, r in ev.iterrows():
        t = min(float(r["time_s"]), sim_time)
        if r["action"] == "isolate" and since is None:
            since = t
        elif r["action"] == "release" and since is not None:
            total += t - since
            since = None
    if since is not None:
        total += sim_time - since
    return total


def phi_for_run(summary: pd.DataFrame, sched_dir: str, sim_time: float) -> list[dict]:
    honest = summary.loc[summary["is_attacker"] == 0, "target"].astype(int).tolist()
    rows = []
    for arm in ARMS:
        path = os.path.join(sched_dir, f"{arm}.csv")
        if not os.path.exists(path):
            continue
        s = pd.read_csv(path)
        per_node = [isolated_seconds(s, h, sim_time) for h in honest]
        rows.append(
            {
                "arm": arm,
                "n_honest": len(honest),
                "honest_isolated": int(sum(x > 0 for x in per_node)),
                "phi_node_s": float(sum(per_node)),
                "phi_bar": float(sum(per_node) / (len(honest) * sim_time)) if honest else np.nan,
            }
        )
    return rows


def bootstrap_ci(x: np.ndarray, n_boot: int = 10000, seed: int = 0) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean; suitable for zero-inflated Phi."""
    x = np.asarray(x, dtype=float)
    if x.size == 0:
        return (np.nan, np.nan)
    rng = np.random.default_rng(seed)
    means = rng.choice(x, size=(n_boot, x.size), replace=True).mean(axis=1)
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def paired_diff_ci(a: np.ndarray, b: np.ndarray, n_boot: int = 10000, seed: int = 0):
    """Bootstrap CI of mean(a - b) over seeds paired by index."""
    d = np.asarray(a, float) - np.asarray(b, float)
    lo, hi = bootstrap_ci(d, n_boot, seed)
    return float(d.mean()), lo, hi


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.phi")
    ap.add_argument("--runs", required=True, help="glob of *-verdicts-summary.csv")
    ap.add_argument("--sched-root", required=True,
                    help="dir holding sched-<ATK>-seed<N>/ folders")
    ap.add_argument("--sim-time", type=float, default=400.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    pat = re.compile(r"(?P<atk>[A-Za-z0-9]+)-seed(?P<seed>\d+)-verdicts-summary\.csv$")
    rows = []
    for f in sorted(glob.glob(args.runs)):
        m = pat.search(os.path.basename(f))
        if not m:
            continue
        atk, seed = m["atk"], int(m["seed"])
        sched = os.path.join(args.sched_root, f"sched-{atk}-seed{seed}")
        for r in phi_for_run(pd.read_csv(f), sched, args.sim_time):
            rows.append({"attack": atk, "seed": seed, **r})

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df.to_csv(args.out, index=False)
    if df.empty:
        print("no runs matched")
        return 1

    out = []
    for (atk, arm), g in df.groupby(["attack", "arm"]):
        lo, hi = bootstrap_ci(g["phi_node_s"].to_numpy())
        out.append({
            "attack": atk, "arm": arm, "seeds": len(g),
            "honest_isolated": f"{g['honest_isolated'].sum()}/{g['n_honest'].sum()}",
            "phi_mean": g["phi_node_s"].mean(), "phi_boot95_lo": lo, "phi_boot95_hi": hi,
            "phi_bar_mean": g["phi_bar"].mean(),
        })
    agg = pd.DataFrame(out)
    agg.to_csv(args.out.replace(".csv", "-agg.csv"), index=False)
    print(agg.to_string(index=False))

    # Paired E-vs-each-D difference, per attack, over identical seeds.
    print("\nPaired difference in Phi, (D-variant - E), node-seconds, bootstrap 95% CI:")
    for atk, g in df.groupby("attack"):
        w = g.pivot(index="seed", columns="arm", values="phi_node_s")
        for arm in ("D", "Dw", "D1"):
            if arm in w and "E" in w:
                x = w[[arm, "E"]].dropna()
                if len(x):
                    m, lo, hi = paired_diff_ci(x[arm].to_numpy(), x["E"].to_numpy())
                    print(f"  {atk:5s} {arm:3s}-E  mean {m:8.1f}  [{lo:8.1f}, {hi:8.1f}]  n={len(x)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
