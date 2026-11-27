"""Trade-off between false isolation and attacker exposure, across policies.

Every policy is a point (x, y):
    x  attacker exposure: post-onset seconds an attacker is not isolated, mean
       over attackers and attacked runs (an attacker never isolated counts
       sim_time - onset; one isolated before onset counts 0)
    y  clean-network false isolation, Phi-bar (honest-beacon service withdrawn)

Pipeline points come from the per-window verdict streams already produced:
    K_k   isolate on the first window with k consecutive malicious windows
          (bad_streak >= k), never release.  K_1 is D1; K_3 isolates exactly
          when E does.
    E     confirmation, release when the verdict clears (offline replay)
    E'    evidence-aware release, as the closed loop would run it
    D, Dw isolate on suspicion (with and without warm-up), never release
Baseline points re-run LND and WD on the raw traces over a threshold sweep
(dense campaign only; sparse and 50-node use the calibrated operating point).

    python3 -m analysis.frontier --campaign results/tables/seeds30 \
        --runs <seeds30/runs> --calib "<calib glob>" --out results/tables/frontier
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import numpy as np
import pandas as pd

from .make_schedules import build_schedules
from .release_check import closed_loop_ea

ONSET = 30.0
COLS = ["time_s", "observer", "target", "action"]
PAT = re.compile(r"(?P<atk>none|A1|A2|A3)-seed(?P<seed>\d+)-verdicts\.csv$")


def intervals(times: list[tuple[float, str]], sim: float) -> list[tuple[float, float]]:
    out, since = [], None
    for t, act in sorted(times):
        t = min(t, sim)
        if act == "isolate" and since is None:
            since = t
        elif act == "release" and since is not None:
            out.append((since, t))
            since = None
    if since is not None:
        out.append((since, sim))
    return out


def iso_time(iv, lo, hi) -> float:
    return sum(max(0.0, min(b, hi) - max(a, lo)) for a, b in iv)


def events(sched, tgt) -> list[tuple[float, str]]:
    df = sched if isinstance(sched, pd.DataFrame) else pd.DataFrame(sched, columns=COLS)
    g = df[pd.to_numeric(df["target"], errors="coerce") == tgt]
    return [(float(r.time_s), r.action) for r in g.itertuples(index=False)]


def k_schedule(v: pd.DataFrame, k: int) -> list[tuple]:
    rows = []
    for tgt, g in v.groupby("target"):
        hit = g[g["bad_streak"] >= k].sort_values("time_s")
        if len(hit):
            rows.append((float(hit.time_s.iloc[0]), "all", int(tgt), "isolate"))
    return rows


def pipeline_policies(v: pd.DataFrame, sim: float) -> dict[str, object]:
    s = build_schedules(v)
    pol = {f"K{k}": k_schedule(v, k) for k in (1, 2, 3, 4, 5, 6, 8, 10)}
    pol.update({"D": s["D"], "Dw": s["Dw"], "E": s["E"],
                "Ea": closed_loop_ea(v, sim)[0]})
    return pol


def score_run(v: pd.DataFrame, pol: dict, sim: float) -> list[dict]:
    att = sorted(int(x) for x in v.loc[v.is_attacker == 1, "target"].unique())
    honest = sorted(set(int(x) for x in v.target.unique()) - set(att))
    out = []
    for name, sch in pol.items():
        phi = sum(iso_time(intervals(events(sch, h), sim), 0.0, sim) for h in honest)
        r = {"policy": name, "phi": phi, "phi_bar": phi / (len(honest) * sim) if honest else np.nan}
        if att:
            r["exposure"] = float(np.mean([(sim - ONSET) - iso_time(intervals(events(sch, a), sim), ONSET, sim)
                                           for a in att]))
        out.append(r)
    return out


def pipeline_points(campaign: str, sim: float) -> pd.DataFrame:
    rows = []
    for f in sorted(glob.glob(os.path.join(campaign, "verdicts", "*-verdicts.csv"))):
        m = PAT.search(os.path.basename(f))
        if not m:
            continue
        v = pd.read_csv(f)
        for r in score_run(v, pipeline_policies(v, sim), sim):
            rows.append({"attack": m["atk"], "seed": int(m["seed"]), **r})
    return pd.DataFrame(rows)


def baseline_sweep(runs: str, calib: list[str], sim: float) -> pd.DataFrame:
    from . import baselines as B
    cal = B.calibrate(calib)
    reps = pd.concat([B._reputation(p.replace("beacon_rx", "behaviour")) for p in calib])
    reps = reps[reps.n >= B.N_MIN].rep.to_numpy()
    lnd_grid = [3, 5, 8, 10, 15, 20, 30]
    wd_grid = {p: float(np.percentile(reps, p)) for p in (0.25, 0.5, 1, 2, 5, 10)}
    rows = []
    pat = re.compile(r"(?P<atk>none|A1|A2|A3)-seed(?P<seed>\d+)-run1-beacon_rx\.csv$")
    for brx in sorted(glob.glob(os.path.join(runs, "**", "*-run1-beacon_rx.csv"), recursive=True)):
        m = pat.search(os.path.basename(brx))
        if not m or not B.run_finished(brx):
            continue
        gt = pd.read_csv(brx, usecols=["beacon_id", "is_attacker"])
        att = sorted(int(x) for x in gt.loc[gt.is_attacker == 1, "beacon_id"].unique())
        beacons = B._beacons(brx)
        honest = [b for b in beacons if b not in att]
        beh = brx.replace("beacon_rx", "behaviour")
        lnd = {t: B.lnd_times(brx, cal["rho"], t) for t in lnd_grid}
        wd = {p: B.wd_times(beh, thr) for p, thr in wd_grid.items()}
        pts = {f"LND t'={t}": x for t, x in lnd.items()}
        pts.update({f"WD p={p}": x for p, x in wd.items()})
        lw = lnd[int(cal["tau_alerts"])]
        for p, x in wd.items():
            pts[f"LND+WD p={p}"] = {k: min(z for z in (lw.get(k), x.get(k)) if z is not None)
                                     for k in set(lw) | set(x)}
        for name, times in pts.items():
            phi = sum(sim - times[h] for h in honest if h in times)
            r = {"attack": m["atk"], "seed": int(m["seed"]), "policy": name,
                 "phi": phi, "phi_bar": phi / (len(honest) * sim)}
            if att:
                r["exposure"] = float(np.mean([(sim - ONSET) - (sim - max(times[a], ONSET)) if a in times
                                               else sim - ONSET for a in att]))
            rows.append(r)
    return pd.DataFrame(rows)


def baseline_calibrated(per_run_csv: str, sim: float) -> pd.DataFrame:
    """Approximate exposure from a baselines_per_run table (no raw traces)."""
    b = pd.read_csv(per_run_csv)
    full = sim - ONSET
    frac = b.get("detected_frac", b["detected"]).fillna(0.0)
    lat = b["latency"].fillna(full)
    b["exposure"] = np.where(b.attack == "none", np.nan, frac * lat + (1 - frac) * full)
    b.loc[b.get("pre_onset", 0) == 1, "exposure"] *= frac[b.get("pre_onset", 0) == 1]
    return b.rename(columns={"method": "policy"})[["attack", "seed", "policy", "phi", "phi_bar", "exposure"]]


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    clean = df[df.attack == "none"].groupby("policy").phi_bar.mean().rename("phi_bar_clean")
    exp = df[df.attack != "none"].groupby("policy").exposure.mean().rename("exposure_s")
    per = df[df.attack != "none"].pivot_table(index="policy", columns="attack", values="exposure")
    per.columns = [f"exposure_{c}" for c in per.columns]
    s = pd.concat([clean, exp, per], axis=1).reset_index()
    # Pareto: no other point is at least as good on both and better on one.
    s["pareto"] = [not any((o.phi_bar_clean <= r.phi_bar_clean and o.exposure_s <= r.exposure_s and
                            (o.phi_bar_clean < r.phi_bar_clean or o.exposure_s < r.exposure_s))
                           for o in s.itertuples() if o.Index != r.Index)
                   for r in s.itertuples()]
    return s.sort_values("exposure_s")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.frontier")
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--runs", help="raw traces for the baseline sweep")
    ap.add_argument("--calib", help="glob of calibration beacon_rx files")
    ap.add_argument("--baselines-csv", help="calibrated baselines_per_run.csv instead of a sweep")
    ap.add_argument("--sim-time", type=float, default=400.0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    df = pipeline_points(a.campaign, a.sim_time)
    if a.runs and a.calib:
        df = pd.concat([df, baseline_sweep(a.runs, sorted(glob.glob(a.calib)), a.sim_time)])
    elif a.baselines_csv:
        df = pd.concat([df, baseline_calibrated(a.baselines_csv, a.sim_time)])
    os.makedirs(a.out, exist_ok=True)
    df.to_csv(os.path.join(a.out, "frontier_per_run.csv"), index=False)
    s = summarise(df)
    s.to_csv(os.path.join(a.out, "frontier.csv"), index=False)
    with pd.option_context("display.width", 200, "display.max_rows", 100):
        print(s.round(3).to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
