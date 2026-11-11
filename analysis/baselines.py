"""Two literature baselines, re-implemented as decision rules on the same traces.

Neither is a full reimplementation of a published system; each reproduces the
evidence class and the decision rule of a well-known design, so that coverage,
latency and false isolation can be measured on identical evidence streams.

LND  Localisation-only alert counting with permanent revocation, after Liu, Ning
     and Du (ICDCS 2005), the evidence class shared by EMBN-MANET. In each window
     an observer raises an alert against a beacon whose mean range residual exceeds
     rho (the 99th percentile of clean-run residuals, calibrated on held-out seeds);
     the beacon is revoked, permanently, once more than tau' alerts accumulate.

WD   Behaviour-only Beta reputation with permanent isolation, after watchdog and
     CONFIDANT-style reputation (Marti et al. 2000; Buchegger and Le Boudec 2002).
     Each beacon's reputation is the mean of Beta(alpha, beta), with alpha and beta
     the faded counts of forwarded and not-forwarded transit packets; it is isolated
     once reputation falls below tau_W (the 1st percentile of honest beacons'
     reputation on held-out clean seeds) with at least n_min packets of evidence.

Thresholds come only from the calibration seeds; no test run informs them.

    python3 -m analysis.baselines --runs results/seeds30/runs \
        --calib "results/seeds30/calib/*/none-seed*-run1-beacon_rx.csv" --out ...
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import numpy as np
import pandas as pd

from .features import run_finished, WindowSpec, load_beacon_rx, load_behaviour, window_localization
from .phi import bootstrap_ci, paired_diff_ci

SPEC = WindowSpec(10.0, 5.0)
ATTACK_START = 30.0
SIM_TIME = 400.0
MIN_RX = 3            # receptions needed for a residual to count in a window
FADE = 0.9            # Beta reputation fading per 10 s update
N_MIN = 20.0          # packets of evidence before WD may isolate


def _beacons(brx: str) -> list[int]:
    return sorted(int(b) for b in pd.read_csv(brx, usecols=["beacon_id"]).beacon_id.unique())


def _loc(brx: str) -> pd.DataFrame:
    w = window_localization(load_beacon_rx(brx), SPEC)
    return w[w.target.isin(_beacons(brx)) & (w.residual_n >= MIN_RX)]


def _reputation(beh_path: str) -> pd.DataFrame:
    """Faded Beta reputation per beacon, updated on non-overlapping 10 s windows."""
    b = load_behaviour(beh_path)
    b = b[b.node.isin(_beacons(beh_path.replace("behaviour", "beacon_rx")))]
    b = b[np.isclose(b.time_s % 10.0, 0.0)]          # non-overlapping windows only
    rows = []
    for node, g in b.sort_values("time_s").groupby("node"):
        a = bt = 0.0
        for _, r in g.iterrows():
            fwd = float(r.forwarded)
            miss = max(float(r.transit_rx) - fwd, 0.0)
            a, bt = FADE * a + fwd, FADE * bt + miss
            n = a + bt
            rows.append({"time_s": r.time_s, "target": int(node), "n": n,
                         "rep": (a + 1.0) / (n + 2.0)})
    return pd.DataFrame(rows)


def calibrate(calib_brx: list[str]) -> dict:
    res = np.concatenate([_loc(p).residual_mean.to_numpy() for p in calib_brx])
    reps = pd.concat([_reputation(p.replace("beacon_rx", "behaviour")) for p in calib_brx])
    reps = reps[reps.n >= N_MIN]
    rho = float(np.percentile(res, 99))
    # tau': the smallest alert count at which no beacon is revoked on any clean
    # calibration run (Liu, Ning and Du size tau' to tolerate benign alerts).
    tau = 1
    while any(lnd_times(p, rho, tau) for p in calib_brx):
        tau += 1
    return {"rho": rho, "tau_w": float(np.percentile(reps.rep, 1)), "tau_alerts": tau}


def lnd_times(brx: str, rho: float, tau_alerts: int) -> dict[int, float]:
    w = _loc(brx).sort_values("time_s")
    alerts = w[w.residual_mean > rho]
    out = {}
    for tgt, g in alerts.groupby("target"):
        if len(g) > tau_alerts:
            out[int(tgt)] = float(g.time_s.iloc[tau_alerts])  # (tau'+1)-th alert
    return out


def wd_times(beh: str, tau_w: float) -> dict[int, float]:
    r = _reputation(beh)
    hit = r[(r.n >= N_MIN) & (r.rep < tau_w)].sort_values("time_s")
    return {int(t): float(g.time_s.iloc[0]) for t, g in hit.groupby("target")}


def score(times: dict[int, float], attackers: list[int], beacons: list[int]) -> dict:
    """Detection is 1 only if every attacker is isolated after onset."""
    honest = [b for b in beacons if b not in attackers]
    phi = sum(SIM_TIME - times[h] for h in honest if h in times)
    out = {"honest_isolated": sum(h in times for h in honest), "n_honest": len(honest),
           "phi": phi, "phi_bar": phi / (len(honest) * SIM_TIME)}
    if attackers:
        ts = [times.get(x) for x in attackers]
        post = [t for t in ts if t is not None and t >= ATTACK_START]
        out["detected"] = int(len(post) == len(attackers))
        out["detected_frac"] = len(post) / len(attackers)
        out["pre_onset"] = int(any(t is not None and t < ATTACK_START for t in ts))
        out["latency"] = float(np.mean(post)) - ATTACK_START if post else np.nan
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.baselines")
    ap.add_argument("--runs", required=True)
    ap.add_argument("--calib", required=True, help="glob of clean calibration beacon_rx files")
    ap.add_argument("--tau-alerts", type=int, default=0,
                    help="override the calibrated tau' (0 = use calibration)")
    ap.add_argument("--sweep", action="store_true", help="also sweep tau' for LND")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    cal = calibrate(sorted(glob.glob(a.calib)))
    if a.tau_alerts:
        cal["tau_alerts"] = a.tau_alerts
    print(f"calibration: rho = {cal['rho']:.2f} m, tau_W = {cal['tau_w']:.3f}, tau' = {cal['tau_alerts']}")
    pat = re.compile(r"(?P<atk>none|A1|A2|A3)-seed(?P<seed>\d+)-run1-beacon_rx\.csv$")
    rows = []
    for brx in sorted(glob.glob(os.path.join(a.runs, "**", "*-run1-beacon_rx.csv"), recursive=True)):
        m = pat.search(os.path.basename(brx))
        if not m or not run_finished(brx):
            continue
        gt = pd.read_csv(brx, usecols=["beacon_id", "is_attacker"])
        att = gt.loc[gt.is_attacker == 1, "beacon_id"].unique()
        attackers = sorted(int(x) for x in att)
        beacons = _beacons(brx)
        lnd = lnd_times(brx, cal["rho"], cal["tau_alerts"])
        wd = wd_times(brx.replace("beacon_rx", "behaviour"), cal["tau_w"])
        # Both detectors run side by side; a beacon is isolated when either fires.
        both = {t: min(x for x in (lnd.get(t), wd.get(t)) if x is not None)
                for t in set(lnd) | set(wd)}
        for name, times in (("LND", lnd), ("WD", wd), ("LND+WD", both)):
            rows.append({"attack": m["atk"], "seed": int(m["seed"]), "method": name,
                         **score(times, attackers, beacons)})
    df = pd.DataFrame(rows)
    os.makedirs(a.out, exist_ok=True)
    df.to_csv(os.path.join(a.out, "baselines_per_run.csv"), index=False)
    pd.Series(cal).to_json(os.path.join(a.out, "baselines_calibration.json"))

    if a.sweep:
        print("LND tau' sweep (clean FI, clean phi_bar, A1 det, A2 det):")
        for tau in (3, 5, 10, 20, 40):
            r = []
            for brx in sorted(glob.glob(os.path.join(a.runs, "**", "*-run1-beacon_rx.csv"), recursive=True)):
                m = pat.search(os.path.basename(brx))
                if not m or not run_finished(brx):
                    continue
                gt = pd.read_csv(brx, usecols=["beacon_id", "is_attacker"])
                att = gt.loc[gt.is_attacker == 1, "beacon_id"].unique()
                r.append({"attack": m["atk"], **score(lnd_times(brx, cal["rho"], tau),
                                                      sorted(int(x) for x in att), _beacons(brx))})
            r = pd.DataFrame(r)
            c, a1, a2 = (r[r.attack == k] for k in ("none", "A1", "A2"))
            print(f"  tau'={tau:2d}  FI {c.honest_isolated.sum()}/{c.n_honest.sum()}  "
                  f"phi_bar {100*c.phi_bar.mean():.1f}%  A1 {int(a1.detected.sum())}/{len(a1)}  "
                  f"A2 {int(a2.detected.sum())}/{len(a2)}  A1 latency {a1.latency.median():.0f}")

    for (meth, atk), g in df.groupby(["method", "attack"]):
        lo, hi = bootstrap_ci(g.phi.to_numpy(float))
        s = f"{meth:3s} {atk:5s} n={len(g):2d} FI {g.honest_isolated.sum()}/{g.n_honest.sum()} " \
            f"phi {g.phi.mean():6.1f} [{lo:.0f},{hi:.0f}] ({100*g.phi_bar.mean():.1f}%)"
        if atk != "none":
            s += f"  detected {g.detected.sum()}/{len(g)} pre-onset {g.pre_onset.sum()}" \
                 f"  latency median {g.latency.median():.1f}"
        print(s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
