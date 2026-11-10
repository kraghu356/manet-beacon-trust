"""Does isolating a beacon change the verdicts that the offline Phi replay assumed?

The 30-seed Phi figures replay each policy over ONE verdict stream from a run in
which nobody was isolated. Here the same clean-network schedules have been
enforced in the simulator (scripts/clean_enforced.sh). We re-verify each enforced
run with the same calibration, rebuild that policy's schedule from the verdicts
produced under isolation, and compare Phi:

    offline   Phi from the replayed schedule (what the paper reports)
    closed    Phi from the schedule the enforced run's own verdicts imply

For D1 the first isolation of each beacon precedes any isolation in the run, so
only beacons isolated later can move. For E, release times depend on verdicts
issued while a beacon is isolated; if an isolated beacon carries too little
transit traffic for behavioural evidence, its trust rests on localisation alone.

    python3 -m analysis.feedback_check --runs results/clean_enforced \
        --offline results/tables/seeds30 --out results/tables/clean_enforced
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import pandas as pd

from .calibrate import Calibration
from .decide import DecisionParams, confirmation_summary, decide
from .features import WindowSpec, build_evidence, load_beacon_rx, load_behaviour
from .make_schedules import build_schedules
from .phi import bootstrap_ci, isolated_seconds, paired_diff_ci
from .trust import TrustParams, compute_trust

SPEC = WindowSpec(10.0, 5.0)


def _phi(schedule: pd.DataFrame, honest: list[int], sim_time: float) -> float:
    return float(sum(isolated_seconds(schedule, h, sim_time) for h in honest))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.feedback_check")
    ap.add_argument("--runs", required=True, help="dir of <ARM>-seed<N>/ enforced runs")
    ap.add_argument("--offline", required=True, help="campaign_eval output (seeds30)")
    ap.add_argument("--sim-time", type=float, default=400.0)
    ap.add_argument("--warmup-windows", type=int, default=3)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    cal = Calibration.from_json(os.path.join(a.offline, "calibration.json"))
    pat = re.compile(r"(?P<arm>D1|E)-seed(?P<seed>\d+)$")
    rows = []
    for d in sorted(glob.glob(os.path.join(a.runs, "*-seed*"))):
        m = pat.search(os.path.basename(d))
        brx = glob.glob(os.path.join(d, "*-run1-beacon_rx.csv"))
        if not m or not brx or not os.path.exists(os.path.join(d, ".done")):
            continue
        arm, seed = m["arm"], int(m["seed"])
        beh = brx[0].replace("-beacon_rx.csv", "-behaviour.csv")
        rx = load_beacon_rx(brx[0])
        ev = build_evidence(rx, load_behaviour(beh), SPEC,
                            beacon_ids=sorted(int(b) for b in rx["beacon_id"].unique()))
        v = decide(compute_trust(ev, cal, TrustParams(mode="fused")), DecisionParams(), mode="fused")
        s = confirmation_summary(v, 30.0)
        honest = s.loc[s["is_attacker"] == 0, "target"].astype(int).tolist()

        closed = pd.DataFrame(build_schedules(v, a.warmup_windows)[arm],
                              columns=["time_s", "observer", "target", "action"])
        offline = pd.read_csv(os.path.join(a.offline, "sched", f"sched-none-seed{seed}", f"{arm}.csv"))
        rows.append({"arm": arm, "seed": seed,
                     "phi_offline": _phi(offline, honest, a.sim_time),
                     "phi_closed": _phi(closed, honest, a.sim_time)})

    if not rows:
        raise SystemExit(f"no finished runs under {a.runs}")
    df = pd.DataFrame(rows).sort_values(["arm", "seed"])
    df["diff"] = df["phi_closed"] - df["phi_offline"]
    os.makedirs(a.out, exist_ok=True)
    df.to_csv(os.path.join(a.out, "feedback_per_run.csv"), index=False)
    print(df.to_string(index=False))

    print("\n=== closed-loop minus offline Phi (node-seconds), paired bootstrap 95% CI ===")
    out = []
    for arm, g in df.groupby("arm"):
        mu, lo, hi = paired_diff_ci(g["phi_closed"].to_numpy(), g["phi_offline"].to_numpy())
        clo, chi = bootstrap_ci(g["phi_closed"].to_numpy())
        out.append({"arm": arm, "seeds": len(g),
                    "phi_offline": round(g["phi_offline"].mean(), 1),
                    "phi_closed": round(g["phi_closed"].mean(), 1),
                    "closed_boot95": f"[{clo:.0f}, {chi:.0f}]",
                    "diff": round(mu, 1), "diff_boot95": f"[{lo:.0f}, {hi:.0f}]"})
        print(f"  {arm:3s} offline {g['phi_offline'].mean():7.1f}  closed {g['phi_closed'].mean():7.1f}"
              f"  diff {mu:7.1f} [{lo:.1f}, {hi:.1f}]  n={len(g)}")
    pd.DataFrame(out).to_csv(os.path.join(a.out, "feedback.csv"), index=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
