"""Closed-loop cost of evidence-aware release (policy Ea) from existing verdicts.

A beacon isolated by Ea while behavioural evidence was available is released only
when behavioural evidence returns. Isolation removes a beacon's transit traffic
(enforced runs: behavioural evidence in 1.6% of isolated windows, 54% otherwise),
so in a closed loop such a beacon stays isolated to the end of the run. Its
closed-loop isolated time is therefore exact: sim_time minus isolation time.
Beacons isolated on localisation alone keep their offline release times.

    python3 -m analysis.release_check --campaign results/tables/seeds30 --out ...
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import numpy as np
import pandas as pd

from .make_schedules import build_schedules
from .phi import bootstrap_ci, isolated_seconds, paired_diff_ci


def closed_loop_ea(v: pd.DataFrame, sim_time: float) -> tuple[pd.DataFrame, list[tuple]]:
    """Ea schedule as a closed loop would produce it."""
    sched = build_schedules(v)["Ea"]
    out = []
    for tgt, g in pd.DataFrame(sched, columns=["time_s", "observer", "target", "action"]).groupby("target"):
        g = g.sort_values("time_s")
        first = g.iloc[0]
        row = v[(v.target == tgt) & (v.time_s == first.time_s)]
        if len(row) and bool(row["beh_available"].iloc[0]):
            out.append((first.time_s, "all", int(tgt), "isolate"))  # never released
        else:
            out += [tuple(r) for r in g.itertuples(index=False)]
    return pd.DataFrame(out, columns=["time_s", "observer", "target", "action"]), sched


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.release_check")
    ap.add_argument("--campaign", required=True, help="campaign_eval output with verdicts/")
    ap.add_argument("--sim-time", type=float, default=400.0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    pat = re.compile(r"(?P<atk>none|A1|A2|A3)-seed(?P<seed>\d+)-verdicts\.csv$")
    rows = []
    for f in sorted(glob.glob(os.path.join(a.campaign, "verdicts", "*-verdicts.csv"))):
        m = pat.search(os.path.basename(f))
        if not m:
            continue
        v = pd.read_csv(f)
        # is_attacker is 0 before onset, so a beacon is honest only if never flagged.
        att = v.loc[v.is_attacker == 1, "target"].unique()
        honest = sorted(set(v["target"].unique()) - set(att))
        sch = build_schedules(v)
        ea_cl, _ = closed_loop_ea(v, a.sim_time)
        r = {"attack": m["atk"], "seed": int(m["seed"]), "n_honest_runs": len(honest)}
        for arm, s in (("D1", pd.DataFrame(sch["D1"], columns=["time_s", "observer", "target", "action"])),
                       ("E", pd.DataFrame(sch["E"], columns=["time_s", "observer", "target", "action"])),
                       ("Ea_closed", ea_cl)):
            r[f"phi_{arm}"] = float(sum(isolated_seconds(s, h, a.sim_time) for h in honest))
        if len(att):
            # attacker exposure after onset (30 s) under closed-loop Ea: time not
            # isolated, averaged over attackers
            r["attacker_exposed_s"] = float(np.mean(
                [(a.sim_time - 30.0) - isolated_seconds(ea_cl, int(x), a.sim_time) for x in att]))
        rows.append(r)
    df = pd.DataFrame(rows)
    os.makedirs(a.out, exist_ok=True)
    df.to_csv(os.path.join(a.out, "release_per_run.csv"), index=False)
    for atk, g in df.groupby("attack"):
        nh = a.sim_time * g["n_honest_runs"].mean() if "n_honest_runs" in g else a.sim_time
        line = [f"{atk:5s} n={len(g):2d}"]
        for arm in ("D1", "E", "Ea_closed"):
            x = g[f"phi_{arm}"].to_numpy(float)
            lo, hi = bootstrap_ci(x)
            line.append(f"{arm} {x.mean():6.1f} [{lo:.0f},{hi:.0f}] ({100*x.mean()/nh:.1f}%)")
        mu, lo, hi = paired_diff_ci(g["phi_D1"].to_numpy(float), g["phi_Ea_closed"].to_numpy(float))
        line.append(f"D1-Ea {mu:.0f} [{lo:.0f},{hi:.0f}]")
        mu, lo, hi = paired_diff_ci(g["phi_Ea_closed"].to_numpy(float), g["phi_E"].to_numpy(float))
        line.append(f"Ea-E {mu:.0f} [{lo:.0f},{hi:.0f}]")
        if atk != "none":
            line.append(f"exposed median {g.attacker_exposed_s.median():.0f}s")
        print("  ".join(line))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
