"""One round of an iterated closed loop: verdicts from an enforced run -> next schedule.

Round 0 enforces the schedule built from a run with no isolation. Each later
round enforces the schedule rebuilt from the verdicts the previous enforced run
produced, so isolation and release feed back into later decisions. Iterating to
a fixed point approximates an online detector without modifying the simulator.

    # write the next round's schedule for policy Ea from an enforced run
    python3 -m analysis.closed_loop next --run DIR --calibration cal.json --arm Ea --out next.csv
    # summarise all rounds
    python3 -m analysis.closed_loop summary --root results/closed_loop --out table.csv
"""

from __future__ import annotations

import argparse
import glob
import os
import re

import pandas as pd

from .calibrate import Calibration
from .decide import DecisionParams, decide
from .features import WindowSpec, build_evidence, load_beacon_rx, load_behaviour
from .make_schedules import _write, build_schedules
from .phi import isolated_seconds

SPEC = WindowSpec(10.0, 5.0)


def verdicts(run_dir: str, cal: Calibration) -> pd.DataFrame:
    brx = glob.glob(os.path.join(run_dir, "*-run1-beacon_rx.csv"))[0]
    rx = load_beacon_rx(brx)
    ev = build_evidence(rx, load_behaviour(brx.replace("beacon_rx", "behaviour")), SPEC,
                        beacon_ids=sorted(int(b) for b in rx["beacon_id"].unique()))
    from .trust import TrustParams, compute_trust
    return decide(compute_trust(ev, cal, TrustParams(mode="fused")), DecisionParams(), mode="fused")


def cmd_next(a) -> int:
    v = verdicts(a.run, Calibration.from_json(a.calibration))
    _write(a.out, build_schedules(v)[a.arm])
    return 0


def cmd_summary(a) -> int:
    pat = re.compile(r"(?P<atk>none|A1|A2|A3)-seed(?P<seed>\d+)-(?P<arm>\w+)-r(?P<k>\d+)$")
    rows = []
    for d in sorted(glob.glob(os.path.join(a.root, "*-r*"))):
        m = pat.search(os.path.basename(d))
        if not m or not os.path.exists(os.path.join(d, ".done")):
            continue
        sch = pd.read_csv(os.path.join(d, "schedule.csv"))
        gt = pd.read_csv(glob.glob(os.path.join(d, "*-run1-beacon_rx.csv"))[0],
                         usecols=["beacon_id", "is_attacker"])
        beacons = sorted(gt.beacon_id.unique())
        att = sorted(gt.loc[gt.is_attacker == 1, "beacon_id"].unique())
        honest = [b for b in beacons if b not in att]
        r = {"attack": m["atk"], "seed": int(m["seed"]), "arm": m["arm"], "round": int(m["k"]),
             "phi": sum(isolated_seconds(sch, int(h), a.sim_time) for h in honest)}
        if att:
            # fraction of post-onset time each attacker spent isolated, averaged
            r["attacker_isolated_frac"] = sum(
                isolated_seconds(sch, int(x), a.sim_time) for x in att) / (len(att) * (a.sim_time - 30.0))
            r["attacker_released"] = int(((sch.target.isin(att)) & (sch.action == "release")).any())
        rows.append(r)
    df = pd.DataFrame(rows)
    df.to_csv(a.out, index=False)
    print(df.groupby(["attack", "arm", "round"]).mean(numeric_only=True).drop(columns="seed").round(3))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.closed_loop")
    sp = ap.add_subparsers(dest="cmd", required=True)
    n = sp.add_parser("next")
    n.add_argument("--run", required=True)
    n.add_argument("--calibration", required=True)
    n.add_argument("--arm", required=True, choices=["E", "Ea", "D1"])
    n.add_argument("--out", required=True)
    s = sp.add_parser("summary")
    s.add_argument("--root", required=True)
    s.add_argument("--sim-time", type=float, default=400.0)
    s.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    return cmd_next(a) if a.cmd == "next" else cmd_summary(a)


if __name__ == "__main__":
    raise SystemExit(main())
