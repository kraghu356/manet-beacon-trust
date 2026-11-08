"""Score an intensity sweep: behaviour-only, localisation-only, OR, fused.

Each sweep run lives in <root>/<label>-seed<N>/ and holds the simulator's
<ATK>-seed<N>-run1-beacon_rx.csv and -behaviour.csv. For every run we decide in
three modes and record whether the attacker was ever confirmed and how many honest
beacons were (false positives). OR = behaviour-only OR localisation-only, i.e. a
disjunctive rule over independently thresholded branches.

    python -m analysis.sweep_eval --root results/sweep_low --calibration results/calibration.json \
        --out results/tables/sweep_low.csv
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
from .trust import TrustParams, compute_trust


def score_run(brx_path: str, beh_path: str, cal: Calibration, attack_start: float) -> dict:
    ev = build_evidence(load_beacon_rx(brx_path), load_behaviour(beh_path),
                        WindowSpec(10.0, 5.0), beacon_ids=[0, 1, 2])
    out, fp_sets = {}, {}
    for mode in ("behaviour", "localization", "fused"):
        trust = compute_trust(ev, cal, TrustParams(mode=mode))
        s = confirmation_summary(decide(trust, DecisionParams(), mode=mode), attack_start)
        atk = s[s["is_attacker"] == 1]
        honest = s[s["is_attacker"] == 0]
        out[f"{mode}_tp"] = int(atk["ever_confirmed"].max()) if len(atk) else 0
        fp_sets[mode] = set(honest.loc[honest["ever_confirmed"] == 1, "target"].astype(int))
        out[f"{mode}_fp"] = len(fp_sets[mode])
        out[f"{mode}_n_honest"] = len(honest)
    out["or_tp"] = int(out["behaviour_tp"] or out["localization_tp"])
    out["or_fp"] = len(fp_sets["behaviour"] | fp_sets["localization"])
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.sweep_eval")
    ap.add_argument("--root", required=True)
    ap.add_argument("--calibration", required=True)
    ap.add_argument("--attack-start", type=float, default=30.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    cal = Calibration.from_json(args.calibration)
    pat = re.compile(r"(?P<label>.+)-seed(?P<seed>\d+)$")
    rows = []
    for d in sorted(glob.glob(os.path.join(args.root, "*-seed*"))):
        m = pat.search(os.path.basename(d))
        brx = glob.glob(os.path.join(d, "*-run1-beacon_rx.csv"))
        beh = glob.glob(os.path.join(d, "*-run1-behaviour.csv"))
        if not (m and brx and beh):
            continue
        r = score_run(brx[0], beh[0], cal, args.attack_start)
        rows.append({"level": m["label"], "seed": int(m["seed"]), **r})

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df.to_csv(args.out, index=False)
    if df.empty:
        print("no runs found under", args.root)
        return 1
    agg = (df.groupby("level")[["behaviour_tp", "localization_tp", "or_tp", "fused_tp",
                                "or_fp", "fused_fp"]].sum()
           .assign(seeds=df.groupby("level").size()))
    agg.to_csv(args.out.replace(".csv", "-agg.csv"))
    print(agg.to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
