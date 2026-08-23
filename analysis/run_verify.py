"""CLI: run the Step 8-9 verification pipeline over simulator output.

    # calibrate on the clean baseline
    python -m analysis.run_verify calibrate \
        --beacon-rx results/none-seed1-run1-beacon_rx.csv \
        --behaviour results/none-seed1-run1-behaviour.csv \
        --out results/calibration.json

    # verify an attack run
    python -m analysis.run_verify verify \
        --beacon-rx results/A3-seed1-run1-beacon_rx.csv \
        --behaviour results/A3-seed1-run1-behaviour.csv \
        --calibration results/calibration.json \
        --mode fused --out results/A3-seed1-verdicts.csv
"""

from __future__ import annotations

import argparse
import sys

from .calibrate import Calibration, calibrate
from .decide import DecisionParams, confirmation_summary, decide
from .features import WindowSpec, build_evidence, load_beacon_rx, load_behaviour
from .trust import TrustParams, compute_trust


def _load(args) -> "tuple":
    brx = load_beacon_rx(args.beacon_rx)
    beh = load_behaviour(args.behaviour)
    spec = WindowSpec(length_s=args.window, step_s=args.step)
    beacons = [int(x) for x in args.beacons.split(",")] if args.beacons else None
    return build_evidence(brx, beh, spec, beacon_ids=beacons)


def cmd_calibrate(args) -> int:
    ev = _load(args)
    cal = calibrate(ev)
    cal.to_json(args.out)
    print(cal.summary())
    print(f"\nWritten to {args.out}")
    if cal.n_residual_samples < 200:
        print(
            "\nWARNING: fewer than 200 residual samples. Thresholds derived from "
            "this calibration will be unstable. Run more seeds."
        )
    return 0


def cmd_verify(args) -> int:
    ev = _load(args)
    cal = Calibration.from_json(args.calibration)

    tp = TrustParams(mode=args.mode, combine=args.combine)
    dp = DecisionParams(
        theta_low=args.theta_low,
        theta_high=args.theta_high,
        persistence=args.persistence,
    )

    trust = compute_trust(ev, cal, tp)
    verdicts = decide(trust, dp, mode=args.mode)
    summary = confirmation_summary(verdicts, attack_start=args.attack_start)

    verdicts.to_csv(args.out, index=False)
    summary_path = args.out.replace(".csv", "-summary.csv")
    summary.to_csv(summary_path, index=False)

    print(summary.to_string(index=False))
    print(f"\nPer-window verdicts: {args.out}\nPer-target summary: {summary_path}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.run_verify")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--beacon-rx", required=True)
        p.add_argument("--behaviour", required=True)
        p.add_argument("--window", type=float, default=10.0)
        p.add_argument("--step", type=float, default=5.0)
        p.add_argument("--beacons", default="0,1,2")

    c = sub.add_parser("calibrate", help="fit thresholds on an attack-free run")
    common(c)
    c.add_argument("--out", default="results/calibration.json")
    c.set_defaults(func=cmd_calibrate)

    v = sub.add_parser("verify", help="score and decide on a run")
    common(v)
    v.add_argument("--calibration", required=True)
    v.add_argument("--mode", default="fused",
                   choices=["fused", "behaviour", "localization"])
    v.add_argument("--combine", default="stouffer",
                   choices=["stouffer", "geometric", "arithmetic"])
    v.add_argument("--theta-low", type=float, default=0.40)
    v.add_argument("--theta-high", type=float, default=0.70)
    v.add_argument("--persistence", type=int, default=3)
    v.add_argument("--attack-start", type=float, default=30.0)
    v.add_argument("--out", default="results/verdicts.csv")
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
