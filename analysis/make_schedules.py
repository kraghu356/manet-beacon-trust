"""Turn Step 9 verdicts into the isolation schedules the simulator replays.

Three arms are generated from the SAME verdict stream, so the comparison in
Step 12 varies one thing only: what the network does with the verdict.

    C  detection only        verdicts produced, nothing isolated
    D  EMBN-style            isolate on first *suspicion*, never release
    E  proposed              isolate on *confirmation*, release if cleared

D is the closest prior work's behaviour as this project models it, and modelling
it honestly means giving it its actual strength: it reacts sooner than E, because
it does not wait for confirmation. E should therefore lose to D on detection
latency and win on false-isolation cost. If E wins on every axis, the D arm has
been strawmanned and a reviewer will find it.
"""

from __future__ import annotations

import argparse
import os

import pandas as pd

from .decide import CONFIRMED, SUSPICIOUS


def _write(path: str, rows: list[tuple]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write("time_s,observer,target,action\n")
        if not rows:
            # The simulator treats an unreadable or empty schedule as an error,
            # so the no-isolation arm gets an explicit no-op rather than nothing.
            fh.write("0.0,all,0,release\n")
            return
        for t, obs, tgt, act in rows:
            fh.write(f"{t},{obs},{tgt},{act}\n")


def build_schedules(verdicts: pd.DataFrame) -> dict[str, list[tuple]]:
    v = verdicts.sort_values("time_s")

    d_rows, e_rows = [], []

    for target, g in v.groupby("target", sort=True):
        g = g.sort_values("time_s")

        # D: first time the node looks bad at all.
        flagged = g[g["verdict"].isin([SUSPICIOUS, CONFIRMED])]
        if len(flagged):
            d_rows.append((float(flagged["time_s"].iloc[0]), "all", int(target), "isolate"))

        # E: confirmation only, with release when the verdict is revised.
        state = "out"
        for _, row in g.iterrows():
            if state == "out" and row["verdict"] == CONFIRMED:
                e_rows.append((float(row["time_s"]), "all", int(target), "isolate"))
                state = "in"
            elif state == "in" and row["verdict"] == "normal":
                e_rows.append((float(row["time_s"]), "all", int(target), "release"))
                state = "out"

    return {"C": [], "D": sorted(d_rows), "E": sorted(e_rows)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.make_schedules")
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args(argv)

    v = pd.read_csv(args.verdicts)
    sched = build_schedules(v)
    for arm, rows in sched.items():
        path = os.path.join(args.outdir, f"{arm}.csv")
        _write(path, rows)
        print(f"{arm}: {len(rows)} event(s) -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
