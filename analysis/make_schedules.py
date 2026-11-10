"""Turn Step 9 verdicts into the isolation schedules the simulator replays.

Three arms are generated from the SAME verdict stream, so the comparison in
Step 12 varies one thing only: what the network does with the verdict.

    C  detection only        verdicts produced, nothing isolated
    D  immediate-isolation    isolate on first *suspicion*, never release (our design, NOT EMBN)
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


def _usable(g: pd.DataFrame, min_observers: int) -> pd.Series:
    """Windows in which a verdict rests on real evidence (finite trust, enough observers)."""
    tm = pd.to_numeric(g["trust_median"], errors="coerce")
    return tm.notna() & (g["n_observers"] >= min_observers)


def build_schedules(
    verdicts: pd.DataFrame,
    warmup_windows: int = 3,
    min_observers: int = 3,
) -> dict[str, list[tuple]]:
    """Build every arm from one verdict stream.

    D   isolate on first SUSPICIOUS window, never release (original arm; it fires on
        start-up transients, which is why D-variants exist).
    Dw  D with a warm-up guard: a target's first `warmup_windows` usable windows are
        ignored before suspicion can isolate it. Attack-agnostic: the guard is counted
        per target from its own first usable window, never from the attack start.
    D1  isolate on the first single window of malicious evidence (bad_streak >= 1:
        trust < theta_low with enough observers and agreement), never release. This is
        'confirmation without persistence', the strongest honest immediate policy.
    E   isolate on CONFIRMED, release when the verdict returns to normal.
    Ea  E with evidence-aware release: a beacon confirmed while behavioural evidence
        was available is released only on a normal window that again has behavioural
        evidence. Isolation removes a beacon's transit traffic, so in a closed loop a
        beacon confirmed on behaviour stays isolated; without this rule E re-admits
        forwarding attackers once their behavioural evidence vanishes.
    """
    v = verdicts.sort_values("time_s")

    d_rows, dw_rows, d1_rows, e_rows, ea_rows = [], [], [], [], []

    for target, g in v.groupby("target", sort=True):
        g = g.sort_values("time_s")
        flagged_mask = g["verdict"].isin([SUSPICIOUS, CONFIRMED])

        # D: first time the node looks bad at all.
        flagged = g[flagged_mask]
        if len(flagged):
            d_rows.append((float(flagged["time_s"].iloc[0]), "all", int(target), "isolate"))

        # Dw: same rule after the target's own warm-up.
        usable_rank = _usable(g, min_observers).cumsum()
        dw = g[flagged_mask & (usable_rank > warmup_windows)]
        if len(dw):
            dw_rows.append((float(dw["time_s"].iloc[0]), "all", int(target), "isolate"))

        # D1: first window of malicious evidence, no persistence requirement.
        if "bad_streak" in g.columns:
            d1 = g[g["bad_streak"] >= 1]
            if len(d1):
                d1_rows.append((float(d1["time_s"].iloc[0]), "all", int(target), "isolate"))

        # E: confirmation only, with release when the verdict is revised.
        state = "out"
        for _, row in g.iterrows():
            if state == "out" and row["verdict"] == CONFIRMED:
                e_rows.append((float(row["time_s"]), "all", int(target), "isolate"))
                state = "in"
            elif state == "in" and row["verdict"] == "normal":
                e_rows.append((float(row["time_s"]), "all", int(target), "release"))
                state = "out"

        # Ea: as E, but release needs the evidence that supported confirmation.
        state, need_beh = "out", False
        for _, row in g.iterrows():
            if state == "out" and row["verdict"] == CONFIRMED:
                ea_rows.append((float(row["time_s"]), "all", int(target), "isolate"))
                state, need_beh = "in", bool(row.get("beh_available", False))
            elif (state == "in" and row["verdict"] == "normal"
                  and (not need_beh or bool(row.get("beh_available", False)))):
                ea_rows.append((float(row["time_s"]), "all", int(target), "release"))
                state = "out"

    return {
        "C": [],
        "D": sorted(d_rows),
        "Dw": sorted(dw_rows),
        "D1": sorted(d1_rows),
        "E": sorted(e_rows),
        "Ea": sorted(ea_rows),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.make_schedules")
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--warmup-windows", type=int, default=3)
    args = ap.parse_args(argv)

    v = pd.read_csv(args.verdicts)
    sched = build_schedules(v, warmup_windows=args.warmup_windows)
    for arm, rows in sched.items():
        path = os.path.join(args.outdir, f"{arm}.csv")
        _write(path, rows)
        print(f"{arm}: {len(rows)} event(s) -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
