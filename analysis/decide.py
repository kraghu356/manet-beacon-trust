"""Step 9 — three-way verdict.

A single threshold turns every ambiguous window into a false accusation. Mobility,
congestion and transient link breakage all depress trust temporarily and none of
them is malice. The third state exists so the mechanism can say *I do not yet know*
and keep watching, which is both more honest and measurably cheaper than isolating
a node that did nothing wrong.

Promotion to `CONFIRMED` requires four things at once:

1. trust below `theta_low`
2. enough independent observers (`min_observers`)
3. observer agreement above `min_agreement`
4. the condition sustained for `persistence` consecutive windows

and, in fused mode, either both evidence branches available or one branch flagging
extremely. Requirement 4 is what converts a transient dip into nothing at all;
requirement 3 is what stops one badly placed observer from convicting a node.

Demotion out of `CONFIRMED` is deliberately slower than promotion into
`SUSPICIOUS`, so a node cannot oscillate its way back into routing.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

NORMAL = "normal"
SUSPICIOUS = "suspicious"
CONFIRMED = "confirmed"


@dataclass
class DecisionParams:
    theta_low: float = 0.40     # below this, evidence points to malicious
    theta_high: float = 0.70    # above this, evidence points to normal
    min_observers: int = 3
    min_agreement: float = 0.5  # fraction of observers whose direct trust < theta_low
    persistence: int = 3        # consecutive windows required to change state
    clear_persistence: int = 6  # consecutive clean windows to leave CONFIRMED
    extreme_single_branch: float = 0.1  # a lone branch this low can still confirm


def _network_view(grp: pd.DataFrame, dp: DecisionParams) -> dict:
    trust = grp["trust"].to_numpy(dtype=float)
    direct = grp["direct_trust"].to_numpy(dtype=float)
    valid = np.isfinite(trust)
    n_obs = int(valid.sum())

    if n_obs == 0:
        return {
            "trust_median": np.nan,
            "n_observers": 0,
            "agreement": np.nan,
            "loc_available": False,
            "beh_available": False,
            "min_branch": np.nan,
        }

    d_valid = direct[np.isfinite(direct)]
    agreement = (
        float(np.mean(d_valid < dp.theta_low)) if d_valid.size else float("nan")
    )

    loc_avail = bool(grp["loc_available"].any())
    beh_avail = bool(grp["beh_available"].any())

    branch_vals = []
    if loc_avail:
        branch_vals.append(float(np.nanmedian(grp.loc[grp["loc_available"], "L"])))
    if beh_avail:
        branch_vals.append(float(np.nanmedian(grp.loc[grp["beh_available"], "B"])))

    return {
        "trust_median": float(np.nanmedian(trust[valid])),
        "n_observers": n_obs,
        "agreement": agreement,
        "loc_available": loc_avail,
        "beh_available": beh_avail,
        "min_branch": float(np.min(branch_vals)) if branch_vals else np.nan,
    }


def decide(trust_df: pd.DataFrame, dp: DecisionParams, mode: str = "fused") -> pd.DataFrame:
    """Collapse per-observer trust into one verdict per target per window."""
    rows = []
    state: dict[int, str] = {}
    bad_streak: dict[int, int] = {}
    good_streak: dict[int, int] = {}

    for (t, target), grp in trust_df.groupby(["time_s", "target"], sort=True):
        v = _network_view(grp, dp)
        tgt = int(target)
        prev = state.get(tgt, NORMAL)

        tm = v["trust_median"]
        enough_observers = v["n_observers"] >= dp.min_observers
        agree = np.isfinite(v["agreement"]) and v["agreement"] >= dp.min_agreement

        if mode == "fused":
            branch_ok = (v["loc_available"] and v["beh_available"]) or (
                np.isfinite(v["min_branch"]) and v["min_branch"] <= dp.extreme_single_branch
            )
        else:
            branch_ok = v["loc_available"] or v["beh_available"]

        looks_bad = bool(np.isfinite(tm) and tm < dp.theta_low and enough_observers
                         and agree and branch_ok)
        looks_fine = bool(np.isfinite(tm) and tm >= dp.theta_high)

        bad_streak[tgt] = bad_streak.get(tgt, 0) + 1 if looks_bad else 0
        good_streak[tgt] = good_streak.get(tgt, 0) + 1 if looks_fine else 0

        if prev == CONFIRMED:
            verdict = NORMAL if good_streak[tgt] >= dp.clear_persistence else CONFIRMED
        elif bad_streak[tgt] >= dp.persistence:
            verdict = CONFIRMED
        elif looks_fine:
            verdict = NORMAL
        elif np.isfinite(tm) and tm < dp.theta_high:
            verdict = SUSPICIOUS
        else:
            verdict = prev  # no usable evidence: hold the previous verdict

        state[tgt] = verdict

        rows.append(
            {
                "time_s": float(t),
                "target": tgt,
                "trust_median": tm,
                "n_observers": v["n_observers"],
                "agreement": v["agreement"],
                "loc_available": v["loc_available"],
                "beh_available": v["beh_available"],
                "bad_streak": bad_streak[tgt],
                "verdict": verdict,
                "is_attacker": int(grp["is_attacker"].max()),
            }
        )

    return pd.DataFrame(rows)


def confirmation_summary(verdicts: pd.DataFrame, attack_start: float) -> pd.DataFrame:
    """Per-target outcome: was it ever confirmed, and how long did it take."""
    out = []
    for target, g in verdicts.groupby("target", sort=True):
        g = g.sort_values("time_s")
        conf = g[g["verdict"] == CONFIRMED]
        was_attacker = bool(g["is_attacker"].max())
        first = float(conf["time_s"].iloc[0]) if len(conf) else np.nan
        out.append(
            {
                "target": int(target),
                "is_attacker": int(was_attacker),
                "ever_confirmed": int(len(conf) > 0),
                "first_confirmation_s": first,
                "detection_latency_s": (first - attack_start)
                if (was_attacker and np.isfinite(first))
                else np.nan,
                "confirmed_windows": int(len(conf)),
                "total_windows": int(len(g)),
            }
        )
    return pd.DataFrame(out)
