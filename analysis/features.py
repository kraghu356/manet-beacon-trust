"""Load simulator output and align it onto a common observation-window grid.

Input schema is fixed by ns3/mbtr-sim.cc. Nothing here computes trust; this module
only turns raw event logs into the per-window feature table that Step 8 consumes.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

MISSING = -1.0  # simulator's sentinel for "no transit traffic in this window"


@dataclass(frozen=True)
class WindowSpec:
    length_s: float = 10.0
    step_s: float = 5.0


def load_beacon_rx(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {
        "time_s",
        "rx_node",
        "beacon_id",
        "rssi_dbm",
        "est_dist_m",
        "claimed_dist_m",
        "residual_m",
        "is_attacker",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"beacon_rx.csv missing columns: {sorted(missing)}")
    return df


def load_behaviour(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {"time_s", "node", "transit_rx", "forwarded", "fwd_ratio", "is_attacker"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"behaviour.csv missing columns: {sorted(missing)}")
    # Turn the sentinel into real NaN so it can never be averaged as if it were a
    # measurement. A node with nothing to forward has not failed to forward.
    df = df.copy()
    for col in ("fwd_ratio", "drop_ratio", "mean_relay_delay_s"):
        if col in df.columns:
            df.loc[df[col] == MISSING, col] = np.nan
    return df


def window_localization(beacon_rx: pd.DataFrame, spec: WindowSpec) -> pd.DataFrame:
    """Aggregate per-packet beacon receptions into (window, observer, target) rows.

    A window ending at t covers samples in (t - length, t]. Windows are placed on
    the same grid the simulator uses for behavioural sampling, so the two feature
    sets join without interpolation.
    """
    if beacon_rx.empty:
        return pd.DataFrame(
            columns=["time_s", "observer", "target", "residual_mean",
                     "residual_std", "residual_n", "rssi_mean"]
        )

    t_max = float(beacon_rx["time_s"].max())
    grid = np.arange(spec.length_s, t_max + spec.step_s, spec.step_s)

    rows = []
    times = beacon_rx["time_s"].to_numpy()
    for t_end in grid:
        mask = (times > t_end - spec.length_s) & (times <= t_end)
        if not mask.any():
            continue
        chunk = beacon_rx.loc[mask]
        grouped = chunk.groupby(["rx_node", "beacon_id"], sort=True)
        for (obs, tgt), g in grouped:
            rows.append(
                {
                    "time_s": float(t_end),
                    "observer": int(obs),
                    "target": int(tgt),
                    "residual_mean": float(g["residual_m"].mean()),
                    "residual_std": float(g["residual_m"].std(ddof=0)),
                    "residual_n": int(len(g)),
                    "rssi_mean": float(g["rssi_dbm"].mean()),
                }
            )
    return pd.DataFrame(rows)


def build_evidence(
    beacon_rx: pd.DataFrame,
    behaviour: pd.DataFrame,
    spec: WindowSpec,
    beacon_ids: list[int] | None = None,
) -> pd.DataFrame:
    """Join localization and behavioural evidence into one table.

    LIMITATION, stated here because it affects how the results may be described:
    behavioural counters produced by the current simulator are node-global, i.e.
    they model an idealised watchdog with perfect promiscuous observation of the
    target. Every observer of a given target therefore sees the same behavioural
    value in a window, and only the localization branch varies per observer. A
    true per-observer watchdog with its own overhearing errors is a refinement,
    and until it exists the behavioural branch should not be described as
    distributed.
    """
    loc = window_localization(beacon_rx, spec)
    if beacon_ids is not None:
        loc = loc[loc["target"].isin(beacon_ids)]

    beh = behaviour.rename(columns={"node": "target"})
    keep = ["time_s", "target", "transit_rx", "forwarded", "fwd_ratio", "is_attacker"]
    if "drop_ratio" in beh.columns:
        keep.append("drop_ratio")
    if "mean_relay_delay_s" in beh.columns:
        keep.append("mean_relay_delay_s")
    beh = beh[keep]

    # Per-window peer statistics over the WHOLE node population, used to tell a
    # misbehaving node apart from a misbehaving network. Congestion depresses
    # every node's forwarding ratio at once; a grey-hole depresses one. Scoring
    # against a static baseline cannot distinguish these, and that is the
    # dominant source of false positives under load.
    #
    # Median and MAD are used rather than mean and SD so that including the
    # attacker's own row in its peer group does not meaningfully shift the
    # reference. With a single attacker among 20 nodes the effect is negligible;
    # if the attacker fraction ever rises above roughly 20%, this assumption
    # breaks and the peer group must exclude flagged nodes explicitly.
    peer = (
        behaviour.dropna(subset=["fwd_ratio"])
        .groupby("time_s")["fwd_ratio"]
        .agg(
            peer_fwd_center="median",
            peer_n="count",
            peer_fwd_mad=lambda s: float(np.median(np.abs(s - np.median(s)))),
        )
        .reset_index()
    )
    peer["peer_fwd_scale"] = 1.4826 * peer["peer_fwd_mad"]

    ev = loc.merge(beh, on=["time_s", "target"], how="left")
    ev = ev.merge(
        peer[["time_s", "peer_fwd_center", "peer_fwd_scale", "peer_n"]],
        on="time_s",
        how="left",
    )
    ev["is_attacker"] = ev["is_attacker"].fillna(0).astype(int)
    ev["transit_rx"] = ev["transit_rx"].fillna(0).astype(int)
    return ev.sort_values(["time_s", "target", "observer"]).reset_index(drop=True)
