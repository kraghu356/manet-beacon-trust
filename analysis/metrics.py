"""Step 13 — the metric suite.

Four families, because a paper reporting only detection accuracy is weak and this
one has an explicit performance-cost constraint in Objective 4:

    security   accuracy, precision, recall, F1, FPR, FNR, isolation rate
    network    PDR, throughput, delay, routing overhead, packet loss
    recovery   recovery time, recovery ratio, throughput debt, route churn
    beacon     localization error, RSSI deviation, beacon consistency

The recovery family is the one most often fudged. "The malicious node was removed"
is not a result. What matters is how much of the pre-attack network came back and
how long it took, and both are computed here from the time-binned throughput curve
rather than from an end-of-run average, which would hide the whole transient.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


@dataclass
class ClassificationMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float
    isolation_rate: float
    mean_detection_latency_s: float

    def as_dict(self) -> dict:
        return asdict(self)


def classification_metrics(summary: pd.DataFrame) -> ClassificationMetrics:
    """From a per-target confirmation summary (analysis.decide.confirmation_summary).

    Deliberately evaluated per *node*, not per window. A node confirmed in 40 of
    50 windows is one true positive, not forty. Per-window scoring inflates every
    figure and is the most common way these tables get overstated.
    """
    y_true = summary["is_attacker"].to_numpy().astype(bool)
    y_pred = summary["ever_confirmed"].to_numpy().astype(bool)

    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    fn = int(np.sum(y_true & ~y_pred))

    def safe(num, den):
        return float(num / den) if den else float("nan")

    precision = safe(tp, tp + fp)
    recall = safe(tp, tp + fn)
    f1 = (
        safe(2 * precision * recall, precision + recall)
        if np.isfinite(precision) and np.isfinite(recall) and (precision + recall) > 0
        else 0.0
    )

    lat = summary.loc[summary["is_attacker"] == 1, "detection_latency_s"]
    lat = lat[np.isfinite(lat)]

    return ClassificationMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy=safe(tp + tn, tp + tn + fp + fn),
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=safe(fp, fp + tn),
        fnr=safe(fn, fn + tp),
        isolation_rate=recall,  # confirmed attackers are the ones that get isolated
        mean_detection_latency_s=float(lat.mean()) if len(lat) else float("nan"),
    )


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


@dataclass
class RecoveryMetrics:
    baseline_kbps: float
    attack_kbps: float
    recovered_kbps: float
    recovery_ratio: float          # recovered / baseline
    degradation_ratio: float       # attack / baseline
    recovery_time_s: float         # isolation -> sustained return to threshold
    throughput_debt_kbit: float    # integrated shortfall vs baseline over the run
    recovered: bool

    def as_dict(self) -> dict:
        return asdict(self)


def recovery_metrics(
    recovery: pd.DataFrame,
    attack_start_s: float,
    isolation_s: float | None,
    sim_end_s: float,
    threshold: float = 0.9,
    sustain_bins: int = 5,
    settle_s: float = 5.0,
) -> RecoveryMetrics:
    """Recovery statistics from the time-binned delivered-throughput curve.

    `baseline` is measured on this run's own pre-attack window, not on a separate
    clean run. Cross-run comparison would fold in topology and mobility
    differences and make recovery look better or worse than it is.

    Recovery is only declared when throughput holds at or above `threshold` of
    baseline for `sustain_bins` consecutive bins. A single lucky bin is not a
    recovered network, and without the sustain requirement AODV's bursty
    post-rediscovery delivery reads as instant recovery.
    """
    df = recovery.copy()
    t = df["bin_start_s"].to_numpy(dtype=float)
    kbps = df["throughput_kbps"].to_numpy(dtype=float)

    pre = (t >= settle_s) & (t < attack_start_s)
    baseline = float(np.mean(kbps[pre])) if pre.any() else float("nan")

    if isolation_s is None:
        atk_window = t >= attack_start_s
        attack_kbps = float(np.mean(kbps[atk_window])) if atk_window.any() else float("nan")
        recovered_kbps = attack_kbps
        return RecoveryMetrics(
            baseline_kbps=baseline,
            attack_kbps=attack_kbps,
            recovered_kbps=recovered_kbps,
            recovery_ratio=(recovered_kbps / baseline) if baseline else float("nan"),
            degradation_ratio=(attack_kbps / baseline) if baseline else float("nan"),
            recovery_time_s=float("nan"),
            throughput_debt_kbit=_debt(t, kbps, baseline, attack_start_s, sim_end_s),
            recovered=False,
        )

    atk_window = (t >= attack_start_s) & (t < isolation_s)
    post_window = t >= isolation_s
    attack_kbps = float(np.mean(kbps[atk_window])) if atk_window.any() else float("nan")
    recovered_kbps = float(np.mean(kbps[post_window])) if post_window.any() else float("nan")

    target = threshold * baseline
    rec_time = float("nan")
    if np.isfinite(baseline):
        idx = np.where(post_window)[0]
        run = 0
        for i in idx:
            run = run + 1 if kbps[i] >= target else 0
            if run >= sustain_bins:
                rec_time = float(t[i - sustain_bins + 1] - isolation_s)
                break

    return RecoveryMetrics(
        baseline_kbps=baseline,
        attack_kbps=attack_kbps,
        recovered_kbps=recovered_kbps,
        recovery_ratio=(recovered_kbps / baseline) if baseline else float("nan"),
        degradation_ratio=(attack_kbps / baseline) if baseline else float("nan"),
        recovery_time_s=rec_time,
        throughput_debt_kbit=_debt(t, kbps, baseline, attack_start_s, sim_end_s),
        recovered=bool(np.isfinite(rec_time)),
    )


def _debt(t, kbps, baseline, start, end) -> float:
    """Integrated throughput shortfall against baseline, in kilobits.

    This is the metric that separates two mechanisms which both eventually
    recover: the one that recovers faster owes less. Reporting only the final
    recovery ratio makes them look identical.
    """
    if not np.isfinite(baseline):
        return float("nan")
    w = (t >= start) & (t <= end)
    if not w.any():
        return float("nan")
    dt = float(np.median(np.diff(t))) if t.size > 1 else 1.0
    shortfall = np.maximum(baseline - kbps[w], 0.0)
    return float(np.sum(shortfall) * dt)


# ---------------------------------------------------------------------------
# Beacon-specific
# ---------------------------------------------------------------------------


def beacon_metrics(beacon_rx: pd.DataFrame, attack_start_s: float) -> pd.DataFrame:
    """Per-beacon localization error and RSSI deviation, before and after attack."""
    rows = []
    for bid, g in beacon_rx.groupby("beacon_id", sort=True):
        pre = g[g["time_s"] < attack_start_s]
        post = g[g["time_s"] >= attack_start_s]
        rows.append(
            {
                "beacon_id": int(bid),
                "residual_pre_m": float(pre["residual_m"].mean()) if len(pre) else np.nan,
                "residual_post_m": float(post["residual_m"].mean()) if len(post) else np.nan,
                "residual_shift_m": (
                    float(post["residual_m"].mean() - pre["residual_m"].mean())
                    if len(pre) and len(post)
                    else np.nan
                ),
                "rssi_std_pre_db": float(pre["rssi_dbm"].std(ddof=0)) if len(pre) else np.nan,
                "rssi_std_post_db": float(post["rssi_dbm"].std(ddof=0)) if len(post) else np.nan,
                "consistency_score": (
                    float(np.exp(-0.5 * (post["residual_m"].mean() /
                                         max(pre["residual_m"].std(ddof=0), 1e-9)) ** 2))
                    if len(pre) > 1 and len(post)
                    else np.nan
                ),
                "is_attacker": int(g["is_attacker"].max()),
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Aggregation across seeds
# ---------------------------------------------------------------------------


def aggregate(runs: list[dict], keys: list[str]) -> pd.DataFrame:
    """Mean and 95% CI across seeds. A single run is not a result."""
    df = pd.DataFrame(runs)
    out = []
    for k in keys:
        if k not in df.columns:
            continue
        v = pd.to_numeric(df[k], errors="coerce").dropna().to_numpy()
        n = v.size
        mean = float(np.mean(v)) if n else float("nan")
        # t-critical for 95% at small n; falls back to the normal value for n>30.
        tcrit = {2: 12.71, 3: 4.30, 4: 3.18, 5: 2.78, 6: 2.57, 7: 2.45,
                 8: 2.36, 9: 2.31, 10: 2.26}.get(n, 1.96)
        ci = float(tcrit * np.std(v, ddof=1) / np.sqrt(n)) if n > 1 else float("nan")
        out.append({"metric": k, "n": n, "mean": mean, "ci95": ci})
    return pd.DataFrame(out)
