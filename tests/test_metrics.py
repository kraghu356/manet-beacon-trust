"""Checks on the Step 13 metric suite and the Step 12 schedule generator.

Recovery metrics are tested against hand-built throughput curves with known
answers, because these are the numbers most likely to be quietly wrong and most
damaging if they are.
"""

from __future__ import annotations

import sys

import numpy as np
import pandas as pd

sys.path.insert(0, ".")

from analysis.decide import CONFIRMED, NORMAL, SUSPICIOUS
from analysis.make_schedules import build_schedules
from analysis.metrics import (
    aggregate,
    classification_metrics,
    recovery_metrics,
)

FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def curve(baseline: float, attack: float, recovered: float,
          attack_start: float, isolation: float, recover_at: float,
          end: float = 200.0, step: float = 1.0) -> pd.DataFrame:
    t = np.arange(0.0, end, step)
    k = np.full(t.shape, baseline)
    k[t < 5.0] = 0.0                       # warm-up
    k[(t >= attack_start) & (t < recover_at)] = attack
    k[t >= recover_at] = recovered
    return pd.DataFrame({"bin_start_s": t, "rx_packets": 0, "rx_bytes": 0,
                         "throughput_kbps": k})


def test_classification() -> None:
    s = pd.DataFrame(
        {
            "target": [0, 1, 2],
            "is_attacker": [0, 0, 1],
            "ever_confirmed": [0, 0, 1],
            "detection_latency_s": [np.nan, np.nan, 15.0],
        }
    )
    m = classification_metrics(s)
    check(m.tp == 1 and m.fp == 0 and m.tn == 2 and m.fn == 0, "perfect case miscounted")
    check(abs(m.f1 - 1.0) < 1e-9, f"F1 should be 1.0, got {m.f1}")
    check(m.fpr == 0.0, "FPR should be 0")
    check(m.mean_detection_latency_s == 15.0, "latency wrong")

    s2 = s.copy()
    s2["ever_confirmed"] = [1, 0, 0]  # one false accusation, attacker missed
    m2 = classification_metrics(s2)
    check(m2.tp == 0 and m2.fp == 1 and m2.fn == 1, "error case miscounted")
    check(m2.f1 == 0.0, "F1 should collapse to 0")
    check(abs(m2.fpr - 0.5) < 1e-9, f"FPR should be 0.5, got {m2.fpr}")


def test_recovery_full() -> None:
    # Attack at 30, isolated at 60, throughput restored at 70.
    df = curve(100.0, 40.0, 100.0, 30.0, 60.0, 70.0)
    m = recovery_metrics(df, attack_start_s=30.0, isolation_s=60.0, sim_end_s=200.0)
    check(abs(m.baseline_kbps - 100.0) < 1e-6, f"baseline {m.baseline_kbps}")
    check(abs(m.attack_kbps - 40.0) < 1e-6, f"attack {m.attack_kbps}")
    check(m.recovered, "should register as recovered")
    check(abs(m.recovery_time_s - 10.0) < 1.01,
          f"recovery time should be ~10 s, got {m.recovery_time_s}")
    check(abs(m.degradation_ratio - 0.4) < 1e-6, "degradation ratio wrong")
    # Debt: 60 kbps short for 40 s (30->70) = 2400 kbit.
    check(abs(m.throughput_debt_kbit - 2400.0) < 60.0,
          f"debt should be ~2400 kbit, got {m.throughput_debt_kbit}")


def test_recovery_partial() -> None:
    # Isolated, but throughput only comes back to 70% — must NOT count as recovered.
    df = curve(100.0, 40.0, 70.0, 30.0, 60.0, 70.0)
    m = recovery_metrics(df, attack_start_s=30.0, isolation_s=60.0, sim_end_s=200.0)
    check(not m.recovered, "70% of baseline must not count as recovered at 90% threshold")
    check(np.isnan(m.recovery_time_s), "recovery time must be undefined when not recovered")
    check(0.6 < m.recovery_ratio < 0.8, f"recovery ratio {m.recovery_ratio}")


def test_recovery_none() -> None:
    # No isolation at all: the undefended arm.
    df = curve(100.0, 40.0, 40.0, 30.0, 999.0, 999.0)
    m = recovery_metrics(df, attack_start_s=30.0, isolation_s=None, sim_end_s=200.0)
    check(not m.recovered, "undefended run must not report recovery")
    check(abs(m.attack_kbps - 40.0) < 1e-6, "attack throughput wrong without isolation")
    check(m.throughput_debt_kbit > 9000, f"debt should be large, got {m.throughput_debt_kbit}")


def test_debt_orders_two_mechanisms() -> None:
    # Both fully recover; the faster one must owe strictly less. This is the
    # discrimination the recovery-ratio metric alone cannot make.
    fast = curve(100.0, 40.0, 100.0, 30.0, 40.0, 45.0)
    slow = curve(100.0, 40.0, 100.0, 30.0, 90.0, 95.0)
    mf = recovery_metrics(fast, 30.0, 40.0, 200.0)
    ms = recovery_metrics(slow, 30.0, 90.0, 200.0)
    check(mf.recovered and ms.recovered, "both should recover")
    check(abs(mf.recovery_ratio - ms.recovery_ratio) < 0.05,
          "recovery ratio should NOT separate these two")
    check(mf.throughput_debt_kbit < ms.throughput_debt_kbit * 0.5,
          "throughput debt must separate fast from slow recovery")


def test_schedules() -> None:
    rows = []
    for t in range(30, 100, 5):
        if t < 45:
            v = NORMAL
        elif t < 60:
            v = SUSPICIOUS
        else:
            v = CONFIRMED
        rows.append({"time_s": float(t), "target": 2, "verdict": v, "is_attacker": 1})
    v = pd.DataFrame(rows)
    s = build_schedules(v)

    check(s["C"] == [], "arm C must isolate nothing")
    check(len(s["D"]) == 1 and s["D"][0][0] == 45.0,
          f"arm D should isolate at first suspicion (45 s), got {s['D']}")
    check(len(s["E"]) == 1 and s["E"][0][0] == 60.0,
          f"arm E should isolate at first confirmation (60 s), got {s['E']}")
    check(s["D"][0][0] < s["E"][0][0],
          "D must react sooner than E, otherwise the prior-work arm is strawmanned")


def test_aggregate() -> None:
    runs = [{"pdr": 0.9}, {"pdr": 0.92}, {"pdr": 0.88}]
    a = aggregate(runs, ["pdr"])
    check(len(a) == 1 and abs(a["mean"].iloc[0] - 0.9) < 1e-9, "aggregate mean wrong")
    check(a["ci95"].iloc[0] > 0, "CI should be positive")


def main() -> int:
    for fn in [
        test_classification,
        test_recovery_full,
        test_recovery_partial,
        test_recovery_none,
        test_debt_orders_two_mechanisms,
        test_schedules,
        test_aggregate,
        test_dataset_splits,
    ]:
        fn()
        print(f"  {fn.__name__:<34} {'FAIL' if FAILS else 'ok'}")
        if FAILS:
            break

    if FAILS:
        print("\nFAILURES:")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("\nAll metric checks passed.")
    return 0




# ---------------------------------------------------------------------------
# Step 14 — dataset splitting
# ---------------------------------------------------------------------------

def test_dataset_splits() -> None:
    from analysis.dataset import RunKey, assemble, check_leakage, split_by_run, tag_run

    frames = []
    for attack in ["none", "A3"]:
        for seed in [1, 2, 3, 4, 5]:
            ev = pd.DataFrame(
                {
                    "time_s": [10.0, 15.0],
                    "observer": [5, 6],
                    "target": [2, 2],
                    "residual_mean": [10.0, 12.0],
                    "residual_std": [1.0, 1.0],
                    "residual_n": [4, 4],
                    "rssi_mean": [-75.0, -76.0],
                    "transit_rx": [30, 31],
                    "fwd_ratio": [0.9, 0.9],
                    "is_attacker": [1 if attack != "none" else 0] * 2,
                    "malicious_drop": [3, 3],
                }
            )
            frames.append(tag_run(ev, RunKey(attack, seed, 1)))

    df = assemble(frames)
    check("malicious_drop" not in df.columns, "leaky ground-truth column not dropped")

    train, test = split_by_run(df, test_seeds=[4, 5], calibration_seeds=[1])
    check(set(test["seed"]) == {4, 5}, "test seeds wrong")
    check(not (set(train["seed"]) & set(test["seed"])), "seed overlap survived split")

    # Calibration seed leaking into test must be refused.
    try:
        split_by_run(df, test_seeds=[1, 2], calibration_seeds=[1])
        FAILS.append("calibration seed in test set was not rejected")
    except ValueError:
        pass

    # A row-level split must be caught.
    try:
        check_leakage(df.iloc[::2], df.iloc[1::2])
        FAILS.append("row-level split was not rejected")
    except ValueError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
