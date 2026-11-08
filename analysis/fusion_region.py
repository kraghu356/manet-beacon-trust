"""When can weighted-Stouffer fusion detect what neither branch detects alone?

Model (the paper's Sec 6.3 assumption): each branch's anomaly grows linearly with
attack intensity f and reaches the common decision threshold at its own intensity
theta_B or theta_L. With effective weights w_B, w_L the fused statistic crosses at

    f_F = sqrt(w_B**2 + w_L**2) / (w_B / theta_B + w_L / theta_L).

A fusion-only region exists iff f_F < min(theta_B, theta_L). For equal weights and
r = max/min this reduces to

    sqrt(2) * r / (1 + r) < 1   <=>   r < 1 + sqrt(2) ~= 2.414

(the region itself then spans (f_F, min theta), at most a factor sqrt(2) wide when
r = 1 -- the earlier draft conflated the region's width with the condition on r).

With unequal weights the bound moves; `max_ratio` solves for it numerically.

    python -m analysis.fusion_region            # bound table + Table 6 crossings
"""

from __future__ import annotations

import math

import numpy as np


def fused_crossing(theta_b: float, theta_l: float, w_b: float = 1.0, w_l: float = 1.0) -> float:
    return math.hypot(w_b, w_l) / (w_b / theta_b + w_l / theta_l)


def region(theta_b: float, theta_l: float, w_b: float = 1.0, w_l: float = 1.0):
    """(lo, hi) intensity interval where only fusion detects, or None."""
    f_f = fused_crossing(theta_b, theta_l, w_b, w_l)
    hi = min(theta_b, theta_l)
    return (f_f, hi) if f_f < hi else None


def max_ratio(w_weak: float, w_strong: float) -> float:
    """Largest sensitivity ratio r = theta_weak/theta_strong admitting a region.

    `w_weak` weights the LESS sensitive branch (larger theta). Region exists iff
    hypot(w_s, w_w) / (w_s + w_w / r) < 1  <=>  r < w_w / (hypot - w_s).
    Returns inf when the weak branch's weight alone can never close the gap.
    """
    h = math.hypot(w_strong, w_weak)
    denom = h - w_strong
    return math.inf if denom <= 0 else w_weak / denom


def crossing_50(x: np.ndarray, k: np.ndarray, n: int):
    """50% crossing of a detection curve, interpolated on log intensity.

    Returns (value, kind) with kind 'interpolated', 'below_range' (curve is already
    >= 50% at the lowest tested intensity: only an upper bound on theta exists) or
    'above_range'.
    """
    x = np.asarray(x, float)
    p = np.asarray(k, float) / n
    if p[0] >= 0.5:
        return float(x[0]), "below_range"
    for i in range(1, len(x)):
        if p[i] >= 0.5 > p[i - 1]:
            lx0, lx1 = math.log(x[i - 1]), math.log(x[i])
            t = (0.5 - p[i - 1]) / (p[i] - p[i - 1])
            return float(math.exp(lx0 + t * (lx1 - lx0))), "interpolated"
    return float(x[-1]), "above_range"


# Table 6 of the current draft (10 seeds per level, x = measured displacement, m).
TABLE6_X = np.array([15.0, 22.5, 30.0, 45.0, 60.0, 74.9, 104.5, 147.1])
TABLE6_BEH = np.array([8, 10, 10, 10, 10, 10, 10, 10])
TABLE6_LOC = np.array([0, 0, 2, 9, 10, 10, 10, 10])


def main() -> int:
    print("Equal-weight bound: r < 1 + sqrt(2) =", round(1 + math.sqrt(2), 4))
    print("\nBound on r for unequal effective weights (weak-branch weight / strong-branch weight):")
    for ratio in (0.25, 0.5, 1.0, 2.0, 4.0):
        print(f"  w_weak/w_strong = {ratio:4.2f}  ->  r_max = {max_ratio(ratio, 1.0):6.3f}")

    tb, kb = crossing_50(TABLE6_X, TABLE6_BEH, 10)
    tl, kl = crossing_50(TABLE6_X, TABLE6_LOC, 10)
    print(f"\nTable 6 crossings: behavioural {tb:.1f} m ({kb}), localisation {tl:.1f} m ({kl})")
    if kb == "below_range":
        print(f"  behavioural theta < {tb:.1f} m, so r > {tl / tb:.2f} (lower bound only)")
        print("  -> extend the sweep below 15 m to locate theta_B and bound r from above")
    else:
        print(f"  r = {tl / tb:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
