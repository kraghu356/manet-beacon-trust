"""Checks on the corrected fusion-only region condition (paper Eq 32)."""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.fusion_region import crossing_50, fused_crossing, max_ratio, region  # noqa: E402

import numpy as np  # noqa: E402

B = 1 + math.sqrt(2)


def test_equal_weight_bound_is_one_plus_root_two():
    assert abs(max_ratio(1.0, 1.0) - B) < 1e-12
    assert region(1.0, B - 1e-6) is not None
    assert region(1.0, B + 1e-6) is None


def test_old_root_two_bound_was_too_strict():
    # r = 2 lies above sqrt(2) yet still admits a region
    lo, hi = region(1.0, 2.0)
    assert lo < hi and abs(lo - 2 * math.sqrt(2) / 3) < 1e-12


def test_region_width_is_root_two_when_equal():
    lo, hi = region(1.0, 1.0)
    assert abs(hi / lo - math.sqrt(2)) < 1e-12


def test_symmetry():
    assert abs(fused_crossing(1.0, 3.0) - fused_crossing(3.0, 1.0)) < 1e-12


def test_measured_ratio_sits_at_boundary():
    assert region(1.0, 2.43) is None
    assert region(1.0, 2.40) is not None


def test_crossing_detects_below_range():
    v, kind = crossing_50(np.array([15.0, 30.0]), np.array([8, 10]), 10)
    assert kind == "below_range" and v == 15.0


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
