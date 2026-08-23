"""Derive every threshold from attack-free data, using robust statistics.

No constant in the trust model is chosen by hand. Each one is expressed as a
multiple of a dispersion estimated from the clean baseline, so a reviewer can
check the calibration independently of the detector, and so the same code
transfers to a different mobility model or field size without retuning.

MAD-based scale is used rather than standard deviation because the baseline is
not guaranteed clean of outliers — a transient partition or a burst of collisions
would inflate an SD-based threshold and silently destroy sensitivity.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

MAD_TO_SIGMA = 1.4826  # consistency factor for a normal distribution


def robust_scale(x: np.ndarray) -> float:
    x = np.asarray(x, dtype=float)
    x = x[np.isfinite(x)]
    if x.size < 2:
        return float("nan")
    med = np.median(x)
    mad = np.median(np.abs(x - med))
    scale = MAD_TO_SIGMA * mad
    # A degenerate MAD (many identical values) would make every deviation
    # infinitely significant. Fall back to a percentile spread instead of
    # returning zero.
    if scale <= 0:
        spread = np.percentile(x, 84) - np.percentile(x, 16)
        scale = max(spread / 2.0, 1e-9)
    return float(scale)


@dataclass
class Calibration:
    """Baseline statistics. All are estimated from attack-free runs only."""

    residual_center: float  # median honest-beacon residual, metres
    residual_scale: float   # robust sigma of honest-beacon residual, metres
    fwd_center: float       # median honest forwarding ratio
    fwd_scale: float        # robust sigma of honest forwarding ratio
    delay_center: float
    delay_scale: float
    n_residual_samples: int
    n_behaviour_samples: int

    def to_json(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump(asdict(self), fh, indent=2)

    @staticmethod
    def from_json(path: str) -> "Calibration":
        with open(path) as fh:
            return Calibration(**json.load(fh))

    def summary(self) -> str:
        return (
            f"residual: {self.residual_center:.2f} +/- {self.residual_scale:.2f} m "
            f"(n={self.n_residual_samples})\n"
            f"fwd_ratio: {self.fwd_center:.4f} +/- {self.fwd_scale:.4f} "
            f"(n={self.n_behaviour_samples})"
        )


def calibrate(evidence: pd.DataFrame) -> Calibration:
    """Fit calibration on an evidence table from a clean run.

    Raises if any attacker rows are present — calibrating on contaminated data is
    the most damaging silent error available here, so it is made loud.
    """
    if evidence["is_attacker"].sum() > 0:
        raise ValueError(
            "Calibration data contains attacker rows. Calibrate on --attack=none only."
        )

    res = evidence["residual_mean"].to_numpy(dtype=float)
    fwd = evidence["fwd_ratio"].to_numpy(dtype=float)
    fwd = fwd[np.isfinite(fwd)]

    if "mean_relay_delay_s" in evidence.columns:
        dly = evidence["mean_relay_delay_s"].to_numpy(dtype=float)
        dly = dly[np.isfinite(dly)]
    else:
        dly = np.array([])

    return Calibration(
        residual_center=float(np.median(res[np.isfinite(res)])),
        residual_scale=robust_scale(res),
        fwd_center=float(np.median(fwd)) if fwd.size else float("nan"),
        fwd_scale=robust_scale(fwd) if fwd.size else float("nan"),
        delay_center=float(np.median(dly)) if dly.size else 0.0,
        delay_scale=robust_scale(dly) if dly.size > 1 else 1.0,
        n_residual_samples=int(np.isfinite(res).sum()),
        n_behaviour_samples=int(fwd.size),
    )
