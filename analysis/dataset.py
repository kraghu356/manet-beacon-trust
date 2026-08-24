"""Step 14 — dataset assembly and leakage-safe splitting.

The dataset is the per-window evidence table plus a ground-truth label. Its one
non-obvious property is that **rows are not independent samples**. Rows from the
same run share topology, mobility and the same attacker; rows from the same
(target, run) are a time series. Splitting at row level would place windows from
one run on both sides of the split and produce accuracy figures that mean nothing.

Every split here is therefore **by run**, and `check_leakage` refuses to return a
split that violates that. It also refuses when calibration runs appear in the test
set, because calibration is fitted on data and a test set that helped set the
thresholds is not a test set.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "residual_mean",
    "residual_std",
    "residual_n",
    "rssi_mean",
    "transit_rx",
    "fwd_ratio",
    "drop_ratio",
    "mean_relay_delay_s",
    "peer_fwd_center",
    "peer_fwd_scale",
]

# Columns that encode the answer. Present for evaluation, never for fitting.
LABEL_COLUMNS = ["is_attacker"]
LEAKY_COLUMNS = ["malicious_drop", "true_x", "true_y", "attack_type"]


@dataclass(frozen=True)
class RunKey:
    attack: str
    seed: int
    run: int

    def as_str(self) -> str:
        return f"{self.attack}-seed{self.seed}-run{self.run}"


def tag_run(evidence: pd.DataFrame, key: RunKey) -> pd.DataFrame:
    df = evidence.copy()
    df["run_id"] = key.as_str()
    df["attack"] = key.attack
    df["seed"] = key.seed
    return df


def assemble(tagged: list[pd.DataFrame]) -> pd.DataFrame:
    """Concatenate tagged per-run evidence tables into one dataset."""
    if not tagged:
        raise ValueError("no runs supplied")
    df = pd.concat(tagged, ignore_index=True)

    present_leaks = [c for c in LEAKY_COLUMNS if c in df.columns]
    if present_leaks:
        df = df.drop(columns=present_leaks)
    return df


def feature_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray]:
    cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    X = df[cols].copy()
    y = df["is_attacker"].to_numpy().astype(int)
    return X, y


def split_by_run(
    df: pd.DataFrame, test_seeds: list[int], calibration_seeds: list[int] | None = None
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split by seed, never by row."""
    test = df[df["seed"].isin(test_seeds)].copy()
    train = df[~df["seed"].isin(test_seeds)].copy()
    check_leakage(train, test, calibration_seeds)
    return train, test


def check_leakage(
    train: pd.DataFrame, test: pd.DataFrame, calibration_seeds: list[int] | None = None
) -> None:
    """Raise loudly rather than return a quietly invalid split."""
    shared_runs = set(train["run_id"]) & set(test["run_id"])
    if shared_runs:
        raise ValueError(
            f"{len(shared_runs)} run(s) appear in both train and test: "
            f"{sorted(shared_runs)[:3]}"
        )

    shared_seeds = set(train["seed"]) & set(test["seed"])
    if shared_seeds:
        raise ValueError(
            f"seeds {sorted(shared_seeds)} appear on both sides; split by seed, not row"
        )

    if calibration_seeds:
        overlap = set(test["seed"]) & set(calibration_seeds)
        if overlap:
            raise ValueError(
                f"calibration seeds {sorted(overlap)} appear in the test set; "
                "thresholds were fitted on this data, so it cannot be a test set"
            )

    if test.empty or train.empty:
        raise ValueError("one side of the split is empty")


def class_balance(df: pd.DataFrame) -> pd.DataFrame:
    """Attacker rows are a small minority. Report it, and never report bare accuracy.

    With one attacker among three beacons, a detector that flags nothing scores
    roughly 67% accuracy on beacon rows and higher still on all-node rows. Accuracy
    is close to meaningless here; precision, recall and FPR are the honest numbers.
    """
    rows = []
    for (attack,), g in df.groupby(["attack"], sort=True):
        pos = int(g["is_attacker"].sum())
        rows.append(
            {
                "attack": attack,
                "rows": len(g),
                "attacker_rows": pos,
                "attacker_fraction": pos / len(g) if len(g) else np.nan,
                "majority_class_accuracy": 1 - (pos / len(g)) if len(g) else np.nan,
            }
        )
    return pd.DataFrame(rows)
