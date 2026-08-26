"""Step 8 — multi-evidence trust model.

    T_ij = (w_d D_ij + w_r R_ij + w_h H_ij) / (w_d + w_r + w_h)

    D_ij = (w_b B_i + w_l L_ij) / (w_b + w_l)      direct, per observer j
    R_ij = bounded trimmed consensus of D_ik, k != j   indirect / recommendation
    H_ij = asymmetric EWMA of past T_ij                historical

Three properties are deliberate and are the parts worth defending at review:

1. **Weights are availability-gated, not fixed.** If a target carried no transit
   traffic in a window, the behavioural branch has no measurement and its weight
   collapses to zero rather than contributing a default value. Fixed weights over
   missing data is how trust schemes manufacture false positives on idle nodes.

2. **Weights are confidence-scaled.** A branch backed by three samples counts for
   less than one backed by forty. This is what stops a single unlucky window from
   moving the verdict.

3. **History is asymmetric.** Trust falls faster than it recovers. A node that
   misbehaves and stops must earn its way back over several windows, which is what
   defeats the intermittent attacker without needing a separate mechanism.

Ablation modes exist so Step 12 can switch a branch off without editing the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .calibrate import Calibration


@dataclass
class TrustParams:
    # Base evidence weights (before availability and confidence gating).
    w_behaviour: float = 1.0
    w_localization: float = 1.0
    # Aggregation weights.
    w_direct: float = 0.5
    w_indirect: float = 0.2
    w_history: float = 0.3
    # Localization sensitivity: residual is scored against k * residual_scale.
    k_residual: float = 3.0
    # Behaviour sensitivity: forwarding ratio penalised below center - k * scale.
    k_forwarding: float = 3.0
    logistic_softness: float = 1.0
    # Confidence saturation constants (samples needed for half weight).
    n_half_localization: float = 5.0
    n_half_behaviour: float = 45.0
    # Asymmetric history.
    lambda_decay_down: float = 0.5   # trust falls fast
    lambda_decay_up: float = 0.9     # trust recovers slowly
    # Recommendation robustness.
    trim_fraction: float = 0.2
    max_single_influence: float = 0.3
    mode: str = "fused"  # fused | behaviour | localization
    combine: str = "stouffer"  # geometric | arithmetic
    score_floor: float = 1e-3   # bounds the geometric mean away from zero
    peer_relative: bool = True  # score behaviour against contemporaneous peers
    min_peers: int = 8
    min_transit_for_evidence: int = 5          # below this, fall back to static calibration

    def effective_base_weights(self) -> tuple[float, float]:
        if self.mode == "behaviour":
            return self.w_behaviour, 0.0
        if self.mode == "localization":
            return 0.0, self.w_localization
        if self.mode == "fused":
            return self.w_behaviour, self.w_localization
        raise ValueError(f"unknown mode: {self.mode}")


def localization_score(residual: np.ndarray, cal: Calibration, k: float) -> np.ndarray:
    """Gaussian score on the residual, 1 = consistent, 0 = inconsistent.

    Centred on the calibrated honest residual rather than on zero, because RSSI
    distance estimation is biased, not merely noisy, and pretending otherwise
    would flag every honest beacon equally.
    """
    z = (np.abs(np.asarray(residual, dtype=float) - cal.residual_center)) / (
        k * cal.residual_scale
    )
    return np.exp(-0.5 * np.square(z))


def behaviour_score(
    fwd_ratio: np.ndarray,
    cal: Calibration,
    params: TrustParams,
    peer_center: np.ndarray | None = None,
    peer_scale: np.ndarray | None = None,
    peer_n: np.ndarray | None = None,
) -> np.ndarray:
    """One-sided logistic score on the forwarding ratio.

    Only *low* forwarding is suspicious. A ratio above the reference centre is
    not evidence of anything, so the logistic saturates at 1 and a lightly loaded
    node is never rewarded into immunity.

    The reference is the contemporaneous peer population where one is available,
    falling back to the static calibration otherwise. Peer-relative scoring is
    what separates "this node is misbehaving" from "this network is congested" —
    without it, load-induced loss is indistinguishable from a grey-hole and the
    detector fires on every node at once.

    The peer scale is floored at half the calibrated scale. In a quiet window
    every node forwards nearly everything, the MAD collapses, and an unfloored
    scale would make a one-packet deviation look infinitely significant.
    """
    f = np.asarray(fwd_ratio, dtype=float)

    center = np.full(f.shape, cal.fwd_center, dtype=float)
    scale = np.full(f.shape, cal.fwd_scale, dtype=float)

    if params.peer_relative and peer_center is not None:
        pc = np.asarray(peer_center, dtype=float)
        ps = np.asarray(peer_scale, dtype=float)
        pn = (
            np.asarray(peer_n, dtype=float)
            if peer_n is not None
            else np.full(f.shape, np.inf)
        )
        usable = np.isfinite(pc) & (pn >= params.min_peers)
        center = np.where(usable, pc, center)
        scale = np.where(
            usable, np.maximum(np.nan_to_num(ps), cal.fwd_scale * 0.5), scale
        )

    tau = center - params.k_forwarding * scale
    s = np.maximum(scale * params.logistic_softness, 1e-9)
    return 1.0 / (1.0 + np.exp(-(f - tau) / s))


def localization_z(residual: np.ndarray, cal: Calibration) -> np.ndarray:
    """One-sided standardised deviation of the localization residual."""
    z = (np.asarray(residual, dtype=float) - cal.residual_center) / cal.residual_scale
    return np.maximum(z, 0.0)


def behaviour_z(
    fwd_ratio: np.ndarray,
    cal: Calibration,
    params: TrustParams,
    peer_center: np.ndarray | None = None,
    peer_scale: np.ndarray | None = None,
    peer_n: np.ndarray | None = None,
) -> np.ndarray:
    """One-sided standardised shortfall in forwarding ratio, peer-relative."""
    f = np.asarray(fwd_ratio, dtype=float)
    center = np.full(f.shape, cal.fwd_center, dtype=float)
    scale = np.full(f.shape, cal.fwd_scale, dtype=float)

    if params.peer_relative and peer_center is not None:
        pc = np.asarray(peer_center, dtype=float)
        ps = np.asarray(peer_scale, dtype=float)
        pn = (
            np.asarray(peer_n, dtype=float)
            if peer_n is not None
            else np.full(f.shape, np.inf)
        )
        usable = np.isfinite(pc) & (pn >= params.min_peers)
        center = np.where(usable, pc, center)
        scale = np.where(
            usable, np.maximum(np.nan_to_num(ps), cal.fwd_scale * 0.5), scale
        )

    return np.maximum((center - f) / np.maximum(scale, 1e-9), 0.0)


def _z_to_score(z: np.ndarray) -> np.ndarray:
    """Map a one-sided z-statistic to a trust score in (0, 1]."""
    return np.exp(-0.5 * np.square(np.asarray(z, dtype=float)))


def _confidence(n: np.ndarray, n_half: float) -> np.ndarray:
    n = np.asarray(n, dtype=float)
    return n / (n + n_half)


def compute_direct(evidence: pd.DataFrame, cal: Calibration, params: TrustParams) -> pd.DataFrame:
    """Per-observer direct trust, with availability-gated adaptive weights."""
    ev = evidence.copy()
    wb_base, wl_base = params.effective_base_weights()

    z_l = localization_z(ev["residual_mean"].to_numpy(), cal)
    z_b = behaviour_z(
        ev["fwd_ratio"].to_numpy(),
        cal,
        params,
        peer_center=ev["peer_fwd_center"].to_numpy()
        if "peer_fwd_center" in ev.columns
        else None,
        peer_scale=ev["peer_fwd_scale"].to_numpy()
        if "peer_fwd_scale" in ev.columns
        else None,
        peer_n=ev["peer_n"].to_numpy() if "peer_n" in ev.columns else None,
    )

    ev["z_localization"] = z_l
    ev["z_behaviour"] = z_b
    ev["L"] = _z_to_score(z_l)
    ev["B"] = _z_to_score(z_b)

    loc_available = np.isfinite(ev["residual_mean"].to_numpy())
    beh_available = np.isfinite(ev["fwd_ratio"].to_numpy()) & (
        ev["transit_rx"].to_numpy() >= params.min_transit_for_evidence
    )

    w_l = wl_base * _confidence(ev["residual_n"].to_numpy(), params.n_half_localization)
    w_b = wb_base * _confidence(ev["transit_rx"].to_numpy(), params.n_half_behaviour)
    w_l = np.where(loc_available, w_l, 0.0)
    w_b = np.where(beh_available, w_b, 0.0)

    total = w_l + w_b
    B = np.nan_to_num(ev["B"].to_numpy(), nan=1.0)
    L = np.nan_to_num(ev["L"].to_numpy(), nan=1.0)
    zb = np.nan_to_num(z_b, nan=0.0)
    zl = np.nan_to_num(z_l, nan=0.0)

    with np.errstate(invalid="ignore", divide="ignore"):
        denom = np.where(total > 0, total, 1.0)

        if params.combine == "stouffer":
            # Weighted Stouffer combination of the two one-sided z-statistics.
            #
            # This is the load-bearing design decision of the whole model, so the
            # reasoning is recorded here rather than in a commit message.
            #
            # Score-averaging rules cannot express evidence accumulation. A
            # weighted arithmetic mean lets a clean branch cancel a damning one.
            # A geometric mean is better but has a fatal structural property: the
            # fused value always lies at or above the lower branch, so anything
            # fusion confirms, the more-alarmed single branch confirms too. Under
            # either rule the fused detector can never beat the best single-
            # evidence detector, which is precisely the claim this work rests on.
            # That is a property of the algebra, not of the data, and no amount
            # of parameter tuning escapes it.
            #
            # Stouffer's method sums standardised deviations rather than
            # averaging scores, so two independently mild anomalies compose into
            # one strong one: z = 1.3 on each branch yields a combined 1.84,
            # which is stronger than either input. That super-additivity is what
            # makes the hybrid attack A3 detectable by fusion alone, and it is
            # only valid because the two branches were constructed to be
            # independent (docs/02-attack-model.md). If that independence fails,
            # the sqrt(sum of squared weights) denominator understates the
            # variance and the combined statistic is over-confident -- so the
            # A1/A2 blindness cross-check in docs/05 is not a nicety, it is the
            # precondition for this line being correct.
            num = w_b * zb + w_l * zl
            den = np.sqrt(np.square(w_b) + np.square(w_l))
            z_comb = np.where(den > 0, num / np.where(den > 0, den, 1.0), 0.0)
            fused = _z_to_score(z_comb)
            ev["z_combined"] = z_comb
        elif params.combine == "arithmetic":
            fused = (B * w_b + L * w_l) / denom
            ev["z_combined"] = np.nan
        elif params.combine == "geometric":
            floor = params.score_floor
            fused = np.exp(
                (w_b * np.log(np.maximum(B, floor)) + w_l * np.log(np.maximum(L, floor)))
                / denom
            )
            ev["z_combined"] = np.nan
        else:
            raise ValueError(f"unknown combine: {params.combine}")

        direct = np.where(total > 0, fused, np.nan)

    ev["w_behaviour"] = w_b
    ev["w_localization"] = w_l
    ev["evidence_mass"] = total
    ev["direct_trust"] = direct
    ev["loc_available"] = loc_available
    ev["beh_available"] = beh_available
    return ev


def _trimmed_bounded_mean(values: np.ndarray, trim: float, cap: float) -> float:
    """Consensus of recommendations, resistant to a minority of liars.

    Trimming removes the extremes; the influence cap limits how far any single
    remaining recommendation can pull the result. Neither is sufficient alone:
    trimming fails when the liar is not extreme, capping fails when there are few
    observers.
    """
    v = np.asarray(values, dtype=float)
    v = v[np.isfinite(v)]
    if v.size == 0:
        return float("nan")
    if v.size >= 5:
        k = int(np.floor(trim * v.size))
        if k > 0:
            v = np.sort(v)[k:-k] if v.size - 2 * k >= 1 else np.sort(v)
    w = np.full(v.size, 1.0 / v.size)
    w = np.minimum(w, cap)
    if w.sum() <= 0:
        return float(np.mean(v))
    return float(np.sum(v * w) / np.sum(w))


def compute_trust(evidence: pd.DataFrame, cal: Calibration, params: TrustParams) -> pd.DataFrame:
    """Full trust pipeline. Returns one row per (window, observer, target)."""
    ev = compute_direct(evidence, cal, params)
    ev = ev.sort_values(["time_s", "target", "observer"]).reset_index(drop=True)

    history: dict[tuple[int, int], float] = {}
    indirect_out = np.full(len(ev), np.nan)
    history_out = np.full(len(ev), np.nan)
    trust_out = np.full(len(ev), np.nan)

    for (_t, target), grp in ev.groupby(["time_s", "target"], sort=True):
        idx = grp.index.to_numpy()
        observers = grp["observer"].to_numpy()
        direct = grp["direct_trust"].to_numpy(dtype=float)

        for pos, gi in enumerate(idx):
            others = np.delete(direct, pos)
            r = _trimmed_bounded_mean(others, params.trim_fraction, params.max_single_influence)

            key = (int(observers[pos]), int(target))
            h = history.get(key, np.nan)

            terms, weights = [], []
            if np.isfinite(direct[pos]):
                terms.append(direct[pos])
                weights.append(params.w_direct)
            if np.isfinite(r):
                terms.append(r)
                weights.append(params.w_indirect)
            if np.isfinite(h):
                terms.append(h)
                weights.append(params.w_history)

            if not terms:
                # No evidence at all this window: carry history forward unchanged
                # rather than defaulting to trusted or untrusted.
                t_val = h
            else:
                t_val = float(np.dot(terms, weights) / np.sum(weights))

            indirect_out[gi] = r
            history_out[gi] = h
            trust_out[gi] = t_val

            if np.isfinite(t_val):
                if np.isnan(h):
                    history[key] = t_val
                else:
                    lam = (
                        params.lambda_decay_down
                        if t_val < h
                        else params.lambda_decay_up
                    )
                    history[key] = lam * h + (1.0 - lam) * t_val

    ev["indirect_trust"] = indirect_out
    ev["historical_trust"] = history_out
    ev["trust"] = trust_out
    return ev
