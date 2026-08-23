"""Synthetic evidence generator matching the ns3/mbtr-sim.cc output schema.

WHAT THIS IS FOR: exercising the Step 8/9 code paths before NS-3 builds, and
regression-testing the decision logic. It is a *test harness*.

WHAT THIS IS NOT: a source of results. Numbers produced from synthetic data must
never appear in the paper, in a figure, or in a claim. The generator draws from
the distributions the detector assumes, so it cannot falsify the detector — it can
only confirm the code runs and the logic branches as designed. Real NS-3 output
will have correlated noise, mobility-driven observer churn and congestion coupling
that none of this reproduces.

Every function here is parameterised so the harness can be made adversarial on
purpose (see tests/test_pipeline.py).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass
class SynthParams:
    n_nodes: int = 20
    n_beacons: int = 3
    attacker: int = 2
    attack: str = "none"          # none | A1 | A2 | A3
    attack_start: float = 30.0
    sim_time: float = 200.0
    beacon_interval: float = 1.0
    window_step: float = 5.0

    # Honest localization noise. residual_bias is nonzero because RSSI distance
    # estimation is biased, not just noisy.
    residual_bias: float = 8.0
    residual_sigma: float = 35.0

    # Honest forwarding. sigma is large because collisions, buffer overflow and
    # mobility-induced link breakage all depress the ratio on a clean network.
    fwd_center: float = 0.94
    fwd_sigma: float = 0.08

    # Attack magnitudes as they appear in the evidence. Only a fraction of a
    # position lie projects onto the observer-target axis, hence the factor.
    offset_m: float = 300.0
    offset_projection: float = 0.7
    drop_prob: float = 0.6

    observers_per_beacon: tuple[int, int] = (5, 10)
    transit_lambda: float = 35.0
    idle_node_fraction: float = 0.15
    seed: int = 1

    def effective_offset(self) -> float:
        if self.attack == "A1":
            return self.offset_m
        if self.attack == "A3":
            return self.offset_m * 0.5
        return 0.0

    def effective_drop(self) -> float:
        if self.attack == "A2":
            return self.drop_prob
        if self.attack == "A3":
            return self.drop_prob * 0.5
        return 0.0


def generate(p: SynthParams) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (beacon_rx, behaviour) frames with the simulator's columns."""
    rng = np.random.default_rng(p.seed)

    idle_nodes = set(
        rng.choice(
            np.arange(p.n_beacons, p.n_nodes),
            size=max(1, int(p.idle_node_fraction * p.n_nodes)),
            replace=False,
        ).tolist()
    )

    # ---- beacon receptions ------------------------------------------------
    rows = []
    times = np.arange(1.0, p.sim_time, p.beacon_interval)
    non_beacons = np.arange(p.n_beacons, p.n_nodes)
    offset = p.effective_offset() * p.offset_projection

    for t in times:
        for b in range(p.n_beacons):
            k = rng.integers(*p.observers_per_beacon)
            obs = rng.choice(non_beacons, size=min(k, non_beacons.size), replace=False)
            attacking = (
                p.attack != "none" and b == p.attacker and t >= p.attack_start
                and offset > 0
            )
            for o in obs:
                # The simulator emits |est_dist - claimed_dist|, so the residual
                # is a magnitude and its honest distribution is half-normal plus
                # an estimation bias. Drawing it signed would give the attacker a
                # spurious advantage: any abs() applied only to the attack branch
                # shifts its mean upward even at zero offset, which manufactures
                # detectability that the offset did not cause.
                res = abs(rng.normal(0.0, p.residual_sigma)) + p.residual_bias
                if attacking:
                    # The lie adds to the honest noise. Only part of it projects
                    # onto the observer-target axis, and that fraction varies
                    # with geometry, so it is noisy too.
                    res += rng.normal(offset, offset * 0.25)
                rows.append(
                    {
                        "time_s": float(t),
                        "rx_node": int(o),
                        "beacon_id": int(b),
                        "seq": int(t / p.beacon_interval),
                        "claimed_x": 0.0,
                        "claimed_y": 0.0,
                        "true_x": 0.0,
                        "true_y": 0.0,
                        "rx_x": 0.0,
                        "rx_y": 0.0,
                        "rssi_dbm": float(rng.normal(-75, 6)),
                        "est_dist_m": 0.0,
                        "claimed_dist_m": 0.0,
                        "true_dist_m": 0.0,
                        "residual_m": float(res),
                        "is_attacker": int(attacking),
                    }
                )
    beacon_rx = pd.DataFrame(rows)

    # ---- behavioural windows ----------------------------------------------
    brows = []
    drop = p.effective_drop()
    for t in np.arange(10.0, p.sim_time, p.window_step):
        for n in range(p.n_nodes):
            lam = 2.0 if n in idle_nodes else p.transit_lambda
            transit = int(rng.poisson(lam))
            attacking = p.attack != "none" and n == p.attacker and t >= p.attack_start and drop > 0

            if transit == 0:
                fwd_ratio, forwarded = -1.0, 0
            else:
                base = np.clip(rng.normal(p.fwd_center, p.fwd_sigma), 0.0, 1.0)
                ratio = base * (1.0 - drop) if attacking else base
                forwarded = int(round(ratio * transit))
                fwd_ratio = forwarded / transit

            brows.append(
                {
                    "time_s": float(t),
                    "node": int(n),
                    "is_beacon": int(n < p.n_beacons),
                    "transit_rx": transit,
                    "forwarded": forwarded,
                    "malicious_drop": int(transit - forwarded) if attacking else 0,
                    "ip_drop": 0,
                    "fwd_ratio": float(fwd_ratio),
                    "drop_ratio": float(1 - fwd_ratio) if transit else -1.0,
                    "mean_relay_delay_s": float(abs(rng.normal(0.02, 0.008)))
                    if transit
                    else -1.0,
                    "is_attacker": int(
                        p.attack != "none" and n == p.attacker and t >= p.attack_start
                    ),
                }
            )
    behaviour = pd.DataFrame(brows)
    return beacon_rx, behaviour
