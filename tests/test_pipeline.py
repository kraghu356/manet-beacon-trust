"""End-to-end exercise of Steps 8-9 on synthetic evidence.

Synthetic data cannot validate the *method* — only that the code runs and that
the logic branches the way the design says it should. See analysis/synth.py.
"""

from __future__ import annotations

import sys

import pandas as pd

sys.path.insert(0, ".")

from analysis import synth
from analysis.calibrate import calibrate
from analysis.decide import CONFIRMED, DecisionParams, confirmation_summary, decide
from analysis.features import WindowSpec, build_evidence
from analysis.trust import TrustParams, compute_trust

SPEC = WindowSpec(length_s=10.0, step_s=5.0)
BEACONS = [0, 1, 2]
ATTACKER = 2


def evidence_for(attack: str, seed: int = 1) -> pd.DataFrame:
    p = synth.SynthParams(attack=attack, seed=seed)
    brx, beh = synth.generate(p)
    return build_evidence(brx, beh, SPEC, beacon_ids=BEACONS)


def run(attack: str, cal, mode: str, seed: int = 1):
    ev = evidence_for(attack, seed)
    tp = TrustParams(mode=mode)
    tr = compute_trust(ev, cal, tp)
    vd = decide(tr, DecisionParams(), mode=mode)
    return confirmation_summary(vd, attack_start=30.0)


def main() -> int:
    clean = evidence_for("none", seed=7)
    cal = calibrate(clean)
    print("Calibration (from attack-free run):")
    print("  " + cal.summary().replace("\n", "\n  "))
    print()

    results = {}
    for attack in ["none", "A1", "A2", "A3"]:
        for mode in ["fused", "behaviour", "localization"]:
            results[(attack, mode)] = run(attack, cal, mode)

    print(f"{'scenario':<10}{'mode':<14}{'attacker':<12}{'latency_s':<12}{'false pos':<10}")
    print("-" * 58)
    for attack in ["none", "A1", "A2", "A3"]:
        for mode in ["fused", "behaviour", "localization"]:
            s = results[(attack, mode)]
            atk = s[s["target"] == ATTACKER]
            honest = s[(s["target"] != ATTACKER) & (s["is_attacker"] == 0)]
            caught = bool(atk["ever_confirmed"].iloc[0]) if len(atk) else False
            lat = atk["detection_latency_s"].iloc[0] if len(atk) else float("nan")
            fp = int(honest["ever_confirmed"].sum())
            flag = "yes" if caught else "no"
            if attack == "none":
                flag = "n/a"
                lat = float("nan")
            print(f"{attack:<10}{mode:<14}{flag:<12}{lat if lat == lat else '-':<12}{fp:<10}")
        print()

    failures = []

    # No attacker present: nothing may be confirmed, in any mode.
    for mode in ["fused", "behaviour", "localization"]:
        s = results[("none", mode)]
        if int(s["ever_confirmed"].sum()) != 0:
            failures.append(f"false positive on clean run, mode={mode}")

    def caught(attack, mode):
        s = results[(attack, mode)]
        row = s[s["target"] == ATTACKER]
        return bool(len(row) and row["ever_confirmed"].iloc[0])

    # Fused must catch all three.
    for attack in ["A1", "A2", "A3"]:
        if not caught(attack, "fused"):
            failures.append(f"fused missed {attack}")

    # Blindness checks from docs/02: these are the ablations that justify fusion.
    if caught("A1", "behaviour"):
        failures.append("behaviour-only detected A1, which has no routing component")
    if caught("A2", "localization"):
        failures.append("localization-only detected A2, which has no position lie")

    # --- benign stress: no attacker, but the network is congested -----------
    # Calibration came from a lightly loaded run. Under load every honest node's
    # forwarding ratio collapses. This is the false-positive case that motivates
    # fusion, and it is where the fused detector must beat behaviour-only.
    stress = synth.SynthParams(
        attack="none", seed=11, fwd_center=0.68, fwd_sigma=0.12
    )
    brx, beh = synth.generate(stress)
    ev_stress = build_evidence(brx, beh, SPEC, beacon_ids=BEACONS)

    print("Benign congestion (no attacker, forwarding ratio depressed network-wide):")
    stress_fp = {}
    for mode in ["fused", "behaviour", "localization"]:
        tr = compute_trust(ev_stress, cal, TrustParams(mode=mode))
        vd = decide(tr, DecisionParams(), mode=mode)
        s = confirmation_summary(vd, attack_start=30.0)
        stress_fp[mode] = int(s["ever_confirmed"].sum())
        print(f"  {mode:<14} false confirmations: {stress_fp[mode]}")
    print()

    if stress_fp["fused"] > stress_fp["behaviour"]:
        failures.append(
            "fusion made congestion false positives worse, not better"
        )

    if failures:
        print("FAILURES:")
        for f in failures:
            print("  - " + f)
        return 1

    print("All structural checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
