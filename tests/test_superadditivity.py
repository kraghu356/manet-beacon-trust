"""Does fusion ever beat BOTH single-evidence detectors?

This is the decisive question for the contribution claimed in docs/01-objectives.md.
The sweep drives the hybrid attack down in intensity on both channels at once and
looks for a region where the fused detector confirms and neither single-evidence
detector does.

Read this carefully: a fusion-only region existing *here* proves only that the
combination rule is algebraically capable of super-additive detection. It says
nothing about whether a real attacker operating against a real NS-3 network lands
in that region. The synthetic generator draws from exactly the distributions the
detector assumes, which is the most favourable case there is.

The honest use of this script is as a negative control. If no fusion-only region
exists even here, the contribution is unsupportable and the design must change
before any simulation time is spent.
"""

from __future__ import annotations

import sys

sys.path.insert(0, ".")

from analysis import synth
from analysis.calibrate import calibrate
from analysis.decide import DecisionParams, confirmation_summary, decide
from analysis.features import WindowSpec, build_evidence
from analysis.trust import TrustParams, compute_trust

SPEC = WindowSpec(10.0, 5.0)
BEACONS = [0, 1, 2]
ATTACKER = 2


def caught(offset_m: float, drop_p: float, mode: str, cal, seed: int) -> bool:
    p = synth.SynthParams(
        attack="A3", seed=seed, offset_m=offset_m * 2.0, drop_prob=drop_p * 2.0
    )  # A3 halves both, so pre-double to hit the requested intensity
    brx, beh = synth.generate(p)
    ev = build_evidence(brx, beh, SPEC, beacon_ids=BEACONS)
    tr = compute_trust(ev, cal, TrustParams(mode=mode))
    vd = decide(tr, DecisionParams(), mode=mode)
    s = confirmation_summary(vd, attack_start=30.0)
    row = s[s["target"] == ATTACKER]
    return bool(len(row) and row["ever_confirmed"].iloc[0])


def main() -> int:
    clean_p = synth.SynthParams(attack="none", seed=7)
    brx, beh = synth.generate(clean_p)
    cal = calibrate(build_evidence(brx, beh, SPEC, beacon_ids=BEACONS))

    offsets = [0, 10, 20, 30, 45, 60, 90]
    drops = [0.0, 0.02, 0.04, 0.06, 0.10, 0.15]
    seeds = [1, 2, 3]

    print("Rows: location offset (m).  Columns: drop probability.")
    print("Cell: F = fused only, B = behaviour also, L = localization also,")
    print("      * = fused only and neither single branch (the region that matters),")
    print("      . = nothing detected.\n")

    header = "        " + "".join(f"{d:>8}" for d in drops)
    print(header)

    fusion_only = 0
    for off in offsets:
        cells = []
        for d in drops:
            f = sum(caught(off, d, "fused", cal, s) for s in seeds)
            b = sum(caught(off, d, "behaviour", cal, s) for s in seeds)
            l = sum(caught(off, d, "localization", cal, s) for s in seeds)
            maj = lambda x: x >= 2
            if maj(f) and not maj(b) and not maj(l):
                cells.append("*")
                fusion_only += 1
            elif maj(f):
                cells.append("B" if maj(b) else "L" if maj(l) else "F")
            else:
                cells.append(".")
        print(f"{off:>6}m " + "".join(f"{c:>8}" for c in cells))

    print()
    if fusion_only == 0:
        print("NO fusion-only region found. The combination rule cannot deliver")
        print("super-additive detection under these assumptions. Do not proceed to")
        print("simulation until the design changes.")
        return 1

    print(f"Fusion-only region found in {fusion_only} cell(s), marked *.")
    print("This is a property of the combination rule, not evidence about MANETs.")
    print("The real question is whether NS-3 attackers land in this region.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
