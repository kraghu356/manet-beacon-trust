"""Aggregation ablation: does indirect and historical trust earn its complexity?"""
import os
import pandas as pd
from analysis.trust import TrustParams, compute_trust
from analysis.decide import DecisionParams, decide
from analysis.features import WindowSpec, build_evidence, load_beacon_rx, load_behaviour
from analysis.calibrate import Calibration

R = os.path.expanduser("~/manet-beacon-trust/results")
CFGS = {"G1_direct": (1.0, 0.0, 0.0),
        "G2_direct_indirect": (0.71, 0.29, 0.0),
        "G3_all": (0.5, 0.2, 0.3)}

cal = Calibration.from_json(f"{R}/calibration.json")
spec = WindowSpec()
rows = []
for atk in ["none", "A1", "A2", "A3"]:
    for s in range(1, 6):
        p = f"{R}/{atk}-seed{s}-run1"
        ev = build_evidence(load_beacon_rx(f"{p}-beacon_rx.csv"),
                            load_behaviour(f"{p}-behaviour.csv"), spec)
        for name, (wd, wi, wh) in CFGS.items():
            tp = TrustParams(w_direct=wd, w_indirect=wi, w_history=wh, mode="fused")
            v = decide(compute_trust(ev, cal, tp), DecisionParams(), mode="fused")
            for tgt, g in v.groupby("target"):
                rows.append({"cfg": name, "attack": atk, "seed": s,
                             "target": int(tgt),
                             "confirmed": bool(g["verdict"].eq("confirmed").any())})
df = pd.DataFrame(rows)
df.to_csv(f"{R}/tables/agg_ablation_raw.csv", index=False)
print(df.groupby(["cfg", "attack"])["confirmed"].agg(["sum", "count"]).to_string())
