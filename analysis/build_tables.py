"""Consolidate per-run CSVs into tables with means and 95% CIs."""
import os, sys, glob, re
import pandas as pd
from analysis.metrics import (classification_metrics, recovery_metrics,
                              beacon_metrics, aggregate)

R = os.path.expanduser("~/manet-beacon-trust/results")
ATTACK_START, SIM_END = 30.0, 400.0

def run_row(prefix, atk, seed):
    row = {"attack": atk, "seed": seed}
    try:
        s = pd.read_csv(f"{R}/arms/{atk}-seed{seed}-verdicts-summary.csv")
        cm = classification_metrics(s)
        row.update({k: getattr(cm, k) for k in vars(cm)})
    except Exception as e:
        print(f"  classification failed {atk} s{seed}: {e}", file=sys.stderr)
    try:
        rec = pd.read_csv(f"{prefix}-recovery.csv")
        rm = recovery_metrics(rec, ATTACK_START, None, SIM_END, settle_s=20.0)
        row.update({k: getattr(rm, k) for k in vars(rm)})
    except Exception as e:
        print(f"  recovery failed {atk} s{seed}: {e}", file=sys.stderr)
    return row

rows = []
for atk in ["none", "A1", "A2", "A3"]:
    for seed in range(1, 6):
        p = f"{R}/{atk}-seed{seed}-run1"
        if os.path.exists(f"{p}-summary.csv"):
            rows.append(run_row(p, atk, seed))

df = pd.DataFrame(rows)
df.to_csv(f"{R}/tables/per_run.csv", index=False)
print(f"\nper-run rows: {len(df)}")
print(df.head(3).to_string())

metrics = [c for c in df.columns if c not in ("attack", "seed")]
out = []
for atk, g in df.groupby("attack"):
    a = aggregate(g.to_dict("records"), metrics)
    a.insert(0, "attack", atk)
    out.append(a)
agg = pd.concat(out, ignore_index=True)
agg.to_csv(f"{R}/tables/aggregated.csv", index=False)
print("\n=== aggregated ===")
print(agg.to_string())
