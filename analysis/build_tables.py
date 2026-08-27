"""Consolidate per-run CSVs into tables with means and 95% CIs."""
import os, sys, glob, re
import pandas as pd
from analysis.metrics import (classification_metrics, recovery_metrics,
                              beacon_metrics, aggregate)

R = os.path.expanduser("~/manet-beacon-trust/results")
ATTACK_START, SIM_END = 30.0, 400.0

def first_isolation(atk, seed, arm):
    f = f"{R}/arms/sched-{atk}-seed{seed}/{arm}.csv"
    try:
        d = pd.read_csv(f)
        iso = d[d["action"].str.contains("isolate")]
        return float(iso["time_s"].min()) if len(iso) else None
    except Exception:
        return None

def run_row(prefix, atk, seed, iso_s=None):
    row = {"attack": atk, "seed": seed}
    try:
        s = pd.read_csv(f"{R}/arms/{atk}-seed{seed}-verdicts-summary.csv")
        cm = classification_metrics(s)
        row.update({k: getattr(cm, k) for k in vars(cm)})
    except Exception as e:
        print(f"  classification failed {atk} s{seed}: {e}", file=sys.stderr)
    try:
        rec = pd.read_csv(f"{prefix}-recovery.csv")
        rm = recovery_metrics(rec, ATTACK_START, iso_s, SIM_END, settle_s=20.0)
        row.update({k: getattr(rm, k) for k in vars(rm)})
    except Exception as e:
        print(f"  recovery failed {atk} s{seed}: {e}", file=sys.stderr)
    return row

rows = []
for atk in ["A1", "A2", "A3"]:
    for seed in range(1, 6):
        for arm in ["C", "D", "E"]:
            p = f"{R}/arms/{atk}-seed{seed}-arm{arm}/{atk}-seed{seed}-run1"
            if os.path.exists(f"{p}-summary.csv"):
                r = run_row(p, atk, seed, first_isolation(atk, seed, arm)); r["arm"] = arm; r["isolation_s"] = first_isolation(atk, seed, arm)
                rows.append(r)

df = pd.DataFrame(rows)
df.to_csv(f"{R}/tables/per_run.csv", index=False)
print(f"\nper-run rows: {len(df)}")
print(df.head(3).to_string())

metrics = [c for c in df.columns if c not in ("attack", "seed", "arm")]
out = []
for (atk, arm), g in df.groupby(["attack","arm"]):
    a = aggregate(g.to_dict("records"), metrics)
    a.insert(0, "attack", atk); a.insert(1, "arm", arm)
    out.append(a)
agg = pd.concat(out, ignore_index=True)
agg.to_csv(f"{R}/tables/aggregated.csv", index=False)
print("\n=== aggregated ===")
print(agg.to_string())
