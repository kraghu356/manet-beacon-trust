#!/usr/bin/env python3
"""Regenerate every data figure of Paper 2 from the files in results/.

    python3 scripts/make_figures.py [--results results] [--out figures]

Each figure is built only if its inputs exist; the script reports what it made
and what it skipped, so it can be run on a partial checkout. Figure numbers
follow the revised manuscript. Fig. 1 (pipeline diagram) and Fig. 7 (single-run
accounting) are not data-driven at campaign level and are not produced here.

Inputs, all produced by the pipeline in this repository:
  Fig 2  coverage               results/tables/seeds30/coverage.csv
  Fig 3  throughput by scenario results/**/<ATK>-seed<N>-run1-summary.csv
  Fig 4  intensity sweeps       results/tables/sweep-agg.csv, sweep_pair2-agg.csv
  Fig 5  first isolation        results/tables/seeds30/sched/sched-*/<ARM>.csv
  Fig 6  recovery ratio         results/tables/per_run.csv
  Fig 8  cumulative false isol. results/tables/seeds30/phi_per_run.csv
  Fig 9  aggregation ablation   results/tables/agg_ablation_raw.csv
  Fig 10 shadowing              results/tables/{seeds30,shadow4,shadow8}/
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys

import numpy as np
import pandas as pd

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# One colour per evidence mode / policy, used consistently across figures.
C = {
    "behaviour": "#3b6fb6", "localization": "#d08a2e", "or": "#7a7a7a", "fused": "#2f8f5b",
    "D": "#b5403a", "Dw": "#d9817b", "D1": "#8e5aa8", "E": "#2f8f5b", "C": "#7a7a7a",
}
ATTACKS = ["none", "A1", "A2", "A3"]
LABEL = {"none": "Clean", "A1": "A1 false location", "A2": "A2 selective fwd.",
         "A3": "A3 hybrid"}
ARM_LABEL = {"C": "C (no isolation)", "D": "D (first suspicion)",
             "Dw": "D$_w$ (warm-up guard)", "D1": "D$_1$ (one malicious window)",
             "E": "E (confirmed, release)"}

plt.rcParams.update({
    "font.size": 9, "axes.titlesize": 9, "axes.labelsize": 9, "legend.fontsize": 8,
    "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 150,
    "savefig.bbox": "tight", "pdf.fonttype": 42,
})


def boot_ci(x, n=5000, seed=0):
    x = np.asarray(x, float)
    x = x[~np.isnan(x)]
    if x.size < 2:
        return (np.nan, np.nan)
    m = np.random.default_rng(seed).choice(x, (n, x.size)).mean(1)
    return np.percentile(m, [2.5, 97.5])


def save(fig, out, name):
    os.makedirs(out, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(out, f"{name}.{ext}"))
    plt.close(fig)
    return name


# --------------------------------------------------------------------- Fig 2
def fig_coverage(R, out):
    f = os.path.join(R, "tables/seeds30/coverage.csv")
    cov = pd.read_csv(f).set_index("attack")
    atk = [a for a in ["A1", "A2", "A3"] if a in cov.index]
    modes = ["behaviour", "localization", "fused"]
    fig, ax = plt.subplots(figsize=(4.6, 2.6))
    w = 0.26
    for i, m in enumerate(modes):
        v = [cov.loc[a, f"{m}_tp"] / cov.loc[a, "seeds"] for a in atk]
        b = ax.bar(np.arange(len(atk)) + (i - 1) * w, v, w, color=C[m],
                   label={"behaviour": "Behaviour only", "localization": "Localisation only",
                          "fused": "Both (fused)"}[m])
        for r, a in zip(b, atk):
            n = int(cov.loc[a, f"{m}_tp"])
            ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 0.02,
                    f"{n}/{int(cov.loc[a, 'seeds'])}", ha="center", va="bottom", fontsize=7)
    ax.set_xticks(range(len(atk)), [LABEL[a] for a in atk])
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("Attacker confirmed (fraction of seeds)")
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.16))
    return save(fig, out, "fig2_coverage")


# --------------------------------------------------------------------- Fig 3
def fig_throughput(R, out):
    pat = re.compile(r"(none|A1|A2|A3)-seed(\d+)-run1-summary\.csv$")
    rows = []
    for p in glob.glob(os.path.join(R, "**", "*-run1-summary.csv"), recursive=True):
        if "shadow" in p or "sweep" in p or "calib" in p:
            continue
        m = pat.search(os.path.basename(p))
        if m:
            d = pd.read_csv(p)
            rows.append({"attack": m[1], "seed": int(m[2]), "kbps": d["throughput_kbps"].iloc[0]})
    if not rows:
        raise FileNotFoundError("no *-run1-summary.csv")
    df = pd.DataFrame(rows).drop_duplicates(["attack", "seed"])
    fig, ax = plt.subplots(figsize=(3.6, 2.4))
    for i, a in enumerate(ATTACKS):
        x = df.loc[df.attack == a, "kbps"].to_numpy()
        if not x.size:
            continue
        lo, hi = boot_ci(x)
        ax.errorbar(i, x.mean(), yerr=[[x.mean() - lo], [hi - x.mean()]], fmt="o",
                    color="k", capsize=3, ms=4)
        ax.scatter(np.full(x.size, i) + np.random.default_rng(i).uniform(-.12, .12, x.size), x,
                   s=6, color="#999", zorder=0)
    ns = {a: int((df.attack == a).sum()) for a in ATTACKS}
    ax.set_xticks(range(len(ATTACKS)),
                  [f"{LABEL[a].split()[0]}\n(n={ns[a]})" for a in ATTACKS])
    ax.set_ylabel("Delivered throughput (kbit/s)")
    return save(fig, out, "fig3_throughput")


# --------------------------------------------------------------------- Fig 4
def fig_sweep(R, out):
    panels = []
    for name, drop, title in (("sweep", 0.3, "Primary"),
                              ("sweep_pair2", 0.15, "Second pairing")):
        p = os.path.join(R, f"tables/{name}-agg.csv")
        if os.path.exists(p):
            panels.append((pd.read_csv(p), drop, title))
    if not panels:
        raise FileNotFoundError("tables/sweep-agg.csv")
    from matplotlib.ticker import FixedLocator, NullLocator
    fig, axes = plt.subplots(1, len(panels), figsize=(3.4 * len(panels), 2.6), sharey=True,
                             sharex=True, squeeze=False)
    ticks = [5, 10, 20, 50, 100]
    for ax, (d, drop, title) in zip(axes[0], panels):
        d = d.assign(f=d["level"].str.lstrip("f").astype(float)).sort_values("f")
        x = 150 * d["f"]
        for col, lab, mk in (("behaviour_tp", "Behaviour only", "s"),
                             ("localization_tp", "Localisation only", "^"),
                             ("or_tp", "Disjunction (OR)", "o"),
                             ("fused_tp", "Fused (Stouffer)", "D")):
            key = col.split("_")[0]
            ax.plot(x, d[col] / d["seeds"], marker=mk, ms=3.5, lw=1.2, color=C[key],
                    label=lab, ls="--" if key == "or" else "-")
        ax.axhline(0.5, color="#bbb", lw=0.8, ls=":")
        ax.set_xscale("log")
        ax.xaxis.set_major_locator(FixedLocator(ticks))
        ax.xaxis.set_minor_locator(NullLocator())
        ax.set_xticklabels([str(t) for t in ticks])
        ax.set_xlim(3, 170)
        ax.set_xlabel("Attacker displacement (m, log scale)")
        ax.set_title(f"{title}\n(drop probability {drop / 150 * 100:.1f}% per metre)")
    axes[0][0].set_ylabel("Attacker confirmed (fraction of 10 seeds)")
    fig.subplots_adjust(wspace=0.12)
    h, l = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, ncol=4, loc="lower center", bbox_to_anchor=(0.5, -0.16))
    return save(fig, out, "fig4_sweep")


# --------------------------------------------------------------------- Fig 5
def fig_first_isolation(R, out):
    root = os.path.join(R, "tables/seeds30/sched")
    rows = []
    for d in glob.glob(os.path.join(root, "sched-*-seed*")):
        m = re.search(r"sched-(\w+)-seed(\d+)$", d)
        for arm in ("D", "Dw", "D1", "E"):
            p = os.path.join(d, f"{arm}.csv")
            if os.path.exists(p):
                s = pd.read_csv(p)
                s = s[s["action"] == "isolate"]
                rows.append({"attack": m[1], "seed": int(m[2]), "arm": arm,
                             "t": s["time_s"].min() if len(s) else np.nan})
    if not rows:
        raise FileNotFoundError(root)
    df = pd.DataFrame(rows)
    atk = [a for a in ["A1", "A2", "A3"] if a in set(df.attack)]
    arms = ["D", "Dw", "D1", "E"]
    fig, ax = plt.subplots(figsize=(4.6, 2.6))
    w = 0.2
    for i, arm in enumerate(arms):
        for j, a in enumerate(atk):
            x = df[(df.attack == a) & (df.arm == arm)]["t"].to_numpy()
            if np.isnan(x).all():
                continue
            mu = np.nanmean(x)
            lo, hi = boot_ci(x)
            ax.bar(j + (i - 1.5) * w, mu, w, color=C[arm],
                   label=ARM_LABEL[arm] if j == 0 else None)
            ax.errorbar(j + (i - 1.5) * w, mu, yerr=[[mu - lo], [hi - mu]], color="k",
                        capsize=2, lw=0.8)
    ax.axhline(30, color="k", lw=0.8, ls="--")
    ax.annotate("attack\nonset", xy=(1.0, 30), xycoords=("axes fraction", "data"),
                xytext=(3, 0), textcoords="offset points", va="center", fontsize=7)
    ax.set_xticks(range(len(atk)), [LABEL[a] for a in atk])
    ax.set_ylabel("First isolation of any beacon (s)")
    ax.legend(frameon=False, fontsize=7, ncol=2, loc="upper center",
              bbox_to_anchor=(0.5, 1.22))
    return save(fig, out, "fig5_first_isolation")


# --------------------------------------------------------------------- Fig 6
def fig_recovery(R, out):
    d = pd.read_csv(os.path.join(R, "tables/per_run.csv"))
    d = d[d["attack"] != "none"]
    atk = [a for a in ["A1", "A2", "A3"] if a in set(d.attack)]
    arms = [a for a in ["C", "D", "E"] if a in set(d.arm)]
    fig, ax = plt.subplots(figsize=(4.0, 2.4))
    w = 0.25
    for i, arm in enumerate(arms):
        for j, a in enumerate(atk):
            x = d[(d.attack == a) & (d.arm == arm)]["recovery_ratio"].to_numpy(float)
            if not x.size:
                continue
            lo, hi = boot_ci(x)
            ax.errorbar(j + (i - 1) * w, np.nanmean(x),
                        yerr=[[np.nanmean(x) - lo], [hi - np.nanmean(x)]], fmt="o",
                        color=C[arm], capsize=3, ms=4, label=ARM_LABEL[arm] if j == 0 else None)
    ax.axhline(1.0, color="#bbb", lw=0.8, ls=":")
    ax.set_xticks(range(len(atk)), [LABEL[a] for a in atk])
    ax.set_ylabel("Throughput recovery ratio $R_{TH}$")
    ax.legend(frameon=False, fontsize=7, ncol=3, loc="upper center",
              bbox_to_anchor=(0.5, 1.18))
    return save(fig, out, "fig6_recovery")


# --------------------------------------------------------------------- Fig 8
def fig_phi(R, out):
    d = pd.read_csv(os.path.join(R, "tables/seeds30/phi_per_run.csv"))
    arms = ["D", "Dw", "D1", "E"]
    fig, ax = plt.subplots(figsize=(4.8, 2.6))
    w = 0.2
    for i, arm in enumerate(arms):
        for j, a in enumerate(ATTACKS):
            x = d[(d.attack == a) & (d.arm == arm)]["phi_bar"].to_numpy() * 100
            if not x.size:
                continue
            lo, hi = boot_ci(x)
            ax.bar(j + (i - 1.5) * w, x.mean(), w, color=C[arm],
                   label=ARM_LABEL[arm] if j == 0 else None)
            ax.errorbar(j + (i - 1.5) * w, x.mean(), yerr=[[x.mean() - lo], [hi - x.mean()]],
                        color="k", capsize=2, lw=0.8)
            if arm == "E":
                ax.text(j + (i - 1.5) * w, hi + 2, f"{x.mean():.1f}", ha="center", fontsize=7)
    ax.set_xticks(range(len(ATTACKS)), [LABEL[a].split()[0] for a in ATTACKS])
    ax.set_ylabel(r"Honest-beacon service withdrawn, $\bar\Phi$ (%)")
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, fontsize=7, ncol=2, loc="upper center",
              bbox_to_anchor=(0.5, 1.2))
    return save(fig, out, "fig8_phi")


# --------------------------------------------------------------------- Fig 9
def fig_ablation(R, out):
    d = pd.read_csv(os.path.join(R, "tables/agg_ablation_raw.csv"))
    d["confirmed"] = d["confirmed"].astype(str).str.lower().eq("true")
    piv = d.groupby(["attack", "cfg"])["confirmed"].sum().unstack("cfg")
    piv = piv.reindex([a for a in ATTACKS if a in piv.index])
    cfgs = list(piv.columns)
    fig, ax = plt.subplots(figsize=(4.2, 2.4))
    w = 0.8 / len(cfgs)
    pal = ["#3b6fb6", "#d08a2e", "#2f8f5b", "#7a7a7a"]
    for i, c in enumerate(cfgs):
        ax.bar(np.arange(len(piv)) + (i - (len(cfgs) - 1) / 2) * w, piv[c], w,
               color=pal[i % 4], label=c.split("_", 1)[-1].replace("_", " + "))
    ax.set_xticks(range(len(piv)), [LABEL.get(a, a).split()[0] for a in piv.index])
    ax.set_ylabel("Confirmations (targets x seeds)")
    ax.legend(frameon=False, fontsize=7, ncol=len(cfgs), loc="upper center",
              bbox_to_anchor=(0.5, 1.16))
    return save(fig, out, "fig9_ablation")


# -------------------------------------------------------------------- Fig 10
def fig_shadow(R, out):
    rows = []
    for sigma, name in ((0, "seeds30"), (4, "shadow4"), (8, "shadow8")):
        cp = os.path.join(R, f"tables/{name}/coverage_per_run.csv")
        pp = os.path.join(R, f"tables/{name}/phi_per_run.csv")
        if not (os.path.exists(cp) and os.path.exists(pp)):
            continue
        rows.append((sigma, pd.read_csv(cp), pd.read_csv(pp)))
    if len(rows) < 2:
        raise FileNotFoundError("tables/shadow4 or shadow8")
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.8, 2.5))
    fig.subplots_adjust(wspace=0.35)
    sig = [r[0] for r in rows]
    for a, mk in zip(["A1", "A2", "A3"], "o^s"):
        mu, lo, hi = [], [], []
        for _, cov, _ in rows:
            x = cov.loc[cov.attack == a, "latency_s"].to_numpy(float)
            m = np.nanmean(x)
            l, h = boot_ci(x)
            mu.append(m), lo.append(m - l), hi.append(h - m)
        a1.errorbar(sig, mu, yerr=[lo, hi], marker=mk, capsize=3, ms=4, label=LABEL[a],
                    color={"A1": "#d08a2e", "A2": "#3b6fb6", "A3": "#555555"}[a])
    a1.set_xticks(sig)
    a1.set_xlabel(r"Shadowing $\sigma_{sh}$ (dB)")
    a1.set_ylabel("Detection latency (s)")
    a1.set_ylim(bottom=0)
    a1.legend(frameon=False, fontsize=7)
    for arm in ("D1", "E"):
        mu, lo, hi = [], [], []
        for _, _, phi in rows:
            x = phi.loc[(phi.attack == "none") & (phi.arm == arm), "phi_bar"].to_numpy() * 100
            m = x.mean()
            l, h = boot_ci(x)
            mu.append(m), lo.append(m - l), hi.append(h - m)
        a2.errorbar(sig, mu, yerr=[lo, hi], marker="o", capsize=3, ms=4, color=C[arm],
                    label=ARM_LABEL[arm])
    a2.set_xticks(sig)
    a2.set_ylim(0, 100)
    a2.set_xlabel(r"Shadowing $\sigma_{sh}$ (dB)")
    a2.set_ylabel(r"$\bar\Phi$, clean network (%)")
    a2.legend(frameon=False, fontsize=7)
    return save(fig, out, "fig10_shadowing")


FIGS = [fig_coverage, fig_throughput, fig_sweep, fig_first_isolation, fig_recovery,
        fig_phi, fig_ablation, fig_shadow]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="figures")
    a = ap.parse_args(argv)
    made, skipped = [], []
    for fn in FIGS:
        try:
            made.append(fn(a.results, a.out))
        except (FileNotFoundError, KeyError, ValueError) as e:
            skipped.append(f"{fn.__name__}: {type(e).__name__}: {e}")
    print("made   :", ", ".join(made) or "none")
    for s in skipped:
        print("skipped:", s)
    return 0 if made else 1


if __name__ == "__main__":
    sys.exit(main())
