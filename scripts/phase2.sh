#!/usr/bin/env bash
# Phase 2 runs requested by the review (Nov 2026). Run one stage at a time:
#
#   STAGE=phi     ./scripts/phase2.sh   # NO ns-3: D-variant schedules + Phi on existing runs
#   STAGE=low     ./scripts/phase2.sh   # sweep below 15 m / 3% drop (30 runs)
#   STAGE=pair2   ./scripts/phase2.sh   # second delta-p pairing, p = 0.3 f (80 runs)
#   STAGE=seeds   ./scripts/phase2.sh   # seeds 6-30, none/A1/A2/A3, sigma = 0 (100 runs + 5 calib)
#   STAGE=shadow  ./scripts/phase2.sh   # sigma = 4 and 8 dB, seeds 1-20 (2 x 85 runs)
#   STAGE=eval    ./scripts/phase2.sh   # score everything above
#
# Every stage skips runs whose outputs already exist, so it can be stopped and resumed.
# Calibration always uses separate clean seeds (101-105), never the test seeds.
set -uo pipefail

NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R="$REPO/results"
BASE="--nFlows=10 --pktRate=12 --simTime=400"
STAGE="${STAGE:?set STAGE=phi|low|pair2|seeds|shadow|all|eval}"
# Parallel runs: ns-3 is single-threaded, so run one simulation per spare core.
JOBS="${JOBS:-$(( $(nproc) > 2 ? $(nproc) - 1 : 1 ))}"
cd "$REPO"

# A run counts as finished only when .done exists: an interrupted run leaves
# partial CSVs behind, and those must be re-run, not skipped.
sim() {  # sim <outdir> <args...>
  local out="$1"; shift
  mkdir -p "$out"
  [ -f "$out/.done" ] && return 0
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  (
    rm -f "$out"/*.csv
    if (cd "$NS3_DIR" && ./ns3 run --no-build "mbtr-sim $BASE $* --outDir=$out") \
         >> "$out/sim.log" 2>&1; then
      touch "$out/.done"
      echo "[$(date +%H:%M)] $out" >> "$R/phase2-progress.log"
    else
      echo "FAILED: $out $*" | tee -a "$R/phase2.log"
    fi
  ) &
}

campaign() {  # campaign <dir> <shadowing dB> <first seed> <last seed>
  local d="$1" sh="$2" s0="$3" s1="$4"
  for s in 101 102 103 104 105; do sim "$d/calib/none-seed$s" --attack=none --seed=$s --shadowing=$sh; done
  for atk in none A1 A2 A3; do
    for s in $(seq "$s0" "$s1"); do sim "$d/runs/$atk-seed$s" --attack=$atk --seed=$s --shadowing=$sh; done
  done
}

case "$STAGE" in
  phi)
    # Existing 5-seed campaign: verdicts already in results/arms; clean runs in results/.
    for s in 1 2 3 4 5; do
      [ -f "$R/arms/none-seed$s-verdicts.csv" ] || python3 -m analysis.run_verify verify \
        --beacon-rx "$R/none-seed$s-run1-beacon_rx.csv" --behaviour "$R/none-seed$s-run1-behaviour.csv" \
        --calibration "$R/calibration.json" --mode fused --attack-start 30 \
        --out "$R/arms/none-seed$s-verdicts.csv"
    done
    for f in "$R"/arms/*-seed*-verdicts.csv; do
      b=$(basename "$f" -verdicts.csv)
      python3 -m analysis.make_schedules --verdicts "$f" --outdir "$R/arms/sched-$b" >/dev/null
    done
    mkdir -p "$R/tables"
    python3 -m analysis.phi --runs "$R/arms/*-seed*-verdicts-summary.csv" \
      --sched-root "$R/arms" --sim-time 400 --out "$R/tables/phi_5seed.csv"
    ;;
  low)
    for f in 0.025 0.05 0.075; do
      off=$(python3 -c "print(300*$f)"); dp=$(python3 -c "print(0.6*$f)")
      for s in $(seq 1 10); do sim "$R/sweep/f$f-seed$s" --attack=A3 --offset=$off --dropProb=$dp --seed=$s; done
    done ;;
  pair2)
    for f in 0.10 0.15 0.20 0.30 0.40 0.50 0.70 1.00; do
      off=$(python3 -c "print(300*$f)"); dp=$(python3 -c "print(0.3*$f)")
      for s in $(seq 1 10); do sim "$R/sweep_pair2/f$f-seed$s" --attack=A3 --offset=$off --dropProb=$dp --seed=$s; done
    done ;;
  seeds)   campaign "$R/seeds30" 0 1 30 ;;
  shadow)  campaign "$R/shadow4" 4 1 20; campaign "$R/shadow8" 8 1 20 ;;
  all)
    # Every ns-3 stage, interleaved across $JOBS cores; then score.
    for st in low pair2 seeds shadow; do STAGE=$st JOBS=$JOBS "$0"; done
    STAGE=eval "$0"
    ;;
  eval)
    mkdir -p "$R/tables"
    [ -d "$R/sweep" ] && python3 -m analysis.sweep_eval --root "$R/sweep" \
      --calibration "$R/calibration.json" --out "$R/tables/sweep.csv"
    [ -d "$R/sweep_pair2" ] && python3 -m analysis.sweep_eval --root "$R/sweep_pair2" \
      --calibration "$R/calibration.json" --out "$R/tables/sweep_pair2.csv"
    for c in seeds30 shadow4 shadow8; do
      [ -d "$R/$c/runs" ] && python3 -m analysis.campaign_eval --runs "$R/$c/runs" \
        --calib-glob "$R/$c/calib/*/none-seed10*-run1-beacon_rx.csv" --out "$R/tables/$c"
    done
    python3 -m analysis.fusion_region ;;
  *) echo "unknown STAGE=$STAGE"; exit 2 ;;
esac

wait
