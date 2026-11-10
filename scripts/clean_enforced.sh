#!/usr/bin/env bash
# Closed-loop check of the offline Phi replay on CLEAN networks (review round 2).
#
# For seeds 1-10 and policies D1 and E, the clean-network isolation schedule that
# the offline replay produced (results/tables/seeds30/sched/sched-none-seed<N>) is
# enforced in the simulator. analysis.feedback_check then re-verifies the enforced
# traces, rebuilds the schedule from the verdicts the network actually produced
# under isolation, and compares Phi from the two schedules.
#
#   ./scripts/clean_enforced.sh                 # 20 runs, resumable (.done markers)
#   JOBS=2 SEEDS="1 2 3 4 5" ./scripts/clean_enforced.sh
#
# Then:
#   python3 -m analysis.feedback_check --runs results/clean_enforced \
#       --offline results/tables/seeds30 --out results/tables/clean_enforced
set -uo pipefail

NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R="$REPO/results"
BASE="--nFlows=10 --pktRate=12 --simTime=400"
JOBS="${JOBS:-$(( $(nproc) > 2 ? $(nproc) - 1 : 1 ))}"
SEEDS="${SEEDS:-$(seq 1 10)}"
SCHED="$R/tables/seeds30/sched"

[ -d "$SCHED" ] || { echo "missing $SCHED (run STAGE=eval of phase2.sh first)"; exit 1; }

for s in $SEEDS; do
  for arm in D1 E; do
    sch="$SCHED/sched-none-seed$s/$arm.csv"
    out="$R/clean_enforced/$arm-seed$s"
    mkdir -p "$out"
    [ -f "$out/.done" ] && continue
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
    (
      rm -f "$out"/*.csv
      if (cd "$NS3_DIR" && ./ns3 run --no-build \
            "mbtr-sim $BASE --attack=none --seed=$s --isolation=$sch --outDir=$out") \
            >> "$out/sim.log" 2>&1; then
        touch "$out/.done"; echo "[$(date +%H:%M)] done $arm seed$s"
      else
        echo "FAILED: $arm seed$s (see $out/sim.log)"
      fi
    ) &
  done
done
wait
echo "finished: $(ls "$R"/clean_enforced/*/.done 2>/dev/null | wc -l) runs complete"
