#!/usr/bin/env bash
# Phase 3 (Q1 upgrade): scale, sparse topology, multiple attackers, closed loop.
# Run one stage at a time; every stage is resumable (.done markers).
#
#   STAGE=sparse     ./scripts/phase3.sh  # 25 nodes, 1000x1000 m: 4 scen x 10 seeds + 5 calib = 45 runs
#   STAGE=scale50    ./scripts/phase3.sh  # 50 nodes, 707 m, 6 beacons, 2 attackers: 45 runs
#   STAGE=scale100   ./scripts/phase3.sh  # 100 nodes, 1000 m, 12 beacons, 4 attackers: 4x5 + 3 = 23 runs
#   STAGE=closedloop ./scripts/phase3.sh  # E and Ea iterated 3 rounds, A2 + clean, seeds 1-10: 120 runs
#   STAGE=eval       ./scripts/phase3.sh  # no ns-3: score everything above
#
# Density is held at the base topology's 25 nodes per 500x500 m in the scaled
# runs; beacons and attackers scale with the node count, flows with sqrt.
set -uo pipefail

NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R="$REPO/results"
JOBS="${JOBS:-$(( $(nproc) > 2 ? $(nproc) - 1 : 1 ))}"
STAGE="${STAGE:?set STAGE=sparse|scale50|scale100|closedloop|eval}"
cd "$REPO"

sim() {  # sim <outdir> <args...>
  local out="$1"; shift
  mkdir -p "$out"
  [ -f "$out/.done" ] && return 0
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  (
    rm -f "$out"/*.csv
    if (cd "$NS3_DIR" && ./ns3 run --no-build "mbtr-sim $* --outDir=$out") >> "$out/sim.log" 2>&1; then
      touch "$out/.done"; echo "[$(date +%H:%M)] $out" >> "$R/phase3-progress.log"
    else
      echo "FAILED: $out $*" | tee -a "$R/phase3.log"
    fi
  ) &
}

campaign() {  # campaign <dir> <seeds> <calib seeds> <args...>
  local d="$1" seeds="$2" cal="$3"; shift 3
  for s in $cal; do sim "$d/calib/none-seed$s" --attack=none --seed=$s "$@"; done
  for atk in none A1 A2 A3; do
    for s in $seeds; do sim "$d/runs/$atk-seed$s" --attack=$atk --seed=$s "$@"; done
  done
  wait
}

case "$STAGE" in
  sparse)
    campaign "$R/sparse" "$(seq 1 10)" "101 102 103 104 105" \
      --nFlows=10 --pktRate=12 --simTime=400 --areaX=1000 --areaY=1000 ;;
  scale50)
    campaign "$R/scale50" "$(seq 1 10)" "101 102 103 104 105" \
      --nNodes=50 --nBeacons=6 --attacker=4 --nAttackers=2 --areaX=707 --areaY=707 \
      --nFlows=14 --pktRate=12 --simTime=400 ;;
  scale100)
    campaign "$R/scale100" "$(seq 1 5)" "101 102 103" \
      --nNodes=100 --nBeacons=12 --attacker=8 --nAttackers=4 --areaX=1000 --areaY=1000 \
      --nFlows=20 --pktRate=12 --simTime=400 ;;
  closedloop)
    CAL="$R/tables/seeds30/calibration.json"
    for atk in A2 none; do
      for arm in E Ea; do
        for s in $(seq 1 10); do
          prev="$R/tables/seeds30/sched/sched-$atk-seed$s/$arm.csv"
          if [ ! -f "$prev" ]; then
            python3 -m analysis.make_schedules --verdicts "$R/tables/seeds30/verdicts/$atk-seed$s-verdicts.csv" \
              --outdir "$R/tables/seeds30/sched/sched-$atk-seed$s" > /dev/null
          fi
          ( for k in 0 1 2; do
              d="$R/closed_loop/$atk-seed$s-$arm-r$k"; mkdir -p "$d"
              [ -f "$d/schedule.csv" ] || cp "$prev" "$d/schedule.csv"
              if [ ! -f "$d/.done" ]; then
                (cd "$NS3_DIR" && ./ns3 run --no-build "mbtr-sim --nFlows=10 --pktRate=12 --simTime=400 \
                   --attack=$atk --seed=$s --isolation=$d/schedule.csv --outDir=$d") >> "$d/sim.log" 2>&1 \
                   && touch "$d/.done" && echo "[$(date +%H:%M)] $d" >> "$R/phase3-progress.log" \
                   || { echo "FAILED: $d" | tee -a "$R/phase3.log"; break; }
              fi
              nxt="$R/closed_loop/$atk-seed$s-$arm-r$((k+1))"; mkdir -p "$nxt"
              python3 -m analysis.closed_loop next --run "$d" --calibration "$CAL" --arm "$arm" \
                --out "$nxt/schedule.csv"
              prev="$nxt/schedule.csv"
            done ) &
          while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
        done
      done
    done
    wait ;;
  eval)
    for d in sparse scale50 scale100; do
      [ -d "$R/$d/runs" ] || continue
      python3 -m analysis.campaign_eval --runs "$R/$d/runs" \
        --calib-glob "$R/$d/calib/*/none-seed*-run1-beacon_rx.csv" --out "$R/tables/$d"
      python3 -m analysis.baselines --runs "$R/$d/runs" \
        --calib "$R/$d/calib/*/none-seed*-run1-beacon_rx.csv" --out "$R/tables/$d/baselines"
      python3 -m analysis.release_check --campaign "$R/tables/$d" --out "$R/tables/$d/release"
    done
    [ -d "$R/closed_loop" ] && python3 -m analysis.closed_loop summary --root "$R/closed_loop" \
      --out "$R/tables/closed_loop.csv" ;;
  *) echo "unknown STAGE=$STAGE"; exit 1 ;;
esac
echo "stage $STAGE finished"
