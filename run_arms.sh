#!/bin/bash
cd ~/manet-beacon-trust
for atk in A1 A2 A3; do
  for s in 1 2 3 4 5; do
    python3 -m analysis.run_verify verify \
      --beacon-rx results/$atk-seed$s-run1-beacon_rx.csv \
      --behaviour results/$atk-seed$s-run1-behaviour.csv \
      --calibration results/calibration.json --mode fused --attack-start 30 \
      --out results/arms/$atk-seed$s-verdicts.csv || continue
    python3 -m analysis.make_schedules \
      --verdicts results/arms/$atk-seed$s-verdicts.csv \
      --outdir results/arms/sched-$atk-seed$s || continue
    for arm in C D E; do
      ( cd ~/ns-3-dev && ./ns3 run "mbtr-sim --attack=$atk --nFlows=10 --pktRate=12 \
        --simTime=400 --seed=$s --isolation=$HOME/manet-beacon-trust/results/arms/sched-$atk-seed$s/$arm.csv \
        --outDir=$HOME/manet-beacon-trust/results/arms/$atk-seed$s-arm$arm" ) \
        >> ~/manet-beacon-trust/results/arms/run.log 2>&1
      echo "done $atk seed$s arm$arm"
    done
  done
done
