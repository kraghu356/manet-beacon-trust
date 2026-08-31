#!/bin/bash
O=$HOME/manet-beacon-trust/results/sweep; mkdir -p $O
for f in 0.10 0.15 0.20 0.30 0.40 0.50 0.70 1.00; do
  off=$(python3 -c "print(300*$f)"); dp=$(python3 -c "print(0.6*$f)")
  for s in 1 2 3 4 5 6 7 8 9 10; do
    d=$O/f$f-seed$s
    [ -f "$d/A3-seed$s-run1-beacon_rx.csv" ] && continue
    mkdir -p $d
    (cd $HOME/ns-3-dev && ./ns3 run "mbtr-sim --attack=A3 --offset=$off --dropProb=$dp --nFlows=10 --pktRate=12 --simTime=400 --seed=$s --outDir=$d") >> $O/sweep.log 2>&1
    echo "[$(date +%H:%M)] f=$f seed=$s" >> $O/progress.log
  done
done
echo DONE >> $O/progress.log
