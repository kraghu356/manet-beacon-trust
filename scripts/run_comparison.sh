#!/usr/bin/env bash
# Step 12 — the comparison matrix.
#
#   A  normal AODV, no attacker              baseline ceiling
#   B  AODV + malicious beacon, no defence   damage floor
#   C  detection only, no isolation          isolates nothing, shows detection is not enough
#   D  EMBN-style elimination                permanent removal, no recovery accounting
#   E  proposed: fused verification + isolation + recovery
#
# C, D and E differ only in the isolation schedule fed to the simulator, which is
# what makes them a fair comparison: identical topology, identical mobility,
# identical seeds, one variable.
set -euo pipefail
NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/results"
SEEDS="${SEEDS:-1 2 3 4 5}"
ATTACK="${ATTACK:-A3}"

mkdir -p "$OUT"
cd "$NS3_DIR"

for seed in $SEEDS; do
  # A — clean ceiling
  ./ns3 run "mbtr-sim --attack=none --seed=$seed --outDir=$OUT/A"

  # B — undefended
  ./ns3 run "mbtr-sim --attack=$ATTACK --seed=$seed --outDir=$OUT/B"

  # C/D/E need verdicts first, produced from B's evidence by the Python pipeline.
  # Generate the three schedules, then replay each.
  python3 -m analysis.make_schedules \
      --verdicts "$OUT/B/${ATTACK}-seed${seed}-run1-verdicts.csv" \
      --outdir "$OUT/schedules/seed${seed}"

  for arm in C D E; do
    ./ns3 run "mbtr-sim --attack=$ATTACK --seed=$seed --outDir=$OUT/$arm \
        --isolation=$OUT/schedules/seed${seed}/${arm}.csv"
  done
done
echo "Comparison runs written under $OUT"
