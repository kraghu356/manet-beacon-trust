#!/usr/bin/env bash
# Step 5 — clean baseline. No malicious nodes. Establishes the reference row
# every later result is measured against.
set -euo pipefail
NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/results"
mkdir -p "$OUT"
cd "$NS3_DIR"
for seed in 1 2 3 4 5; do
  ./ns3 run "mbtr-sim --attack=none --seed=$seed --run=1 --outDir=$OUT"
done
echo "Baseline written to $OUT"
