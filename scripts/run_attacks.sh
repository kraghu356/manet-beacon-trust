#!/usr/bin/env bash
# Steps 6-7 — single malicious beacon, one scenario at a time.
set -euo pipefail
NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/results"
mkdir -p "$OUT"
cd "$NS3_DIR"
for atk in A1 A2 A3; do
  for seed in 1 2 3 4 5; do
    ./ns3 run "mbtr-sim --attack=$atk --seed=$seed --run=1 --outDir=$OUT"
  done
done
echo "Attack runs written to $OUT"
