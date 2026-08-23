#!/usr/bin/env bash
# Clone, configure and build NS-3, then link this project's simulator into scratch/.
# No NS-3 source file is modified.
set -euo pipefail

NS3_DIR="${NS3_DIR:-$HOME/ns-3-dev}"
NS3_BRANCH="${NS3_BRANCH:-ns-3.42}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -d "$NS3_DIR" ]; then
  echo "==> Cloning NS-3 ($NS3_BRANCH) into $NS3_DIR"
  git clone --depth 1 --branch "$NS3_BRANCH" \
    https://github.com/nsnam/ns-3-dev-git.git "$NS3_DIR"
else
  echo "==> Reusing existing NS-3 at $NS3_DIR"
fi

cd "$NS3_DIR"

echo "==> Configuring (optimized build, examples off, tests off)"
./ns3 configure --build-profile=optimized --disable-examples --disable-tests

echo "==> Linking simulator into scratch/"
# A scratch SUBDIRECTORY is built as one program from all sources inside it,
# which is how mbtr-sim.cc and mbtr-isolation.h stay together. A bare
# scratch/*.cc file would not find the header.
mkdir -p scratch/mbtr-sim
ln -sf "$REPO_DIR/ns3/mbtr-sim.cc" scratch/mbtr-sim/mbtr-sim.cc
ln -sf "$REPO_DIR/ns3/mbtr-isolation.h" scratch/mbtr-sim/mbtr-isolation.h

echo "==> Building (this takes a while on first run)"
./ns3 build

cat <<EOF

Done.

  NS-3:      $NS3_DIR
  Simulator: scratch/mbtr-sim/ -> $REPO_DIR/ns3/

Smoke test:
  cd "$NS3_DIR" && ./ns3 run "mbtr-sim --help"
EOF
