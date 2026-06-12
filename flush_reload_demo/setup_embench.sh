#!/usr/bin/env bash
# setup_embench.sh
#
# Clones and builds the embench-iot benchmark suite as NATIVE binaries
# (no GDB/Verilator target needed) so each benchmark can be run as a normal
# Linux process — used as "background noise" generators in the HPC
# experiment.
#
# This uses the current embench-iot build system (scons + the
# examples/native/speed config), not the old build_all.py.
#
# Usage:
#   ./setup_embench.sh [install_dir]
#
# Default install_dir = ./embench-iot
#
# After running, native benchmark executables are at:
#   <install_dir>/bd-native/src/<benchmark_name>/<benchmark_name>
#
# Pass "<install_dir>/bd-native" as --benchdir to run_experiment.sh.

set -euo pipefail

INSTALL_DIR="${1:-$(pwd)/embench-iot}"

echo "[setup] Installing embench-iot into: $INSTALL_DIR"

if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    rm -rf "$INSTALL_DIR"
    git clone https://github.com/embench/embench-iot.git "$INSTALL_DIR"
else
    echo "[setup] Repo already present, skipping clone."
fi

cd "$INSTALL_DIR"

# ── dependencies ──────────────────────────────────────────────────────────
echo "[setup] Checking/installing scons + pyelftools..."
python3 -c "import scons" 2>/dev/null || pip3 install scons --break-system-packages -q
python3 -c "import elftools" 2>/dev/null || pip3 install pyelftools --break-system-packages -q

# ── build ────────────────────────────────────────────────────────────────
echo "[setup] Building benchmarks (native, -O2)..."
scons \
    --config-dir=examples/native/speed/ \
    --build-dir=bd-native \
    cflags="-O2 -fdata-sections -ffunction-sections" \
    ldflags="-O2 -Wl,-gc-sections" \
    user_libs=-lm

echo "[setup] Build complete."
echo "[setup] Native benchmark binaries are under: $INSTALL_DIR/bd-native/src/*/"
echo ""
echo "[setup] Listing discovered benchmark executables:"
find "$INSTALL_DIR/bd-native/src" -maxdepth 2 -type f -executable -not -name "*.o"

echo ""
echo "[setup] Use this as --benchdir for run_experiment.sh:"
echo "[setup]   --benchdir $INSTALL_DIR/bd-native"
