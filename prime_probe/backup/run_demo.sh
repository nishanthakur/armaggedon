#!/usr/bin/env bash
# run_demo.sh – Automated demo launcher for Prime+Probe attack
#
# What this script does:
#   1. Pins victim and attacker to the same CPU core (core 1).
#      Same-core placement guarantees they share the L1 and L2 caches,
#      making the timing signal much stronger.
#   2. Optionally accepts a SECRET value (0-15) as argument.
#   3. Starts the victim in the background, waits for it to initialise,
#      then launches the attacker in the foreground.
#   4. Kills the victim when the attacker finishes.
#
# Usage:
#   chmod +x run_demo.sh
#   ./run_demo.sh [secret_value]       # e.g.  ./run_demo.sh 11
#   ./run_demo.sh                      # uses default secret = 7

set -euo pipefail

SECRET=${1:-7}

# Validate secret range
if [[ $SECRET -lt 0 || $SECRET -gt 15 ]]; then
    echo "Error: secret must be between 0 and 15"
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo "  Prime+Probe Demo  –  Pi 3B (Cortex-A53)"
echo "  SECRET = $SECRET"
echo "════════════════════════════════════════════════════════"
echo ""

# Clean up any leftover shared memory from previous run
rm -f /dev/shm/pp_demo_shm
echo "[run] Cleaned up old shared memory."

# Ensure binaries exist
if [[ ! -f ./victim || ! -f ./attacker ]]; then
    echo "[run] Binaries not found. Running 'make' first …"
    make
fi

# ── Disable CPU frequency scaling for stable cycle counts ──────────────
# Cycle counter values are less noisy at a fixed frequency.
echo "[run] Fixing CPU frequency to 1.2 GHz for stable timing …"
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | tee "$cpu" >/dev/null 2>&1 || true
done

# ── Pin both processes to CPU core 1 ───────────────────────────────────
# taskset -c 1 ensures both processes run on core 1.
# They share core 1's L1-D (32 KB) and the shared L2 (512 KB).
CPU_CORE=1
echo "[run] Pinning both processes to CPU core $CPU_CORE."
echo ""

# ── Start victim in background ──────────────────────────────────────────
echo "[run] Launching victim (secret=$SECRET) in background …"
taskset -c $CPU_CORE ./victim $SECRET &
VICTIM_PID=$!
echo "[run] Victim PID = $VICTIM_PID"

# Wait for victim to initialise shared memory (~0.3 s should be plenty)
sleep 0.5

# ── Start attacker in foreground ────────────────────────────────────────
echo "[run] Launching attacker …"
echo ""
taskset -c $CPU_CORE ./attacker

ATTACK_EXIT=$?

# ── Kill victim ──────────────────────────────────────────────────────────
echo ""
echo "[run] Killing victim (PID=$VICTIM_PID) …"
kill $VICTIM_PID 2>/dev/null || true
wait $VICTIM_PID 2>/dev/null || true

echo "[run] Demo complete. Exit code from attacker: $ATTACK_EXIT"
exit $ATTACK_EXIT
