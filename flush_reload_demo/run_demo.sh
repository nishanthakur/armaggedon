#!/usr/bin/env bash
# run_demo.sh — Flush+Reload Demo (Raspberry Pi 3B, ARMv8)
#
# Pinning:
#   victim   → core 0
#   attacker → core 1
#
# Both cores share the same 512 KB unified L2 on the Cortex-A53, so:
#   - victim warms the spy line into L2 on core 0
#   - attacker flushes / reloads from core 1
#   - The flush (dc civac) is coherent across cores — it removes the line
#     from the shared L2, not just core 1's private view
#
# Usage:
#   ./run_demo.sh          # run with default settings

set -euo pipefail

VICTIM_CORE=0
ATTACKER_CORE=1
SPY_FILE=/tmp/fr_demo_spy

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Flush+Reload Demo  —  Raspberry Pi 3B / ARMv8             ║"
echo "║   Victim  = core $VICTIM_CORE  |  Attacker = core $ATTACKER_CORE              ║"
echo "║   Spy file: $SPY_FILE                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Clean up stale spy file
rm -f "$SPY_FILE"
echo "[run] Removed stale spy file (if any)."

# Build if needed
if [[ ! -f ./victim || ! -f ./attacker ]]; then
    echo "[run] Binaries not found — building …"
    make
fi

# Set performance governor for consistent timing
echo "[run] Setting CPU governor to 'performance' …"
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee "$gov" >/dev/null 2>&1 || true
done

# Launch victim on core 0
echo "[run] Launching victim on core $VICTIM_CORE …"
taskset -c $VICTIM_CORE ./victim &
VICTIM_PID=$!
echo "[run] Victim PID = $VICTIM_PID"
echo ""

# Wait for victim to write the spy file and warm up
sleep 1.0
echo "[run] Launching attacker on core $ATTACKER_CORE …"
echo "[run] Attacker will flush the spy line and observe victim accesses."
echo ""

taskset -c $ATTACKER_CORE ./attacker
ATTACK_EXIT=$?

echo ""
echo "[run] Attacker exited (code=$ATTACK_EXIT)."
echo "[run] Stopping victim (PID=$VICTIM_PID) …"
kill -TERM "$VICTIM_PID" 2>/dev/null || true
wait "$VICTIM_PID" 2>/dev/null || true
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
if [[ $ATTACK_EXIT -eq 0 ]]; then
echo "║  Demo complete — session token extracted via cache timing.  ║"
else
echo "║  Demo complete — attacker exited with code $ATTACK_EXIT.            ║"
fi
echo "╚══════════════════════════════════════════════════════════════╝"
exit $ATTACK_EXIT
