#!/usr/bin/env bash
# run_demo.sh – Prime+Probe Demo v9
#
# BUG 2 FIX: victim and attacker are now pinned to DIFFERENT cores.
#
#   OLD (broken):  both on core 1  →  shared time-slice, prime() evicts
#                  victim's lines before probe() can observe them.
#
#   NEW (fixed):   victim  → core 0
#                  attacker → core 1
#
#   On Raspberry Pi 3B (Cortex-A53) cores 0-3 all share the same 512 KB
#   unified L2 cache, so the attack channel is preserved: victim warms its
#   slot into the shared L2 on core 0, then attacker on core 1 can observe
#   the timing difference during probe.
#
# Usage:
#   ./run_demo.sh          # victim picks slot randomly (0–255)
#   ./run_demo.sh 200      # victim uses slot 200

set -euo pipefail

SLOT=${1:-""}
VICTIM_CORE=0          # FIX (Bug 2): was CPU_CORE=1 for both
ATTACKER_CORE=1        # FIX (Bug 2): was CPU_CORE=1 for both

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Prime+Probe Demo v9  —  256-slot edition                  ║"
echo "║   Attacker searches all 256 slots blindly                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
if [[ -z "$SLOT" ]]; then
printf  "║   Slot      = random 0–255 (attacker must discover it)      ║\n"
else
printf  "║   Slot      = %-47s║\n" "$SLOT"
fi
printf  "║   Victim    = core %-42s║\n" "$VICTIM_CORE"
printf  "║   Attacker  = core %-42s║\n" "$ATTACKER_CORE"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── clean up any stale shared memory ────────────────────────────────────
rm -f /dev/shm/pp_demo_shm
echo "[run] Cleaned up stale shared memory."

# ── build if needed ──────────────────────────────────────────────────────
if [[ ! -f ./victim || ! -f ./attacker ]]; then
    echo "[run] Binaries not found — building …"
    make
fi

# ── set CPU governor to performance on all cores ─────────────────────────
echo "[run] Setting CPU governor to 'performance' …"
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | tee "$gov" >/dev/null 2>&1 || true
done

# ── launch victim on core 0 ──────────────────────────────────────────────
if [[ -z "$SLOT" ]]; then
    echo "[run] Launching victim (random slot) on core $VICTIM_CORE …"
    taskset -c $VICTIM_CORE ./victim &
else
    echo "[run] Launching victim (slot=$SLOT) on core $VICTIM_CORE …"
    taskset -c $VICTIM_CORE ./victim "$SLOT" &
fi
VICTIM_PID=$!
echo "[run] Victim PID = $VICTIM_PID  (running continuously)"
echo ""

# ── wait for victim to initialise (writes 1 MB of junk + token) ──────────
# Slightly longer than v8 to give the junk-fill time to complete and ensure
# the victim is well into its refresh loop before the attacker starts.
sleep 1.5

# ── launch attacker on core 1 ────────────────────────────────────────────
echo "[run] Launching attacker on core $ATTACKER_CORE …"
echo "[run] Attacker has NO knowledge of which slot holds the token."
echo "[run] It will stop automatically once the slot is discovered."
echo ""
taskset -c $ATTACKER_CORE ./attacker
ATTACK_EXIT=$?

echo ""
echo "[run] Attacker exited (code=$ATTACK_EXIT)."
echo "[run] Sending SIGTERM to victim (PID=$VICTIM_PID) …"
kill -TERM $VICTIM_PID 2>/dev/null || true
wait $VICTIM_PID 2>/dev/null || true
echo "[run] Victim stopped."
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
if [[ $ATTACK_EXIT -eq 0 ]]; then
echo "║  Demo complete — session token successfully extracted.      ║"
else
echo "║  Demo complete — attacker exited with code $ATTACK_EXIT.            ║"
fi
echo "╚══════════════════════════════════════════════════════════════╝"
exit $ATTACK_EXIT
