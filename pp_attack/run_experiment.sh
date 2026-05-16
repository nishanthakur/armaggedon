#!/bin/bash
cd /opt/armageddon/pp_attack

echo "════════════════════════════════════"
echo "  PHASE 1: BASELINE (no victim)"
echo "════════════════════════════════════"
pkill rsa_victim 2>/dev/null
sleep 1
taskset -c 0 ./prime_probe > baseline.csv 2>&1
echo "Baseline done. $(grep -c '^[0-9]' baseline.csv) rounds captured."

echo ""
echo "════════════════════════════════════"
echo "  PHASE 2: UNDER ATTACK"
echo "════════════════════════════════════"
taskset -c 1 ./rsa_victim > /tmp/victim.log 2>&1 &
VPID=$!
echo "Victim PID: $VPID"
sleep 2  # let victim warm up

taskset -c 0 ./prime_probe > attack.csv 2>&1
echo "Attack run done."
kill $VPID 2>/dev/null

echo ""
echo "════════════════════════════════════"
echo "  RESULTS COMPARISON"
echo "════════════════════════════════════"

echo ""
echo "--- BASELINE ---"
grep '^[0-9]' baseline.csv | awk -F',' '
    {e+=$2; m+=$3; r+=$4; c+=$6; n++}
    END {
        printf "Avg evicted sets : %.1f / %d\n", e/n, 32
        printf "Avg HPC misses   : %.1f\n", m/n
        printf "Avg HPC refs     : %.1f\n", r/n
        printf "Avg cycles       : %.1f\n", c/n
    }'

grep '^[0-9]' baseline.csv | awk -F',' '{print $9}' | \
    sort | uniq -c | sort -rn | \
    awk '{printf "  %-20s %d rounds\n", $2, $1}'

echo ""
echo "--- UNDER ATTACK ---"
grep '^[0-9]' attack.csv | awk -F',' '
    {e+=$2; m+=$3; r+=$4; c+=$6; n++}
    END {
        printf "Avg evicted sets : %.1f / %d\n", e/n, 32
        printf "Avg HPC misses   : %.1f\n", m/n
        printf "Avg HPC refs     : %.1f\n", r/n
        printf "Avg cycles       : %.1f\n", c/n
    }'

grep '^[0-9]' attack.csv | awk -F',' '{print $9}' | \
    sort | uniq -c | sort -rn | \
    awk '{printf "  %-20s %d rounds\n", $2, $1}'

echo ""
echo "════════════════════════════════════"
echo "  Done. Files: baseline.csv attack.csv"
echo "════════════════════════════════════"
