#!/bin/bash
cd /opt/armageddon/pp_attack

echo "════════════════════════════════════"
echo " PHASE 1: BASELINE (no victim)"
echo "════════════════════════════════════"
pkill rsa_victim 2>/dev/null
sleep 1
taskset -c 0 ./prime_probe > pp_baseline.csv 2>&1
echo "Baseline done."

echo ""
echo "════════════════════════════════════"
echo " PHASE 2: UNDER ATTACK"
echo "════════════════════════════════════"
taskset -c 1 ./rsa_victim > /tmp/victim.log 2>&1 &
VPID=$!
echo "Victim PID: $VPID"
sleep 2

taskset -c 0 ./prime_probe > pp_attack.csv 2>&1
kill $VPID 2>/dev/null
echo "Attack done."

echo ""
echo "════════════════════════════════════"
echo " COMPARISON"
echo "════════════════════════════════════"

for f in pp_baseline.csv pp_attack.csv; do
    echo ""
    echo "--- $f ---"
    grep '^[0-9]' $f | awk -F',' '
        {e+=$2; m+=$6; r+=$7; c+=$9; n++}
        END {
            printf "Avg evicted sets  : %.2f / 64 (%.1f%%)\n",
                   e/n, e/n/64*100
            printf "Avg HPC misses    : %.1f\n", m/n
            printf "Avg HPC refs      : %.1f\n", r/n
            printf "Avg cycles core1  : %.1f\n", c/n
        }'
    echo "Status distribution:"
    grep '^[0-9]' $f | awk -F',' '{print $11}' | \
        sort | uniq -c | sort -rn | \
        awk '{printf "  %-20s %d rounds\n", $2, $1}'
done
