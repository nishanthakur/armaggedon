#!/usr/bin/env bash
# =============================================================================
# run_experiment.sh — Flush+Reload HPC Experimental Protocol
#
# Implements the professor's pseudocode exactly:
#   FOR EACH noise_level IN NOISE_LEVELS:
#     FOR rep FROM 1 TO REP_COUNT:
#       Launch noise_level background benchmarks
#       Use perf to log raw + filtered HPC while running the attack
#       Save log
#       Kill background processes
#
# Outputs:
#   results/
#     raw/        — one perf stat output file per (noise_level, rep)
#     csv/        — aggregated CSV per noise level + combined CSV
#     logs/       — run log
#
# Usage:
#   bash run_experiment.sh [OPTIONS]
#
# Options:
#   --target    PATH    Victim binary      (default: ./flush_reload_demo/victim)
#   --attacker  PATH    Attacker binary    (default: ./flush_reload_demo/attacker)
#   --benchdir  PATH    Embench build dir  (default: ./bd-rpi3b)
#   --reps      N       Repetitions        (default: 1000)
#   --events    LIST    Comma-separated perf events
#                       (default: cycles,instructions,cache-references,
#                                 cache-misses,L1-dcache-loads,
#                                 L1-dcache-load-misses)
#   --noise     LIST    Comma-separated noise levels (default: 1,5,10,100)
#   --victim-core  N    CPU core for victim   (default: 0)
#   --attacker-core N   CPU core for attacker (default: 1)
#   --noise-core   N    CPU core for noise    (default: 2)
#   --dry-run           Print config and exit
#   --help
#
# Notes on noise_level=1:
#   The protocol defines 1 as "Baseline without noise".
#   This script treats noise_level=1 as: launch 0 background benchmarks
#   (pure baseline), matching the intent.  Levels 5,10,100 launch that many
#   concurrent Embench benchmark instances as background noise.
# =============================================================================

set -euo pipefail

# ── colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠${NC} $*"; }
err()  { echo -e "${RED}[$(date '+%H:%M:%S')] ✗${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

# ── defaults ──────────────────────────────────────────────────────────────────
#SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="/root"

TARGET_BINARY="${SCRIPT_DIR}/flush_reload_demo/victim"
ATTACKER_BINARY="${SCRIPT_DIR}/flush_reload_demo/attacker"
BENCH_DIR="${SCRIPT_DIR}/bd-rpi3b"
REP_COUNT=1000
#EVENTS="cycles,instructions,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses"
EVENTS="cycles,instructions,l2d_cache,l2d_cache_refill,l2d_cache_wb,cache-references,cache-misses"
NOISE_LEVELS_STR="1,5,10,100"
VICTIM_CORE=0
ATTACKER_CORE=1
NOISE_CORE=2
DRY_RUN=0

RESULTS_DIR="${SCRIPT_DIR}/results"
RAW_DIR="${RESULTS_DIR}/raw"
CSV_DIR="${RESULTS_DIR}/csv"
LOG_DIR="${RESULTS_DIR}/logs"
SPY_FILE="/tmp/fr_demo_spy"

# ── argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)        TARGET_BINARY="$2";    shift 2 ;;
        --attacker)      ATTACKER_BINARY="$2";  shift 2 ;;
        --benchdir)      BENCH_DIR="$2";        shift 2 ;;
        --reps)          REP_COUNT="$2";        shift 2 ;;
        --events)        EVENTS="$2";           shift 2 ;;
        --noise)         NOISE_LEVELS_STR="$2"; shift 2 ;;
        --victim-core)   VICTIM_CORE="$2";      shift 2 ;;
        --attacker-core) ATTACKER_CORE="$2";    shift 2 ;;
        --noise-core)    NOISE_CORE="$2";       shift 2 ;;
        --dry-run)       DRY_RUN=1;             shift ;;
        --help|-h)
            grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Parse noise levels into array; treat level=1 as baseline (0 noise processes)
IFS=',' read -ra NOISE_LEVELS <<< "$NOISE_LEVELS_STR"
# Parse events into perf-compatible comma string (already is)
PERF_EVENTS="$EVENTS"

# ── preflight checks ──────────────────────────────────────────────────────────
preflight() {
    log "Running preflight checks …"

    # perf
    if ! command -v perf &>/dev/null; then
        die "perf not found. Install: sudo apt install linux-tools-\$(uname -r)"
    fi

    # perf_event_paranoid
    PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 99)
    if [[ "$PARANOID" -gt 1 ]]; then
        warn "perf_event_paranoid=$PARANOID — HPC collection may fail for unprivileged users."
        warn "Fix: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    fi

    # taskset
    if ! command -v taskset &>/dev/null; then
        die "taskset not found. Install: sudo apt install util-linux"
    fi

    # binaries
    [[ -x "$TARGET_BINARY"   ]] || die "Victim binary not found or not executable: $TARGET_BINARY"
    [[ -x "$ATTACKER_BINARY" ]] || die "Attacker binary not found or not executable: $ATTACKER_BINARY"

    # CPU cores
    NCPU=$(nproc)
    for core in $VICTIM_CORE $ATTACKER_CORE $NOISE_CORE; do
        [[ "$core" -lt "$NCPU" ]] || \
            die "Core $core requested but system only has $NCPU cores (0–$((NCPU-1)))"
    done

    # Embench benchmarks — build a list of executables
    BENCH_EXECS=()
    if [[ -d "$BENCH_DIR" ]]; then
        while IFS= read -r -d '' exe; do
            BENCH_EXECS+=("$exe")
        done < <(find "$BENCH_DIR/src" -type f -executable -not -name "*.o" -print0 2>/dev/null)
    fi

    if [[ ${#BENCH_EXECS[@]} -eq 0 ]]; then
        warn "No Embench benchmarks found in $BENCH_DIR/src"
        warn "Noise processes will use 'dd if=/dev/urandom of=/dev/null' as fallback."
        USE_DD_NOISE=1
    else
        ok "Found ${#BENCH_EXECS[@]} Embench benchmarks for noise generation"
        USE_DD_NOISE=0
    fi

    # CPU governor check
    GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
    if [[ "$GOV" != "performance" ]]; then
        warn "CPU governor is '$GOV' — recommend 'performance' for stable timing."
        warn "Fix: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
    fi

    ok "Preflight complete."
}

# ── launch N noise processes, return PIDs ─────────────────────────────────────
launch_noise() {
    local n="$1"
    local -n _pids="$2"    # nameref — caller passes array name
    _pids=()

    [[ "$n" -eq 0 ]] && return

    for (( i=0; i<n; i++ )); do
        if [[ "${USE_DD_NOISE:-0}" -eq 1 ]]; then
            # Fallback: memory bandwidth + compute noise
            taskset -c "$NOISE_CORE" \
                bash -c 'while true; do dd if=/dev/urandom bs=4096 count=256 2>/dev/null | md5sum > /dev/null; done' &
        else
            # Round-robin across available Embench benchmarks
            local idx=$(( i % ${#BENCH_EXECS[@]} ))
            local bench="${BENCH_EXECS[$idx]}"
            taskset -c "$NOISE_CORE" \
                bash -c "while true; do \"$bench\" 2>/dev/null; done" &
        fi
        _pids+=("$!")
    done
}

# ── kill a list of PIDs quietly ───────────────────────────────────────────────
kill_pids() {
    local -n _pids="$1"
    for pid in "${_pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    # Give them a moment, then SIGKILL stragglers
    sleep 0.2
    for pid in "${_pids[@]}"; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    wait "${_pids[@]}" 2>/dev/null || true
    _pids=()
}

# ── parse perf stat output into key=value pairs ───────────────────────────────
# perf stat -x, outputs CSV: value,unit,event,run%,...
# We capture both raw (-x,) and human-readable (no -x) versions.
parse_perf_csv_line() {
    local raw_file="$1"
    local out_file="$2"   # append one CSV row here
    local noise_level="$3"
    local rep="$4"

    # perf -x, output format (comma-separated):
    # value,unit,event,variance,run_count,run_ratio
    # We extract value per event in EVENTS order.
    local row="${noise_level},${rep}"
    IFS=',' read -ra event_list <<< "$EVENTS"
    for evt in "${event_list[@]}"; do
        # Grab the first matching value; <not counted> → NA
        local val
        val=$(grep -m1 ",${evt}," "$raw_file" 2>/dev/null | cut -d',' -f1 || echo "NA")
        val="${val// /}"  # strip spaces
        [[ -z "$val" || "$val" == "<not" ]] && val="NA"
        row="${row},${val}"
    done
    echo "$row" >> "$out_file"
}

# ── write CSV header ──────────────────────────────────────────────────────────
write_csv_header() {
    local file="$1"
    local header="noise_level,rep"
    IFS=',' read -ra event_list <<< "$EVENTS"
    for evt in "${event_list[@]}"; do
        header="${header},${evt}"
    done
    echo "$header" > "$file"
}

# ── print configuration summary ───────────────────────────────────────────────
print_config() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║        Flush+Reload HPC Experimental Protocol               ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Victim binary   :${NC} $TARGET_BINARY"
    echo -e "  ${BOLD}Attacker binary :${NC} $ATTACKER_BINARY"
    echo -e "  ${BOLD}Bench dir       :${NC} $BENCH_DIR"
    echo -e "  ${BOLD}Noise levels    :${NC} [${NOISE_LEVELS[*]}]  (level=1 → pure baseline)"
    echo -e "  ${BOLD}Repetitions     :${NC} $REP_COUNT"
    echo -e "  ${BOLD}Perf events     :${NC} $PERF_EVENTS"
    echo -e "  ${BOLD}CPU pinning     :${NC} victim=core${VICTIM_CORE}  attacker=core${ATTACKER_CORE}  noise=core${NOISE_CORE}"
    echo -e "  ${BOLD}Results dir     :${NC} $RESULTS_DIR"
    echo ""
    echo -e "  ${BOLD}Total runs      :${NC} $((${#NOISE_LEVELS[@]} * REP_COUNT))"

    # Estimate duration: each attacker run takes ~200 samples × 70ms = ~14s
    local secs_per_rep=16
    local total_secs=$(( ${#NOISE_LEVELS[@]} * REP_COUNT * secs_per_rep ))
    local total_min=$(( total_secs / 60 ))
    echo -e "  ${BOLD}Estimated time  :${NC} ~${total_min} min  (assuming ~${secs_per_rep}s per rep)"
    echo ""
}

# ── main experiment loop ──────────────────────────────────────────────────────
run_experiment() {
    local run_log="${LOG_DIR}/run_$(date '+%Y%m%d_%H%M%S').log"
    exec > >(tee -a "$run_log") 2>&1

    log "Results dir : $RESULTS_DIR"
    log "Run log     : $run_log"

    # Combined CSV (all noise levels together for easy R/Python import)
    local combined_csv="${CSV_DIR}/all_results.csv"
    write_csv_header "$combined_csv"

    local total_reps=$(( ${#NOISE_LEVELS[@]} * REP_COUNT ))
    local global_rep=0
    local start_epoch=$SECONDS

    for noise_level in "${NOISE_LEVELS[@]}"; do

        # Level 1 = baseline = 0 actual noise processes
        local actual_noise=0
        [[ "$noise_level" -gt 1 ]] && actual_noise="$noise_level"

        local noise_label
        [[ "$actual_noise" -eq 0 ]] && noise_label="baseline" || noise_label="noise${noise_level}"

        local noise_csv="${CSV_DIR}/results_${noise_label}.csv"
        write_csv_header "$noise_csv"

        echo ""
        log "════════════════════════════════════════════════════════"
        log "  Noise level = ${noise_level}  (${actual_noise} background processes)"
        log "  Output CSV  : $noise_csv"
        log "════════════════════════════════════════════════════════"

        for (( rep=1; rep<=REP_COUNT; rep++ )); do
            global_rep=$(( global_rep + 1 ))

            # Progress indicator every 10 reps
            if (( rep % 10 == 1 )); then
                local elapsed=$(( SECONDS - start_epoch ))
                local pct=$(( global_rep * 100 / total_reps ))
                log "  [noise=${noise_level}] rep ${rep}/${REP_COUNT}  |  overall ${global_rep}/${total_reps} (${pct}%)  |  elapsed ${elapsed}s"
            fi

            # ── output file for this run ──────────────────────────────────
            local raw_file="${RAW_DIR}/noise${noise_level}_rep${rep}.perf"

            # ── clean up any stale spy file ───────────────────────────────
            rm -f "$SPY_FILE"

            # ── 1. Launch background noise ────────────────────────────────
            declare -a NOISE_PIDS=()
            launch_noise "$actual_noise" NOISE_PIDS

            # ── 2. Launch victim (pinned to core VICTIM_CORE) ─────────────
            taskset -c "$VICTIM_CORE" "$TARGET_BINARY" \
                > "${RAW_DIR}/noise${noise_level}_rep${rep}.victim.log" 2>&1 &
            VICTIM_PID=$!

            # Wait for victim to create spy file (max 5s)
		local na_row="${noise_level},${rep}"
                IFS=',' read -ra el <<< "$EVENTS"
                for _ in "${el[@]}"; do na_row="${na_row},NA"; done
                echo "$na_row" >> "$noise_csv"

            # ── 3. Run attacker under perf stat (pinned to core ATTACKER_CORE) ─
            # -x, → machine-readable CSV output
            # -e  → event list
            # --  → everything after is the measured command
            perf stat \
                -x , \
                -e "$PERF_EVENTS" \
                -o "$raw_file" \
                -- taskset -c "$ATTACKER_CORE" "$ATTACKER_BINARY" \
                > "${RAW_DIR}/noise${noise_level}_rep${rep}.attacker.log" 2>&1
            PERF_EXIT=$?

            # ── 4. Stop victim ────────────────────────────────────────────
            kill -TERM "$VICTIM_PID" 2>/dev/null || true
            wait "$VICTIM_PID" 2>/dev/null || true

            # ── 5. Stop noise ─────────────────────────────────────────────
            if [[ ${#NOISE_PIDS[@]} -gt 0 ]]; then
                kill_pids NOISE_PIDS
            fi

            # ── 6. Clean up spy file ──────────────────────────────────────
            rm -f "$SPY_FILE"

            # ── 7. Parse perf output → CSV row ───────────────────────────
            if [[ $PERF_EXIT -eq 0 && -f "$raw_file" ]]; then
                parse_perf_csv_line "$raw_file" "$noise_csv" "$noise_level" "$rep"
                parse_perf_csv_line "$raw_file" "$combined_csv" "$noise_level" "$rep"
            else
                warn "  perf exited with code $PERF_EXIT for noise=${noise_level} rep=${rep}"
                local na_row="${noise_level},${rep}"
                IFS=',' read -ra el <<< "$EVENTS"
                for _ in "${el[@]}"; do na_row="${na_row},NA"; done
                echo "$na_row" >> "$noise_csv"
                echo "$na_row" >> "$combined_csv"
            fi

        done # reps

        ok "Noise level ${noise_level} complete — CSV: $noise_csv"

    done # noise levels

    local total_elapsed=$(( SECONDS - start_epoch ))
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║                  Experiment Complete                        ║${NC}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
    printf  "  %-30s %s\n" "Total runs:"          "$total_reps"
    printf  "  %-30s %s\n" "Total elapsed:"       "${total_elapsed}s  (~$(( total_elapsed/60 )) min)"
    printf  "  %-30s %s\n" "Combined CSV:"        "$combined_csv"
    printf  "  %-30s %s\n" "Per-level CSVs:"      "$CSV_DIR/"
    printf  "  %-30s %s\n" "Raw perf files:"      "$RAW_DIR/"
    printf  "  %-30s %s\n" "Run log:"             "$run_log"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
print_config
preflight

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Dry run — exiting without running the experiment."
    exit 0
fi

# Create output directories
mkdir -p "$RAW_DIR" "$CSV_DIR" "$LOG_DIR"

# Trap to clean up if script is interrupted mid-run
cleanup_on_exit() {
    warn "Interrupted — cleaning up …"
    # Kill any leftover victim / attacker / noise processes
    pkill -f "$(basename "$TARGET_BINARY")"   2>/dev/null || true
    pkill -f "$(basename "$ATTACKER_BINARY")" 2>/dev/null || true
    rm -f "$SPY_FILE"
    warn "Partial results saved in $RESULTS_DIR"
}
trap cleanup_on_exit INT TERM

run_experiment
