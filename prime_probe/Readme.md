# Prime+Probe Cache Side-Channel Demo
## Raspberry Pi 3B (Cortex-A53, ARMv8) · Ubuntu 24.04

---

## Files

| File | Role |
|---|---|
| `victim.c` | Victim process: holds a secret (0–15), repeatedly accesses secret-derived memory |
| `attacker.c` | Attacker process: Prime+Probe to infer the victim's secret |
| `Makefile` | Builds both binaries with `-O1 -march=armv8-a` |
| `run_demo.sh` | Automated launcher: pins both to core 1, fixes CPU frequency |

---

## Quick Start

```bash
# Build
make

# Run demo with secret = 11
sudo ./run_demo.sh 11
```

You should see the attacker's bar chart show slot 11 as having the highest
probe latency (most cache misses) → inferred secret = 11.

---

## Attack Theory

### Cache Geometry (Pi 3B)

```
L1-D:  32 KB,  4-way,  64-byte lines → 128 sets    (per core)
L2:   512 KB, 16-way,  64-byte lines → 512 sets    (shared)
```

### Prime+Probe – Three Phases

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  PRIME    Fill all spy-buffer cache lines with attacker data.   │
│           The attacker now "owns" all relevant L2 cache sets.   │
│                                                                 │
│  WAIT     Victim wakes up, accesses memory slot[secret].        │
│           This evicts attacker lines from exactly those L2 sets │
│           that map to slot[secret].                             │
│                                                                 │
│  PROBE    Re-read each slot, measure access time (cycles).      │
│           Slow slot (cache miss, ~200+ cy) → victim was here    │
│           Fast slot (cache hit,   ~20 cy) → victim wasn't here  │
│                                                                 │
│  INFER    Slot with max misses = victim's secret value.         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Why Shared Memory?

POSIX `shm_open` backed by `/dev/shm` maps the **same physical page frames**
into both processes' virtual address spaces.  The L2 cache set index is
determined by physical address bits `[14:6]` (9 bits → 512 sets).  Because
both processes share physical pages, the attacker's virtual address for slot N
maps to the **exact same** L2 cache sets as the victim's virtual address for
slot N — even though virtual addresses differ.

### Timing Source

We use `perf_event_open(PERF_COUNT_HW_CPU_CYCLES)` which reads the Cortex-A53
`PMCCNTR_EL0` hardware cycle counter from user space via the kernel's
`armv8_cortex_a53` PMU driver.  This requires `perf_event_paranoid ≤ 1`
(your system has `1`) and running as root.

Cycle counts:
- L1-D hit:  ~4 cycles
- L2 hit:    ~20 cycles
- DRAM miss: ~200–350 cycles

Miss threshold in `attacker.c`: **100 cycles** (between L2 hit and DRAM miss).

---

## Tuning for PhD Students / HPC Detection

To integrate Hardware Performance Counter (HPC) monitoring alongside the
attack, connect to the attacker via `perf stat` in a second terminal:

```bash
# In terminal 2 — monitor HPCs on the attacker process
perf stat -e \
  cache-misses,cache-references,\
  L1-dcache-loads,L1-dcache-load-misses,\
  l2_cache/l2_cache_miss_ld/,\
  cycles,instructions \
  -p $(pgrep attacker) --interval-print 500
```

Or record a full trace:
```bash
perf record -e cache-misses,cycles -g -p $(pgrep attacker) -- sleep 10
perf report
```

### Key HPCs to watch for Prime+Probe detection

| HPC event | What it reveals |
|---|---|
| `l2_cache_refill` / `l2_cache_miss_ld` | Spike during PROBE phase = attacker re-loading evicted lines |
| `l2_cache_wb` | Writebacks during PRIME = attacker evicting old data |
| `cpu_cycles` per window | Alternating high/low pattern (prime/probe rhythm) |
| `mem_access` | Unusually uniform stride pattern across entire buffer |
| IPC (instructions/cycles) | Drops sharply during PROBE (memory-bound stalls) |

The periodic `PRIME → WAIT → PROBE` pattern creates a **recognisable
temporal signature** in L2 miss rate that differs from normal application
behaviour.

---

## Adjustable Parameters in `attacker.c`

| Constant | Default | Effect |
|---|---|---|
| `MISS_THRESHOLD` | 100 cycles | Lower = more false positives; raise if L2 is slow |
| `WAIT_US` | 50 000 µs | Must be < victim's access interval (100 ms) |
| `NUM_ITERATIONS` | 200 | More = better statistics; slower demo |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `perf_event_open: Permission denied` | Run as root: `sudo ./run_demo.sh` |
| Attacker infers wrong slot | Try `MISS_THRESHOLD` ±20 cycles; check CPU freq is fixed |
| All slots show similar latency | Ensure both processes are on the same core (`taskset -c 1`) |
| Shared memory not found | Start victim first; wait for "Shared memory mapped" message |
