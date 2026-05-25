# Flush+Reload Demo — Raspberry Pi 3B / ARMv8 / Ubuntu 24.04

A minimal, heavily-commented demonstration of the **Flush+Reload** cache
side-channel attack, designed for PhD-level coursework on Hardware
Performance Counter (HPC)-based detection systems.

---

## What it demonstrates

A victim process simulates an HTTPS session handler by periodically reading a
session token from a file-backed shared memory page.  An attacker process maps
the same physical page and repeatedly:

1. **Flushes** the cache line using `dc civac` (ARM's clean-and-invalidate
   instruction).
2. **Waits** ~70 ms — long enough for the victim to reload the line.
3. **Reloads** the line and measures access latency with `cntvct_el0`.

A fast reload (< threshold ns) means the victim touched the line while the
attacker was waiting — a **cache HIT**, proving the victim is alive and
actively using that memory.  After observing enough hits, the attacker reads
the page contents and prints the extracted session token.

---

## Key difference from Prime+Probe

| Aspect | Flush+Reload | Prime+Probe |
|---|---|---|
| Shared resource needed? | Yes (shared physical page) | No |
| Eviction buffer needed? | No | Yes (must be ≥ 4 × L2) |
| Granularity | Exact cache line | Cache set |
| Noise | Very low | Moderate |
| Signal | Direct hit/miss per line | Indirect via set occupancy |

Flush+Reload is **simpler and higher-signal**; it requires a file-backed or
`shm_open` shared mapping between victim and attacker.

---

## Files

```
victim.c     – Session token service (touches spy page every 80 ms)
attacker.c   – F+R sampler: flush → wait → reload → measure
Makefile     – gcc -O1 -march=armv8-a
run_demo.sh  – Pins victim to core 0, attacker to core 1; launches both
```

---

## Build & Run

```bash
# On the Raspberry Pi 3B (Ubuntu 24.04 aarch64):
make
bash run_demo.sh

# Or step by step:
taskset -c 0 ./victim &
sleep 1
taskset -c 1 ./attacker
```

---

## Expected output (attacker terminal)

```
╔══════════════════════════════════════════════════════════════╗
║  Flush+Reload Demo  –  ATTACKER  (ARMv8 / Cortex-A53)      ║
...
[attacker] Calibration results:
[attacker]   L2 cache HIT  =    320 ns
[attacker]   DRAM miss     =   2800 ns
[attacker]   Threshold     =   1560 ns

  Sample  Reload(ns)  Decision  Running hit count
  1       2750        miss      0 hits so far  (warmup)
  ...
  15      310         HIT ◄     1 hits so far
  16      290         HIT ◄     2 hits so far
  ...
[attacker] ★ 5 consecutive cache HITS — victim access confirmed!

  ╔══════════════════════════════════════════════════════════════╗
  ║       *** FLUSH+RELOAD ATTACK SUCCESSFUL ***                ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  EXTRACTED SESSION TOKEN:                                   ║
  ║    SESSION | id=8f3a1c9d2e7b4056 | user=bob | role=admin   ║
  ╚══════════════════════════════════════════════════════════════╝
```

---

## HPC detection hooks (for student projects)

The attack produces characteristic hardware events that detection systems can
monitor via `perf_event_open`:

| HPC event | What to look for |
|---|---|
| `CACHE_MISSES` | Spike on the attacker's core after each flush |
| `CACHE_REFERENCES` | Paired hit spike ~70 ms later (reload phase) |
| `L2D_CACHE_REFILL` | Elevated on attacker core, correlated with victim's access interval |
| `MEM_ACCESS` | Periodic pattern matching the F+R wait period |

Suggested detection approach:
- Sample the four events above on all cores at 10 ms intervals.
- Look for a **periodic pattern** of `L2D_CACHE_REFILL` on one core that
  is phase-locked to victim's access interval.
- Cross-correlate with the victim core's `CACHE_REFERENCES` to confirm
  shared-page access.

---

## Troubleshooting

**Hit rate is 0% / all misses**
- Check CPU governor: `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`
  → should be `performance`.  Set with `run_demo.sh` or manually.
- Verify both processes are on different cores (`taskset -c 0` and `taskset -c 1`).
- Try increasing `WAIT_US` in `attacker.c` (e.g. 100000 for 100 ms) if the
  victim's `ACCESS_INTERVAL_US` (80 ms) is close to the wait time.

**`dc civac` causes SIGILL**
- Very unlikely on Ubuntu 24.04 aarch64, but if it occurs, check
  `/proc/sys/kernel/perf_event_paranoid` and kernel version (need ≥ 4.15).

**Timer reads 0**
- The virtual counter (`cntvct_el0`) requires EL0 access enabled.
  Usually set by the kernel. Check: `dmesg | grep -i arch_timer`.
