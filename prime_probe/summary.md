# Prime+Probe Cache Side-Channel Attack
### Raspberry Pi 3B (Cortex-A53, ARMv8) · Ubuntu 24.04
#### Internship Demonstration Report

---

## Table of Contents

1. [What is a Cache Side-Channel Attack?](#1-what-is-a-cache-side-channel-attack)
2. [Hardware Background: The Cache Hierarchy](#2-hardware-background-the-cache-hierarchy)
3. [Prime+Probe: The Attack Explained](#3-primeprobe-the-attack-explained)
4. [Our Setup](#4-our-setup)
5. [Code Architecture](#5-code-architecture)
6. [Key Implementation Decisions](#6-key-implementation-decisions)
7. [Bugs Encountered and How We Fixed Them](#7-bugs-encountered-and-how-we-fixed-them)
8. [Results and Interpretation](#8-results-and-interpretation)
9. [What PhD Students Can Detect Using HPCs](#9-what-phd-students-can-detect-using-hpcs)
10. [Glossary](#10-glossary)

---

## 1. What is a Cache Side-Channel Attack?

A **side-channel attack** exploits unintended information leaked by the *physical behaviour* of hardware — not by breaking cryptography or exploiting a software bug. The "channel" through which information leaks is a physical side-effect such as timing, power consumption, or electromagnetic radiation.

A **cache side-channel attack** specifically exploits the fact that accessing data already in the CPU cache is much faster than fetching it from main memory (DRAM). By carefully measuring how long memory accesses take, an attacker process can infer what memory a victim process has recently accessed — and therefore deduce secret information.

### Why is this serious?

- It works **across process isolation boundaries** — the OS cannot simply separate processes to prevent it.
- It does not require any software vulnerability in the victim.
- It can leak cryptographic keys, passwords, and sensitive data purely by observing timing.
- It was the foundational technique behind real-world attacks like **Flush+Reload**, **Meltdown**, and **Spectre**.

---

## 2. Hardware Background: The Cache Hierarchy

To understand the attack, you first need to understand how CPU caches work.

### Why caches exist

Main memory (DRAM) is slow — accessing it takes ~100–300 ns (~200 CPU cycles on a 1.2 GHz processor). The CPU would stall constantly if it fetched every instruction and data item from DRAM. Caches are small, fast memory built directly into the CPU chip that store recently-used data so future accesses are fast.

### Our hardware: Raspberry Pi 3B (Cortex-A53)

```
┌─────────────────────────────────────────────────────┐
│                  CPU Core (1.2 GHz)                  │
│                                                      │
│   ┌──────────────┐       ┌──────────────┐           │
│   │   L1 Data    │       │ L1 Instruction│           │
│   │    Cache     │       │    Cache      │           │
│   │  32 KB       │       │  32 KB        │           │
│   │  4-way       │       │  2-way        │           │
│   │  128 sets    │       │               │           │
│   │  ~4 cycles   │       │               │           │
│   └──────┬───────┘       └───────────────┘           │
│          │                                           │
│   ┌──────▼───────────────────────────────┐          │
│   │            L2 Unified Cache          │          │
│   │   512 KB  ·  16-way  ·  512 sets     │          │
│   │   64-byte cache lines                │          │
│   │   ~20 cycles                         │          │
│   └──────────────────────┬───────────────┘          │
└─────────────────────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │       Main Memory        │
              │          DRAM            │
              │      ~200+ cycles        │
              └──────────────────────────┘
```

### Key terminology

| Term | Meaning |
|---|---|
| **Cache line** | Smallest unit of data transferred between cache and DRAM — 64 bytes on Cortex-A53 |
| **Cache set** | A group of cache slots that a given memory address can map to |
| **Associativity (N-way)** | How many lines can coexist in one set; L2 is 16-way, so each set holds 16 lines |
| **Cache hit** | Data was found in cache → fast (~4–20 cycles) |
| **Cache miss** | Data not in cache → must fetch from DRAM → slow (~200+ cycles) |
| **Eviction** | When a cache set is full and a new line must replace an existing one |

### How cache set mapping works

The L2 cache set a memory address maps to is determined by **bits [14:6] of the physical address** (9 bits → 512 sets). This is fixed hardware behaviour and is the same regardless of which process is accessing the memory. This is what makes the attack possible: if two processes share the same physical memory page, they share the same L2 cache sets.

---

## 3. Prime+Probe: The Attack Explained

Prime+Probe is one of the classic cache side-channel techniques. It requires **no special privileges** and works even when the attacker and victim share no code — only cache sets.

### The three phases

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   PHASE 1: PRIME                                                     │
│   ──────────────                                                     │
│   Attacker fills the target cache sets with its OWN data.           │
│   After this, the attacker "owns" those cache sets.                 │
│                                                                      │
│   [Attacker data] [Attacker data] [Attacker data] ... (all sets)    │
│                                                                      │
│   PHASE 2: WAIT                                                      │
│   ─────────────                                                      │
│   Attacker sleeps. Victim process runs and accesses secret-          │
│   dependent memory. This EVICTS some of the attacker's lines        │
│   from whichever cache sets the victim's memory maps to.            │
│                                                                      │
│   [Attacker data] [VICTIM data!] [Attacker data] ... (one set hit)  │
│                              ↑                                       │
│                    victim's secret caused this eviction              │
│                                                                      │
│   PHASE 3: PROBE                                                     │
│   ──────────────                                                     │
│   Attacker re-reads all of its primed data and measures time.       │
│   Fast access → cache hit → attacker's data still there             │
│                → victim did NOT access this set                      │
│   Slow access → cache miss → attacker's data was evicted            │
│                → victim DID access this set → reveals the secret    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Signal polarity in our implementation

In our specific setup, the signal polarity is **inverted** from the classic description above. Here is why:

After PRIME, the attacker fills L2 with **eviction buffer data** (a private 1 MB buffer). This pushes ALL shared spy-buffer slots out to DRAM. Then:

- Victim warms **only** `slot[secret]` back into L2.
- On PROBE: `slot[secret]` = **FAST** (L2 hit, victim just loaded it).
- All other slots = **SLOW** (still cold in DRAM, nobody loaded them).

**Therefore: the SECRET is the slot with the LOWEST probe latency.**

---

## 4. Our Setup

### Hardware and OS

| Component | Value |
|---|---|
| Board | Raspberry Pi 3B |
| CPU | Broadcom BCM2837, 4× Cortex-A53 @ 1.2 GHz |
| Architecture | ARMv8 (AArch64) |
| OS | Ubuntu 24.04 (kernel 6.8.0-1053-raspi) |
| L1-D cache | 32 KB, 4-way, 64-byte lines, 128 sets |
| L2 cache | 512 KB, 16-way, 64-byte lines, 512 sets |
| L3 cache | None |
| Timer | CNTVCT_EL0 @ 19.2 MHz (52.1 ns/tick) |
| PMU | armv8_cortex_a53, 7 hardware counters |
| perf_event_paranoid | 1 (allows user-space HPC access) |
| ASLR | 2 (full — mitigated by shared physical pages) |

### Attack scenario

```
┌──────────────────────────────────────────────────────────────┐
│                      CPU Core 1                               │
│                                                               │
│   ┌─────────────────┐          ┌──────────────────────────┐  │
│   │   VICTIM         │          │   ATTACKER                │  │
│   │   (background)   │          │   (foreground)            │  │
│   │                  │          │                           │  │
│   │  secret = 11     │          │  Goal: find secret        │  │
│   │  touches         │          │  without being told       │  │
│   │  slot[11] every  │          │                           │  │
│   │  100 ms          │          │  Uses Prime+Probe         │  │
│   └────────┬─────────┘          └──────────┬────────────────┘  │
│            │                               │                   │
│            └────────── shared L2 ──────────┘                   │
│                           cache                                │
└──────────────────────────────────────────────────────────────┘
           │                           │
           └───── POSIX shared ────────┘
                   memory
                /dev/shm/pp_demo_shm
                (same physical pages
                 → same L2 cache sets)
```

Both processes are pinned to **CPU core 1** using `taskset -c 1` so they share the same L1 and L2 caches.

### Shared memory layout

The spy buffer is a 64 KB POSIX shared memory object divided into 16 slots of 4 KB each:

```
Offset 0x0000  ┌──────────────────┐  ← slot 0  (secret=0 maps here)
               │   4096 bytes      │
Offset 0x1000  ├──────────────────┤  ← slot 1
               │   4096 bytes      │
               │       ...         │
Offset 0xB000  ├──────────────────┤  ← slot 11 (secret=11 maps here)
               │   4096 bytes      │  ← VICTIM TOUCHES THIS
Offset 0xC000  ├──────────────────┤  ← slot 12
               │       ...         │
Offset 0xF000  ├──────────────────┤  ← slot 15
               │   4096 bytes      │
Offset 0x10000 └──────────────────┘
```

Each 4 KB slot sits on a different memory page. Different pages map to different L2 cache set groups. This makes each slot's cache footprint distinguishable from the others.

---

## 5. Code Architecture

### Files

| File | Role |
|---|---|
| `victim.c` | Opens shared memory, repeatedly touches `slot[secret]` every 100 ms |
| `attacker.c` | Runs Prime+Probe loop, infers secret from probe latencies |
| `Makefile` | Builds both with `-O1 -march=armv8-a` |
| `run_demo.sh` | Automates the demo: pins to core 1, fixes CPU freq, starts both processes |

### victim.c — what it does

```
1. Parse secret (0-15) from command line
2. Create POSIX shared memory object (/dev/shm/pp_demo_shm), 64 KB
3. Map it with MAP_SHARED (same physical pages for both processes)
4. Every 100 ms:
       → touch every cache line in slot[secret] (64 reads, one per line)
       → this brings slot[secret] into L2 cache
```

### attacker.c — what it does

```
1. Read timer frequency from CNTFRQ_EL0 register
2. Allocate 1 MB private eviction buffer (MAP_ANONYMOUS|MAP_PRIVATE)
   → Pre-fault all pages with memset so no page-fault jitter later
3. Open and map the shared memory (MAP_SHARED)
4. Calibrate hit/miss threshold:
   → Warm a 4 KB region → measure L2-hit time (fast)
   → Flush with DC CIVAC → measure DRAM-miss time (slow)
   → Threshold = midpoint
5. For 300 iterations:
   a. PRIME:  stride through 1 MB eviction buffer (2 passes)
              → fills L2, evicts all spy-buffer lines
   b. WAIT:   sleep 50 ms → victim wakes and warms slot[secret]
   c. PROBE:  read each of 16 slots, measure time with CNTVCT_EL0
              → slot[secret] = fast (L2 hit)
              → other slots = slow (DRAM miss)
6. Infer secret = slot with most hits (lowest latency)
7. Print bar chart and result
```

---

## 6. Key Implementation Decisions

### Timer: CNTVCT_EL0 (not perf ioctl)

The ARMv8 virtual counter register `CNTVCT_EL0` is readable from user space with a single `mrs` instruction:

```c
__asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(val) :: "memory");
```

This was critical. An earlier version used `perf_event_open` + `ioctl` calls inside the timing loop. Each `ioctl` is a **syscall costing ~1000–3000 cycles** (~2500 ns). With 4 ioctls per slot, the overhead completely buried the cache signal. `CNTVCT_EL0` has essentially zero overhead.

The `ISB` (Instruction Synchronisation Barrier) before the read serialises the instruction pipeline, preventing speculative out-of-order execution from giving an incorrect timestamp.

### Timing bracket: entire slot at once (not per cache line)

At 19.2 MHz, the timer has 52.1 ns resolution. A single cache line access takes:
- L2 hit: ~17 ns → 0.3 ticks (rounds to 0 or 1, indistinguishable)
- DRAM miss: ~167 ns → 3.2 ticks

Timing each line individually gave a signal of only ~2–3 ticks — too noisy. The fix was to time **all 64 lines in one bracket**:

```
  ISB → t0 = read_timer()
  [read 64 lines, no ISB between them]
  DSB → t1 = read_timer()
  return (t1 - t0) in nanoseconds
```

This accumulates the signal across 64 lines:
- Hit slot: 64 × 17 ns ≈ **1088 ns (~21 ticks)**
- Miss slot: 64 × 167 ns ≈ **10688 ns (~205 ticks)**

A ~10× difference — clearly visible.

### Eviction buffer: 1 MB private, separate from spy buffer

The L2 is 512 KB. An eviction buffer must be **larger than the cache** to displace all existing occupants. We use 1 MB (2× L2):

```
L2 has 512 sets × 16 ways = 8192 cache lines
1 MB ÷ 64 bytes = 16384 cache lines

Striding 1 MB brings 32 new lines into each of 512 sets,
replacing all 16 ways at least twice — guaranteed full eviction
regardless of LRU or PLRU replacement policy.
```

The buffer is `MAP_ANONYMOUS | MAP_PRIVATE` so it has completely separate physical pages from the shared spy buffer. All pages are pre-faulted with `memset` before the attack loop to eliminate page-fault latency jitter.

### Compiler barrier vs memory barrier

```c
__asm__ volatile("" ::: "memory");   // compiler barrier only
                                     // prevents compiler reordering/elision
                                     // NO CPU effect

__asm__ volatile("dsb sy" ::: "memory");  // full hardware barrier
                                           // ensures all memory accesses
                                           // are complete before continuing
```

We use compiler barriers inside the load loops (so the compiler doesn't eliminate the "dead" loads) and hardware barriers only at phase boundaries (prime→wait, probe→timestamp) where ordering truly matters.

### CPU frequency pinning

The `run_demo.sh` script sets all CPU cores to `performance` governor:

```bash
echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

At variable frequency, the same number of timer ticks represents different amounts of real work. Fixing the frequency to 1.2 GHz gives stable, reproducible timing measurements.

---

## 7. Bugs Encountered and How We Fixed Them

This section documents the three bugs we hit during development and their exact diagnostics, which may be useful for understanding the subtleties of cache timing attacks.

---

### Bug 1: syscall overhead buried the signal

**Symptom:**
```
All slots showed ~9500 cycles, miss_count = 200/200 for every slot
```

**Root cause:**

The timer implementation used `perf_event_open` + `ioctl` calls *inside* the per-slot probe loop:
```c
// WRONG: 4 syscalls per slot = ~8000 cycles overhead
ioctl(fd, PERF_EVENT_IOC_RESET, 0);
ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
// ... 64 memory reads ...
ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
read(fd, &count, sizeof(count));
```

Each `ioctl` syscall costs ~1000–3000 cycles on the Pi 3B (due to context switch, kernel validation, and return). The 4 ioctls added ~8000 cycles of overhead to every single slot measurement. The actual cache signal (~200 cycles difference between hit and miss) was completely invisible.

**Fix:** Replace with a single `mrs cntvct_el0` instruction — zero syscall cost.

---

### Bug 2: per-line ISB overhead swamped the signal

**Symptom:**
```
All slots showed ~500 ns, miss_count = 0–5/200 for every slot
(slot 11 not distinguishable)
```

**Root cause:**

After fixing Bug 1, the code timed each cache line individually with an `ISB` before every read:
```c
// WRONG: ISB before every line adds ~1-2 ticks overhead each time
for (offset = 0; offset < SLOT_SIZE; offset += 64) {
    __asm__ volatile("isb" ::: "memory");   // ~1-2 ticks overhead
    t0 = read_timer();
    (void)slot[offset];
    t1 = read_timer();
    total += (t1 - t0);
}
```

At 52.1 ns/tick, the `ISB` added 52–104 ns per line. Actual hit/miss difference per line was only ~2–3 ticks (~104–156 ns). The ISB overhead was the same magnitude as the signal — impossible to distinguish.

**Fix:** One timer bracket around all 64 line reads. No ISB between individual reads.

---

### Bug 3: eviction buffer too small to fill the L2

**Symptom:**
```
Slot 11 (actual secret) showed LOWEST latency (458 ns)
but was still not correctly identified — all miss counts were near 0,
and inference picked slot 0 or 6 based on minor noise
```

**Root cause:**

The prime phase walked the 64 KB spy buffer (shared memory), but the L2 is 512 KB:

```
Spy buffer:   64 KB  =  1024 cache lines  =  fills 2 lines per L2 set
L2 capacity: 512 KB  =  8192 cache lines  =  16 lines per L2 set (16-way)

64 KB stride only displaces 2 of the 16 ways in each set.
The victim's 64 lines (from slot[11]) easily survived in the other 14 ways.
```

So after "priming", the victim's slot[11] was still warm in L2. When the victim touched it again, it stayed in L2. When we probed, slot[11] was fast — but it was fast because the prime **failed to evict it**, not because the victim had just loaded it. There was no signal difference between the secret slot and others because the prime didn't actually reset the cache state.

**Fix:** Allocate a **private 1 MB buffer** (2 × 512 KB L2) for priming. Walk this instead of the spy buffer. The 1 MB stride brings 32 lines into each of the 512 L2 sets, replacing all 16 ways at minimum twice — guaranteed full eviction.

---

## 8. Results and Interpretation

### Actual output (secret = 11)

```
Calibration: L2-hit = 130 ns  |  DRAM-miss = 2223 ns
Threshold:   1176 ns

Slot 11:  Avg = 1206 ns  |  hit_count = 152/300  (50%)
Slot  0:  Avg = 1910 ns  |  hit_count =   0/300
Slot  6:  Avg = 2523 ns  |  hit_count =   2/300
(all other slots: Avg 1790–2192 ns, hit_count 0–17)
```

### Bar chart interpretation

```
  │ Slot │  Avg ns  │ Latency bar
  │  11  │     1206 │                     ← SHORT bar = FAST = L2 hit = SECRET
  │   9  │     1790 │ #################
  │   0  │     1910 │ #####################
  │   6  │     2523 │ ######################################## ← SLOW = DRAM miss
```

Slot 11 has a **near-empty bar** because it is consistently the fastest slot to probe. All other slots have significantly longer bars because they are consistently slow (DRAM misses).

### Why hit rate is 50% (not higher)

```
Timeline:
  t =   0 ms   Attacker finishes PRIME
  t =  50 ms   Attacker PROBES  ← 50 ms wait
  t = 100 ms   Victim touches slot[11]   ← victim's 100 ms interval

In approximately half of iterations, the victim runs BEFORE the probe
(slot[11] is warm → L2 hit → counted as a hit).
In the other half, the victim runs AFTER the probe
(slot[11] still cold from prime → DRAM miss → not counted as hit).
```

A 50% hit rate is perfectly sufficient for a correct inference — slot 11's count (152) is 9× higher than any other slot's count (17 at most). The inference is unambiguous.

### False positives (slots 12=8, 13=7, 14=17)

These are caused by OS kernel threads and hardware interrupts occasionally touching shared-memory pages during the wait window. They are statistical noise and would decrease with more iterations. They pose no threat to correct inference as long as they stay well below the signal (152).

---

## 9. What PhD Students Can Detect Using HPCs

The Cortex-A53's PMU (Performance Monitoring Unit) exposes 7 programmable hardware counters accessible via `perf_event_open`. The Prime+Probe attack creates a distinctive temporal signature in these counters that differs from normal application behaviour.

### Monitoring the attacker in real time

Run in a second terminal while the attack is running:

```bash
# Attach to the attacker process and sample every 500 ms
sudo perf stat -p $(pgrep attacker) \
  -e cache-misses,cache-references,cycles,instructions \
  --interval-print 500
```

Or record a full trace:
```bash
sudo perf record -e cache-misses,cycles -g -p $(pgrep attacker)
sudo perf report
```

### HPC events that reveal the attack

| HPC Event | What it shows during attack | Normal behaviour |
|---|---|---|
| `l2_cache_refill` | Periodic spike during PROBE (attacker reloads cold lines) | Low, steady |
| `l2_cache_wb` | Spike during PRIME (eviction buffer displaces spy lines) | Low |
| `mem_access` | Very uniform stride pattern (32-byte stride over 1 MB) | Irregular |
| `cache-misses` | High during PROBE, low during WAIT — periodic pattern | Steady |
| `IPC` (instr/cycle) | Drops sharply during PROBE (memory-bound stalls) | Steady |
| `bus_access` | Elevated during PRIME and PROBE (DRAM traffic) | Low |

### The temporal signature to detect

```
Time →
           PRIME          WAIT        PROBE
           (1 MB stride)  (50 ms)     (64 KB read)
           │              │           │
L2 misses: ████████████   ░░░░░░░░░   ████████
DRAM bus:  ████████████   ░░░░░░░░░   ████████
IPC:       ░░░░░░░░░░░░   ████████    ░░░░░░░░

Pattern repeats every ~60 ms with machine-like regularity.
Normal applications do not show this alternating burst/quiet/burst pattern.
```

### Detection strategies

1. **Threshold-based:** alert when L2 miss rate exceeds X% for more than Y ms
2. **Pattern-based:** detect the periodic alternation between high-miss and low-miss phases
3. **Stride detection:** flag processes with unusually regular memory access strides (exactly 64 bytes across 1 MB)
4. **Bus traffic anomaly:** flag processes generating DRAM traffic disproportionate to their instruction count

---

## 10. Glossary

| Term | Definition |
|---|---|
| **Cache hit** | Requested data found in cache — fast access (~4–20 cycles) |
| **Cache miss** | Requested data not in cache — must fetch from DRAM (~200+ cycles) |
| **Cache line** | Smallest unit transferred between cache and DRAM (64 bytes here) |
| **Cache set** | The group of cache slots a given address can map to |
| **Associativity** | Number of lines that can share a cache set (L2 = 16-way) |
| **Eviction** | Replacing an existing cache line with new data when a set is full |
| **LRU / PLRU** | Least Recently Used / Pseudo-LRU — cache replacement policies |
| **PRIME** | Filling cache sets with attacker-controlled data |
| **PROBE** | Re-reading primed data and measuring reload time |
| **Side-channel** | Information leaked via physical behaviour rather than software interface |
| **POSIX shm** | POSIX shared memory — maps the same physical pages into multiple processes |
| **CNTVCT_EL0** | ARMv8 virtual counter register — hardware timer readable from user space |
| **CNTFRQ_EL0** | ARMv8 register storing timer frequency (19.2 MHz on this Pi) |
| **DSB** | Data Synchronisation Barrier — waits for all memory accesses to complete |
| **ISB** | Instruction Synchronisation Barrier — flushes the CPU pipeline |
| **DC CIVAC** | ARMv8 cache flush instruction — evicts a specific cache line to DRAM |
| **PMU** | Performance Monitoring Unit — hardware block that counts microarchitectural events |
| **HPC** | Hardware Performance Counter — a PMU counter measuring one event type |
| **perf_event_open** | Linux syscall to access PMU counters from user space |
| **MAP_SHARED** | mmap flag: maps the same physical pages — writes visible to all mappers |
| **MAP_PRIVATE** | mmap flag: private copy-on-write mapping — separate physical pages |
| **taskset** | Linux tool to pin a process to specific CPU cores |
| **ASLR** | Address Space Layout Randomisation — randomises virtual addresses (does not protect physical addresses) |

---

*Generated during internship demonstration — Prime+Probe cache side-channel attack on Raspberry Pi 3B (ARMv8/Cortex-A53) · May 2026*

