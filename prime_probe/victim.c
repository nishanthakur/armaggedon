/*
 * victim.c  –  Prime+Probe Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 *
 * ROLE
 * ----
 * This process holds a 1-byte SECRET value (0-15).  Every ~100 ms it
 * "processes" the secret by touching exactly one 4-KB aligned region of a
 * large shared-memory buffer whose index is derived from the secret value.
 *
 * Because the buffer lives in shared memory (POSIX shm), it is mapped into
 * both the victim's and the attacker's virtual address spaces.  The physical
 * pages – and therefore the L2 cache sets – are the same for both processes.
 *
 * The attacker can therefore infer which index the victim accessed by
 * observing which cache sets were evicted during the victim's memory touch.
 *
 * CACHE GEOMETRY (Pi 3B, Cortex-A53)
 * ------------------------------------
 *  L1-D : 32 KB, 4-way,  64-byte lines → 128 sets
 *  L2   : 512 KB, 16-way, 64-byte lines → 512 sets   ← primary spy target
 *  Line size: 64 bytes
 *
 * SHARED-MEMORY LAYOUT
 * ----------------------
 *  One "slot" per possible secret value (16 slots × 4096 bytes = 64 KB).
 *  Each slot is exactly one page (4 KB), which maps to a distinct group of
 *  L2 cache sets, making the access pattern distinguishable from the outside.
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

/* ── tunables ──────────────────────────────────────────────────────────── */

/* Name of the POSIX shared-memory object both processes open */
#define SHM_NAME        "/pp_demo_shm"

/*
 * Number of distinct secret values.
 * We use 4 bits → 16 possible values (0-15).
 * Each value maps to one 4-KB memory slot.
 */
#define NUM_SECRETS     16

/*
 * Size of one memory slot in bytes.
 * Must be a multiple of the page size (4096) so each slot occupies
 * a different page and therefore different cache-set groups.
 */
#define SLOT_SIZE       4096

/* Total shared buffer: 16 × 4096 = 65 536 bytes */
#define TOTAL_SHM_SIZE  (NUM_SECRETS * SLOT_SIZE)

/* How long to sleep between secret accesses (milliseconds) */
#define ACCESS_INTERVAL_MS  100

/* ── globals ───────────────────────────────────────────────────────────── */

static volatile int keep_running = 1;

/* ── helpers ───────────────────────────────────────────────────────────── */

static void handle_sigint(int sig) { (void)sig; keep_running = 0; }

/*
 * sleep_ms – portable millisecond sleep using nanosleep(2).
 */
static void sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/*
 * touch_secret_slot
 * -----------------
 * Performs a dependent load across the entire slot that corresponds to
 * `secret`.  We read every cache line in the slot (one 64-byte stride)
 * so that all relevant L2 cache sets are populated.
 *
 * The compiler barrier (__asm__ volatile("" ::: "memory")) prevents the
 * compiler from optimising away the loads.
 */
static void touch_secret_slot(volatile uint8_t *shm_base, uint8_t secret)
{
    /* Base address of this secret's dedicated 4-KB slot */
    volatile uint8_t *slot = shm_base + (size_t)secret * SLOT_SIZE;

    /* Walk every cache line in the slot to ensure all sets are warmed */
    for (size_t offset = 0; offset < SLOT_SIZE; offset += 64) {
        (void)slot[offset];                     /* load – brings line into cache */
        __asm__ volatile("" ::: "memory");      /* compiler barrier              */
    }
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------
     * 1.  Parse the secret from the command line (default = 7).
     *     Usage:  ./victim [secret_value_0_to_15]
     * ------------------------------------------------------------------ */
    uint8_t secret = 7;
    if (argc > 1) {
        int v = atoi(argv[1]);
        if (v < 0 || v >= NUM_SECRETS) {
            fprintf(stderr, "[victim] secret must be 0-%d\n", NUM_SECRETS - 1);
            return 1;
        }
        secret = (uint8_t)v;
    }

    printf("[victim] PID=%d  SECRET=%d\n", getpid(), secret);
    printf("[victim] Opening shared memory '%s' (%d bytes)\n",
           SHM_NAME, TOTAL_SHM_SIZE);

    /* ------------------------------------------------------------------
     * 2.  Create (or open) the POSIX shared-memory object.
     *     O_CREAT | O_RDWR: create if absent, open for read/write.
     *     Mode 0666: world-readable so the attacker (another UID) can open it.
     * ------------------------------------------------------------------ */
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) { perror("[victim] shm_open"); return 1; }

    /* Set the size of the shared-memory object */
    if (ftruncate(shm_fd, TOTAL_SHM_SIZE) == -1) {
        perror("[victim] ftruncate"); return 1;
    }

    /* ------------------------------------------------------------------
     * 3.  Map the shared memory into our address space.
     *     MAP_SHARED: writes/reads are visible to all other mappings of
     *     the same shm object, and both processes share the same physical
     *     page frames → same cache sets.
     * ------------------------------------------------------------------ */
    volatile uint8_t *shm_base = mmap(NULL, TOTAL_SHM_SIZE,
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) { perror("[victim] mmap"); return 1; }

    /* Initialise the shared buffer with non-zero data so pages are faulted in */
    memset((void *)shm_base, 0xAB, TOTAL_SHM_SIZE);

    printf("[victim] Shared memory mapped at %p\n", (void *)shm_base);
    printf("[victim] Accessing slot %d every %d ms  (Ctrl-C to stop)\n\n",
           secret, ACCESS_INTERVAL_MS);

    /* ------------------------------------------------------------------
     * 4.  Repeatedly touch the secret slot so the attacker has multiple
     *     observation windows.
     * ------------------------------------------------------------------ */
    signal(SIGINT, handle_sigint);

    uint64_t iteration = 0;
    while (keep_running) {
        touch_secret_slot(shm_base, secret);

        if (iteration % 10 == 0)            /* print every second */
            printf("[victim] iter=%-6lu  touched slot %d\n",
                   (unsigned long)iteration, secret);

        iteration++;
        sleep_ms(ACCESS_INTERVAL_MS);
    }

    /* ------------------------------------------------------------------
     * 5.  Cleanup
     * ------------------------------------------------------------------ */
    printf("\n[victim] Shutting down …\n");
    munmap((void *)shm_base, TOTAL_SHM_SIZE);
    close(shm_fd);
    /* NOTE: we do NOT unlink the shm here; the attacker may still need it */
    return 0;
}
