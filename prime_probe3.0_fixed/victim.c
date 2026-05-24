/*
 * victim.c  –  Prime+Probe Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 * VERSION 6 – no logic changes from v5; version bump to match attacker v9.
 *
 * The victim is correct as-is.  All bugs were in attacker.c and run_demo.sh.
 * Kept here unchanged except for the version banner.
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

/* ── tunables (must match attacker.c) ─────────────────────────────────── */
#define SHM_NAME            "/pp_demo_shm"
#define NUM_SLOTS           256                         /* full byte range    */
#define SLOT_SIZE           4096                        /* one page per slot  */
#define TOTAL_SHM_SIZE      (NUM_SLOTS * SLOT_SIZE)     /* 1 MB               */
#define ACCESS_INTERVAL_MS  100

/* ── session token fields ─────────────────────────────────────────────── */
#define SESSION_ID    "a3f8c1d2e4b90712"
#define SESSION_USER  "alice"
#define SESSION_ROLE  "admin"

/* ── globals ───────────────────────────────────────────────────────────── */
static volatile int keep_running = 1;
static void handle_signal(int s) { (void)s; keep_running = 0; }

static void sleep_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/*
 * fill_all_slots_with_junk()
 * --------------------------
 * Fills all 256 × 4 KB = 1 MB with pseudo-random bytes so the attacker
 * cannot identify the secret slot by content inspection — every slot
 * looks populated.  Uses a simple xorshift32 for speed.
 */
static void fill_all_slots_with_junk(volatile uint8_t *shm_base)
{
    uint32_t rng = 0xDEADBEEF;
    uint8_t *p   = (uint8_t *)shm_base;
    for (size_t i = 0; i < TOTAL_SHM_SIZE; i++) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        p[i] = (uint8_t)(rng & 0xff);
    }
    printf("[victim] All %d slots (%d KB) filled with junk.\n",
           NUM_SLOTS, (int)(TOTAL_SHM_SIZE / 1024));
}

/*
 * write_session_token()
 * ---------------------
 * Writes the session token into the chosen slot, refreshing the dynamic
 * fields (expires, iter) each call.  Bytes beyond the null terminator
 * retain the junk fill so the slot size stays at 4 KB.
 */
static void write_session_token(volatile uint8_t *shm_base,
                                 int slot, uint64_t iter)
{
    uint8_t *p   = (uint8_t *)(shm_base + (size_t)slot * SLOT_SIZE);
    time_t   now = time(NULL);
    int len = snprintf((char *)p, SLOT_SIZE,
        "SESSION"
        " | id=%s"
        " | user=%s"
        " | role=%s"
        " | expires=%lu"
        " | iter=%llu",
        SESSION_ID, SESSION_USER, SESSION_ROLE,
        (unsigned long)(now + 3600),
        (unsigned long long)iter);
    if (len > 0 && len < SLOT_SIZE)
        p[len] = '\0';
}

/*
 * touch_slot()
 * ------------
 * Walks every 64-byte cache line of the slot to warm it in L2.
 */
static void touch_slot(volatile uint8_t *shm_base, int slot)
{
    volatile uint8_t *p = shm_base + (size_t)slot * SLOT_SIZE;
    for (size_t off = 0; off < SLOT_SIZE; off += 64) {
        (void)p[off];
        __asm__ volatile("" ::: "memory");
    }
}

/* ── main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* Choose slot: argv[1] or random */
    int slot;
    if (argc > 1) {
        slot = atoi(argv[1]);
        if (slot < 0 || slot >= NUM_SLOTS) {
            fprintf(stderr, "[victim] slot must be 0-%d\n", NUM_SLOTS - 1);
            return 1;
        }
    } else {
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        slot = rand() % NUM_SLOTS;
    }

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   Prime+Probe Demo v9 — VICTIM  (runs until killed)     ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("[victim] PID=%d\n", getpid());
    printf("[victim] Total slots      : %d  (%d KB shared memory)\n",
           NUM_SLOTS, (int)(TOTAL_SHM_SIZE / 1024));
    printf("[victim] Session token in : slot %d  "
           "(attacker must discover this from %d candidates)\n",
           slot, NUM_SLOTS);
    printf("[victim] Session user     : %s\n", SESSION_USER);
    printf("[victim] Session role     : %s\n\n", SESSION_ROLE);

    /* ── shared memory ── */
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0644);
    if (shm_fd < 0) { perror("[victim] shm_open"); return 1; }
    if (ftruncate(shm_fd, TOTAL_SHM_SIZE) < 0) {
        perror("[victim] ftruncate"); return 1;
    }
    volatile uint8_t *shm_base = mmap(NULL, TOTAL_SHM_SIZE,
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) { perror("[victim] mmap"); return 1; }
    printf("[victim] Shared memory at %p (%d KB)\n\n",
           (void *)shm_base, (int)(TOTAL_SHM_SIZE / 1024));

    /* ── initialise ── */
    fill_all_slots_with_junk(shm_base);
    write_session_token(shm_base, slot, 0);
    printf("[victim] Session token written to slot %d:\n", slot);
    printf("[victim]   %.100s\n\n",
           (char *)(shm_base + (size_t)slot * SLOT_SIZE));
    printf("[victim] Running — refreshing slot %d every %d ms\n\n",
           slot, ACCESS_INTERVAL_MS);

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* ── main loop ── */
    uint64_t iter = 1;
    while (keep_running) {
        write_session_token(shm_base, slot, iter);
        touch_slot(shm_base, slot);

        if (iter % 20 == 0)
            printf("[victim] iter=%-8llu  slot=%d  ts=%lu\n",
                   (unsigned long long)iter, slot, (unsigned long)time(NULL));
        iter++;
        sleep_ms(ACCESS_INTERVAL_MS);
    }

    printf("\n[victim] Shutting down …\n");
    munmap((void *)shm_base, TOTAL_SHM_SIZE);
    close(shm_fd);
    shm_unlink(SHM_NAME);
    printf("[victim] Done.\n");
    return 0;
}
