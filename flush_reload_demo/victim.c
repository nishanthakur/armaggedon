/*
 * victim.c  –  Flush+Reload Demo  (Raspberry Pi 3B, ARMv8 / Cortex-A53)
 *
 * CONCEPT
 * -------
 * The victim process simulates an HTTPS session handler.  It holds a
 * session token in a memory-mapped file (the "spy file") and periodically
 * reads it — modelling a web server checking authentication on each
 * request.
 *
 * The attacker maps the SAME physical pages of the spy file and measures
 * read latency.  After the victim reads a line, it lands in the shared L2;
 * the attacker sees a fast (cache-hit) access.  After the attacker flushes
 * the line, it falls back to DRAM; the attacker sees a slow (miss) access.
 * This is the classic Flush+Reload channel.
 *
 * SHARED RESOURCE
 * ---------------
 * A file-backed shared mapping (mmap MAP_SHARED of a real file) so both
 * processes map the SAME physical pages — the prerequisite for F+R.
 * (POSIX shm_open/shm_fd would also work; a named file is used here so
 * students can inspect it with hexdump/xxd independently.)
 *
 * BUILD
 *   gcc -O1 -march=armv8-a -o victim victim.c -lrt
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
#define SPY_FILE         "/tmp/fr_demo_spy"
#define FILE_SIZE        4096            /* one page; one cache-line of interest */
#define ACCESS_INTERVAL_US  80000        /* 80 ms between token reads             */

/* ── session token (realistic-looking) ────────────────────────────────── */
#define SESSION_ID    "8f3a1c9d2e7b4056"
#define SESSION_USER  "bob"
#define SESSION_ROLE  "admin"

static volatile int keep_running = 1;
static void handle_signal(int s) { (void)s; keep_running = 0; }

static void sleep_us(long us)
{
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000L };
    nanosleep(&ts, NULL);
}

/* Write session token at offset 0 of the mapped page */
static void refresh_token(volatile uint8_t *base, uint64_t iter)
{
    int len = snprintf((char *)base, FILE_SIZE,
        "SESSION"
        " | id=%s"
        " | user=%s"
        " | role=%s"
        " | expires=%lu"
        " | iter=%llu",
        SESSION_ID, SESSION_USER, SESSION_ROLE,
        (unsigned long)(time(NULL) + 3600),
        (unsigned long long)iter);
    if (len > 0 && len < FILE_SIZE)
        ((uint8_t *)base)[len] = '\0';
}

/* Read every cache line of the spy region — warms the line into L2 */
static void touch_page(volatile uint8_t *base)
{
    for (size_t off = 0; off < FILE_SIZE; off += 64) {
        (void)base[off];
        __asm__ volatile("" ::: "memory");
    }
    __asm__ volatile("dsb sy\nisb" ::: "memory");
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  Flush+Reload Demo  –  VICTIM  (ARMv8)      ║\n");
    printf("║  Simulates a session-token service.         ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    printf("[victim] PID=%d\n", getpid());
    printf("[victim] Spy file : %s\n", SPY_FILE);
    printf("[victim] Token    : SESSION | id=%s | user=%s | role=%s\n\n",
           SESSION_ID, SESSION_USER, SESSION_ROLE);

    /* Create / open spy file */
    int fd = open(SPY_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) { perror("[victim] open"); return 1; }
    if (ftruncate(fd, FILE_SIZE) < 0) { perror("[victim] ftruncate"); return 1; }

    volatile uint8_t *base = mmap(NULL, FILE_SIZE,
                                   PROT_READ | PROT_WRITE,
                                   MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { perror("[victim] mmap"); return 1; }

    /* Write initial token */
    refresh_token(base, 0);
    printf("[victim] Initial token written:\n");
    printf("[victim]   %.120s\n\n", (char *)base);
    printf("[victim] Running — refreshing token every %d ms\n\n",
           (int)(ACCESS_INTERVAL_US / 1000));

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    uint64_t iter = 1;
    while (keep_running) {
        refresh_token(base, iter);
        touch_page(base);           /* bring the line back into L2 */

        if (iter % 25 == 0)
            printf("[victim] iter=%-6llu  ts=%lu\n",
                   (unsigned long long)iter, (unsigned long)time(NULL));
        iter++;
        sleep_us(ACCESS_INTERVAL_US);
    }

    printf("\n[victim] Shutting down …\n");
    munmap((void *)base, FILE_SIZE);
    close(fd);
    unlink(SPY_FILE);
    printf("[victim] Removed spy file.  Done.\n");
    return 0;
}
