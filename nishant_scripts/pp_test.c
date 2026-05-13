#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libflush/libflush.h"

#define THRESHOLD   2200   // adjust based on calibration output
#define RUNS        100000

int main(void) {
    libflush_session_t *session;
    libflush_session_args_t args;
    memset(&args, 0, sizeof(args));

    if (libflush_init(&session, &args) != 0) {
        fprintf(stderr, "libflush_init failed\n");
        return 1;
    }

    // Allocate a target buffer (simulate "victim" memory)
    size_t buf_size = 4096 * 16;
    void *target = aligned_alloc(64, buf_size);
    if (!target) { perror("aligned_alloc"); return 1; }
    memset(target, 0xAB, buf_size);

    size_t hits = 0, misses = 0;
    void *probe_addr = target;  // probe first cache line

    for (size_t i = 0; i < RUNS; i++) {
        // PRIME: fill eviction set
        libflush_prime(session, probe_addr);

        // Simulate "victim access" every other run
        if (i % 2 == 0)
            *(volatile char *)probe_addr;  // victim-like access

        // PROBE: measure re-access time
        uint64_t t = libflush_probe_time(session, probe_addr);

        if (t < THRESHOLD)
            hits++;
        else
            misses++;
    }

    printf("Hits (victim accessed):  %zu / %zu\n", hits,   RUNS / 2);
    printf("Misses (no access):      %zu / %zu\n", misses, RUNS / 2);

    libflush_destroy(session);
    free(target);
    return 0;
}
