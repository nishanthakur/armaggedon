# Makefile – Prime+Probe Demo (Raspberry Pi 3B, ARMv8 / Cortex-A53)
#
# Build:   make
# Clean:   make clean

CC      = gcc

# -O1         : Minimal optimisation – keeps loads visible to the CPU but
#               avoids over-aggressive dead-code / dead-store elimination.
#               (Do NOT use -O0: it adds huge stack overhead that pollutes timing.
#                Do NOT use -O2/-O3: speculative prefetch hides the timing signal.)
#
# -march=armv8-a : Enable ARMv8 instructions including DSB/ISB barriers.
#
# -Wall -Wextra  : Enable warnings.
#
# -lrt           : Link librt for shm_open / shm_unlink (POSIX shared memory).

CFLAGS  = -O1 -march=armv8-a -Wall -Wextra -g
LDFLAGS = -lrt

TARGETS = victim attacker

.PHONY: all clean

all: $(TARGETS)

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: victim"

attacker: attacker.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: attacker"

clean:
	rm -f $(TARGETS)
	# Also clean up any leftover shared memory object
	rm -f /dev/shm/pp_demo_shm
	@echo "  Cleaned."
