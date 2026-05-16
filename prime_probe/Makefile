# Makefile – Prime+Probe Demo v2 (Raspberry Pi 3B, ARMv8 / Cortex-A53)

CC      = gcc

# -O1             : Minimal optimisation – keeps loads visible without
#                   dead-store elimination killing our timing accesses.
# -march=armv8-a  : Enables mrs/msr/dc/dsb/isb instructions.
# -lrt            : POSIX shared memory (shm_open, shm_unlink).

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
	rm -f /dev/shm/pp_demo_shm
	@echo "  Cleaned."
