# Makefile — Flush+Reload Demo (Raspberry Pi 3B, ARMv8 / Cortex-A53)

CC      = gcc
CFLAGS  = -O1 -march=armv8-a -Wall -Wextra -g
# No -lrt needed: open()/mmap() on a real file; no shm_open

TARGETS = victim attacker

.PHONY: all clean run

all: $(TARGETS)

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: victim"

attacker: attacker.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: attacker"

run: all
	@bash run_demo.sh

clean:
	rm -f $(TARGETS)
	rm -f /tmp/fr_demo_spy
	@echo "  Cleaned."
