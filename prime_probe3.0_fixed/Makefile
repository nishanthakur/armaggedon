# Makefile – Prime+Probe Demo v9

CC      = gcc
CFLAGS  = -O1 -march=armv8-a -Wall -Wextra -g
LDFLAGS = -lrt

TARGETS = victim attacker

.PHONY: all clean run

all: $(TARGETS)

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: victim"

attacker: attacker.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: attacker"

run: all
	@bash run_demo.sh $(SLOT)

clean:
	rm -f $(TARGETS)
	rm -f /dev/shm/pp_demo_shm
	@echo "  Cleaned."
