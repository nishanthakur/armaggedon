#include "support.h"

void initialise_board(void) { }

void start_trigger(void) {
    __asm__ volatile ("" : : : "memory");
}

void stop_trigger(void) {
    __asm__ volatile ("" : : : "memory");
}
